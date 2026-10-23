"""Web 交互控制台：纯标准库 http.server，离线零依赖。

功能：
- 静态前端（irlog/web/）：证据管理 / 分析中心 / 告警看板 / 时间线 / IOC 情报 / 报告中心 / 审计日志
- 选择/上传证据文件（上传落盘到 evidence-dir，分析时只读打开）
- 启动分析（后台线程），进度轮询
- 告警 / 时间线 / IOC 管理 / 报告预览下载 / 历史运行 / 审计日志查询
- 全程审计留痕

安全措施：
- 静态文件与证据 API 均限制在各自目录内（防路径穿越）
- 上传文件名净化（basename + 白名单字符）
- 分析在子线程执行，不阻塞 UI；服务仅绑定 127.0.0.1（默认）
"""
from __future__ import annotations

import html
import json
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from . import __version__
from .audit import AuditLog
from .config import Config
from .detectors import ALL_DETECTORS, IOCStore
from .engine import run_analysis
from .evidence import EvidenceSet, chain_of_custody, sha256_file
from .parsers import detect_parser
from .report_html import write_html_report
from .report_json import write_json_report
from .report_playbook import write_playbook_html
from .rulepack import (RulePack, CustomRule, Pattern, builtin_inventory,
                       export_pack, parse_pack, backup_file)
from .detectors.custom import test_rule_against_text

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_UPLOAD = 2 << 30  # 2GB
SAFE_NAME = re.compile(r"[^A-Za-z0-9._\-\u4e00-\u9fff]")
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def _safe_filename(name: str) -> str:
    name = os.path.basename(name or "upload.bin")
    name = SAFE_NAME.sub("_", name)
    return name[:120] or "upload.bin"


def parse_multipart(data: bytes, boundary: bytes) -> list[tuple[str, bytes]]:
    """解析 multipart/form-data，返回 [(文件名, 内容)]。

    字节级保真：仅剥离每个 part 分隔符前的那一个 CRLF，
    文件内容自带的尾部换行、以 `--` 结尾等内容均原样保留
    （证据完整性要求，早年 rstrip 实现会损坏日志尾部）。
    """
    out: list[tuple[str, bytes]] = []
    delim = b"--" + boundary
    for part in data.split(delim):
        # 跳过前导区与结束标记（b"" / b"--" / b"--\r\n"）
        if part in (b"", b"--", b"--\r\n") or not part.startswith(b"\r\n"):
            continue
        head, sep, body = part[2:].partition(b"\r\n\r\n")
        if not sep:
            continue
        m = re.search(r'filename="([^"]*)"', head.decode("utf-8", "replace"))
        if not m:
            continue
        if body.endswith(b"\r\n"):  # 分隔符前的 CRLF，仅此一个
            body = body[:-2]
        out.append((unquote(m.group(1)), body))
    return out


class Task:
    def __init__(self, task_id: str, paths: list[str]) -> None:
        self.id = task_id
        self.paths = paths
        self.status = "running"      # running / done / error
        self.progress = 0.0
        self.message = ""
        self.result = None
        self.error = None
        self.created = time.time()


class State:
    def __init__(self, evidence_dir: str | None, workdir: str) -> None:
        self.evidence_dir = os.path.abspath(evidence_dir or os.path.join(os.getcwd(), "evidence"))
        self.workdir = os.path.abspath(workdir)
        os.makedirs(self.evidence_dir, exist_ok=True)
        os.makedirs(self.workdir, exist_ok=True)
        self.audit = AuditLog(self.workdir)
        self.tasks: dict[str, Task] = {}
        self.ioc_store = IOCStore()
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "IRLogAnalyzer/" + __version__
    state: State = None  # type: ignore

    # ---- 基础响应 ----
    def _send_json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text: str, code: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, ctype: str) -> None:
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def log_message(self, fmt, *args) -> None:  # 静默默认访问日志（审计日志另走 audit.jsonl）
        pass

    # ---- 路由 ----
    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                self._serve_static("index.html")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
            elif path == "/api/files":
                self._api_files()
            elif path == "/api/rules":
                self._send_json({
                    "version": __version__,
                    "rules": [{"id": c.rule_id, "title": c.title,
                               "description": c.description, "mitre": c.mitre}
                              for c in ALL_DETECTORS],
                })
            elif path == "/api/ioc":
                self._send_json({
                    "files": self._ioc_files(),
                    "count": len(self.state.ioc_store.items),
                    "items": self.state.ioc_store.items,
                })
            elif path == "/api/runs":
                self._api_runs()
            elif path == "/api/audit":
                qs = parse_qs(urlparse(self.path).query)
                n = min(2000, max(1, int((qs.get("n") or ["200"])[0])))
                self._send_json({"entries": self._audit_tail(n)})
            elif path.startswith("/api/task/"):
                tid = path.rsplit("/", 1)[-1]
                t = self.state.tasks.get(tid)
                if not t:
                    self._send_json({"error": "task not found"}, 404)
                    return
                payload = {"status": t.status, "progress": t.progress, "message": t.message}
                if t.status == "done":
                    payload["result"] = t.result
                if t.status == "error":
                    payload["error"] = t.error
                self._send_json(payload)
            elif path.startswith("/api/rulepack"):
                self._api_rulepack_get(path)
            elif path.startswith("/api/report/"):
                self._api_report(path.rsplit("/", 1)[-1])
            else:
                self._send_json({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            if path == "/api/upload":
                self._api_upload(length)
            elif path == "/api/analyze":
                self._api_analyze(self._read_body(length))
            elif path == "/api/ioc":
                self._api_ioc(self._read_body(length))
            elif path == "/api/rulepack":
                self._api_rulepack_post(self._read_body(length))
            elif path == "/api/rulepack/import":
                self._api_rulepack_import(self._read_body(length))
            elif path == "/api/rulepack/test":
                self._api_rulepack_test(self._read_body(length))
            else:
                self._send_json({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api/files":
                self._api_file_delete(parsed.query)
            elif path == "/api/ioc":
                self._api_ioc({"action": "clear"})
            elif path == "/api/rulepack":
                self._api_rulepack_delete(parsed.query)
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def _read_body(self, length: int) -> dict:
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # ---- 静态文件 ----
    def _serve_static(self, name: str) -> None:
        base = os.path.realpath(WEB_DIR)
        full = os.path.realpath(os.path.join(base, os.path.basename(unquote(name))))
        if not full.startswith(base + os.sep) or not os.path.isfile(full):
            self._send_json({"error": "not found"}, 404)
            return
        ext = os.path.splitext(full)[1].lower()
        self._send_file(full, STATIC_TYPES.get(ext, "application/octet-stream"))

    # ---- API 实现 ----
    def _resolve_evidence(self, name: str) -> str | None:
        """把用户提供的文件名解析到 evidence-dir 内（防路径穿越）。"""
        base = os.path.realpath(self.state.evidence_dir)
        full = os.path.realpath(os.path.join(base, os.path.basename(unquote(name))))
        if not full.startswith(base + os.sep) and full != base:
            return None
        return full if os.path.isfile(full) else None

    def _api_file_delete(self, query: str) -> None:
        """删除证据目录内的单个文件（删除前计算 SHA256 留证，全程审计）。"""
        name = (parse_qs(query).get("name") or [""])[0]
        if not name:
            self._send_json({"error": "缺少参数 name"}, 400)
            return
        base = os.path.realpath(self.state.evidence_dir)
        full = os.path.realpath(os.path.join(base, os.path.basename(unquote(name))))
        if not full.startswith(base + os.sep):
            self._send_json({"error": "非法文件路径"}, 400)
            return
        if not os.path.isfile(full):
            self._send_json({"error": "文件不存在"}, 404)
            return
        fname = os.path.basename(full)
        digest = sha256_file(full)  # 删除前留证，便于审计追溯
        try:
            os.remove(full)
        except OSError as exc:
            self._send_json({"error": f"删除失败: {exc}"}, 500)
            return
        self.state.audit.record(self.client_address[0], "delete_file", file=fname, sha256=digest)
        self._send_json({"deleted": fname})

    def _api_files(self):
        base = self.state.evidence_dir
        items = []
        if os.path.isdir(base):
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name)
                if os.path.isfile(p):
                    try:
                        parser = detect_parser(p)
                        items.append({
                            "name": name,
                            "size": os.path.getsize(p),
                            "sha256": sha256_file(p),
                            "log_type": parser.name if parser else "generic",
                            "selected": True,
                        })
                    except OSError:
                        continue
        self._send_json(items)

    def _ioc_files(self):
        out = []
        ioc_dir = os.path.join(self.state.workdir, "ioc")
        if os.path.isdir(ioc_dir):
            out = sorted(f for f in os.listdir(ioc_dir) if f.lower().endswith((".txt", ".csv")))
        return out

    def _api_runs(self):
        """历史运行列表（从工作目录的报告 JSON 提取摘要）。"""
        runs = []
        if os.path.isdir(self.state.workdir):
            for name in os.listdir(self.state.workdir):
                if not (name.startswith("IR-") and name.endswith(".json")):
                    continue
                try:
                    with open(os.path.join(self.state.workdir, name), encoding="utf-8") as f:
                        d = json.load(f)
                    runs.append({
                        "run_id": d.get("run_id", name[:-5]),
                        "started": d.get("started"),
                        "finished": d.get("finished"),
                        "duration_sec": d.get("duration_sec"),
                        "total_events": d.get("stats", {}).get("total_events"),
                        "alert_count": d.get("stats", {}).get("alert_count"),
                        "severity_summary": d.get("severity_summary", {}),
                    })
                except (OSError, json.JSONDecodeError):
                    continue
        runs.sort(key=lambda r: r["run_id"], reverse=True)
        self._send_json({"runs": runs[:100]})

    def _audit_tail(self, n: int) -> list:
        path = os.path.join(self.state.workdir, "audit.jsonl")
        if not os.path.isfile(path):
            return []
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()[-n:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _api_upload(self, length: int) -> None:
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype or length <= 0 or length > MAX_UPLOAD:
            self._send_json({"error": "invalid upload"}, 400)
            return
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
        data = self.rfile.read(length)
        saved = []
        for fname, content in parse_multipart(data, boundary):
            safe = _safe_filename(fname)
            dest = os.path.join(self.state.evidence_dir, safe)
            with open(dest, "wb") as f:
                f.write(content)
            saved.append(safe)
        if not saved:
            self._send_json({"error": "未解析到上传文件（multipart 格式异常）"}, 400)
            return
        self.state.audit.record(self.client_address[0], "upload", files=saved)
        self._send_json({"saved": saved})

    def _api_analyze(self, body: dict) -> None:
        names = body.get("files") or []
        ioc_file = body.get("ioc_file") or ""
        operator = body.get("operator") or "web-analyst"
        rules = body.get("rules") or "all"
        overrides = body.get("overrides") or []
        paths = []
        for n in names:
            p = self._resolve_evidence(n)
            if p:
                paths.append(p)
        if not paths:
            self._send_json({"error": "没有有效的证据文件"}, 400)
            return
        cfg = Config()
        cfg.rules = rules
        try:
            cfg.apply_overrides(list(overrides))
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
            return
        self.state.audit.record(self.client_address[0], "analyze-start",
                                files=names, operator=operator, rules=rules,
                                overrides=list(overrides))
        tid = uuid.uuid4().hex[:12]
        task = Task(tid, paths)
        self.state.tasks[tid] = task
        if ioc_file:
            ioc_path = os.path.join(self.state.workdir, "ioc", os.path.basename(ioc_file))
            if os.path.isfile(ioc_path):
                self.state.ioc_store.load_file(ioc_path)
        threading.Thread(target=self._run_task, args=(task, operator, cfg), daemon=True).start()
        self._send_json({"task_id": tid})

    def _run_task(self, task: Task, operator: str, cfg: Config) -> None:
        try:
            evidence = EvidenceSet()
            for p in task.paths:
                evidence.add_file(p)
            pack = RulePack.load(self.state.workdir)
            result = run_analysis(task.paths, cfg, self.state.ioc_store,
                                  progress=lambda msg, frac: self._update(task, msg, frac),
                                  rulepack=pack, workdir=self.state.workdir)
            custody = chain_of_custody(result.run_id, operator, evidence,
                                       result.started, result.finished, __version__)
            prefix = os.path.join(self.state.workdir, result.run_id)
            write_json_report(prefix + ".json", result, custody)
            write_html_report(prefix + ".html", result, custody)
            task.result = result.to_dict()
            task.result["report_json"] = prefix + ".json"
            task.result["report_html"] = prefix + ".html"
            if result.alerts:      # 有告警才产出手册
                write_playbook_html(prefix + "-playbook.html", result, custody)
                task.result["report_playbook"] = prefix + "-playbook.html"
            task.status = "done"
            task.progress = 1.0
            task.message = "分析完成"
            self.state.audit.record(operator, "analyze-done", run_id=result.run_id,
                                    alerts=len(result.alerts))
        except Exception as exc:  # noqa: BLE001
            task.status = "error"
            task.error = f"{type(exc).__name__}: {exc}"
            self.state.audit.record("system", "analyze-error", task_id=task.id, error=task.error)

    @staticmethod
    def _update(task: Task, msg: str, frac: float) -> None:
        task.message = msg
        task.progress = max(task.progress, min(1.0, frac))

    def _api_ioc(self, body: dict) -> None:
        action = body.get("action") or "add"
        store = self.state.ioc_store
        if action == "clear":
            store.items.clear()
            self.state.audit.record(self.client_address[0], "ioc-clear")
            self._send_json({"cleared": True, "count": 0})
            return
        if action == "load_file":
            fname = os.path.basename(body.get("file") or "")
            path = os.path.join(self.state.workdir, "ioc", fname)
            if not fname or not os.path.isfile(path):
                self._send_json({"error": "IOC 文件不存在"}, 400)
                return
            n = store.load_file(path)
            self.state.audit.record(self.client_address[0], "ioc-load-file", file=fname, count=n)
            self._send_json({"loaded": n, "count": len(store.items)})
            return
        text = body.get("text") or ""
        n = 0
        for line in text.splitlines():
            if line.strip() and not line.strip().startswith("#"):
                store.add(line.strip(), source="web-paste")
                n += 1
        self.state.audit.record(self.client_address[0], "ioc-import", count=n)
        self._send_json({"imported": n, "count": len(store.items)})

    def _api_report(self, run_id: str) -> None:
        qs = parse_qs(urlparse(self.path).query)
        fmt = (qs.get("format") or ["html"])[0]
        if fmt not in ("html", "json", "playbook"):
            fmt = "html"
        safe_id = re.sub(r"[^A-Za-z0-9\-]", "", run_id)
        if fmt == "playbook":
            path = os.path.join(self.state.workdir, f"{safe_id}-playbook.html")
        else:
            path = os.path.join(self.state.workdir, f"{safe_id}.{fmt}")
        if not os.path.isfile(path):
            self._send_json({"error": "report not found"}, 404)
            return
        self.state.audit.record(self.client_address[0], "report-download", run_id=safe_id, fmt=fmt)
        ctype = ("text/html; charset=utf-8" if fmt in ("html", "playbook")
                 else "application/json")
        self._send_file(path, ctype)

    # ---- 规则库管理 ----
    def _rulepack(self) -> RulePack:
        return RulePack.load(self.state.workdir)

    def _api_rulepack_get(self, path: str) -> None:
        if path == "/api/rulepack/export":
            pack = self._rulepack()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="irlog-rules-pack.json"')
            data = export_pack(pack)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.state.audit.record(self.client_address[0], "rulepack-export")
            return
        pack = self._rulepack()
        custom = [r.to_dict() for r in pack.rules.values()]
        self._send_json({
            "version": __version__,
            "updated": pack.to_dict().get("updated_human"),
            "disabled_builtin": pack.disabled_builtin,
            "builtin": builtin_inventory(),
            "custom": custom,
            "custom_count": len(pack.custom_rules()),
            "attachment_count": sum(1 for r in pack.rules.values() if r.attaches_to),
            "rule_file": RulePack.path_of(self.state.workdir),
        })

    def _build_rule(self, body: dict) -> tuple[CustomRule, list]:
        rid = (body.get("rule_id") or "").strip()
        try:
            severity = int(body.get("severity", 3))
        except (TypeError, ValueError):
            severity = 3
        rule = CustomRule(
            rule_id=rid,
            title=(body.get("title") or "").strip(),
            severity=severity,
            description=(body.get("description") or "").strip(),
            mitre=(body.get("mitre") or "").strip(),
            recommendation=(body.get("recommendation") or "").strip(),
            scope=(body.get("scope") or "all").strip(),
            attaches_to=(body.get("attaches_to") or "").strip() or None,
            enabled=bool(body.get("enabled", True)),
        )
        for i, p in enumerate(body.get("patterns") or []):
            rule.patterns.append(Pattern(
                id=(p.get("id") or f"p{i+1}").strip(),
                kind=(p.get("kind") or "keyword").strip(),
                value=(p.get("value") or "").strip(),
                note=(p.get("note") or "").strip(),
                enabled=bool(p.get("enabled", True)),
            ))
        errs = rule.validate()
        return rule, errs

    def _api_rulepack_post(self, body: dict) -> None:
        rule, errs = self._build_rule(body)
        if errs:
            self._send_json({"error": "；".join(errs)}, 400)
            return
        pack = self._rulepack()
        is_new = rule.rule_id not in pack.rules
        pack.upsert(rule)
        pack.save(self.state.workdir)
        self.state.audit.record(self.client_address[0], "rulepack-upsert",
                                rule_id=rule.rule_id, is_new=is_new,
                                attaches_to=rule.attaches_to)
        self._send_json({"ok": True, "is_new": is_new, "rule_id": rule.rule_id,
                         "rule": rule.to_dict()})

    def _api_rulepack_delete(self, query: str) -> None:
        rid = (parse_qs(query).get("id") or [""])[0].strip()
        if not rid:
            self._send_json({"error": "缺少参数 id"}, 400)
            return
        pack = self._rulepack()
        if pack.remove(rid):
            pack.save(self.state.workdir)
            self.state.audit.record(self.client_address[0], "rulepack-delete", rule_id=rid)
            self._send_json({"deleted": rid})
        else:
            self._send_json({"error": "规则不存在"}, 404)

    def _api_rulepack_import(self, body: dict) -> None:
        mode = (body.get("mode") or "merge").strip()
        content = body.get("content") or ""
        if isinstance(content, (list, dict)):
            import json as _json
            content = _json.dumps(content)
        pack, err = parse_pack(content.encode("utf-8"))
        if err:
            self._send_json({"error": err}, 400)
            return
        cur = self._rulepack()
        if mode == "replace":
            # 替换前先备份现库
            backup_file(RulePack.path_of(self.state.workdir))
            cur.replace_with(pack)
        else:
            cur.merge(pack)
        cur.save(self.state.workdir)
        self.state.audit.record(self.client_address[0], "rulepack-import",
                                mode=mode, rules=len(pack.rules))
        self._send_json({"ok": True, "mode": mode, "rules": len(pack.rules),
                         "total": len(cur.rules)})

    def _api_rulepack_test(self, body: dict) -> None:
        text = body.get("text") or ""
        rule, errs = self._build_rule(body.get("rule") or {})
        if errs:
            self._send_json({"error": "；".join(errs)}, 400)
            return
        res = test_rule_against_text(rule, text)
        matched = any(r.get("ok") for r in res)
        self._send_json({"matched": matched, "results": res})


def run_server(host: str = "127.0.0.1", port: int = 8611,
               evidence_dir: str | None = None, workdir: str = "irlog-output") -> int:
    state = State(evidence_dir, workdir)
    Handler.state = state
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[Web] 应急响应日志分析平台已启动（交互控制台）")
    print(f"[Web] 访问地址: http://{host}:{port}")
    print(f"[Web] 证据目录: {state.evidence_dir}")
    print(f"[Web] 工作目录: {state.workdir}（报告/IOC/审计日志）")
    print(f"[Web] 按 Ctrl+C 停止服务")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Web] 服务已停止")
    finally:
        httpd.server_close()
    return 0

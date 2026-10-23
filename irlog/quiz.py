"""取证问答引擎（靶场题型自动求解）。

针对 Web 访问日志（IIS W3C / Nginx / Apache）单遍流式求解取证题目，并给出
每一步的判定依据与原始证据，避免"只给数字不给理由"。

内置题型：
  Q1 指定状态码（默认 200）请求数量
  Q2 出现的请求方法种类数
  Q3 存在文件上传漏洞的路径（上传接口）
  Q4 攻击者上传并成功利用的 Webshell 文件名
  Q5 4xx 客户端错误条数
  FLAG 按模板拼接上述答案

判定思路（Q3/Q4 是关联分析，不能靠单点特征）：
  上传接口 = 请求中带上传语义（路径/参数关键词、PUT 方法）+ 服务端成功响应
             + 其后出现了"此前从未被请求过的脚本文件"；三项互相印证才计高分。
  Webshell  = 上传之后首次出现的脚本文件 + 被 POST 交互且返回成功
             + 客户端 UA 命中已知木马客户端指纹 + 响应耗时异常 + 参数含执行语义。
"""
from __future__ import annotations

import os
import re
import time
from typing import Optional

from .models import Event, A_HTTP_REQUEST
from .parsers import iter_events
from .webstats import WebStats

# ---- 上传语义 ----
# 强特征：本身就是上传/写入语义
UPLOAD_PATH_STRONG_RE = re.compile(
    r"(upload|upfile|upimg|upattach|import|editor|kindeditor|ueditor|fckeditor|"
    r"ckeditor|filemanager|attachment|swfupload|fileupload)", re.I)
# 弱特征：CMS 的插件/模板/主题安装类入口，常被用于"上传压缩包 getshell"
UPLOAD_PATH_WEAK_RE = re.compile(r"(plugin|template|theme|widget|media|install|zip)", re.I)
UPLOAD_QUERY_RE = re.compile(
    r"(action=(upload|upfile|upimg|upload_zip|import|install|addattach|addfile|addimage|addmedia)|"
    r"upload_zip|upfile|upimg|"
    r"(?:^|[?&])(do|op|mode|a|m|s|task|act)=upload|swfupload|import|"
    r"type=file|fileupload|ajax_upload)", re.I)

# ---- 可执行脚本后缀 ----
SCRIPT_EXTS = ("php", "php3", "php4", "php5", "php7", "phtml", "pht", "phar",
               "asp", "aspx", "asa", "cer", "cdx", "ashx", "asmx",
               "jsp", "jspx", "jspa", "jsw", "jsv", "jtml", "war", "do")

# ---- Webshell 客户端 / 管理工具 UA 指纹 ----
# 中国菜刀（China Chopper）客户端默认 UA 集合
CHINA_CHOPPER_UAS = (
    "opera/9.80 (windows nt 5.1; u; en) presto/2.9.168 version/11.51",
    "mozilla/5.0 (x11; linux x86_64; rv:28.0) gecko/20100101 firefox/28.0",
    "mozilla/5.0 (windows nt 6.1; wow64; rv:31.0) gecko/20130401 firefox/31.0",
    "mozilla/5.0 (macintosh; u; intel mac os x 10_6_6; ko-kr) applewebkit/533.20.25 "
    "(khtml, like gecko) version/5.0.4 safari/533.20.27",
    "mozilla/5.0 (x11; openbsd amd64; rv:28.0) gecko/20100101 firefox/28.0",
    "mozilla/5.0 (x11; linux x86_64) applewebkit/537.36 (khtml, like gecko) "
    "chrome/34.0.1847.137 safari/4e423f",
    "mozilla/5.0 (windows nt 6.1; wow64; rv:31.0) gecko/20130401 firefox/31.0",
)
SHELL_CLIENT_RE = re.compile(r"(antsword|godzilla|behinder|冰蝎|哥斯拉|蚁剑|caidao|chopper)", re.I)

# ---- 执行语义参数 ----
EXEC_PARAM_RE = re.compile(
    r"(?:^|[?&;])(cmd|exec|command|code|payload|eval|system|passthru|shell_exec|"
    r"assert|base64_decode|call_user_func|preg_replace|pass|x|z0|z1|z2|func)\s*=", re.I)

STATIC_EXT_RE = re.compile(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map|txt|xml)$", re.I)

# 写方法：即使返回 404 也要记录（攻击者可能用 PUT/POST 探测上传点）
WRITE_METHODS = ("POST", "PUT", "DELETE", "PATCH")

FLAG_TEMPLATE = "flag{%s-%s-%s-%s-%s}"


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _ext(path: str) -> str:
    tail = path.rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[-1].lower() if "." in tail else ""


_WS_RE = re.compile(r"\s+")


def _ua_norm(s: str) -> str:
    """IIS W3C 把 UA 中的空格写成 '+'（连续空格会变成 ++），统一还原并压缩空白。"""
    return _WS_RE.sub(" ", (s or "").replace("+", " ")).strip().lower()


class QuizEngine:
    """流式消费事件 -> 求解取证题目。"""

    def __init__(self, config=None, max_records: int = 200000, stats: Optional[WebStats] = None) -> None:
        self.config = config
        # 与引擎共用统计器时不再重复累加（stats 由引擎统一驱动）
        self._own_stats = stats is None
        self.stats = stats if stats is not None else WebStats()
        self.max_records = max_records
        self.records: dict = {}          # path -> 聚合记录（仅记录非 404 或写方法的路径）
        self.upload_events: list = []    # 上传动作候选（原始证据）
        self.total_seen = 0

    # ---------------- 采集 ----------------
    def feed(self, ev: Event) -> None:
        if ev.action != A_HTTP_REQUEST:
            return
        self.total_seen += 1
        if self._own_stats:
            self.stats.feed(ev)
        # 热路径：绝大多数事件是 404 扫描噪音，先做最廉价的判断再进入记录逻辑
        status = ev.status
        method = (ev.method or "").upper()
        if status == 404 and method not in WRITE_METHODS:
            return
        path = (ev.uri or "").split("?", 1)[0]
        if not path:
            return
        query = ev.uri.split("?", 1)[1] if "?" in (ev.uri or "") else ""
        if path not in self.records and len(self.records) >= self.max_records:
            return
        rec = self.records.setdefault(path, {
            "count": 0, "methods": set(), "statuses": {}, "first_ts": None, "last_ts": None,
            "queries": set(), "uas": set(), "post_ok": 0, "get_ok": 0, "put": 0,
            "max_time_taken": 0, "ips": set(), "evidence": [], "after_upload": False,
        })
        rec["count"] += 1
        rec["methods"].add(method)
        if status is not None:
            rec["statuses"][status] = rec["statuses"].get(status, 0) + 1
        if query and len(rec["queries"]) < 8:
            rec["queries"].add(query[:200])
        if ev.user_agent and len(rec["uas"]) < 6:
            rec["uas"].add(ev.user_agent[:160])
        if ev.src_ip:
            rec["ips"].add(ev.src_ip)
        if method == "POST" and status is not None and 200 <= status < 400:
            rec["post_ok"] += 1
        if method == "GET" and status is not None and 200 <= status < 400:
            rec["get_ok"] += 1
        if method == "PUT":
            rec["put"] += 1
        tt = ev.detail.get("time_taken")
        if tt:
            try:
                rec["max_time_taken"] = max(rec["max_time_taken"], int(tt))
            except ValueError:
                pass
        if ev.ts is not None:
            rec["first_ts"] = ev.ts if rec["first_ts"] is None else min(rec["first_ts"], ev.ts)
            rec["last_ts"] = ev.ts if rec["last_ts"] is None else max(rec["last_ts"], ev.ts)
        if len(rec["evidence"]) < 5:
            rec["evidence"].append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.ts)) if ev.ts else None,
                "ip": ev.src_ip, "method": method, "status": status,
                "uri": ev.uri, "ua": ev.user_agent,
                "raw": ev.raw[:500],
            })

    # ---------------- 求解 ----------------
    def _upload_candidates(self) -> list:
        """带上传语义的接口候选 + 打分。"""
        out = []
        for path, rec in self.records.items():
            if "POST" not in rec["methods"] and "PUT" not in rec["methods"]:
                continue
            if STATIC_EXT_RE.search(path):
                continue
            qtext = " ".join(rec["queries"]).lower()
            score = 0
            reasons = []
            if UPLOAD_QUERY_RE.search(qtext):
                score += 4
                reasons.append("请求参数含上传动作语义")
            if UPLOAD_PATH_STRONG_RE.search(path):
                score += 3
                reasons.append("路径含上传/文件管理类关键词")
            elif UPLOAD_PATH_WEAK_RE.search(path):
                score += 1
                reasons.append("路径含插件/模板/安装类关键词（CMS 压缩包上传入口）")
            if rec["put"]:
                score += 2
                reasons.append(f"PUT 方法（WebDAV 写入）{rec['put']} 次")
            ok = sum(v for s, v in rec["statuses"].items() if 200 <= s < 400)
            if ok:
                score += 3
                reasons.append(f"服务端成功响应 {ok} 次")
            else:
                score -= 3
                reasons.append("无成功响应（未利用成功）")
            if score <= 0:
                continue
            out.append({
                "path": path, "score": score, "reasons": reasons,
                "count": rec["count"], "ok": ok,
                "first_ts": rec["first_ts"], "last_ts": rec["last_ts"],
                "methods": sorted(rec["methods"]), "statuses": dict(sorted(rec["statuses"].items())),
                "queries": sorted(rec["queries"])[:5], "ips": sorted(rec["ips"])[:5],
                "evidence": rec["evidence"][:3],
            })
        # 与"上传后出现的新脚本"做关联加分
        scripts = [(p, r["first_ts"]) for p, r in self.records.items()
                   if _ext(p) in SCRIPT_EXTS and r["first_ts"]]
        for cand in out:
            base = cand["first_ts"]
            if not base:
                continue
            born = [p for p, ts in scripts if base - 5 <= ts <= base + 7200]
            if born:
                cand["score"] += 4
                cand["reasons"].append(f"其后首次出现 {len(born)} 个新脚本文件（疑似落盘）")
                cand["born_files"] = sorted(born)[:10]
        return sorted(out, key=lambda x: (-x["score"], x["path"]))

    def _webshell_candidates(self, upload: Optional[dict]) -> list:
        out = []
        base_ts = upload["first_ts"] if upload else None
        for path, rec in self.records.items():
            ext = _ext(path)
            if ext not in SCRIPT_EXTS:
                continue
            if STATIC_EXT_RE.search(path):
                continue
            score = 0
            reasons = []
            # 1) 上传之后才首次出现（此前日志中从未被成功访问过）
            if base_ts and rec["first_ts"] and rec["first_ts"] >= base_ts - 5:
                score += 3
                reasons.append("在上传动作之后首次出现（此前未被访问过）")
            # 2) 木马客户端交互：POST 且成功
            if rec["post_ok"]:
                score += 5
                reasons.append(f"POST 交互成功 {rec['post_ok']} 次（木马客户端特征）")
            # 3) UA 指纹（IIS 日志用 '+' 代替空格，比较前需还原）
            uas = _ua_norm(" || ".join(rec["uas"]))
            if any(u in uas for u in CHINA_CHOPPER_UAS):
                score += 5
                reasons.append("客户端 UA 命中中国菜刀/China Chopper 指纹")
            elif SHELL_CLIENT_RE.search(uas):
                score += 5
                reasons.append("客户端 UA 命中冰蝎/哥斯拉/蚁剑等木马客户端")
            # 4) 执行语义参数
            if any(EXEC_PARAM_RE.search(q) for q in rec["queries"]):
                score += 3
                reasons.append("请求参数含命令执行语义")
            # 5) 响应成功
            if any(200 <= s < 300 for s in rec["statuses"]):
                score += 2
                reasons.append("存在 200 成功响应（文件真实存在）")
            if 500 in rec["statuses"] and not any(200 <= s < 300 for s in rec["statuses"]):
                score -= 2
                reasons.append("仅返回 500（脚本执行报错，未利用成功）")
            # 6) 响应耗时异常（命令执行）
            if rec["max_time_taken"] >= 1000:
                score += 2
                reasons.append(f"响应耗时 {rec['max_time_taken']}ms（疑似执行系统命令）")
            # 7) 位于可写目录
            if re.search(r"/(content|upload|uploads|images|files|attachments|plugins|themes|templates)/", path, re.I):
                score += 1
                reasons.append("位于可写/资源目录")
            if score <= 0:
                continue
            out.append({
                "path": path, "file": path.rsplit("/", 1)[-1], "score": score,
                "reasons": reasons, "count": rec["count"],
                "first_ts": rec["first_ts"], "last_ts": rec["last_ts"],
                "methods": sorted(rec["methods"]), "statuses": dict(sorted(rec["statuses"].items())),
                "uas": sorted(rec["uas"])[:4], "ips": sorted(rec["ips"])[:5],
                "max_time_taken": rec["max_time_taken"],
                "evidence": rec["evidence"][:4],
            })
        return sorted(out, key=lambda x: (-x["score"], x["path"]))

    def solve(self, status_code: int = 200) -> dict:
        uploads = self._upload_candidates()
        top_upload = uploads[0] if uploads else None
        shells = self._webshell_candidates(top_upload)
        top_shell = shells[0] if shells else None

        n200 = self.stats.count_status(status_code)
        methods = self.stats.methods()
        n4xx = self.stats.count_status_class("4xx")
        upload_path = top_upload["path"] if top_upload else None
        shell_file = top_shell["file"] if top_shell else None
        flag = FLAG_TEMPLATE % (n200, len(methods), upload_path or "?",
                                shell_file or "?", n4xx)

        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "questions": [
                {
                    "no": 1, "title": f"状态码为 {status_code} 的请求数量",
                    "answer": n200, "answer_text": str(n200),
                    "reason": f"全量日志中 sc-status={status_code} 的条目计数",
                    "detail": dict(sorted(self.stats.by_status.items(), key=lambda kv: str(kv[0]))),
                },
                {
                    "no": 2, "title": "出现了多少种请求方法",
                    "answer": len(methods), "answer_text": str(len(methods)),
                    "reason": "按 cs-method 去重计数",
                    "detail": {m: c for m, c in methods},
                },
                {
                    "no": 3, "title": "存在文件上传漏洞的路径",
                    "answer": upload_path, "answer_text": upload_path or "未识别",
                    "reason": "；".join(top_upload["reasons"]) if top_upload else "未发现带上传语义且响应成功的接口",
                    "candidates": uploads[:5],
                },
                {
                    "no": 4, "title": "攻击者上传并利用成功的 Webshell 文件名",
                    "answer": shell_file, "answer_text": shell_file or "未识别",
                    "reason": "；".join(top_shell["reasons"]) if top_shell else "未发现上传后被成功利用的脚本文件",
                    "candidates": shells[:5],
                },
                {
                    "no": 5, "title": "4xx 客户端请求错误条数",
                    "answer": n4xx, "answer_text": str(n4xx),
                    "reason": "状态码 400-499 全部条目计数",
                    "detail": {str(k): v for k, v in sorted(self.stats.by_status.items()) if 400 <= k < 500},
                },
            ],
            "flag": flag,
            "flag_template": FLAG_TEMPLATE,
            "web_stats": self.stats.to_dict(),
            "top_upload": top_upload,
            "top_shell": top_shell,
        }


def run_quiz(paths: list[str], config=None, status_code: int = 200,
             progress=None) -> dict:
    """对一批日志文件求解取证题目。"""
    eng = QuizEngine(config)
    for i, p in enumerate(paths):
        if not os.path.isfile(p):
            continue
        try:
            for ev in iter_events(p):
                eng.feed(ev)
        except Exception as exc:  # 单文件失败不影响整体
            if progress:
                progress(f"[跳过] {p}: {type(exc).__name__}: {exc}", 1.0)
        if progress:
            progress(f"[{i + 1}/{len(paths)}] 已统计 {p}", 1.0)
    return eng.solve(status_code)

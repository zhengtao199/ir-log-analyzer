"""Web 日志统计分析器。

应急响应里常要先回答一类「事实型」问题：状态码 200 有多少条、出现了几种
请求方法、4xx 有多少条、谁在扫描、上传漏洞走的是哪个路径、webshell 落地
在哪个文件。这些不是「威胁告警」，而是**统计结论**，因此单独成一个模块。

内存策略：全部是聚合计数与有上限的采样列表，key  cardinality 有封顶
（超限后只增量、不新增 key），GB 级访问日志也能在常量内存下跑完。
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .models import (A_HTTP_REQUEST, A_LOGON_FAILED, A_LOGON_SUCCESS, A_DB_QUERY,
                    A_DB_ADMIN, A_COMMAND_EXEC, A_SUDO_COMMAND, A_USER_CREATED,
                    A_GROUP_MEMBER_ADDED, A_SERVICE_INSTALL, A_SCHEDULED_TASK,
                    A_PROCESS_CREATE, Event)

# ---------------------------------------------------------------- 常量

SCRIPT_EXTS = frozenset((
    "php", "phtml", "php3", "php4", "php5", "php7", "phps", "inc",
    "jsp", "jspx", "jspa", "jsw", "jsv", "war", "jar",
    "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx", "cer",
    "cgi", "pl", "py", "rb", "sh",
))

# Web 可写/可落地目录：攻击者上传的 webshell 通常落在这里。
# 刻意不放 includes/libs/api/data 这类源码/数据目录 —— 遍历读到源码是
# 「敏感文件泄露」（归 web-attack），不是可写目录，混在一起会大量误报。
WRITABLE_DIRS_RE = re.compile(
    r"/(?:content/plugins|plugins|uploads?|uploadfiles?|uploadfile|"
    r"attach(?:ment)?s?|tmp|temp|cache|runtime|"
    r"static/upload|editor|ueditor|kindeditor|fckeditor|userfiles|media|"
    r"wp-content/(?:uploads|plugins))/", re.I)

# 登录动作（强信号：后台登录页的 POST）
LOGIN_ACTION_RE = re.compile(
    r"(?:^|[?&])(?:action|do|act|op|m|a)\s*=\s*"
    r"(?:do)?(?:login|log_in|signin|sign_in|dologin|dosignin|userlogin|"
    r"admin_login|checklogin|login_check|auth|verify)"
    r"|(?:^|[?&])(?:login|signin|password|passwd|pwd)\s*="
    r"|/(?:wp-login|login|signin|log_in|admin/login|user/login|member/login|"
    r"system/login|manage/login|backend/login)\.php", re.I)

# 上传动作（文件上传漏洞的入口特征）
UPLOAD_ACTION_RE = re.compile(
    r"(?:^|[?&])(?:action|do|act|op|m|a|cmd|method)\s*=\s*[^&]*upload"
    r"|(?:^|[?&])(?:upload|upfile|file_upload|uploadfile|attach|attachment|"
    r"import|file)\s*="
    r"|/(?:upload|upfile|attachment|attach|import|file|uploadfile)"
    r"(?:\.php|\.asp|\.aspx|\.jsp|\.cgi|[/?]|$)", re.I)

# 参数 fuzzing 特征：URI 里堆了大量参数名（扫描器行为），
# 此时其中的 code=/cmd= 之类不能当作 webshell 证据
PARAM_FUZZ_MIN = 12


def script_ext_of(path: str) -> Optional[str]:
    """取路径的脚本扩展名（小写），非脚本返回 None。"""
    base = path.rsplit("/", 1)[-1]
    if "." not in base:
        return None
    ext = base.rsplit(".", 1)[-1].lower()
    return ext if ext in SCRIPT_EXTS else None


def param_count(uri: str) -> int:
    """统计 URI 查询串里的参数个数（用于识别 fuzzing）。"""
    q = uri.find("?")
    if q < 0:
        return 0
    tail = uri[q + 1:]
    if not tail:
        return 0
    n = 0
    for part in tail.split("&"):
        if part and "=" in part:
            n += 1
    return n


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class WebLogStats:
    """Web 访问日志统计累积器（喂 A_HTTP_REQUEST 事件）。

    用法::

        stats = WebLogStats()
        for ev in events:
            stats.feed(ev)
        summary = stats.to_dict()
    """

    # 各类 key 的 cardinality 上限（超限只增量不新增，保证常量内存）
    MAX_URI_KEYS = 5000
    MAX_IP_KEYS = 5000
    MAX_PATH_KEYS = 8000
    # 安全相关事件的采样上限
    MAX_EVENTS = 200

    def __init__(self) -> None:
        self.total = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.status_counts: dict[int, int] = {}
        self.method_counts: dict[str, int] = {}
        self.client_counts: dict[str, int] = {}
        self.uri_counts: dict[str, int] = {}
        self.script_post_counts: dict[str, int] = {}   # (ip|path) -> 次数
        self.path_first_seen: dict[str, float] = {}     # 脚本路径 -> 首次出现时间

        # 安全相关采样
        self.login_success: list[dict] = []
        self.uploads: list[dict] = []
        self.webshell_hits: list[dict] = []

    # ------------------------------------------------------------ 摄取

    def feed(self, ev: Event) -> None:
        if ev.action != A_HTTP_REQUEST:
            return
        self.total += 1
        if ev.ts is not None:
            if self.first_ts is None or ev.ts < self.first_ts:
                self.first_ts = ev.ts
            if self.last_ts is None or ev.ts > self.last_ts:
                self.last_ts = ev.ts

        if ev.status is not None:
            self.status_counts[ev.status] = self.status_counts.get(ev.status, 0) + 1
        method = (ev.method or "?").upper()
        self.method_counts[method] = self.method_counts.get(method, 0) + 1

        ip = ev.src_ip or "-"
        if ip in self.client_counts or len(self.client_counts) < self.MAX_IP_KEYS:
            self.client_counts[ip] = self.client_counts.get(ip, 0) + 1

        uri = ev.uri or ""
        if uri:
            # 超长 fuzzing URI 截断后做 key，避免把内存撑爆
            key = uri if len(uri) <= 300 else uri[:300]
            if key in self.uri_counts or len(self.uri_counts) < self.MAX_URI_KEYS:
                self.uri_counts[key] = self.uri_counts.get(key, 0) + 1

        self._track_security(ev, ip, uri, method)

    def _track_security(self, ev: Event, ip: str, uri: str, method: str) -> None:
        path = uri.split("?", 1)[0]
        status = ev.status
        ext = script_ext_of(path)
        if ext is None:
            return

        # 1) 脚本路径首次出现时间（用于「上传后落地」判定）
        if path in self.path_first_seen or len(self.path_first_seen) < self.MAX_PATH_KEYS:
            prev = self.path_first_seen.get(path)
            if prev is None or (ev.ts is not None and ev.ts < prev):
                self.path_first_seen[path] = ev.ts if ev.ts is not None else prev or 0.0

        # 2) 后台登录成功：POST + 登录动作 + 302/200
        if method == "POST" and status in (200, 302) and LOGIN_ACTION_RE.search(uri):
            self._push(self.login_success, {
                "ts": ev.ts, "ip": ip, "method": method, "uri": uri,
                "status": status, "user_agent": ev.user_agent,
            })

        # 3) 文件上传：POST/PUT + 上传动作 + 成功状态
        if method in ("POST", "PUT") and status in (200, 201, 204, 302) \
                and UPLOAD_ACTION_RE.search(uri):
            self._push(self.uploads, {
                "ts": ev.ts, "ip": ip, "method": method, "uri": uri,
                "status": status, "user_agent": ev.user_agent,
            })

        # 4) Webshell 交互：POST 到脚本且成功（可写目录内的脚本最可疑）
        if method == "POST" and status == 200:
            k = f"{ip}|{path}"
            if k in self.script_post_counts or len(self.script_post_counts) < self.MAX_PATH_KEYS:
                self.script_post_counts[k] = self.script_post_counts.get(k, 0) + 1
            if WRITABLE_DIRS_RE.search(path):
                self._push(self.webshell_hits, {
                    "ts": ev.ts, "ip": ip, "uri": uri, "ext": ext,
                    "count": self.script_post_counts.get(k, 0),
                    "writable": True,
                })

    def _push(self, bucket: list, item: dict) -> None:
        if len(bucket) < self.MAX_EVENTS:
            bucket.append(item)

    # ------------------------------------------------------------ 派生结论

    def post_upload_scripts(self) -> list[dict]:
        """上传动作之后才首次出现的脚本（疑似上传落地的 webshell）。

        判定：脚本路径的首次出现时间 >= 某次上传的时间，且该脚本被 POST 成功访问过。
        """
        if not self.uploads or not self.path_first_seen:
            return []
        earliest_upload = min(u["ts"] for u in self.uploads if u.get("ts") is not None) \
            if any(u.get("ts") is not None for u in self.uploads) else None
        if earliest_upload is None:
            return []
        out = []
        for key, cnt in self.script_post_counts.items():
            ip, _, path = key.partition("|")
            first = self.path_first_seen.get(path)
            if first is None or first < earliest_upload:
                continue
            out.append({
                "ip": ip, "path": path, "first_seen": first, "post_count": cnt,
                "writable": bool(WRITABLE_DIRS_RE.search(path)),
            })
        out.sort(key=lambda x: -x["post_count"])
        return out

    # ------------------------------------------------------------ 输出

    def status_class_summary(self) -> dict:
        """按 2xx/3xx/4xx/5xx 汇总。"""
        buckets = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
        for code, n in self.status_counts.items():
            b = f"{code // 100}xx"
            if b in buckets:
                buckets[b] += n
        return buckets

    def to_dict(self) -> dict:
        top_uris = sorted(self.uri_counts.items(), key=lambda kv: -kv[1])[:20]
        top_ips = sorted(self.client_counts.items(), key=lambda kv: -kv[1])[:20]
        landed = self.post_upload_scripts()
        return {
            "total_requests": self.total,
            "first_time": _fmt_ts(self.first_ts),
            "last_time": _fmt_ts(self.last_ts),
            "status_counts": {str(k): v for k, v in sorted(self.status_counts.items())},
            "status_class_summary": self.status_class_summary(),
            "method_counts": dict(sorted(self.method_counts.items(),
                                         key=lambda kv: -kv[1])),
            "method_kinds": len(self.method_counts),
            "client_error_4xx": sum(n for c, n in self.status_counts.items() if 400 <= c < 500),
            "server_error_5xx": sum(n for c, n in self.status_counts.items() if 500 <= c < 600),
            "success_2xx": sum(n for c, n in self.status_counts.items() if 200 <= c < 300),
            "top_client_ips": [{"ip": k, "count": v} for k, v in top_ips],
            "top_uris": [{"uri": k, "count": v} for k, v in top_uris],
            "distinct_uris": len(self.uri_counts),
            "distinct_clients": len(self.client_counts),
            "login_success": [_with_time(e) for e in self.login_success],
            "uploads": [_with_time(e) for e in self.uploads],
            "webshell_hits": [_with_time(e) for e in self.webshell_hits[:20]],
            "post_upload_scripts": [_with_time(e) for e in landed],
            "attack_chain": self._chain(landed),
        }

    def _chain(self, landed: list[dict]) -> list[dict]:
        """还原「登录后台 -> 上传 -> webshell 落地 -> 交互」链路。"""
        chain = []
        for e in self.login_success[:5]:
            chain.append({"stage": "后台登录成功", "ts": _fmt_ts(e.get("ts")),
                          "detail": f"{e.get('ip')} {e.get('method')} {e.get('uri')}"
                                    f" -> {e.get('status')}"})
        for e in self.uploads[:5]:
            chain.append({"stage": "文件上传", "ts": _fmt_ts(e.get("ts")),
                          "detail": f"{e.get('ip')} {e.get('method')} {e.get('uri')}"
                                    f" -> {e.get('status')}"})
        for e in landed[:5]:
            chain.append({"stage": "脚本落地", "ts": _fmt_ts(e.get("first_seen")),
                          "detail": f"{e.get('path')}（上传后首次出现，POST 成功 "
                                    f"{e.get('post_count')} 次）"})
        for e in self.webshell_hits[:5]:
            chain.append({"stage": "后门交互", "ts": _fmt_ts(e.get("ts")),
                          "detail": f"{e.get('ip')} POST {e.get('uri')} -> 200"})
        return chain


def _with_time(d: dict) -> dict:
    out = dict(d)
    out["time"] = _fmt_ts(d.get("ts"))
    return out


# ================================================================ Windows

# 重点 Windows 事件 ID（含 Sysmon）
WIN_LOGON_FAIL = "4625"
WIN_LOGON_OK = "4624"
WIN_EXPLICIT_CRED = "4648"
WIN_NTLM_FAIL = "4776"
WIN_SPECIAL_PRIV = "4672"
WIN_ACCOUNT_IDS = {"4720", "4722", "4724", "4726", "4738", "4798"}
WIN_GROUP_IDS = {"4728", "4732", "4756"}
WIN_SERVICE_IDS = {"7045", "4697"}
WIN_TASK_IDS = {"4698", "4702"}
WIN_PROC_CREATE = {"4688", "1"}
WIN_LOG_CLEARED = {"1102", "104"}
WIN_AUDIT_POLICY = {"4719"}
WIN_SHARE_ACCESS = {"5140", "5145"}


class WindowsLogStats:
    """Windows 安全 / Sysmon 日志统计：登录、账号变更、持久化、日志清除。"""

    MAX_KEYS = 5000

    def __init__(self) -> None:
        self.total = 0
        self.event_counts: dict[str, int] = {}
        self.logon_failed = 0
        self.logon_success = 0
        self.logon_type_counts: dict[str, int] = {}
        self.fail_by_ip: dict[str, int] = {}
        self.fail_by_user: dict[str, int] = {}
        self.ok_by_ip: dict[str, int] = {}
        self.account_changes: list[dict] = []
        self.group_changes: list[dict] = []
        self.services: list[dict] = []
        self.tasks: list[dict] = []
        self.log_cleared: list[dict] = []
        self.audit_policy: list[dict] = []
        self.share_access: list[dict] = []
        self.proc_creates = 0
        self._cap = 100

    def feed(self, ev: Event) -> None:
        self.total += 1
        eid = str(ev.event_id or "").strip()
        if eid:
            if eid in self.event_counts or len(self.event_counts) < 200:
                self.event_counts[eid] = self.event_counts.get(eid, 0) + 1

        if ev.action == A_LOGON_FAILED or eid == WIN_LOGON_FAIL:
            self.logon_failed += 1
            self._bump(self.fail_by_ip, ev.src_ip)
            self._bump(self.fail_by_user, ev.user)
        elif ev.action == A_LOGON_SUCCESS or eid == WIN_LOGON_OK:
            self.logon_success += 1
            self._bump(self.ok_by_ip, ev.src_ip)
            lt = ev.logon_type or "?"
            self.logon_type_counts[lt] = self.logon_type_counts.get(lt, 0) + 1

        if eid in WIN_ACCOUNT_IDS:
            self._push(self.account_changes, ev, eid)
        if eid in WIN_GROUP_IDS:
            self._push(self.group_changes, ev, eid)
        if eid in WIN_SERVICE_IDS:
            self._push(self.services, ev, eid)
        if eid in WIN_TASK_IDS:
            self._push(self.tasks, ev, eid)
        if eid in WIN_LOG_CLEARED:
            self._push(self.log_cleared, ev, eid)
        if eid in WIN_AUDIT_POLICY:
            self._push(self.audit_policy, ev, eid)
        if eid in WIN_SHARE_ACCESS:
            self._push(self.share_access, ev, eid)
        if eid in WIN_PROC_CREATE or ev.action == A_PROCESS_CREATE:
            self.proc_creates += 1

    def _bump(self, d: dict, key) -> None:
        if not key:
            return
        if key in d or len(d) < self.MAX_KEYS:
            d[key] = d.get(key, 0) + 1

    def _push(self, bucket: list, ev: Event, eid: str) -> None:
        if len(bucket) < self._cap:
            bucket.append({"ts": ev.ts, "event_id": eid, "user": ev.user,
                           "src_ip": ev.src_ip, "host": ev.host,
                           "process": ev.process, "file_path": ev.file_path,
                           "source": ev.source, "raw": ev.raw[:400]})

    def to_dict(self) -> dict:
        return {
            "total_events": self.total,
            "event_counts": dict(sorted(self.event_counts.items(),
                                        key=lambda kv: -kv[1])[:20]),
            "logon_failed": self.logon_failed,
            "logon_success": self.logon_success,
            "logon_type_counts": dict(sorted(self.logon_type_counts.items(),
                                             key=lambda kv: -kv[1])),
            "fail_by_ip": [{"ip": k, "count": v} for k, v in
                           sorted(self.fail_by_ip.items(), key=lambda kv: -kv[1])[:10]],
            "fail_by_user": [{"user": k, "count": v} for k, v in
                             sorted(self.fail_by_user.items(), key=lambda kv: -kv[1])[:10]],
            "ok_by_ip": [{"ip": k, "count": v} for k, v in
                         sorted(self.ok_by_ip.items(), key=lambda kv: -kv[1])[:10]],
            "account_changes": [_with_time(x) for x in self.account_changes],
            "group_changes": [_with_time(x) for x in self.group_changes],
            "services": [_with_time(x) for x in self.services],
            "scheduled_tasks": [_with_time(x) for x in self.tasks],
            "log_cleared": [_with_time(x) for x in self.log_cleared],
            "audit_policy": [_with_time(x) for x in self.audit_policy],
            "share_access_count": len(self.share_access),
            "process_creates": self.proc_creates,
        }


# ================================================================ Linux

class LinuxLogStats:
    """Linux auth/secure 日志统计：SSH 爆破、成功登录、sudo、账号变更。"""

    MAX_KEYS = 5000

    def __init__(self) -> None:
        self.total = 0
        self.failed = 0
        self.success = 0
        self.invalid_user = 0
        self.sudo = 0
        self.fail_by_ip: dict[str, int] = {}
        self.fail_by_user: dict[str, int] = {}
        self.ok_by_ip: dict[str, int] = {}
        self.sudo_cmds: list[dict] = []
        self.account_changes: list[dict] = []
        self.process_counts: dict[str, int] = {}
        self._cap = 100

    def feed(self, ev: Event) -> None:
        self.total += 1
        msg = (ev.detail.get("message") or "")
        low = (msg + " " + (ev.raw or "")).lower()
        proc = ev.detail.get("process") or ""
        if proc:
            if proc in self.process_counts or len(self.process_counts) < 100:
                self.process_counts[proc] = self.process_counts.get(proc, 0) + 1

        if ev.action == A_LOGON_FAILED or "failed password" in low:
            self.failed += 1
            self._bump(self.fail_by_ip, ev.src_ip)
            self._bump(self.fail_by_user, ev.user)
        elif ev.action == A_LOGON_SUCCESS or "accepted password" in low \
                or "accepted publickey" in low:
            self.success += 1
            self._bump(self.ok_by_ip, ev.src_ip)
        if "invalid user" in low:
            self.invalid_user += 1

        if ev.action == A_SUDO_COMMAND or "sudo:" in low:
            self.sudo += 1
            if len(self.sudo_cmds) < self._cap:
                self.sudo_cmds.append({"ts": ev.ts, "user": ev.user,
                                       "host": ev.host, "message": msg[:300],
                                       "source": ev.source})
        if ev.action in (A_USER_CREATED, A_GROUP_MEMBER_ADDED) or \
                any(k in low for k in ("useradd", "usermod", "adduser", "passwd")):
            if len(self.account_changes) < self._cap:
                self.account_changes.append({"ts": ev.ts, "user": ev.user,
                                             "host": ev.host, "message": msg[:300],
                                             "source": ev.source})

    def _bump(self, d: dict, key) -> None:
        if not key:
            return
        if key in d or len(d) < self.MAX_KEYS:
            d[key] = d.get(key, 0) + 1

    def to_dict(self) -> dict:
        return {
            "total_events": self.total,
            "failed_logins": self.failed,
            "success_logins": self.success,
            "invalid_user": self.invalid_user,
            "sudo_commands": self.sudo,
            "fail_by_ip": [{"ip": k, "count": v} for k, v in
                           sorted(self.fail_by_ip.items(), key=lambda kv: -kv[1])[:10]],
            "fail_by_user": [{"user": k, "count": v} for k, v in
                             sorted(self.fail_by_user.items(), key=lambda kv: -kv[1])[:10]],
            "ok_by_ip": [{"ip": k, "count": v} for k, v in
                         sorted(self.ok_by_ip.items(), key=lambda kv: -kv[1])[:10]],
            "sudo_samples": [_with_time(x) for x in self.sudo_cmds[:10]],
            "account_changes": [_with_time(x) for x in self.account_changes],
            "top_processes": [{"process": k, "count": v} for k, v in
                              sorted(self.process_counts.items(), key=lambda kv: -kv[1])[:10]],
        }


# ================================================================ 数据库

DB_RISK_RE = re.compile(
    r"(?:union\s+all\s+select|union\s+select|information_schema|sleep\(|benchmark\(|"
    r"pg_sleep\(|waitfor\s+delay|load_file\(|into\s+outfile|into\s+dumpfile|"
    r"xp_cmdshell|sp_configure|openrowset|bulk\s+insert|utl_http|utl_file|"
    r"dbms_lock\.sleep|pg_read_file|lo_import|copy\s+.+\s+to\s+program|"
    r"0x[0-9a-f]{20,})", re.I)
DB_DESTRUCTIVE_RE = re.compile(
    r"(?:drop\s+table|drop\s+database|truncate\s+table|"
    r"(?:delete|update)\s+[^;]*;?\s*$)", re.I)
DB_PRIV_RE = re.compile(
    r"(?:grant\s+all|with\s+grant\s+option|create\s+user|alter\s+user|drop\s+user|"
    r"flush\s+privileges|alter\s+login|add\s+role\s+member|grant\s+dba|sysadmin|"
    r"db_owner|super_priv)", re.I)
DB_BULK_RE = re.compile(r"select\s+\*|select\s+[\w.,\s`\"]+\s+from", re.I)
DB_AUTH_FAIL_RE = re.compile(
    r"(?:access denied for user|login failed for user|password authentication failed|"
    r"authentication failed)", re.I)


class DatabaseLogStats:
    """数据库日志统计：注入语句、破坏性语句、提权、拖库、认证失败。"""

    MAX_KEYS = 5000

    def __init__(self) -> None:
        self.total = 0
        self.queries = 0
        self.admin_ops = 0
        self.auth_failed = 0
        self.risky: list[dict] = []
        self.destructive: list[dict] = []
        self.privilege: list[dict] = []
        self.bulk: list[dict] = []
        self.by_user: dict[str, int] = {}
        self.by_ip: dict[str, int] = {}
        self.by_engine: dict[str, int] = {}
        self.stmt_kinds: dict[str, int] = {}
        self._cap = 100
        self._bulk_by_user: dict[str, int] = {}

    def feed(self, ev: Event) -> None:
        self.total += 1
        sql = ev.detail.get("sql") or ""
        if not sql and ev.action not in (A_DB_QUERY, A_DB_ADMIN):
            # 错误日志里的认证失败等
            if DB_AUTH_FAIL_RE.search(ev.raw or ""):
                self.auth_failed += 1
                self._bump(self.by_ip, ev.src_ip)
            return
        engine = ev.detail.get("engine") or "?"
        if engine in self.by_engine or len(self.by_engine) < 20:
            self.by_engine[engine] = self.by_engine.get(engine, 0) + 1

        if ev.action == A_DB_ADMIN:
            self.admin_ops += 1
        else:
            self.queries += 1
        self._bump(self.by_user, ev.user)
        self._bump(self.by_ip, ev.src_ip)

        low = sql.lower()
        head = low.lstrip()[:6]
        for k in ("select", "insert", "update", "delete", "create", "drop",
                  "alter", "grant", "truncate", "show", "use"):
            if head.startswith(k):
                self.stmt_kinds[k] = self.stmt_kinds.get(k, 0) + 1
                break
        else:
            self.stmt_kinds["other"] = self.stmt_kinds.get("other", 0) + 1

        if DB_RISK_RE.search(sql):
            self._push(self.risky, ev, sql, "注入/危险函数")
        if DB_DESTRUCTIVE_RE.search(sql):
            self._push(self.destructive, ev, sql, "破坏性语句")
        if DB_PRIV_RE.search(sql):
            self._push(self.privilege, ev, sql, "权限变更")
        if DB_BULK_RE.search(sql):
            u = ev.user or "-"
            self._bulk_by_user[u] = self._bulk_by_user.get(u, 0) + 1
            if self._bulk_by_user[u] >= 5 and len(self.bulk) < self._cap:
                self.bulk.append({"ts": ev.ts, "user": ev.user, "ip": ev.src_ip,
                                  "sql": sql[:300], "source": ev.source})

    def _bump(self, d: dict, key) -> None:
        if not key:
            return
        if key in d or len(d) < self.MAX_KEYS:
            d[key] = d.get(key, 0) + 1

    def _push(self, bucket: list, ev: Event, sql: str, kind: str) -> None:
        if len(bucket) < self._cap:
            bucket.append({"ts": ev.ts, "user": ev.user, "ip": ev.src_ip,
                           "kind": kind, "sql": sql[:300], "source": ev.source,
                           "raw": ev.raw[:400]})

    def to_dict(self) -> dict:
        return {
            "total_events": self.total,
            "queries": self.queries,
            "admin_ops": self.admin_ops,
            "auth_failed": self.auth_failed,
            "by_engine": dict(self.by_engine),
            "stmt_kinds": dict(sorted(self.stmt_kinds.items(), key=lambda kv: -kv[1])),
            "by_user": [{"user": k, "count": v} for k, v in
                        sorted(self.by_user.items(), key=lambda kv: -kv[1])[:10]],
            "by_ip": [{"ip": k, "count": v} for k, v in
                      sorted(self.by_ip.items(), key=lambda kv: -kv[1])[:10]],
            "risky_statements": [_with_time(x) for x in self.risky[:20]],
            "destructive_statements": [_with_time(x) for x in self.destructive[:20]],
            "privilege_changes": [_with_time(x) for x in self.privilege[:20]],
            "bulk_reads": [_with_time(x) for x in self.bulk[:20]],
        }


# ================================================================ 统一门面

class LogStats:
    """按日志类型分发的统计门面。

    ``to_dict()`` 按类型给出各自的统计结论，供 profiles.py 生成
    「每类日志回答各自的应急问题」面板。
    """

    def __init__(self) -> None:
        self.web = WebLogStats()
        self.windows = WindowsLogStats()
        self.linux = LinuxLogStats()
        self.database = DatabaseLogStats()
        self.generic_total = 0
        self.by_log_type: dict[str, int] = {}

    def feed(self, ev: Event) -> None:
        lt = ev.log_type or ""
        self.by_log_type[lt] = self.by_log_type.get(lt, 0) + 1
        if lt in ("web-access", "iis"):
            self.web.feed(ev)
        elif lt in ("winsec", "sysmon"):
            self.windows.feed(ev)
        elif lt in ("linux-auth", "linux-syslog"):
            self.linux.feed(ev)
        elif lt == "database":
            self.database.feed(ev)
        elif lt == "pcap":
            # 流量包里重组出来的 HTTP 请求也落到 Web 统计（便于 pcap 类型的 KPI 体现）
            if ev.action == A_HTTP_REQUEST:
                self.web.feed(ev)
        else:
            self.generic_total += 1

    def to_dict(self) -> dict:
        return {
            "by_log_type": dict(self.by_log_type),
            "web": self.web.to_dict(),
            "windows": self.windows.to_dict(),
            "linux": self.linux.to_dict(),
            "database": self.database.to_dict(),
            "generic": {"total_events": self.generic_total},
        }

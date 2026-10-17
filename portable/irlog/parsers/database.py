"""数据库日志解析器：MySQL / PostgreSQL / SQL Server / MongoDB / Redis。

应急响应里数据库日志常被忽略，但它往往是最硬的两类证据：

1. **谁在撞库**——`Access denied for user` / `password authentication failed`
   / `Login failed for user` 直接给出 源IP + 账号，归一化后**复用现有暴力破解
   与账号滥用规则**，无需新增检测逻辑。
2. **注入有没有成功**——Web 日志里只有 URL 中的可疑字符串（尝试），
   而 MySQL general log / PostgreSQL `statement:` 记录的是**真正落到库里执行的
   SQL**（结果）。`UNION SELECT`、`INTO OUTFILE`、`SLEEP()` 出现在这里即代表
   注入已经打穿，价值远高于 Web 侧告警。

覆盖格式
--------
- MySQL 错误日志（8.0 带 `[MY-xxxx]` 与 5.x 旧式 `261014 10:30:01`）
- MySQL general query log（tab 分隔：`...\t  12 Connect\troot@10.0.0.5 on db`）
- MySQL slow query log（`# User@Host:` + `# Query_time:` + SQL）
- PostgreSQL csvlog（`ts,user,db,pid,client,..,FATAL,28000,"password authentication failed..."`）
- SQL Server 错误日志（`Login failed for user 'sa'. [CLIENT: 10.0.0.5]`）
- MongoDB JSON 日志（`"c":"ACCESS","msg":"Authentication failed"`）
- Redis 日志（`1:M 14 Oct 2026 10:30:01.123 * ...`）

设计：单一解析器内按行特征分派，避免多个解析器互相抢文件；所有分支均为
流式逐行处理，慢查询的多行上下文用「最近一次头部」记住，不缓存全量。
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Generator, Optional

from ..models import (
    Event,
    A_LOGON_FAILED, A_LOGON_SUCCESS, A_DB_QUERY, A_DB_ADMIN, A_GENERIC,
)
from .base import LogParser, register

# ---------------- 时间解析 ----------------
_MYSQL_ISO_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?")
_MYSQL_OLD_RE = re.compile(r"^(\d{2})(\d{2})(\d{2})\s+(\d{1,2}):(\d{2}):(\d{2})")
_PG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*(?P<tz>[A-Z]{2,5})?")
_MSSQL_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")
_REDIS_TS_RE = re.compile(r"^\d+:[A-Za-z]\s+\d{1,2}\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")

RMONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _mk_ts(y, mo, d, h, mi, s, frac="") -> Optional[float]:
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s),
                      int((frac or "0")[:6].ljust(6, "0")))
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def _parse_iso_ts(line: str) -> Optional[float]:
    m = _MYSQL_ISO_RE.search(line)
    if not m:
        return None
    return _mk_ts(m.group(1)[:4], m.group(1)[5:7], m.group(1)[8:10],
                  m.group(2), m.group(3), m.group(4), m.group(5) or "0")


# ---------------- MySQL ----------------
# 8.0: 2026-10-14T10:30:01.123456Z 12 [Warning] [MY-010926] [Server] Access denied ...
# 5.x: 2026-10-14T10:30:01.123456Z 12 [Warning] Access denied for user 'root'@'10.0.0.5'
MY_ACCESS_DENIED_RE = re.compile(
    r"Access denied for user '(?P<user>[^']*)'@'(?P<host>[^']*)'", re.I)
# 5.7 旧式：161014 10:30:01 [Warning] Access denied for user 'root'@'10.0.0.5'
MY_ABORTED_RE = re.compile(
    r"Aborted connection \d+ to db: '(?P<db>[^']*)' user: '(?P<user>[^']*)' host: '(?P<host>[^']*)'", re.I)
# general log: 2026-10-14T10:30:01.123456Z\t   12 Connect\troot@10.0.0.5 on db using TCP/IP
# 线程号（第 2 列）是 general log 里唯一的会话标识：Connect 行带账号与来源，
# 后续 Query 行只有线程号，必须靠它把 SQL 关联回发起者。
MY_GENERAL_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<tid>\d+)\s+(?P<op>Connect|Query|Quit|Init DB|Execute|Field List|Statistics|Prepare)"
    r"\s+(?P<rest>.*)$")
MY_CONNECT_RE = re.compile(
    r"\b(?P<op>Connect|Quit|Init DB|Query)\s+(?P<rest>.*)$")
MY_CONNECT_DETAIL_RE = re.compile(
    r"^(?P<user>[^@]*)@(?P<host>\S+)(?:\s+on\s+(?P<db>\S*))?", re.I)
# slow log
MY_SLOW_USER_RE = re.compile(
    r"^# User@Host:\s+(?P<user>\S+?)\[(?:[^\]]*)\]\s+@\s+(?P<host>\S+)?\s*\[", re.I)
MY_SLOW_QTIME_RE = re.compile(r"^# Query_time:\s*(?P<qt>[\d.]+)", re.I)
MY_SLOW_TIME_RE = re.compile(r"^# Time:\s*(?P<ts>\S+)")

# ---------------- PostgreSQL ----------------
PG_LOGIN_FAILED_RE = re.compile(
    r"""(?:password authentication failed for user|authentication failed for user|"""
    r"""no encryption|role "(?P<role1>[^"]+)" does not exist)""", re.I)
PG_USER_RE = re.compile(r"""user (?:")?(?P<user>[A-Za-z_][\w.$-]*)""", re.I)
PG_CLIENT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[^,]*,\"(?P<user>[^\"]*)\",\"(?P<db>[^\"]*)\","
                          r"(?P<pid>\d+),\"(?P<client>[^\"]*)\"", re.I)
PG_AUTH_OK_RE = re.compile(r"connection authorized:\s*user=(?P<user>\S+)(?:\s+database=(?P<db>\S+))?", re.I)
PG_STATEMENT_RE = re.compile(r"^(?:statement:|execute [^:]*:)\s*(?P<sql>.*)$", re.I)
PG_SEVERITY_RE = re.compile(r",(?P<sev>FATAL|ERROR|WARNING|LOG|NOTICE|PANIC),")

# ---------------- SQL Server ----------------
MSSQL_LOGIN_FAILED_RE = re.compile(
    r"Login failed for user '?(?P<user>[^'\.]*)(?:'\.)?.*?\[CLIENT:\s*(?P<ip>[0-9a-fA-F:.]+)\s*\]", re.I)
MSSQL_LOGIN_FAILED2_RE = re.compile(r"Login failed for user '?(?P<user>[^']*)'?", re.I)
MSSQL_LOGIN_OK_RE = re.compile(
    r"Login succeeded for user '?(?P<user>[^']*)'.*?\[CLIENT:\s*(?P<ip>[0-9a-fA-F:.]+)\s*\]", re.I)
MSSQL_CLIENT_RE = re.compile(r"\[CLIENT:\s*(?P<ip>[0-9a-fA-F:.]+)\s*\]", re.I)

# ---------------- Redis ----------------
REDIS_AUTH_RE = re.compile(r"Auth fail|Wrong password|invalid password|"
                           r"Authenticated with|Ready to accept", re.I)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _first_ip(text: str) -> Optional[str]:
    m = IPV4_RE.search(text or "")
    return m.group(0) if m else None


def _is_ip(text: str) -> bool:
    return bool(text) and bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text))


class DatabaseParser(LogParser):
    """MySQL / PostgreSQL / SQL Server / MongoDB / Redis 日志解析器。"""

    name = "database"

    # ---- 嗅探 ----
    def detect(self, sample_lines: list[str]) -> bool:
        text = "\n".join(sample_lines[:20])
        if not text:
            return False
        # MySQL 错误日志 / general log（ISO 时间戳 + 线程号）
        if re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", text) and re.search(
                r"\[(?:Warning|Note|Error)\]|Access denied|\bConnect\b|\bQuery\b", text):
            return True
        # MySQL 5.x 旧式时间戳
        if re.search(r"^\d{6}\s+\d{2}:\d{2}:\d{2}\s+\[(?:Warning|Note|Error)\]", text, re.M):
            return True
        # MySQL 慢查询
        if re.search(r"^# (?:Time|User@Host|Query_time):", text, re.M):
            return True
        # PostgreSQL csvlog
        if re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[^,]*,", text, re.M) and re.search(
                r",(?:FATAL|ERROR|LOG|WARNING|NOTICE|PANIC),|statement:|connection authorized", text):
            return True
        # SQL Server
        if re.search(r"Login (?:failed|succeeded) for user|\[CLIENT:", text, re.I):
            return True
        # MongoDB JSON
        if text.lstrip().startswith("{") and re.search(r'"\$date"|"c":"(?:ACCESS|NETWORK|COMMAND)"', text):
            return True
        # Redis
        if re.search(r"^\d+:[A-Za-z] \d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2}", text, re.M):
            return True
        return False

    # ---- 解析 ----
    def parse(self, path: str) -> Generator[Event, None, None]:
        # 慢查询日志的上下文（仅保留最近一次头部，常量内存）
        ctx = {"ts": None, "user": None, "host": None, "qtime": None}
        # general log 线程号 -> (user, src_ip, db)；仅保留当前文件内映射
        threads: dict[str, tuple] = {}
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            yield self._parse_line(line, ctx, threads)

    def _parse_line(self, line: str, ctx: dict, threads: dict) -> Event:
        ev = Event(ts=None, log_type="database", source="", action=A_GENERIC,
                   detail={}, raw=line[:2000])

        # ===== 慢查询日志：头部行更新上下文，SQL 行产出事件 =====
        if line.startswith("#"):
            m = MY_SLOW_TIME_RE.match(line)
            if m:
                ctx["ts"] = _parse_iso_ts(m.group("ts"))
            m = MY_SLOW_USER_RE.match(line)
            if m:
                ctx["user"] = m.group("user")
                h = m.group("host") or ""
                ctx["host"] = h if _is_ip(h) else None
            m = MY_SLOW_QTIME_RE.match(line)
            if m:
                try:
                    ctx["qtime"] = float(m.group("qt"))
                except ValueError:
                    ctx["qtime"] = None
            ev.detail["slow_log_header"] = True
            return ev

        # ===== PostgreSQL csvlog =====
        if self._looks_like_pg(line):
            return self._parse_pg(line, ev)

        # ===== MongoDB JSON =====
        if line.lstrip().startswith("{") and '"$date"' in line:
            return self._parse_mongo(line, ev)

        # ===== Redis =====
        mr = _REDIS_TS_RE.match(line)
        if mr:
            return self._parse_redis(line, ev, mr)

        # ===== SQL Server（含 EXEC 扩展存储过程；放在 PG 之后，两者时间戳前缀相似）=====
        if _MSSQL_TS_RE.match(line):
            return self._parse_mssql(line, ev)

        # ===== MySQL（错误日志 / general log / 慢查询 SQL 行）=====
        return self._parse_mysql(line, ev, ctx, threads)

    # ---------- 各分支 ----------
    @staticmethod
    def _looks_like_pg(line: str) -> bool:
        if not _PG_TS_RE.match(line):
            return False
        return bool(PG_SEVERITY_RE.search(line) or "statement:" in line or
                    "connection authorized" in line)

    def _parse_pg(self, line: str, ev: Event) -> Event:
        ts = None
        mt = _PG_TS_RE.match(line)
        if mt:
            ts = _mk_ts(mt.group(1)[:4], mt.group(1)[5:7], mt.group(1)[8:10],
                        mt.group(2), mt.group(3), mt.group(4))
        cm = PG_CLIENT_RE.match(line)
        user = db = client_ip = None
        if cm:
            user = cm.group("user") or None
            db = cm.group("db") or None
            client = cm.group("client") or ""
            if ":" in client:
                client = client.rsplit(":", 1)[0]
            if _is_ip(client):
                client_ip = client
        ev.ts = ts
        ev.detail.update({"engine": "postgresql", "db": db, "pid": cm.group("pid") if cm else None,
                          "client": cm.group("client") if cm else None})

        sevm = PG_SEVERITY_RE.search(line)
        severity = sevm.group("sev").upper() if sevm else ""

        # 认证失败
        if severity == "FATAL" and re.search(r"password authentication failed|authentication failed", line, re.I):
            ev.action = A_LOGON_FAILED
            um = PG_USER_RE.search(line)
            ev.user = (um.group("user") if um else None) or user
            ev.src_ip = client_ip
            ev.detail["message"] = line[:400]
            return ev
        # 连接建立（成功）
        am = PG_AUTH_OK_RE.search(line)
        if am:
            ev.action = A_LOGON_SUCCESS
            ev.user = am.group("user")
            ev.src_ip = client_ip
            ev.detail["db"] = am.group("db") or db
            return ev
        # SQL 语句：csvlog 最后一个字段是被引号包裹的消息，需剥掉外层引号
        if "statement:" in line or PG_STATEMENT_RE.search(line):
            sm = PG_STATEMENT_RE.search(line)
            sql = sm.group("sql") if sm else line.split("statement:", 1)[-1]
            ev.action = A_DB_QUERY
            ev.user = user
            ev.src_ip = client_ip
            ev.detail["sql"] = _clean_sql(_unquote_csv(sql))
            return ev
        ev.action = A_GENERIC
        ev.user = user
        ev.src_ip = client_ip
        ev.detail["message"] = line[:400]
        ev.detail["severity"] = severity
        return ev

    @staticmethod
    def _parse_mongo(line: str, ev: Event) -> Event:
        ev.detail["engine"] = "mongodb"
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            ev.action = A_GENERIC
            ev.detail["message"] = line[:400]
            return ev
        t = obj.get("t", {})
        ts_raw = t.get("$date") if isinstance(t, dict) else None
        ev.ts = _parse_iso_ts(str(ts_raw)) if ts_raw else None
        msg = str(obj.get("msg", ""))
        attr = obj.get("attr") or {}
        client = str(attr.get("client") or attr.get("remote") or "")
        if ":" in client:
            client = client.rsplit(":", 1)[0]
        user = attr.get("user") or obj.get("user")
        ev.detail.update({"component": obj.get("c"), "db": attr.get("db"),
                          "msg": msg, "client": client or None})
        if re.search(r"Authentication failed|Unauthorized|UserNotFound|AuthenticationFailed", msg, re.I):
            ev.action = A_LOGON_FAILED
        elif re.search(r"Authentication succeeded|Authorization succeeded", msg, re.I):
            ev.action = A_LOGON_SUCCESS
        elif re.search(r"drop|remove|delete|createUser|grantRoles|shutdown", msg, re.I):
            ev.action = A_DB_ADMIN
        else:
            ev.action = A_GENERIC
        ev.user = user or None
        ev.src_ip = client if _is_ip(client) else None
        return ev

    @staticmethod
    def _parse_redis(line: str, ev: Event, mr) -> Event:
        ev.detail["engine"] = "redis"
        mon = RMONTHS.get(mr.group(1).title())
        ev.ts = _mk_ts(mr.group(2), mon or 1, 1, mr.group(3), mr.group(4), mr.group(5))
        body = line[mr.end():].strip()
        ip = _first_ip(body)
        ev.detail["message"] = body[:400]
        low = body.lower()
        if "auth fail" in low or "wrong password" in low or "invalid password" in low:
            ev.action = A_LOGON_FAILED
            ev.src_ip = ip
        elif "authenticated" in low or "ready to accept" in low:
            ev.action = A_LOGON_SUCCESS
            ev.src_ip = ip
        elif re.search(r"\b(debug|config set|slaveof|replicaof|module load)\b", low):
            ev.action = A_DB_ADMIN
            ev.src_ip = ip
        else:
            ev.action = A_GENERIC
            ev.src_ip = ip
        return ev

    @staticmethod
    def _parse_mssql(line: str, ev: Event) -> Event:
        mt = _MSSQL_TS_RE.match(line)
        if mt:
            ev.ts = _mk_ts(mt.group(1)[:4], mt.group(1)[5:7], mt.group(1)[8:10],
                           mt.group(2), mt.group(3), mt.group(4), mt.group(5) or "0")
        ev.detail["engine"] = "mssql"
        ipm = MSSQL_CLIENT_RE.search(line)
        ev.src_ip = ipm.group("ip") if ipm else None
        fm = MSSQL_LOGIN_FAILED_RE.search(line)
        if "Login failed" in line:
            ev.action = A_LOGON_FAILED
            um = MSSQL_LOGIN_FAILED2_RE.search(line)
            ev.user = um.group("user") if um else None
            ev.detail["message"] = line[:400]
            return ev
        om = MSSQL_LOGIN_OK_RE.search(line)
        if om:
            ev.action = A_LOGON_SUCCESS
            ev.user = om.group("user")
            ev.detail["message"] = line[:400]
            return ev
        ev.action = A_GENERIC
        ev.detail["message"] = line[:400]
        # SQL Server 的 EXEC / 扩展存储过程同样要送进数据库攻击检测
        if re.search(r"\b(?:EXEC|EXECUTE)\s+(?:sp_|xp_|master\.\.)", line, re.I) \
                or re.search(r"\bxp_[a-z]+\b", line, re.I):
            ev.action = A_DB_QUERY
            ev.detail["sql"] = _clean_sql(line[mt.end():].strip() if mt else line)
        return ev

    @staticmethod
    def _parse_mysql(line: str, ev: Event, ctx: dict, threads: dict) -> Event:
        ev.detail["engine"] = "mysql"
        # 时间戳：ISO（错误日志/general log）或 5.x 旧式
        ts = _parse_iso_ts(line)
        if ts is None:
            mo = _MYSQL_OLD_RE.match(line)
            if mo:
                ts = _mk_ts(2000 + int(mo.group(1)), mo.group(2), mo.group(3),
                            mo.group(4), mo.group(5), mo.group(6))
        ev.ts = ts if ts is not None else ctx.get("ts")

        # ---- 认证失败 ----
        dm = MY_ACCESS_DENIED_RE.search(line)
        if dm:
            ev.action = A_LOGON_FAILED
            ev.user = dm.group("user") or None
            h = dm.group("host")
            ev.src_ip = h if _is_ip(h) else None
            ev.detail["message"] = line[:400]
            return ev

        # ---- 中断连接（常伴随扫描/半连接）----
        am = MY_ABORTED_RE.search(line)
        if am:
            ev.action = A_LOGON_FAILED
            ev.user = am.group("user") or None
            h = am.group("host")
            ev.src_ip = h if _is_ip(h) else None
            ev.detail["aborted_connection"] = True
            ev.detail["db"] = am.group("db") or None
            ev.detail["message"] = line[:400]
            return ev

        # ---- general log：按线程号把 SQL 关联回发起会话 ----
        gm = MY_GENERAL_RE.match(line)
        if gm:
            tid = gm.group("tid")
            op = gm.group("op")
            rest = gm.group("rest").strip()
            who = threads.get(tid)
            if op == "Connect":
                dm2 = MY_CONNECT_DETAIL_RE.match(rest)
                if dm2:
                    user = dm2.group("user") or None
                    h = dm2.group("host")
                    ip = h if _is_ip(h) else None
                    db = dm2.group("db") or None
                    threads[tid] = (user, ip, db)
                    if len(threads) > 5000:      # 防长跑日志无限增长
                        threads.pop(next(iter(threads)), None)
                    ev.action = A_LOGON_SUCCESS
                    ev.user, ev.src_ip = user, ip
                    ev.detail.update({"db": db, "thread_id": tid, "message": line[:400]})
                    return ev
            if op == "Query":
                ev.action = A_DB_QUERY
                if who:
                    ev.user, ev.src_ip, ev.detail["db"] = who[0], who[1], who[2]
                ev.detail["thread_id"] = tid
                ev.detail["sql"] = _clean_sql(rest)
                return ev
            ev.action = A_GENERIC
            ev.detail.update({"op": op, "thread_id": tid, "message": line[:400]})
            if who:
                ev.user, ev.src_ip = who[0], who[1]
            return ev

        # ---- general log：Connect / Query（非标准列分隔的兜底）----
        cm = MY_CONNECT_RE.search(line)
        if cm:
            op = cm.group("op")
            rest = cm.group("rest").strip()
            if op == "Connect":
                dm2 = MY_CONNECT_DETAIL_RE.match(rest)
                if dm2:
                    ev.action = A_LOGON_SUCCESS
                    ev.user = dm2.group("user") or None
                    h = dm2.group("host")
                    ev.src_ip = h if _is_ip(h) else None
                    ev.detail["db"] = dm2.group("db") or None
                    ev.detail["message"] = line[:400]
                    return ev
            if op == "Query":
                ev.action = A_DB_QUERY
                ev.user = ctx.get("user")
                ev.src_ip = ctx.get("host")
                ev.detail["sql"] = _clean_sql(rest)
                return ev
            ev.action = A_GENERIC
            ev.detail["op"] = op
            ev.detail["message"] = line[:400]
            return ev

        # ---- 慢查询日志中的 SQL 行 ----
        if ctx.get("user") and not line.startswith("#"):
            if MY_SET_NOISE_RE.match(line.strip()):
                ev.action = A_GENERIC
                ev.detail["message"] = line[:200]
                return ev
            ev.action = A_DB_QUERY
            ev.user = ctx.get("user")
            ev.src_ip = ctx.get("host")
            ev.detail["sql"] = _clean_sql(line)
            ev.detail["slow_query"] = True
            if ctx.get("qtime") is not None:
                ev.detail["query_time"] = ctx["qtime"]
            return ev

        ev.action = A_GENERIC
        ev.detail["message"] = line[:400]
        return ev


def _unquote_csv(s: str) -> str:
    """剥掉 csvlog 消息字段的外层引号，并把转义的双引号还原。"""
    s = (s or "").strip()
    # csvlog 消息字段以引号结尾，剥掉外层那一个（SQL 本身极少以引号收尾）
    if s.endswith('"'):
        s = s[:-1]
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s.replace('""', '"')


def _clean_sql(sql: str) -> str:
    """去掉行尾空白与控制字符，保留原文大小写（注入特征大小写不敏感匹配）。"""
    return re.sub(r"\s+", " ", (sql or "").strip())[:4000]


# 慢查询日志里 MySQL 自带的 SET 前缀语句，非业务 SQL，避免污染检测
MY_SET_NOISE_RE = re.compile(r"^SET\s+(?:timestamp|names|autocommit|sql_mode|"
                             r"character_set|session|global)\b", re.I)


register(DatabaseParser())

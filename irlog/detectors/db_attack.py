"""数据库攻击与高危操作检测：SQL 注入落地、破坏性语句、提权与拖库。

为什么单独一条规则
------------------
Web 侧规则（web-attack）只能看到 **URL 里的可疑字符串**，那是"尝试"；
而 MySQL general log / PostgreSQL `statement:` 记录的是 **真正被数据库执行的 SQL**，
那是"结果"。一旦 `UNION SELECT`、`INTO OUTFILE`、`SLEEP()` 出现在这里，
说明注入已经打穿，处置优先级和 Web 侧试探完全不同，必须单独成规则。

检测分层
--------
- L1 SQL 注入落地：联合查询、布尔/报错/时间盲注、`information_schema` 探测、
  `LOAD_FILE`/`INTO OUTFILE` 文件读写、堆叠查询（`;` 后接语句）、编码绕过
- L2 破坏/篡改：`DROP DATABASE/TABLE`、`TRUNCATE`、无 WHERE 的 `DELETE`/`UPDATE`
- L3 权限与账号：`GRANT ALL`、`CREATE USER`、`ALTER USER`、`xp_cmdshell`、
  `sp_configure`、`CREATE FUNCTION ... SONAME`（UDF 提权）
- L4 批量拖库：同一账号在时间窗内对敏感表（默认 users/account/card/...）
  的查询次数超阈值

严重度：注入落地 / 破坏 / 提权 → 紧急(1)；账号与权限变更 → 高危(2)；拖库 → 中危(3)
"""
from __future__ import annotations

import re
from collections import deque

from ..models import A_DB_QUERY, A_DB_ADMIN, Event
from .base import Detector

# ---- L1 SQL 注入落地 ----
SQLI_UNION_RE = re.compile(r"union\s+(?:all\s+)?select", re.I)
SQLI_TAUTOLOGY_RE = re.compile(
    r"(?:'|\"|`|\s|^)(?:or|and)\s+(?:1\s*=\s*1|'[^']*'\s*=\s*'[^']*'|"
    r"\d+\s*=\s*\d+|true\b)", re.I)
SQLI_TIME_BLIND_RE = re.compile(
    r"\b(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\(|dbms_pipe\.receive_message)", re.I)
SQLI_ERROR_BASED_RE = re.compile(
    r"\b(extractvalue\s*\(|updatexml\s*\(|exp\s*\(\s*~|"          # MySQL 报错注入
    r"cast\s*\(\s*\(?select|convert\s*\(\s*int\s*,)", re.I)         # MSSQL 报错注入
SQLI_SCHEMA_RE = re.compile(
    r"\b(information_schema|sysobjects|syscolumns|all_tables|"
    r"pg_catalog\s*\.\s*pg_|sqlite_master)\b", re.I)
SQLI_FILE_IO_RE = re.compile(
    r"\b(load_file\s*\(|into\s+(?:outfile|dumpfile)|"
    r"pg_read_file|pg_ls_dir|"
    r"copy\s+\w+\s+(?:from|to)\s+(?:program|'/)|"      # PG COPY TO/FROM PROGRAM：命令执行/外传
    r"xp_cmdshell)\b", re.I)
SQLI_STACKED_RE = re.compile(r";\s*(?:select|insert|update|delete|drop|alter|create)\b", re.I)
SQLI_COMMENT_RE = re.compile(r"/\*!?\d*|--\s|#\s*$|;\s*--", re.I)
SQLI_HEX_RE = re.compile(r"\b(0x[0-9a-f]{8,}|char\s*\(\s*\d+\s*(?:,\s*\d+\s*){3,}|"
                         r"concat\s*\(\s*0x|unhex\s*\()", re.I)

# ---- L2 破坏/篡改 ----
DESTRUCTIVE_RE = re.compile(
    r"\b(drop\s+(?:database|table|schema)|truncate\s+table|"
    r"delete\s+from\s+\w+\s*(?:;|$)|update\s+\w+\s+set\s+[^;]*?(?:;|$))", re.I)
DESTRUCTIVE_SAFE_RE = re.compile(r"\bwhere\b", re.I)

# ---- L3 权限/账号/后门 ----
PRIV_RE = re.compile(
    r"\b(grant\s+all|grant\s+.*\b(?:super|file|process|shutdown)\b|"
    r"create\s+user|alter\s+user|drop\s+user|create\s+role|"
    r"sp_configure|sp_addsrvrolemember|xp_cmdshell|xp_regwrite|"
    r"create\s+function\s+.*\bsoname\b|create\s+aggregate\s+.*\bsoname\b|"
    r"set\s+global\s+\w+|alter\s+system\s+set)", re.I)

# ---- L4 拖库：敏感表 ----
SENSITIVE_TABLE_RE = re.compile(
    r"(?:from|join|update|into)\s+[`\"\[]?(?P<tbl>[a-z0-9_]*)"
    r"(?:user|account|member|admin|credential|password|passwd|card|bank|"
    r"payment|idcard|identity|phone|mobile|email|token|secret|wallet|salary)"
    r"[a-z0-9_]*[`\"\]]?", re.I)


class DbAttackDetector(Detector):
    rule_id = "db-attack"
    title = "数据库攻击 / 高危操作"
    description = "发现 SQL 注入落地执行、破坏性语句、提权建账号或敏感表批量查询"
    mitre = ("T1190 Exploit Public-Facing Application / T1213 Data from Information Repositories / "
             "T1505.003 Web Shell / T1078 Valid Accounts")
    recommendation = ("1) 立即定位来源应用与账号，确认注入点并下线修复；"
                      "2) 核查被读取/导出的表与行数，评估数据泄露范围；"
                      "3) 回收数据库账号权限、改密并排查新增账号与 UDF；"
                      "4) 检查是否产生 outfile 落盘文件并清除")

    def __init__(self, config):
        super().__init__(config)
        self.hits: dict = {}                 # (who, src_ip, kind) -> 聚合
        self.dump_state: dict = {}           # (user, src_ip) -> 滑动窗口

    # ---- 分类 ----
    def _classify(self, ev: Event) -> tuple[list[str], int]:
        sql = ev.detail.get("sql") or ""
        if ev.action == A_DB_ADMIN:
            msg = ev.detail.get("msg", "") or ""
            return ([f"数据库管理类操作：{msg[:120]}"], 2)
        if not sql:
            return ([], 0)
        reasons: list[str] = []
        severity = 0

        # L1 注入落地（命中即紧急）
        inj: list[str] = []
        if SQLI_UNION_RE.search(sql):
            inj.append("UNION SELECT 联合查询")
        if SQLI_TAUTOLOGY_RE.search(sql):
            inj.append("恒真条件绕过认证")
        if SQLI_TIME_BLIND_RE.search(sql):
            inj.append("时间盲注函数（SLEEP/BENCHMARK/WAITFOR）")
        if SQLI_ERROR_BASED_RE.search(sql):
            inj.append("报错注入函数（extractvalue/updatexml/cast）")
        if SQLI_FILE_IO_RE.search(sql):
            inj.append("文件读写或命令执行函数（LOAD_FILE/INTO OUTFILE/xp_cmdshell）")
        if SQLI_STACKED_RE.search(sql):
            inj.append("堆叠查询（; 后接语句）")
        if SQLI_HEX_RE.search(sql):
            inj.append("十六进制/CHAR 编码绕过")
        if SQLI_SCHEMA_RE.search(sql):
            inj.append("系统表探测（information_schema/sysobjects）")
        if len(inj) >= 2 or (inj and (SQLI_FILE_IO_RE.search(sql) or SQLI_TAUTOLOGY_RE.search(sql))):
            reasons.append("SQL 注入已落地执行：" + "、".join(inj))
            severity = 1
        elif SQLI_SCHEMA_RE.search(sql) or SQLI_TIME_BLIND_RE.search(sql) \
                or SQLI_ERROR_BASED_RE.search(sql) or SQLI_UNION_RE.search(sql):
            # 单特征，但命中敏感表（说明拖库已成功）同样按紧急处理
            if SQLI_UNION_RE.search(sql) and SENSITIVE_TABLE_RE.search(sql):
                reasons.append("SQL 注入已落地执行（联合查询读取敏感表）：" + "、".join(inj))
                severity = 1
            else:
                reasons.append("疑似 SQL 注入（单特征）：" + "、".join(inj))
                severity = 2
        elif inj:
            reasons.append("可疑 SQL 特征：" + "、".join(inj))
            severity = 3

        # L2 破坏：无 WHERE 约束的 DELETE/UPDATE 才告警；带 WHERE 属正常业务语句
        dm = DESTRUCTIVE_RE.search(sql)
        if dm and not DESTRUCTIVE_SAFE_RE.search(sql):
            reasons.append(f"破坏性语句（无 WHERE 约束）：{dm.group(0)[:80]}")
            severity = 1 if severity == 0 else severity

        # L3 权限/账号
        pm = PRIV_RE.search(sql)
        if pm:
            reasons.append(f"权限或账号变更：{pm.group(0)[:80]}")
            severity = 2 if severity == 0 else severity

        return (reasons, severity)

    # ---- 拖库 ----
    def _dump_check(self, ev: Event) -> None:
        sql = ev.detail.get("sql") or ""
        if not re.match(r"\s*select", sql, re.I):
            return
        m = SENSITIVE_TABLE_RE.search(sql)
        if not m:
            return
        key = (ev.user or "-", ev.src_ip or "-")
        n = self._window_push(self.dump_state, key, ev.ts,
                              self.config.db_dump_window_sec)
        if n < self.config.db_dump_min_queries:
            return
        tbl = m.group("tbl") or m.group(0)[:40]
        # key 结构与主流程保持一致（user, src_ip, kind）
        k = (key[0], key[1], "dump")
        st = self.hits.setdefault(k, {"count": 0, "reasons": set(), "severity": 3,
                                      "first": None, "last": None, "evidence": [],
                                      "user": ev.user, "src_ip": ev.src_ip})
        st["count"] += 1
        st["reasons"].add(f"敏感表批量查询：`{tbl}` 类表 {n} 次/{self.config.db_dump_window_sec}s")
        st["severity"] = min(st["severity"], 3)
        self._touch_ts(st, ev)
        self._add_evidence(st, ev)

    # ---- 工具 ----
    @staticmethod
    def _touch_ts(st: dict, ev: Event) -> None:
        if ev.ts is None:
            return
        st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
        st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)

    def _add_evidence(self, st: dict, ev: Event) -> None:
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    # ---- 主流程 ----
    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return
        if ev.action not in (A_DB_QUERY, A_DB_ADMIN):
            return
        reasons, severity = self._classify(ev)
        if reasons:
            who = ev.user or ev.src_ip or "-"
            key = (who, ev.src_ip or "-", reasons[0][:60])
            st = self.hits.setdefault(key, {"count": 0, "reasons": set(), "severity": severity,
                                            "first": None, "last": None, "evidence": [],
                                            "user": ev.user, "src_ip": ev.src_ip})
            st["count"] += 1
            st["reasons"].update(reasons)
            st["severity"] = min(st["severity"], severity)
            self._touch_ts(st, ev)
            self._add_evidence(st, ev)
            sql = ev.detail.get("sql") or ev.detail.get("msg") or ""
            if sql and len(st.setdefault("sample_sql", [])) < 5:
                st["sample_sql"].append(sql[:300])
        self._dump_check(ev)

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (_who, _ip, _kind), st in sorted(self.hits.items(), key=lambda kv: kv[1]["severity"]):
            rs = sorted(st["reasons"])
            entities = {
                "user": st.get("user"),
                "src_ip": st.get("src_ip"),
                "reasons": rs,
            }
            if st.get("sample_sql"):
                entities["sample_sql"] = st["sample_sql"][:3]
            self._alert(st["severity"], st["count"], entities,
                        st["evidence"], st["first"], st["last"])
            who = st.get("user") or st.get("src_ip") or "未知账号"
            self.alerts[-1].description = (
                f"数据库攻击/高危操作：{who} 共 {st['count']} 次"
                f"（{'；'.join(r[:70] for r in rs[:2])}）")
        return self.alerts

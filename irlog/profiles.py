"""日志类型画像（LOG_PROFILES）：类型决定分析维度。

核心原则：**一套规则打天下不如按类型回答各自的应急问题。**

每个 profile 描述一类日志——
- 它关注什么（KPI）
- 它的结论怎么生成（文字，自动）
- 它重点看哪些规则
- 它在综合视图里是什么颜色

新增日志类型只需在这里加一个 profile，解析/检测/前端都不用动。
"""
from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------- 类型定义

PROFILES: dict = {
    "web-access": {
        "name": "Web 访问日志",
        "short": "Web",
        "category": "web",
        "color": "#2874a6",
        "parsers": ["web-access", "iis"],
        "question": "谁在攻击、打了什么漏洞、有没有 2xx 成功",
        "kpis": ["总请求数", "独立客户端 IP", "4xx 客户端错误", "2xx 成功请求",
                 "请求方法种类", "攻击命中请求"],
        "focus_rules": ["web-attack", "webshell", "attack-chain", "http-content"],
        "conclusion": "_web_conclusion",
        "export_hint": "Nginx/Apache：access.log / access_log；IIS：%SystemDrive%\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log",
    },
    "winsec": {
        "name": "Windows 安全日志",
        "short": "Windows",
        "category": "windows",
        "color": "#7d3c98",
        "parsers": ["winsec", "sysmon"],
        "question": "谁在爆破、谁登录成功、有没有持久化和提权",
        "kpis": ["总事件数", "登录失败", "登录成功", "高危事件", "账号变更",
                 "服务/计划任务创建", "日志清除"],
        "focus_rules": ["brute-force", "account-abuse", "ransomware",
                        "command-obfuscation", "webshell"],
        "conclusion": "_windows_conclusion",
        "export_hint": ("wevtutil qe Security /f:csv /q:\"*\" > security.csv\n"
                        "或 PowerShell: Get-WinEvent -LogName Security | Export-Csv security.csv\n"
                        "（本工具不解析 .evtx 二进制，需先按上面命令导出）"),
    },
    "linux-auth": {
        "name": "Linux 认证日志",
        "short": "Linux",
        "category": "linux",
        "color": "#1e8449",
        "parsers": ["linux-auth", "linux-syslog"],
        "question": "SSH 爆破、成功登录、sudo 提权、账号变更",
        "kpis": ["总事件数", "失败登录", "成功登录", "独立来源 IP", "sudo 次数",
                 "账号变更"],
        "focus_rules": ["brute-force", "account-abuse", "command-obfuscation"],
        "conclusion": "_linux_conclusion",
        "export_hint": "/var/log/secure（RHEL/CentOS）或 /var/log/auth.log（Debian/Ubuntu）",
    },
    "database": {
        "name": "数据库日志",
        "short": "数据库",
        "category": "db",
        "color": "#148f77",
        "parsers": ["database"],
        "question": "有没有注入语句、有没有批量拖库、有没有权限变更",
        "kpis": ["总语句数", "高危语句", "来源账号数", "认证失败",
                 "DDL 变更", "批量读取"],
        "focus_rules": ["db-attack", "attack-chain"],
        "conclusion": "_database_conclusion",
        "export_hint": ("MySQL 慢查询 # Time:/# Query_time:；错误日志 [ERROR]/[Warning]；\n"
                        "通用日志 Query/Connect；PostgreSQL STATEMENT:/duration:；\n"
                        "SQL Server errorlog Login failed/Error:"),
    },
    "pcap": {
        "name": "流量包（pcap/pcapng）",
        "short": "流量",
        "category": "net",
        "color": "#b9770e",
        "parsers": ["pcap"],
        "question": "有没有扫描、C2 信标、DNS 隧道、明文凭据、数据外传",
        "kpis": ["总报文", "TCP 会话", "DNS 查询", "TLS 连接", "明文凭据"],
        "focus_rules": ["net-anomaly", "stream-content", "http-content", "ioc"],
        "conclusion": "_pcap_conclusion",
        "export_hint": "tcpdump -w capture.pcap / Wireshark 导出 .pcap 或 .pcapng",
    },
    "generic": {
        "name": "通用应用日志",
        "short": "通用",
        "category": "generic",
        "color": "#5d6d7e",
        "parsers": ["generic", "jsonl"],
        "question": "至少能看时间和来源，不追求深度检测",
        "kpis": ["总事件数", "独立来源 IP", "涉及账号"],
        "focus_rules": ["ioc", "command-obfuscation"],
        "conclusion": "_generic_conclusion",
        "export_hint": "任意文本日志：JSON lines / logfmt / 时间+级别+消息",
    },
}

# 解析器名 -> profile key
PARSER_TO_PROFILE: dict = {}
for _k, _p in PROFILES.items():
    for _pn in _p["parsers"]:
        PARSER_TO_PROFILE[_pn] = _k

CATEGORY_NAMES = {
    "web": "Web", "windows": "Windows", "db": "数据库",
    "linux": "Linux", "net": "流量", "generic": "通用",
}


def profile_of(log_type: Optional[str]) -> Optional[dict]:
    if not log_type:
        return None
    return PROFILES.get(PARSER_TO_PROFILE.get(log_type, log_type))


def profile_list() -> list:
    return [{"key": k, **v} for k, v in PROFILES.items()]


# ---------------------------------------------------------------- 结论生成

def _fmt(ts) -> str:
    return ts or "?"


def _top(items: list, key: str, n: int = 3) -> list:
    return items[:n]


def _web_conclusion(s: dict, alerts: list) -> list:
    """Web：谁在攻击、打了什么漏洞、有没有 2xx 成功。"""
    out = []
    ips = s.get("top_client_ips") or []
    if ips:
        hot = "、".join(f"{x['ip']}（{x['count']} 次）" for x in ips[:3])
        out.append(f"请求最活跃的来源：{hot}")
    sc = s.get("status_counts") or {}
    if sc:
        top = "、".join(f"{k} → {v} 次" for k, v in list(sc.items())[:5])
        out.append(f"状态码分布：{top}")
    cls = s.get("status_class_summary") or {}
    if cls.get("4xx"):
        out.append(f"4xx 客户端错误合计 {cls['4xx']} 条"
                   f"（其中 404 占多数通常是扫描探测，403 需关注是否命中敏感路径）")
    # 攻击 + 2xx = 最高优先级
    hit_ok = [a for a in alerts
              if a.get("rule_id") in ("web-attack", "webshell", "attack-chain", "http-content")]
    if hit_ok:
        worst = sorted(hit_ok, key=lambda a: a.get("severity", 9))[0]
        out.append(f"存在 {len(hit_ok)} 类 Web 侧告警，最高为「{worst.get('title')}」"
                   f"（{worst.get('severity_label')}），需优先核查是否攻击成功")
    else:
        out.append("未发现 Web 攻击特征命中")
    landed = s.get("post_upload_scripts") or []
    if landed:
        out.append("⚠ 上传后才出现的脚本（疑似 webshell）："
                   + "、".join(f"{x['path']}（POST {x['post_count']} 次）" for x in landed[:3]))
    ups = s.get("uploads") or []
    if ups:
        paths = sorted({u["uri"].split("?")[0] for u in ups})
        out.append(f"文件上传接口被调用 {len(ups)} 次，入口：{'、'.join(paths[:3])}")
    logins = s.get("login_success") or []
    if logins:
        out.append(f"后台登录成功 {len(logins)} 次，来源："
                   + "、".join(sorted({l['ip'] for l in logins})[:3]))
    chain = s.get("attack_chain") or []
    if len(chain) >= 3:
        out.append("⚠ 检测到多阶段攻击链（登录 → 上传 → 后门落地 → 交互），"
                   "详见综合关联视图")
    return out


def _windows_conclusion(s: dict, alerts: list) -> list:
    """Windows：谁在爆破、谁登录成功、有没有持久化和提权。"""
    out = []
    if s.get("log_cleared"):
        out.append(f"🔴 安全日志被清除 {len(s['log_cleared'])} 次 —— "
                   "这是最典型的反取证行为，必须置顶排查")
    if s.get("audit_policy"):
        out.append(f"审计策略被修改 {len(s['audit_policy'])} 次（事件 4719），"
                   "可能导致后续事件不再记录")
    if s.get("logon_failed"):
        ips = s.get("fail_by_ip") or []
        users = s.get("fail_by_user") or []
        line = f"登录失败合计 {s['logon_failed']} 次"
        if ips:
            line += "，Top 来源：" + "、".join(f"{x['ip']}（{x['count']} 次）" for x in ips[:3])
        if users:
            line += "；Top 目标账号：" + "、".join(f"{x['user']}（{x['count']} 次）" for x in users[:3])
        out.append(line)
        # 爆破成功判定：同一 IP 既有失败又有成功
        fail_ips = {x["ip"]: x["count"] for x in (s.get("fail_by_ip") or [])}
        ok_ips = {x["ip"]: x["count"] for x in (s.get("ok_by_ip") or [])}
        both = [ip for ip in fail_ips if ip in ok_ips]
        if both:
            out.append(f"🔴 疑似爆破成功：{'、'.join(both[:3])} 先出现登录失败、"
                       "随后出现登录成功，需立即核实这些登录")
    if s.get("logon_success"):
        lt = s.get("logon_type_counts") or {}
        rdp = lt.get("10", 0)
        line = f"登录成功合计 {s['logon_success']} 次"
        if lt:
            line += "（登录类型分布：" + "、".join(
                f"type {k}={v}" for k, v in list(lt.items())[:4]) + "）"
        out.append(line)
        if rdp:
            out.append(f"其中 RDP（LogonType 10）登录 {rdp} 次，"
                       "需确认来源 IP 是否在允许范围内")
    if s.get("account_changes"):
        out.append(f"账号变更 {len(s['account_changes'])} 次（新建/启用/重置密码/改属性）")
    if s.get("group_changes"):
        out.append(f"⚠ 安全组成员变更 {len(s['group_changes'])} 次，"
                   "重点核查是否被加入 Administrators 等特权组")
    if s.get("services") or s.get("scheduled_tasks"):
        out.append(f"⚠ 持久化迹象：新增服务 {len(s.get('services') or [])} 个、"
                   f"计划任务 {len(s.get('scheduled_tasks') or [])} 个")
    if s.get("share_access_count"):
        out.append(f"网络共享访问 {s['share_access_count']} 次（事件 5140/5145），"
                   "结合登录类型 3 可判断横向移动")
    if not any([s.get("logon_failed"), s.get("logon_success"), s.get("account_changes")]):
        out.append("未发现登录/账号相关事件（可能未开启对应审计策略）")
    return out


def _linux_conclusion(s: dict, alerts: list) -> list:
    """Linux：SSH 爆破、成功登录、sudo 提权、账号变更。"""
    out = []
    if s.get("failed_logins"):
        ips = s.get("fail_by_ip") or []
        users = s.get("fail_by_user") or []
        line = f"SSH 登录失败合计 {s['failed_logins']} 次"
        if ips:
            line += "，Top 来源：" + "、".join(f"{x['ip']}（{x['count']} 次）" for x in ips[:3])
        if users:
            line += "；Top 目标账号：" + "、".join(f"{x['user']}（{x['count']} 次）" for x in users[:3])
        out.append(line)
        fail_ips = {x["ip"] for x in (s.get("fail_by_ip") or [])}
        ok_ips = {x["ip"] for x in (s.get("ok_by_ip") or [])}
        both = sorted(fail_ips & ok_ips)
        if both:
            out.append(f"🔴 疑似爆破成功：{'、'.join(both[:3])} 先失败后成功登录，"
                       "需立即核实并禁用相关凭据")
    if s.get("invalid_user"):
        out.append(f"无效用户名尝试 {s['invalid_user']} 次（用户名枚举）")
    if s.get("success_logins"):
        out.append(f"登录成功 {s['success_logins']} 次")
    if s.get("sudo_commands"):
        out.append(f"sudo 提权 {s['sudo_commands']} 次")
        risky = [c for c in (s.get("sudo_samples") or [])
                 if re.search(r"useradd|visudo|chmod\s+777|/etc/passwd|curl.*\|\s*(?:ba)?sh|"
                              r"nc\s|ncat|/dev/tcp", c.get("message", ""), re.I)]
        if risky:
            out.append(f"⚠ sudo 执行了敏感命令 {len(risky)} 次，例如："
                       f"{risky[0]['message'][:80]}")
    if s.get("account_changes"):
        out.append(f"账号变更 {len(s['account_changes'])} 次（useradd/usermod/passwd）")
    if not any([s.get("failed_logins"), s.get("success_logins")]):
        out.append("未发现认证相关事件（可能不是 secure/auth.log，或未记录 SSH）")
    return out


def _database_conclusion(s: dict, alerts: list) -> list:
    """数据库：注入、拖库、权限变更。"""
    out = []
    if s.get("risky_statements"):
        out.append(f"🔴 检出注入/危险函数语句 {len(s['risky_statements'])} 条，"
                   "来源账号：" + "、".join(sorted(
                       {x.get("user") or "?" for x in s["risky_statements"]})[:3]))
        out.append(f"样例：{s['risky_statements'][0]['sql'][:120]}")
    if s.get("destructive_statements"):
        out.append(f"🔴 破坏性语句 {len(s['destructive_statements'])} 条"
                   "（DROP/TRUNCATE/无 WHERE 的 DELETE）")
    if s.get("privilege_changes"):
        out.append(f"⚠ 权限变更 {len(s['privilege_changes'])} 次"
                   "（GRANT/CREATE USER/ALTER LOGIN 等）")
    if s.get("bulk_reads"):
        out.append(f"⚠ 批量读取迹象 {len(s['bulk_reads'])} 条"
                   "（同一账号高频 SELECT，可能是拖库）")
    if s.get("auth_failed"):
        ips = s.get("by_ip") or []
        line = f"数据库认证失败 {s['auth_failed']} 次"
        if ips:
            line += "，来源 IP：" + "、".join(f"{x['ip']}（{x['count']} 次）" for x in ips[:3])
        out.append(line)
    kinds = s.get("stmt_kinds") or {}
    if kinds:
        out.append("语句类型分布：" + "、".join(f"{k}={v}" for k, v in list(kinds.items())[:6]))
    if s.get("by_engine"):
        out.append("数据库引擎：" + "、".join(f"{k}（{v} 条）" for k, v in s["by_engine"].items()))
    if not any([s.get("risky_statements"), s.get("destructive_statements"),
                s.get("privilege_changes"), s.get("auth_failed")]):
        out.append("未发现高危数据库操作")
    return out


def _pcap_conclusion(s: dict, alerts: list) -> list:
    """流量包：扫描、C2、隧道、凭据、外传。"""
    out = []
    if not s:
        return ["未解析到流量事件"]
    total = s.get("total_requests") or 0
    if total:
        out.append(f"共还原 {total} 条 HTTP 请求")
    ups = s.get("uploads") or []
    if ups:
        out.append(f"流量中的上传动作 {len(ups)} 次")
    hits = s.get("webshell_hits") or []
    if hits:
        out.append(f"⚠ 可写目录脚本被 POST {len(hits)} 次（疑似 webshell 交互）")
    net_alerts = [a for a in alerts if a.get("rule_id") in
                  ("net-anomaly", "stream-content", "http-content")]
    if net_alerts:
        worst = sorted(net_alerts, key=lambda a: a.get("severity", 9))[0]
        out.append(f"流量侧告警 {len(net_alerts)} 类，最高「{worst.get('title')}」"
                   f"（{worst.get('severity_label')}）")
    else:
        out.append("未发现流量侧威胁特征")
    out.append("说明：HTTPS 载荷与 IP 分片无法还原，只能取 TLS SNI/JA3 与明文流量")
    return out


def _generic_conclusion(s: dict, alerts: list) -> list:
    out = []
    if s.get("total_events"):
        out.append(f"通用日志共 {s['total_events']} 条事件")
    hits = [a for a in alerts]
    if hits:
        out.append(f"命中 {len(hits)} 类规则，最高「{hits[0].get('title')}」")
    else:
        out.append("未命中规则（通用类型只做 IOC 与命令混淆检测，深度有限）")
    out.append("建议：如能确定日志真实类型，请在证据列表里手动改判，"
               "以启用该类型专属规则")
    return out


CONCLUSION_FNS = {
    "_web_conclusion": _web_conclusion,
    "_windows_conclusion": _windows_conclusion,
    "_linux_conclusion": _linux_conclusion,
    "_database_conclusion": _database_conclusion,
    "_pcap_conclusion": _pcap_conclusion,
    "_generic_conclusion": _generic_conclusion,
}


def stats_key_for(profile_key: str) -> str:
    return {"web-access": "web", "winsec": "windows", "linux-auth": "linux",
            "database": "database", "pcap": "web", "generic": "generic"}.get(
                profile_key, "generic")


def build_type_reports(log_stats: dict, alerts: list) -> list:
    """按日志类型生成分析报告（KPI + 结论）。只生成实际加载了的类型。"""
    by_type = log_stats.get("by_log_type") or {}
    loaded = set()
    for lt in by_type:
        pk = PARSER_TO_PROFILE.get(lt)
        if pk:
            loaded.add(pk)
    out = []
    for key, prof in PROFILES.items():
        if key not in loaded:
            continue
        fn = CONCLUSION_FNS[prof["conclusion"]]
        s = log_stats.get(stats_key_for(key)) or {}
        scoped = [a for a in alerts
                  if a.get("rule_id") in prof["focus_rules"]]
        conclusions = fn(s, scoped)
        out.append({
            "key": key,
            "name": prof["name"],
            "short": prof["short"],
            "category": prof["category"],
            "color": prof["color"],
            "question": prof["question"],
            "kpis": _kpis_for(key, s),
            "kpi_labels": prof["kpis"],
            "conclusions": conclusions,
            "focus_rules": prof["focus_rules"],
            "alert_count": len(scoped),
            "events": sum(by_type.get(p, 0) for p in prof["parsers"]),
            "export_hint": prof["export_hint"],
        })
    out.sort(key=lambda r: -r["alert_count"])
    return out


def _kpis_for(key: str, s: dict) -> list:
    def k(label, value, tone="normal"):
        return {"label": label, "value": value, "tone": tone}

    if key == "web-access":
        cls = s.get("status_class_summary") or {}
        return [
            k("总请求数", s.get("total_requests", 0)),
            k("独立客户端 IP", s.get("distinct_clients", 0)),
            k("2xx 成功请求", cls.get("2xx", 0), "good"),
            k("4xx 客户端错误", cls.get("4xx", 0), "warn"),
            k("请求方法种类", s.get("method_kinds", 0)),
            k("后台登录成功", len(s.get("login_success") or []),
              "bad" if s.get("login_success") else "normal"),
            k("文件上传调用", len(s.get("uploads") or []),
              "bad" if s.get("uploads") else "normal"),
            k("上传后落地脚本", len(s.get("post_upload_scripts") or []),
              "bad" if s.get("post_upload_scripts") else "normal"),
        ]
    if key == "winsec":
        tone = "bad" if s.get("log_cleared") else "normal"
        return [
            k("总事件数", s.get("total_events", 0)),
            k("登录失败", s.get("logon_failed", 0), "warn"),
            k("登录成功", s.get("logon_success", 0)),
            k("账号变更", len(s.get("account_changes") or []), "warn"),
            k("组成员变更", len(s.get("group_changes") or []), "warn"),
            k("服务/计划任务", len(s.get("services") or []) + len(s.get("scheduled_tasks") or []), "warn"),
            k("日志清除", len(s.get("log_cleared") or []), tone),
            k("进程创建", s.get("process_creates", 0)),
        ]
    if key == "linux-auth":
        return [
            k("总事件数", s.get("total_events", 0)),
            k("失败登录", s.get("failed_logins", 0), "warn"),
            k("成功登录", s.get("success_logins", 0)),
            k("无效用户名", s.get("invalid_user", 0), "warn"),
            k("sudo 次数", s.get("sudo_commands", 0)),
            k("账号变更", len(s.get("account_changes") or []), "warn"),
        ]
    if key == "database":
        return [
            k("总语句数", s.get("queries", 0)),
            k("高危语句", len(s.get("risky_statements") or []), "bad"),
            k("破坏性语句", len(s.get("destructive_statements") or []), "bad"),
            k("权限变更", len(s.get("privilege_changes") or []), "warn"),
            k("批量读取", len(s.get("bulk_reads") or []), "warn"),
            k("认证失败", s.get("auth_failed", 0), "warn"),
        ]
    if key == "pcap":
        return [
            k("HTTP 请求", s.get("total_requests", 0)),
            k("上传调用", len(s.get("uploads") or []), "warn"),
            k("可写目录 POST", len(s.get("webshell_hits") or []), "bad"),
        ]
    return [k("总事件数", s.get("total_events", 0))]


# ---------------------------------------------------------------- 跨类型关联

def _as_ips(value) -> list:
    """实体里的 src_ip / candidate_ips 可能是字符串或列表，统一成 IP 字符串列表。"""
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            if v:
                out.append(str(v))
        return out
    return [str(value)]


def build_correlation(log_stats: dict, alerts: list) -> dict:
    """跨类型综合关联：统一攻击者画像 + 跨源时间线 + 关联结论 + 全局 IOC。"""
    ips: dict = {}

    def _ip(ip) -> list:
        out = []
        for x in _as_ips(ip):
            e = ips.setdefault(x, {
                "ip": x, "types": set(), "web_attacks": 0, "win_fail": 0, "win_ok": 0,
                "db_risky": 0, "linux_fail": 0, "linux_ok": 0, "first": None, "last": None,
                "critical": False, "high": False,
            })
            out.append(e)
        return out

    def _flag(a: dict) -> None:
        if a.get("severity") == 1:
            for e in cur:
                e["critical"] = True
        elif a.get("severity") == 2:
            for e in cur:
                e["high"] = True

    cur = []  # 当前批次命中的条目（供 _flag 使用）
    # Web 侧
    w = log_stats.get("web") or {}
    for x in (w.get("top_client_ips") or []):
        for e in _ip(x["ip"]):
            e["types"].add("web")
    for a in alerts:
        if a.get("rule_id") in ("web-attack", "webshell", "attack-chain", "http-content"):
            cur = _ip((a.get("entities") or {}).get("src_ip"))
            for e in cur:
                e["types"].add("web")
                e["web_attacks"] += a.get("count") or 1
                _span(e, a)
            _flag(a)

    # Windows 侧
    win = log_stats.get("windows") or {}
    for x in (win.get("fail_by_ip") or []):
        for e in _ip(x["ip"]):
            e["types"].add("windows")
            e["win_fail"] += x["count"]
    for x in (win.get("ok_by_ip") or []):
        for e in _ip(x["ip"]):
            e["types"].add("windows")
            e["win_ok"] += x["count"]
    for a in alerts:
        if a.get("rule_id") in ("brute-force", "account-abuse", "ransomware",
                                "command-obfuscation"):
            cur = _ip((a.get("entities") or {}).get("candidate_ips"))
            for e in cur:
                e["types"].add("windows")
                _span(e, a)
            _flag(a)

    # Linux 侧
    lin = log_stats.get("linux") or {}
    for x in (lin.get("fail_by_ip") or []):
        for e in _ip(x["ip"]):
            e["types"].add("linux")
            e["linux_fail"] += x["count"]
    for x in (lin.get("ok_by_ip") or []):
        for e in _ip(x["ip"]):
            e["types"].add("linux")
            e["linux_ok"] += x["count"]
    for a in alerts:
        if a.get("rule_id") in ("brute-force", "account-abuse"):
            for e in _ip((a.get("entities") or {}).get("candidate_ips")):
                e["types"].add("linux")

    # 数据库侧
    db = log_stats.get("database") or {}
    for x in (db.get("by_ip") or []):
        for e in _ip(x["ip"]):
            e["types"].add("database")
    for x in (db.get("risky_statements") or []):
        for e in _ip(x.get("ip")):
            e["db_risky"] += 1
            e["types"].add("database")

    # 关联结论
    conclusions = _correlation_conclusions(ips, log_stats, alerts)

    # 结论等级回写到对应 IP 画像：一条 critical/high 结论点名的 IP，
    # 其画像风险应同步升级，避免「结论说紧急、画像却标低风险」的不一致。
    for c in conclusions:
        lvl = c.get("level")
        if lvl not in ("critical", "high"):
            continue
        for ip in (c.get("ips") or []):
            e = ips.get(ip)
            if not e:
                continue
            if lvl == "critical":
                e["critical"] = True
            else:
                e["high"] = True

    # 全局 IOC
    iocs = _global_iocs(log_stats, alerts)

    # 跨源时间线
    timeline = [{
        "time": a.get("first_time"),
        "ip": (_as_ips((a.get("entities") or {}).get("src_ip")) or [""])[0],
        "rule": a.get("rule_id"), "title": a.get("title"),
        "severity": a.get("severity"), "severity_label": a.get("severity_label"),
    } for a in alerts if a.get("first_time")]
    timeline.sort(key=lambda x: x["time"] or "")

    # IP 画像（结论回写后再统一计算风险等级）
    profiles = []
    for e in ips.values():
        risk = "low"
        if e["critical"]:
            risk = "critical"
        elif e["high"] or len(e["types"]) >= 3:
            risk = "high"
        elif e["types"]:
            risk = "medium"
        profiles.append({
            "ip": e["ip"],
            "types": sorted(e["types"]),
            "web_attacks": e["web_attacks"],
            "win_fail": e["win_fail"], "win_ok": e["win_ok"],
            "db_risky": e["db_risky"],
            "linux_fail": e["linux_fail"], "linux_ok": e["linux_ok"],
            "risk": risk,
            "first": e["first"], "last": e["last"],
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    profiles.sort(key=lambda p: (order.get(p["risk"], 9), -len(p["types"])))

    return {
        "ip_profiles": profiles[:50],
        "conclusions": conclusions,
        "iocs": iocs,
        "timeline": timeline[:300],
        "type_count": len({t for e in ips.values() for t in e["types"]}),
    }


def _span(e: dict, a: dict) -> None:
    t = a.get("first_time")
    if not t:
        return
    if e["first"] is None or t < e["first"]:
        e["first"] = t
    t2 = a.get("last_time") or t
    if e["last"] is None or t2 > e["last"]:
        e["last"] = t2


def _correlation_conclusions(ips: dict, log_stats: dict, alerts: list) -> list:
    out = []
    # 1) Web 注入 -> 数据库高危语句
    web_atk = {ip for ip, e in ips.items() if e["web_attacks"]}
    db_ips = {ip for ip, e in ips.items() if e["db_risky"]}
    both = sorted(web_atk & db_ips)
    if both:
        out.append({
            "level": "critical",
            "text": f"疑似 Web 注入打到数据库：{'、'.join(both[:3])} 在 Web 日志中有攻击命中，"
                    f"同时在数据库日志中出现注入/危险函数语句。需立即核查该库数据完整性，"
                    f"并检查是否有 into outfile / load_file 等文件读写。",
            "ips": both[:5],
        })
    # 2) Linux 爆破成功 + Windows 网络登录
    lin_ok = {ip for ip, e in ips.items() if e["linux_ok"] and e["linux_fail"]}
    win_net = {ip for ip, e in ips.items() if e["win_ok"]}
    cross = sorted(lin_ok & win_net)
    if cross:
        out.append({
            "level": "critical",
            "text": f"疑似跨主机横向移动：{'、'.join(cross[:3])} 在 Linux 侧先爆破后登录成功，"
                    f"同时在 Windows 侧出现登录成功。需核查该 IP 能否同时触达两类主机。",
            "ips": cross[:5],
        })
    # 3) 爆破 -> 提权（Windows 失败后成功 + 特权/组成员变更）
    win_both = {ip for ip, e in ips.items() if e["win_fail"] and e["win_ok"]}
    if win_both:
        win = log_stats.get("windows") or {}
        priv = len(win.get("group_changes") or []) + len(win.get("account_changes") or [])
        if priv:
            out.append({
                "level": "critical",
                "text": f"疑似爆破后提权：{'、'.join(sorted(win_both)[:3])} 先大量登录失败、"
                        f"随后登录成功，且同期有 {priv} 次账号/组成员变更。"
                        f"需核查是否被加入 Administrators 等特权组。",
                "ips": sorted(win_both)[:5],
            })
    # 4) 多类型同时出现
    multi = [e for e in ips.values() if len(e["types"]) >= 2]
    if multi:
        names = "、".join(f"{e['ip']}（{'/'.join(sorted(e['types']))}）" for e in multi[:3])
        out.append({
            "level": "high",
            "text": f"{len(multi)} 个 IP 同时出现在多种日志中：{names}。"
                    f"单一来源跨多类资产活动，通常是同一攻击者在推进。",
            "ips": [e["ip"] for e in multi[:5]],
        })
    # 5) 日志清除
    win = log_stats.get("windows") or {}
    if win.get("log_cleared"):
        out.append({
            "level": "critical",
            "text": f"Windows 安全日志被清除 {len(win['log_cleared'])} 次。"
                    f"这是反取证行为，后续事件可能已不可见，需结合网络侧日志补齐时间线。",
            "ips": [],
        })
    if not out:
        out.append({
            "level": "info",
            "text": "未发现跨类型的强关联。若只导入了一类日志，关联视图信息有限——"
                    "建议同时导入 Web + Windows + 数据库日志以获得完整攻击链。",
            "ips": [],
        })
    return out


def _global_iocs(log_stats: dict, alerts: list) -> dict:
    """汇总所有类型的 IOC，分类展示。"""
    ips, users, paths, sqls, cmds, uas = set(), set(), set(), set(), set(), set()

    w = log_stats.get("web") or {}
    for x in (w.get("top_client_ips") or []):
        ips.add(x["ip"])
    for u in (w.get("login_success") or []):
        if u.get("user_agent"):
            uas.add(u["user_agent"][:80])
    for x in (w.get("post_upload_scripts") or []):
        paths.add(x["path"])
    for a in alerts:
        if a.get("rule_id") in ("web-attack", "webshell", "attack-chain", "http-content"):
            for ip in _as_ips((a.get("entities") or {}).get("src_ip")):
                ips.add(ip)
            u = (a.get("entities") or {}).get("uri")
            if u:
                paths.add(u)

    win = log_stats.get("windows") or {}
    for x in (win.get("fail_by_user") or []):
        if x["user"]:
            users.add(x["user"])
    for x in (win.get("fail_by_ip") or []):
        ips.add(x["ip"])
    for x in (win.get("services") or []):
        if x.get("process"):
            cmds.add(x["process"])
    for x in (win.get("scheduled_tasks") or []):
        if x.get("process"):
            cmds.add(x["process"])

    lin = log_stats.get("linux") or {}
    for x in (lin.get("fail_by_user") or []):
        if x["user"]:
            users.add(x["user"])
    for x in (lin.get("fail_by_ip") or []):
        ips.add(x["ip"])

    db = log_stats.get("database") or {}
    for x in (db.get("risky_statements") or []):
        sqls.add(x["sql"][:120])
    for x in (db.get("by_user") or []):
        if x["user"]:
            users.add(x["user"])

    for a in alerts:
        for ip in _as_ips((a.get("entities") or {}).get("candidate_ips")):
            ips.add(ip)
        p = (a.get("entities") or {}).get("process")
        if p:
            cmds.add(p)
        for ip in _as_ips((a.get("entities") or {}).get("src_ip")):
            ips.add(ip)

    return {
        "attack_ips": sorted(ips),
        "target_accounts": sorted(users),
        "sensitive_paths": sorted(paths),
        "risky_sql": sorted(sqls)[:20],
        "suspicious_commands": sorted(cmds)[:20],
        "scanner_user_agents": sorted(uas)[:20],
    }

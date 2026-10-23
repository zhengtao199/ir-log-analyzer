"""自定义规则库：查看 / 修改 / 新增检测规则。

设计目标
--------
让使用工具的人能把自己的环境特征（自有系统路径、内部域名、业务专有名词、
历史事件的 IOC）固化成检测规则，而不用改代码。

三条使用路径
------------
1. **查看**：`builtin_inventory()` 给出 13 类内置规则各自在匹配什么
   （特征 ID、类型、内容、说明），与代码里的正则同源，由测试守护不漂移。
2. **追加**：`attaches_to` 指向某个内置规则 ID 时，自定义特征命中后按该
   内置规则的 ID 与标题出告警 —— 相当于「给 Webshell 规则加了一条 payload」。
3. **新建**：不设 `attaches_to` 就是一条独立的新规则分类，自定义 ID、标题、
   严重度、MITRE、处置建议，分析时作为独立检测器运行。

持久化与合规
------------
规则库存到工作目录的 ``rules/custom.json``，**不属于证据链**（证据链只覆盖
被分析的日志原件）。所有增删改都会写入审计日志（谁、何时、改了哪条）。
导入支持「合并」与「整体替换」两种语义，替换前会先备份原文件。
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from .models import SEVERITY_LABELS

RULES_SUBDIR = "rules"
RULES_FILE = "custom.json"
PACK_VERSION = 1

# 匹配范围：决定特征拿事件的哪段文本去比
SCOPES = {
    "all": "全部（URI + 请求体 + 进程命令行 + 原始日志）",
    "uri": "仅 Web 请求 URI",
    "body": "仅 HTTP 请求体",
    "process": "仅进程 / 命令行",
    "raw": "仅原始日志行",
    "fields": "仅结构化字段（IP/账号/域名/文件路径）",
}
DEFAULT_SCOPE = "all"

SEVERITY_CHOICES = tuple(sorted(SEVERITY_LABELS.items()))  # [(1,'紧急'),...]


# ---------------------------------------------------------------- 数据模型

@dataclass
class Pattern:
    """一条匹配特征。kind=regex 时 value 是正则，kind=keyword 时是普通文本。"""
    id: str
    kind: str = "keyword"          # keyword | regex
    value: str = ""
    note: str = ""
    enabled: bool = True

    def compile(self) -> "re.Pattern":
        flags = re.IGNORECASE
        if self.kind == "regex":
            return re.compile(self.value, flags)
        return re.compile(re.escape(self.value), flags)


@dataclass
class CustomRule:
    """一条自定义规则（或挂在内置规则下的附加特征集）。"""
    rule_id: str
    title: str
    severity: int = 3
    description: str = ""
    mitre: str = ""
    recommendation: str = ""
    scope: str = DEFAULT_SCOPE
    patterns: list = field(default_factory=list)     # [Pattern]
    enabled: bool = True
    attaches_to: Optional[str] = None                # 归属的内置规则 ID
    builtin: bool = False                            # True = 内置规则的附加特征
    created: float = 0.0
    updated: float = 0.0

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        d = asdict(self)
        d["patterns"] = [asdict(p) for p in self.patterns]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CustomRule":
        pats = [Pattern(**{k: v for k, v in p.items()
                           if k in Pattern.__dataclass_fields__})
                for p in (d.get("patterns") or [])]
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        known["patterns"] = pats
        return cls(**known)

    # ---- 运行时 ----
    def active_patterns(self) -> list:
        return [p for p in self.patterns if p.enabled and p.value.strip()]

    def match_text(self, ev) -> str:
        """按 scope 取待匹配文本。"""
        scope = self.scope or DEFAULT_SCOPE
        detail = ev.detail or {}      # 部分事件可能没有结构化字段
        if scope == "uri":
            return ev.uri or ""
        if scope == "body":
            return detail.get("http_body") or ""
        if scope == "process":
            return " ".join(x for x in (ev.process, ev.parent_process,
                                        detail.get("CommandLine"),
                                        detail.get("command")) if x)
        if scope == "raw":
            return ev.raw or ""
        if scope == "fields":
            parts = [ev.src_ip, ev.dst_ip, ev.user, ev.host, ev.domain,
                     ev.file_path, ev.hashes, ev.user_agent, ev.uri]
            return " ".join(str(x) for x in parts if x)
        # all：尽量宽，覆盖 Web / 主机 / 数据库 / 流量各类日志
        parts = [ev.uri, detail.get("http_body"), ev.process, ev.parent_process,
                 detail.get("CommandLine"), detail.get("command"),
                 detail.get("sql"), detail.get("query"), ev.domain, ev.raw]
        return " ".join(str(x) for x in parts if x)

    def validate(self) -> list[str]:
        """返回人类可读的问题列表（空列表 = 通过）。"""
        errs = []
        if not self.rule_id or not re.fullmatch(r"[a-z0-9][a-z0-9\-]{1,48}", self.rule_id or ""):
            errs.append("规则 ID 只能用小写字母/数字/连字符，2-49 字符，且需以字母或数字开头")
        if not self.title.strip():
            errs.append("规则名称不能为空")
        if self.severity not in SEVERITY_LABELS:
            errs.append(f"严重度必须是 {sorted(SEVERITY_LABELS)} 之一")
        if self.scope not in SCOPES:
            errs.append(f"匹配范围必须是 {sorted(SCOPES)} 之一")
        if not self.patterns:
            errs.append("至少需要一条匹配特征")
        for p in self.patterns:
            if not p.value.strip():
                errs.append(f"特征 {p.id or '(未命名)'} 的内容为空")
                continue
            if p.kind not in ("keyword", "regex"):
                errs.append(f"特征 {p.id} 的类型必须是 keyword 或 regex")
            elif p.kind == "regex":
                try:
                    p.compile()
                except re.error as exc:
                    errs.append(f"特征 {p.id} 的正则无法编译: {exc}")
        return errs


@dataclass
class RulePack:
    """规则库：自定义规则 + 被屏蔽的内置特征。"""
    version: int = PACK_VERSION
    rules: dict = field(default_factory=dict)        # rule_id -> CustomRule
    disabled_builtin: list = field(default_factory=list)   # 要屏蔽的内置特征文本
    updated: float = 0.0

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "updated": self.updated,
            "updated_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated or time.time())),
            "disabled_builtin": list(self.disabled_builtin),
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RulePack":
        pack = cls(version=int(d.get("version") or PACK_VERSION),
                   updated=float(d.get("updated") or 0.0),
                   disabled_builtin=list(d.get("disabled_builtin") or []))
        for rid, rd in (d.get("rules") or {}).items():
            rd = dict(rd)
            rd.setdefault("rule_id", rid)
            try:
                pack.rules[rid] = CustomRule.from_dict(rd)
            except (TypeError, ValueError):
                continue
        return pack

    # ---- 文件 ----
    @staticmethod
    def path_of(workdir: str) -> str:
        return os.path.join(os.path.abspath(workdir), RULES_SUBDIR, RULES_FILE)

    @classmethod
    def load(cls, workdir: str) -> "RulePack":
        p = cls.path_of(workdir)
        if not os.path.isfile(p):
            return cls()
        try:
            with open(p, encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            # 规则库损坏不应让分析跑不起来：退回空库并保留坏文件供人工检查
            return cls()

    def save(self, workdir: str) -> str:
        self.updated = time.time()
        d = os.path.dirname(self.path_of(workdir))
        os.makedirs(d, exist_ok=True)
        p = self.path_of(workdir)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)      # 原子替换，避免写一半
        return p

    # ---- 增删改 ----
    def upsert(self, rule: CustomRule) -> None:
        now = time.time()
        old = self.rules.get(rule.rule_id)
        rule.updated = now
        rule.created = old.created if old else now
        self.rules[rule.rule_id] = rule

    def remove(self, rule_id: str) -> bool:
        return self.rules.pop(rule_id, None) is not None

    def set_builtin_disabled(self, texts: list) -> None:
        self.disabled_builtin = [t for t in (texts or []) if t and t.strip()]

    def merge(self, other: "RulePack") -> dict:
        """合并导入：同 ID 覆盖，新 ID 追加；返回统计。"""
        added, updated = [], []
        for rid, r in other.rules.items():
            if rid in self.rules:
                updated.append(rid)
            else:
                added.append(rid)
            self.upsert(r)
        # 禁用项取并集
        merged = list(dict.fromkeys(list(self.disabled_builtin) + list(other.disabled_builtin)))
        self.disabled_builtin = merged
        return {"added": added, "updated": updated,
                "disabled_builtin": len(merged)}

    def replace_with(self, other: "RulePack") -> None:
        self.rules = dict(other.rules)
        self.disabled_builtin = list(other.disabled_builtin)
        self.version = other.version

    # ---- 查询 ----
    def custom_rules(self) -> list:
        """独立的新规则分类（不含挂在内置规则下的附加特征）。"""
        return [r for r in self.rules.values() if not r.attaches_to]

    def attachments(self) -> dict:
        """{内置规则 ID: [CustomRule, ...]}"""
        out: dict = {}
        for r in self.rules.values():
            if r.attaches_to:
                out.setdefault(r.attaches_to, []).append(r)
        return out

    def enabled_rules(self) -> list:
        return [r for r in self.rules.values() if r.enabled]


# ---------------------------------------------------------------- 内置规则清单

def builtin_inventory() -> list:
    """内置规则的匹配特征清单（供页面查看）。

    与检测器代码同源；`tests/test_rulepack.py` 会逐条核对这里写的内容
    确实存在于对应检测器源码里，防止文档与实现漂移。
    """
    from .detectors import ALL_DETECTORS
    meta = {c.rule_id: c for c in ALL_DETECTORS}
    out = []
    for rule_id, c in meta.items():
        out.append({
            "rule_id": rule_id,
            "title": c.title,
            "description": c.description,
            "mitre": c.mitre,
            "recommendation": c.recommendation,
            "severity": getattr(c, "default_severity", None),
            "builtin": True,
            "patterns": BUILTIN_PATTERNS.get(rule_id, []),
        })
    return out


def builtin_rule_ids() -> list:
    from .detectors import ALL_DETECTORS
    return [c.rule_id for c in ALL_DETECTORS]


# 各内置规则的主要匹配特征（kind: keyword/regex）
BUILTIN_PATTERNS: dict = {
    "brute-force": [
        {"id": "logon-failed-action", "kind": "keyword", "value": "logon-failed",
         "note": "归一化动作：登录失败（Windows 4625 / Linux sshd 认证失败 / Web 登录 4xx）"},
        {"id": "window-threshold", "kind": "keyword", "value": "brute_force_threshold",
         "note": "窗口内失败次数阈值（默认 5），可由 --set 覆盖"},
    ],
    "webshell": [
        {"id": "writable-dir-script", "kind": "regex",
         "value": r"/(?:content/plugins|plugins|uploads?|attach(?:ment)?s?|tmp|temp|cache|runtime|editor|ueditor|userfiles|media)/",
         "note": "可写目录中的脚本文件（webshell 典型落地位置）"},
        {"id": "cmd-params", "kind": "regex",
         "value": r"(?:^|[?&])(cmd|exec|command|code|payload|eval|system|passthru|shell_exec|assert|base64_decode)\s*=",
         "note": "URI 含命令执行类参数（参数堆叠 >=12 个时判为 fuzzing，不采信）"},
        {"id": "shell-tokens", "kind": "regex",
         "value": r"\b(whoami|net\s+user|ipconfig|/etc/passwd|systeminfo|tasklist|powershell|eval\(|assert\()\b",
         "note": "URI/请求体含系统命令特征"},
        {"id": "web-proc-spawn", "kind": "keyword",
         "value": "w3wp.exe|httpd|php-cgi|tomcat|inetinfo",
         "note": "Web 服务进程派生命令行解释器（主机侧）"},
    ],
    "web-attack": [
        {"id": "sqli", "kind": "regex",
         "value": r"(?:union\s+all\s+select|sleep\(|benchmark\(|waitfor\s+delay|information_schema|xp_cmdshell|'\s*or\s+'?1'?\s*=\s*'?1)",
         "note": "SQL 注入特征"},
        {"id": "xss", "kind": "regex",
         "value": r"(?:<script|javascript:|onerror\s*=|onload\s*=|\balert\s*\(|document\.cookie)",
         "note": "XSS 特征"},
        {"id": "traversal", "kind": "regex",
         "value": r"(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
         "note": "路径遍历 / 敏感文件探测"},
        {"id": "long-uri", "kind": "keyword", "value": "web_attack_path_len",
         "note": "URI 超长（默认 >512，疑似溢出/混淆）"},
        {"id": "404-scan", "kind": "keyword", "value": "web_attack_404_burst",
         "note": "单 IP 404 次数超限（默认 >50，目录扫描）"},
    ],
    "account-abuse": [
        {"id": "logon-success-odd", "kind": "keyword", "value": "logon-success",
         "note": "登录成功但来源/时间/主机异常（下班时间、新设备、非常用地）"},
        {"id": "lateral-type3", "kind": "keyword", "value": "lateral_type3_burst",
         "note": "网络登录（type 3）突增，横向移动特征"},
        {"id": "lateral-hosts", "kind": "keyword", "value": "lateral_max_hosts",
         "note": "单账号登录主机数超限（默认 >3）"},
    ],
    "exfiltration": [
        {"id": "big-response", "kind": "keyword", "value": "exfil_response_bytes",
         "note": "单请求响应体超限（默认 50MB）"},
        {"id": "daily-bytes", "kind": "keyword", "value": "exfil_daily_bytes",
         "note": "单 IP 单日出向流量超限（默认 500MB）"},
        {"id": "sensitive-file", "kind": "regex",
         "value": r"(?:/etc/passwd|/etc/shadow|\.ssh/id_rsa|web\.config|connectionstrings|\.sql$|\.mdb$|\.bak$)",
         "note": "敏感文件被成功下载（200）"},
    ],
    "ransomware": [
        {"id": "filecreate-burst", "kind": "keyword", "value": "ransomware_filecreate_burst",
         "note": "单进程窗口内文件创建数超限（默认 100）"},
        {"id": "ransom-exts", "kind": "keyword",
         "value": "locked|enc|encrypted|crypt|crypto|lockbit|ryuk|conti",
         "note": "勒索软件典型扩展名"},
        {"id": "ransom-note", "kind": "regex",
         "value": r"(?:readme.*decrypt|how[_ ]?to[_ ]?decrypt|your files (?:have been|are) encrypted|勒索|解密)",
         "note": "勒索信文件特征"},
    ],
    "command-obfuscation": [
        {"id": "ps-encoded", "kind": "regex",
         "value": r"(?:powershell|pwsh).{0,40}(?:-e|-ec|-en|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
         "note": "PowerShell -EncodedCommand 编码命令"},
        {"id": "b64-payload", "kind": "keyword", "value": "obf_b64_min_len",
         "note": "长度超限的 Base64 候选串（默认 >40），并做熵判定"},
        {"id": "hex-payload", "kind": "regex", "value": r"[0-9a-fA-F]{40,}",
         "note": "长 hex 串（疑似编码载荷）"},
        {"id": "caret-obfusc", "kind": "keyword", "value": "obf_caret_min",
         "note": "cmd ^ 插入混淆最少出现次数（默认 3）"},
        {"id": "lolbas", "kind": "regex",
         "value": r"\b(certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|installutil|cmstp)\b",
         "note": "LOLBAS 自带工具滥用"},
        {"id": "download-exec", "kind": "regex",
         "value": r"(?:curl|wget|iwr|certutil\s+-urlcache).{0,80}(?:\|\s*(?:sh|bash|iex)|-\w*outfile)",
         "note": "下载-落地-执行链 / 解码器管道"},
    ],
    "db-attack": [
        {"id": "sqli-in-sql", "kind": "regex",
         "value": r"(?:union\s+all\s+select|sleep\(|benchmark\(|waitfor\s+delay|information_schema|xp_cmdshell|load_file\(|into\s+outfile)",
         "note": "数据库语句中的注入特征"},
        {"id": "destructive", "kind": "regex",
         "value": r"(?:drop\s+table|truncate\s+table|delete\s+from\s+\S+\s*;|shutdown|drop\s+database)",
         "note": "破坏性语句（不带 WHERE 的 DELETE/DROP/TRUNCATE）"},
        {"id": "privilege-escalation", "kind": "regex",
         "value": r"(?:grant\s+all|create\s+user|alter\s+user|super_priv|db_owner|sysadmin)",
         "note": "数据库提权语句"},
        {"id": "dump-tables", "kind": "keyword", "value": "db_dump_min_queries",
         "note": "窗口内敏感表查询次数超限（默认 20，拖库）"},
    ],
    "net-anomaly": [
        {"id": "port-scan", "kind": "keyword", "value": "net_scan_ports",
         "note": "窗口内单源访问不同目的端口数超限（默认 20）"},
        {"id": "host-scan", "kind": "keyword", "value": "net_scan_hosts",
         "note": "窗口内单源同端口访问不同主机数超限（默认 20，横向扫描）"},
        {"id": "c2-beacon", "kind": "keyword", "value": "net_beacon_cv",
         "note": "等间隔心跳：次数>=6 且间隔变异系数<=0.35"},
        {"id": "dns-tunnel", "kind": "keyword", "value": "net_dns_entropy",
         "note": "超长/高熵 DNS 标签（隧道）；NXDOMAIN 超限判 DGA"},
        {"id": "plaintext-cred", "kind": "regex",
         "value": r"(?:USER\s+\S+|PASS\s+\S+|Authorization:\s*Basic)",
         "note": "流量中的明文凭据（FTP/HTTP Basic）"},
        {"id": "remote-ports", "kind": "keyword",
         "value": "4444|5555|6666|1337|31337|metasploit|meterpreter",
         "note": "常见远控/反弹 shell 端口"},
    ],
    "stream-content": [
        {"id": "reverse-shell", "kind": "regex",
         "value": r"(?:bash\s+-i|/dev/tcp/|nc\s+-e|socket\(|reverse)",
         "note": "反向 shell：客户端发命令 + 服务端回显 uid=0(root)"},
        {"id": "cred-pair", "kind": "regex", "value": r"(?:USER\s+\S+.*PASS\s+\S+)",
         "note": "跨报文拼合的完整凭据对（报告中口令脱敏）"},
        {"id": "stream-encoded", "kind": "keyword", "value": "obf_b64_min_len",
         "note": "会话内 Base64/hex 编码载荷"},
    ],
    "http-content": [
        {"id": "cmd-echo", "kind": "regex",
         "value": r"(?:uid=0\(root\)|Windows IP 配置|Volume Serial Number|Microsoft Windows \[Version)",
         "note": "HTTP 响应体中的命令执行回显"},
        {"id": "sensitive-in-body", "kind": "regex",
         "value": r"(?:root:x:0:0|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16})",
         "note": "响应体含敏感文件内容（passwd/私钥/云密钥）"},
        {"id": "oneline-shell", "kind": "regex",
         "value": r"(?:eval\(|assert\(|system\(|passthru\(|shell_exec\()",
         "note": "一句话木马源码"},
        {"id": "download-exec-script", "kind": "regex",
         "value": r"(?:curl\s+[^|]*\|\s*(?:sh|bash)|powershell.{0,40}-enc|certutil.{0,20}-decode)",
         "note": "下载执行类脚本"},
        {"id": "binary-magic", "kind": "keyword",
         "value": "MZ|ELF|PK\\x03\\x04|#!",
         "note": "按魔数识别下载的可执行文件"},
    ],
    "attack-chain": [
        {"id": "admin-login-ok", "kind": "regex",
         "value": r"(?:^|[?&])(?:action|do|act|op|m|a)\s*=\s*(?:do)?(?:login|signin|dologin|dosignin|checklogin)",
         "note": "后台登录成功：POST 后返回 200/302"},
        {"id": "upload-action", "kind": "regex",
         "value": r"(?:^|[?&])(?:action|do|act|op|cmd|method)\s*=\s*[^&]*upload",
         "note": "文件上传接口被成功调用"},
        {"id": "post-upload-script", "kind": "keyword", "value": "path_first_seen >= upload_ts",
         "note": "上传动作之后才首次出现的脚本，且被 POST 成功访问"},
        {"id": "writable-post", "kind": "regex",
         "value": r"/(?:content/plugins|plugins|uploads?|attach(?:ment)?s?|tmp|temp|cache|runtime|editor|userfiles|media)/",
         "note": "Web 可写目录中的脚本被反复 POST 成功"},
    ],
    "ioc": [
        {"id": "ioc-any", "kind": "keyword", "value": "<IOC 列表>",
         "note": "来自 --ioc / Web 导入的 IOC（IP/域名/Hash/URL/邮箱），逐字段匹配"},
    ],
}


# ---------------------------------------------------------------- 导入导出

def export_pack(pack: RulePack) -> bytes:
    """导出为 JSON 字节流（供下载 / 分享）。"""
    return json.dumps(pack.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")


def parse_pack(data: bytes) -> tuple[Optional[RulePack], Optional[str]]:
    """解析导入内容，返回 (pack, 错误信息)。"""
    try:
        d = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"不是合法的 JSON: {exc}"
    if not isinstance(d, dict):
        return None, "JSON 顶层必须是对象"
    if "rules" not in d and "disabled_builtin" not in d:
        return None, "缺少 rules 或 disabled_builtin 字段，不像本工具导出的规则包"
    pack = RulePack.from_dict(d)
    if not pack.rules and not pack.disabled_builtin:
        return None, "规则包为空"
    bad = []
    for rid, r in pack.rules.items():
        errs = r.validate()
        if errs:
            bad.append(f"{rid}: {'; '.join(errs)}")
    if bad:
        return None, "规则包中有无效规则 -> " + " | ".join(bad[:5])
    return pack, None


def backup_file(path: str) -> Optional[str]:
    """备份现有规则库（导入替换前调用）。"""
    if not os.path.isfile(path):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    dst = f"{path}.bak-{stamp}"
    try:
        with open(path, "rb") as s, open(dst, "wb") as d:
            d.write(s.read())
        return dst
    except OSError:
        return None

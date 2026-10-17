"""统一事件与告警数据模型。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Event:
    """归一化日志事件（所有解析器输出此结构）。"""

    ts: Optional[float] = None                 # unix 秒；无法解析时为 None
    log_type: str = ""                         # winsec / sysmon / linux-auth / web-access / iis / jsonl / generic
    source: str = ""                           # 证据文件路径
    event_id: Optional[str] = None             # Windows 事件 ID 或等价分类
    action: str = ""                           # 归一化动作：logon-failed / http-request / process-create ...
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None               # 域名（DNS 查询 / TLS SNI / HTTP Host）
    uri: Optional[str] = None                  # Web 请求路径
    method: Optional[str] = None
    status: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None
    process: Optional[str] = None              # 进程名/镜像
    parent_process: Optional[str] = None
    file_path: Optional[str] = None
    hashes: Optional[str] = None               # md5/sha1/sha256 串
    logon_type: Optional[str] = None
    detail: dict = field(default_factory=dict)
    raw: str = ""

    def key_fields(self) -> dict:
        """供 IOC 匹配的字段集合。"""
        out = {}
        for k in ("src_ip", "dst_ip", "user", "host", "domain", "uri", "process",
                  "file_path", "hashes", "user_agent"):
            v = getattr(self, k)
            if v:
                out[k] = v
        return out


# 归一化动作常量（跨日志源统一语义，检测器只认这些）
A_LOGON_FAILED = "logon-failed"
A_LOGON_SUCCESS = "logon-success"
A_SESSION_END = "session-end"             # 会话关闭（session closed / Disconnected）
A_LOGON_SPECIAL = "logon-special-privileges"
A_USER_CREATED = "user-created"
A_GROUP_MEMBER_ADDED = "group-member-added"
A_HTTP_REQUEST = "http-request"
A_PROCESS_CREATE = "process-create"
A_DB_QUERY = "db-query"                  # 数据库 SQL 语句（general log / pg statement / 慢查询）
A_DB_ADMIN = "db-admin"                  # 数据库高危管理操作（建账号/授权/删库等）
A_COMMAND_EXEC = "command-exec"           # Linux 侧命令执行（sshd execute/sudo 等）
A_FILE_CREATE = "file-create"
A_OBJECT_ACCESS = "object-access"
A_OBJECT_DELETE = "object-delete"
A_SHARE_ACCESS = "share-access"
A_SERVICE_INSTALL = "service-install"
A_SCHEDULED_TASK = "scheduled-task"
A_SUDO_COMMAND = "sudo-command"
A_NETWORK_CONN = "network-connection"
A_NET_DNS = "net-dns"                    # DNS 查询/响应（qname/qtype/rcode）
A_NET_TLS = "net-tls"                    # TLS ClientHello（SNI / JA3）
A_NET_CRED = "net-cred"                  # 明文协议凭据（FTP/Telnet/HTTP-Basic/邮件）
A_NET_FLOW = "net-flow"                  # 流摘要（包数/字节/时长，EOF 汇总）
A_NET_STREAM = "net-stream"              # TCP 重组流内容（追踪流：双向应用层数据还原）
A_GENERIC = "generic"


@dataclass
class Alert:
    """一条检测告警。"""

    rule_id: str
    title: str
    severity: int = 2                          # 1=紧急 2=高危 3=中危 4=低危
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    count: int = 0
    entities: dict = field(default_factory=dict)   # ip/user/host/uri 等
    evidence: list = field(default_factory=list)   # [(ts, source, raw)] 采样
    description: str = ""
    mitre: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "severity_label": SEVERITY_LABELS.get(self.severity, str(self.severity)),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_time": fmt_ts(self.first_ts),
            "last_time": fmt_ts(self.last_ts),
            "count": self.count,
            "entities": self.entities,
            "evidence": [
                {"ts": e[0], "time": fmt_ts(e[0]), "source": e[1], "raw": e[2]}
                for e in self.evidence
            ],
            "description": self.description,
            "mitre": self.mitre,
            "recommendation": self.recommendation,
        }


SEVERITY_LABELS = {1: "紧急", 2: "高危", 3: "中危", 4: "低危"}


def fmt_ts(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def now_ts() -> float:
    return time.time()

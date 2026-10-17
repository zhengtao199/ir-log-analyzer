"""解析器注册表：按嗅探优先级排序导入。

顺序原则：越具体的越靠前 ——
pcap > winxml > iis > web-access > database > linux-auth > linux-syslog > generic。
pcap 走二进制魔数嗅探（先于所有文本解析器）；database 需早于 linux-auth/generic：
PostgreSQL csvlog 与 SQL Server 错误日志都以日期开头，但格式不符合 syslog。
"""
from .base import (  # noqa: F401
    LogParser, detect_parser, iter_events, register, registered, is_probably_log,
)

# 导入即注册（顺序 = 文本嗅探优先级；二进制魔数嗅探独立先行）
from . import pcap         # noqa: F401
from . import winxml       # noqa: F401
from . import iis          # noqa: F401
from . import webaccess    # noqa: F401
from . import database     # noqa: F401
from . import linux        # noqa: F401
from . import generic      # noqa: F401

__all__ = ["detect_parser", "iter_events", "register", "registered", "sniff", "LogParser"]

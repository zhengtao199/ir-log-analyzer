"""Web 访问日志解析器：Nginx / Apache combined 与 common 格式。

combined:
    1.2.3.4 - - [15/Oct/2026:09:30:01 +0800] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
也支持 URI 带引号/中文、vhost 前缀（Nginx）等常见变体。
"""
from __future__ import annotations

import calendar
import re
from typing import Generator, Optional

from ..models import Event, A_HTTP_REQUEST
from .base import LogParser, register

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# 带 vhost 前缀：host ip - - [time] ...（Nginx $host 场景）
VHOST_ACCESS_RE = re.compile(
    r'^(?P<vhost>\S+)\s+(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# [14/Oct/2026:10:00:01 +0800]
CLF_TIME_RE = re.compile(
    r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_time(s: str) -> Optional[float]:
    """CLF 时间 -> unix 秒（快路径：手工解析，避免 strptime 开销）。"""
    m = CLF_TIME_RE.match(s)
    if not m:
        return None
    day, mon, year, hh, mm, ss, tz = m.groups()
    month = MONTHS.get(mon)
    if not month:
        return None
    try:
        ts = calendar.timegm((int(year), month, int(day), int(hh), int(mm), int(ss), 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    if tz:
        try:
            sign = 1 if tz[0] == "+" else -1
            ts -= sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        except ValueError:
            pass
    return float(ts)


class WebAccessParser(LogParser):
    name = "web-access"

    def detect(self, sample_lines: list[str]) -> bool:
        text = "\n".join(sample_lines[:10])
        if text.lstrip().startswith("#"):
            return False
        return bool(ACCESS_RE.search(text) or VHOST_ACCESS_RE.search(text))

    def parse(self, path: str) -> Generator[Event, None, None]:
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            m = ACCESS_RE.match(line) or VHOST_ACCESS_RE.match(line)
            if not m:
                continue
            g = m.groupdict()
            status = int(g["status"])
            try:
                nbytes = int(g["bytes"]) if g["bytes"] not in ("-", None) else 0
            except ValueError:
                nbytes = 0
            yield Event(
                ts=_parse_time(g["time"]),
                log_type="web-access",
                source=path,
                event_id=str(status),
                action=A_HTTP_REQUEST,
                host=g.get("vhost"),
                user=g["user"] if g["user"] not in ("-", None) else None,
                src_ip=g["ip"],
                uri=g["uri"],
                method=g["method"],
                status=status,
                bytes_sent=nbytes,
                user_agent=g.get("ua"),
                detail={"referer": g.get("referer"), "proto": g.get("proto")},
                raw=line[:2000],
            )


register(WebAccessParser())

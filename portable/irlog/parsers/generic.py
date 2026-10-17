"""通用解析器：JSON Lines（中间件/框架可扩展接入）与正则兜底。

JSON Lines：每行一个 JSON 对象，兼容常见字段命名
（time/timestamp/@timestamp/ts, message/msg/raw, ip/src_ip/client_ip,
user/username, uri/url/path/request, level/severity, host/hostname）。
中间件（Tomcat catalina.out、MySQL 慢日志、Redis、K8s 审计等）可先经
Filebeat/Logstash 转 JSON 后接入，或后续按本模式扩展专用解析器。
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Generator, Optional

from ..models import Event, A_GENERIC
from .base import LogParser, register

TS_KEYS = ("time", "timestamp", "@timestamp", "ts", "datetime", "eventTime", "log_time")
MSG_KEYS = ("message", "msg", "raw", "log", "line", "_raw")
IP_KEYS = ("src_ip", "ip", "client_ip", "remote_addr", "source_ip", "c-ip")
USER_KEYS = ("user", "username", "account", "cs-username")
URI_KEYS = ("uri", "url", "path", "request", "cs-uri-stem")
HOST_KEYS = ("host", "hostname", "computer", "machine")
LEVEL_KEYS = ("level", "severity", "loglevel")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 兜底时间：2026-10-15 09:30:01,123 / 09:30:01 / ISO8601
FALLBACK_TS_RE = re.compile(
    r"(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
    r"|(\d{2}:\d{2}:\d{2})"
)


def _coerce_ts(v) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        # >1e12 视为毫秒
        return v / 1000.0 if v > 1e12 else float(v)
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.isdigit():
            n = int(s)
            return n / 1000.0 if n > 1e12 else float(n)
    except ValueError:
        pass
    try:
        s2 = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


class JsonLinesParser(LogParser):
    name = "jsonl"

    def detect(self, sample_lines: list[str]) -> bool:
        ok = 0
        for line in sample_lines[:10]:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                json.loads(line)
                ok += 1
            except json.JSONDecodeError:
                return False
        return ok >= 1

    def parse(self, path: str) -> Generator[Event, None, None]:
        for line in self.read_lines(path, errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            lower = {str(k).lower(): v for k, v in obj.items()}

            def pick(keys):
                for k in keys:
                    if k in lower and lower[k] not in (None, "", "-"):
                        return lower[k]
                return None

            msg = pick(MSG_KEYS)
            raw = json.dumps(obj, ensure_ascii=False)
            uri = pick(URI_KEYS)
            yield Event(
                ts=_coerce_ts(pick(TS_KEYS)),
                log_type="jsonl",
                source=path,
                action=A_GENERIC,
                host=str(pick(HOST_KEYS)) if pick(HOST_KEYS) else None,
                user=str(pick(USER_KEYS)) if pick(USER_KEYS) else None,
                src_ip=str(pick(IP_KEYS)) if pick(IP_KEYS) else None,
                uri=str(uri) if uri else None,
                detail={"message": str(msg)[:1000] if msg else "", "fields": obj},
                raw=raw[:2000],
            )


class GenericParser(LogParser):
    """兜底解析器：尽力提取时间与 IP，原样保留，保证任何文本日志可入时间线。"""

    name = "generic"

    def detect(self, sample_lines: list[str]) -> bool:
        return True

    def parse(self, path: str) -> Generator[Event, None, None]:
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            ts = None
            m = FALLBACK_TS_RE.search(line)
            if m:
                ts = _coerce_ts(m.group(1) or m.group(2))
            ipm = IP_RE.search(line)
            yield Event(
                ts=ts,
                log_type="generic",
                source=path,
                action=A_GENERIC,
                src_ip=ipm.group(0) if ipm else None,
                detail={"message": line[:500]},
                raw=line[:2000],
            )


register(JsonLinesParser())
register(GenericParser())

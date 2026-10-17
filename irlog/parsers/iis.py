"""IIS W3C 扩展日志解析器。

格式特征：以 # 开头的指令行，#Fields 定义字段顺序，例如：
    #Software: Microsoft Internet Information Services 10.0
    #Version: 1.0
    #Date: 2026-10-15 09:30:00
    #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-bytes
    2026-10-15 09:30:00 10.0.0.1 GET /a.php - 80 - 1.2.3.4 Mozilla/5.0 200 1024
"""
from __future__ import annotations

import calendar
from typing import Generator, Optional

from ..models import Event, A_HTTP_REQUEST
from .base import LogParser, register


class IISW3CParser(LogParser):
    name = "iis"

    def detect(self, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if line.startswith("#Fields:"):
                return True
            if line.startswith("#Software:") and "Internet Information Services" in line:
                return True
        return False

    def parse(self, path: str) -> Generator[Event, None, None]:
        fields: list[str] = []
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            if line.startswith("#Fields:"):
                fields = line.split(":", 1)[1].split()
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            values = line.split()
            if len(values) != len(fields):
                continue
            row = dict(zip(fields, values))
            ev = self._to_event(row, path, line)
            if ev is not None:
                yield ev

    def _to_event(self, row: dict, path: str, raw: str) -> Optional[Event]:
        import time as _time

        ts = None
        date, tm = row.get("date"), row.get("time")
        if date and tm:
            try:
                y, mo, d = (int(x) for x in date.split("-"))
                hh, mm, ss = (int(x) for x in tm.split(":"))
                ts = float(calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0)))
            except (ValueError, OverflowError):
                ts = None
        status = row.get("sc-status")
        try:
            status_i = int(status) if status else None
        except ValueError:
            status_i = None
        try:
            nbytes = int(row.get("sc-bytes", "0") or 0)
        except ValueError:
            nbytes = 0
        uri = row.get("cs-uri-stem", "")
        query = row.get("cs-uri-query", "-")
        if query and query != "-":
            uri = f"{uri}?{query}"
        user = row.get("cs-username", "-")
        return Event(
            ts=ts,
            log_type="iis",
            source=path,
            event_id=status,
            action=A_HTTP_REQUEST,
            src_ip=row.get("c-ip"),
            uri=uri,
            method=row.get("cs-method"),
            status=status_i,
            bytes_sent=nbytes,
            user_agent=row.get("cs(User-Agent)") if row.get("cs(User-Agent)") != "-" else None,
            user=user if user != "-" else None,
            detail={"s-port": row.get("s-port"), "referer": row.get("cs(Referer)")},
            raw=raw[:2000],
        )


register(IISW3CParser())

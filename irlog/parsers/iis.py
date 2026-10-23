"""IIS W3C 扩展日志解析器。

格式特征：以 # 开头的指令行，#Fields 定义字段顺序，例如：
    #Software: Microsoft Internet Information Services 10.0
    #Version: 1.0
    #Date: 2026-10-15 09:30:00
    #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-bytes
    2026-10-15 09:30:00 10.0.0.1 GET /a.php - 80 - 1.2.3.4 Mozilla/5.0 200 1024

容错：字段数多于 #Fields 时把多余部分并入最后一个字段（UA/Referer 未做空格转义的场景），
少于则丢弃该行，避免整行丢失导致统计失真。
"""
from __future__ import annotations

import calendar
from typing import Generator, Optional

from ..models import Event, A_HTTP_REQUEST
from .base import LogParser, register

# 需要原样带入 detail 的字段（用于研判/统计，缺失时自动忽略）
_EXTRA_FIELDS = {
    "cs(Referer)": "referer",
    "time-taken": "time_taken",
    "sc-bytes": "sc_bytes",
    "cs-bytes": "cs_bytes",
    "sc-substatus": "sc_substatus",
    "sc-win32-status": "sc_win32_status",
    "cs-version": "cs_version",
    "cs-host": "cs_host",
    "s-ip": "s_ip",
    "s-port": "s_port",
    "s-computername": "s_computername",
}


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
        n_fields = 0
        # 预先算出本文件实际存在的 detail 字段映射，避免逐行做 13 次字典查找
        extra: list = []
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            if line.startswith("#Fields:"):
                fields = line.split(":", 1)[1].split()
                n_fields = len(fields)
                present = set(fields)
                extra = [(k, v) for k, v in _EXTRA_FIELDS.items() if k in present]
                continue
            if line.startswith("#"):
                continue
            if not n_fields:
                continue
            values = line.split()
            if len(values) < n_fields:
                continue
            if len(values) > n_fields:  # 末字段含未转义空格 -> 合并
                head = values[: n_fields - 1]
                head.append(" ".join(values[n_fields - 1:]))
                values = head
            row = dict(zip(fields, values))
            ev = self._to_event(row, path, line, extra)
            if ev is not None:
                yield ev

    def _to_event(self, row: dict, path: str, raw: str, extra: list) -> Optional[Event]:
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
        ua = row.get("cs(User-Agent)")
        detail = {}
        for src, dst in extra:
            v = row.get(src)
            if v and v != "-":
                detail[dst] = v
        if query and query != "-":
            detail["query"] = query
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
            user_agent=ua if ua != "-" else None,
            user=user if user != "-" else None,
            detail=detail,
            raw=raw[:2000],
        )


register(IISW3CParser())

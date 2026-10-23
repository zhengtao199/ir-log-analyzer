"""Web 访问日志单遍统计器。

只做聚合计数（不缓存事件对象），内存占用与日志规模无关：
状态码分布、请求方法集合、4xx/5xx 计数、Top 客户端 IP、Top 路径、Top UA。
Top 表采用「有界字典」：超过上限后只累加计数不再新增键，防止大文件下内存膨胀。
"""
from __future__ import annotations

from typing import Optional

from .models import Event, A_HTTP_REQUEST


class _Bounded:
    """有界计数表：达到上限后只对已存在的键累加。"""

    def __init__(self, limit: int = 50000) -> None:
        self.limit = limit
        self.data: dict = {}
        self.overflow = False

    def add(self, key, n: int = 1) -> None:
        d = self.data
        if key in d:
            d[key] += n
        elif len(d) < self.limit:
            d[key] = n
        else:
            self.overflow = True

    def top(self, n: int = 20) -> list:
        return sorted(self.data.items(), key=lambda kv: -kv[1])[:n]


class WebStats:
    def __init__(self, top_limit: int = 50000) -> None:
        self.total = 0
        self.by_status: dict[int, int] = {}
        self.by_method: dict[str, int] = {}
        self.by_class: dict[str, int] = {}      # 2xx / 3xx / 4xx / 5xx / other
        self.ip = _Bounded(top_limit)
        self.uri = _Bounded(top_limit)
        self.ua = _Bounded(top_limit)
        self.bytes_sent = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

    def feed(self, ev: Event) -> None:
        if ev.action != A_HTTP_REQUEST:
            return
        self.total += 1
        if ev.method:
            m = ev.method.upper()
            self.by_method[m] = self.by_method.get(m, 0) + 1
        if ev.status is not None:
            self.by_status[ev.status] = self.by_status.get(ev.status, 0) + 1
            cls = f"{ev.status // 100}xx" if 100 <= ev.status < 600 else "other"
            self.by_class[cls] = self.by_class.get(cls, 0) + 1
        if ev.src_ip:
            self.ip.add(ev.src_ip)
        if ev.uri:
            self.uri.add(ev.uri.split("?", 1)[0])
        if ev.user_agent:
            self.ua.add(ev.user_agent)
        if ev.bytes_sent:
            self.bytes_sent += ev.bytes_sent
        if ev.ts is not None:
            self.first_ts = ev.ts if self.first_ts is None else min(self.first_ts, ev.ts)
            self.last_ts = ev.ts if self.last_ts is None else max(self.last_ts, ev.ts)

    # ---- 查询接口 ----
    def count_status(self, status: int) -> int:
        return self.by_status.get(status, 0)

    def count_status_class(self, cls: str) -> int:
        return self.by_class.get(cls, 0)

    def method_count(self) -> int:
        return len(self.by_method)

    def methods(self) -> list:
        return sorted(self.by_method.items(), key=lambda kv: -kv[1])

    def to_dict(self, top_n: int = 15) -> dict:
        return {
            "total_requests": self.total,
            "by_status": dict(sorted(self.by_status.items(), key=lambda kv: str(kv[0]))),
            "by_status_class": dict(sorted(self.by_class.items())),
            "by_method": dict(sorted(self.by_method.items(), key=lambda kv: -kv[1])),
            "method_kinds": self.method_count(),
            "bytes_sent": self.bytes_sent,
            "top_src_ip": [{"ip": k, "count": v} for k, v in self.ip.top(top_n)],
            "top_uri": [{"uri": k, "count": v} for k, v in self.uri.top(top_n)],
            "top_user_agent": [{"ua": k, "count": v} for k, v in self.ua.top(top_n)],
            "truncated": self.uri.overflow or self.ip.overflow or self.ua.overflow,
        }

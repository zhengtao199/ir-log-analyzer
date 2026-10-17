"""IOC 匹配检测：IP / 域名 / 文件哈希 / URL / 文件路径。

IOC 输入格式（txt 每行一条，# 开头为注释；或 csv 首列为 ioc）：
    203.0.113.66
    evil.example.com
    2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE
    http://c2.example.com/gate.php
    类型可显式标注：ip:1.2.3.4 / domain:xxx / sha256:xxx / url:xxx
匹配字段：src_ip / dst_ip / uri / hashes / file_path / user_agent / user。
"""
from __future__ import annotations

import csv
import re
from typing import Optional

from ..models import Event
from .base import Detector

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
URL_RE = re.compile(r"^https?://", re.I)

TYPE_LABELS = {"ip": "IP", "domain": "域名", "hash": "文件哈希", "url": "URL", "path": "文件路径", "raw": "关键字"}


def classify(value: str) -> str:
    v = value.strip()
    if IP_RE.match(v):
        return "ip"
    if URL_RE.match(v):
        return "url"
    if HASH_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v) and "." in v:
        return "domain"
    if v.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:\\", v):
        return "path"
    return "raw"


class IOCStore:
    """IOC 集合（按类型分桶，匹配时先精确后子串）。"""

    def __init__(self) -> None:
        self.items: list[dict] = []          # {"value":, "type":, "source":}
        self._by_type: dict = {}

    def add(self, value: str, source: str = "manual") -> None:
        v = value.strip()
        if not v or v.startswith("#"):
            return
        # 支持 type:value 显式标注
        if ":" in v and not v.lower().startswith(("http:", "https:")):
            prefix, _, rest = v.partition(":")
            if prefix.lower() in TYPE_LABELS and rest.strip():
                v, itype = rest.strip(), prefix.lower()
            else:
                itype = classify(v)
        else:
            itype = classify(v)
        item = {"value": v.lower() if itype in ("hash", "domain") else v, "type": itype, "source": source}
        self.items.append(item)
        self._by_type.setdefault(itype, []).append(item)

    def load_file(self, path: str) -> int:
        n = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
                f.seek(0)
                is_csv = "," in head.splitlines()[0] if head else False
                if is_csv:
                    for row in csv.reader(f):
                        if row and row[0].strip() and not row[0].startswith("#"):
                            self.add(row[0].strip(), source=path)
                            n += 1
                else:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            self.add(line.strip(), source=path)
                            n += 1
        except OSError:
            return 0
        return n

    def match(self, ev: Event) -> list[dict]:
        """返回事件命中的 IOC 列表。"""
        hits = []
        fields = {
            "ip": [ev.src_ip, ev.dst_ip],
            "hash": [ev.hashes],
            "domain": [ev.dst_ip, ev.user_agent, ev.domain],
            "url": [ev.uri],
            "path": [ev.file_path, ev.uri],
            "raw": [ev.uri, ev.user_agent, ev.domain, ev.raw[:500], ev.detail.get("message")],
        }
        for itype, items in self._by_type.items():
            for item in items:
                v = item["value"]
                for fv in fields.get(itype, []):
                    if not fv:
                        continue
                    fvs = str(fv).lower()
                    if itype in ("ip", "hash"):
                        if fvs == v:
                            hits.append(item)
                            break
                    else:
                        if v.lower() in fvs:
                            hits.append(item)
                            break
        return hits


class IOCDetector(Detector):
    rule_id = "ioc"
    title = "IOC 命中"
    description = "事件字段命中威胁情报 IOC（IP/域名/哈希/URL/路径）"
    mitre = "T1204 / 情报驱动检测"
    recommendation = "1) 命中 IOC 的主机按失陷处理，隔离并取证；2) 关联同源所有事件回溯攻击链；3) 更新情报源并监控同 IOC 群"

    def __init__(self, config, ioc_store: Optional[IOCStore] = None):
        super().__init__(config)
        self.store = ioc_store or IOCStore()
        self.hits: dict = {}   # (type, value) -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled or not self.store.items:
            return
        for item in self.store.match(ev):
            key = (item["type"], item["value"])
            st = self.hits.setdefault(key, {"count": 0, "fields": set(), "first": None, "last": None, "evidence": [], "source": item["source"]})
            st["count"] += 1
            if ev.ts is not None:
                st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
            if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (itype, value), st in sorted(self.hits.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(1, st["count"], {"ioc": value, "ioc_type": TYPE_LABELS.get(itype, itype), "ioc_source": st["source"]},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                f"IOC 命中：{TYPE_LABELS.get(itype, itype)} {value} 在日志中出现 {st['count']} 次")
        return self.alerts

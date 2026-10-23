"""数据外传检测：超大响应体、单 IP 日流量超限、敏感文件批量下载。"""
from __future__ import annotations

import re

from ..models import A_HTTP_REQUEST, Event
from .base import Detector

SENSITIVE_RE = re.compile(
    r"\.zip|\.tar\.gz|\.tgz|\.sql|\.bak|\.old|\.xlsx|\.csv|\.pdf|\.docx|"
    r"/etc/passwd|id_rsa|web\.config|appsettings\.json|/backup|/dump|/export|/download", re.I)


class ExfiltrationDetector(Detector):
    rule_id = "exfiltration"
    ACTIONS = {A_HTTP_REQUEST}
    title = "数据外传"
    description = "发现超大响应体下载、单 IP 流量异常或敏感文件批量访问"
    mitre = "T1041 Exfiltration Over C2 Channel / T1567 Exfiltration Over Web Service"
    recommendation = "1) 立即确认下载内容与账号归属；2) 核查出口流量与 C2 通信；3) 评估数据泄露范围并启动应急响应流程"

    def __init__(self, config):
        super().__init__(config)
        self.big: dict = {}        # (ip, uri) -> {...}
        self.daily: dict = {}      # ip -> {"bytes":, "day":, "evidence":[]}
        self.sensitive: dict = {}  # ip -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST:
            return
        ip = ev.src_ip or "-"
        nb = ev.bytes_sent or 0

        # 1) 单请求超大
        if nb >= self.config.exfil_response_bytes:
            st = self.big.setdefault((ip, ev.uri or "-"), {"count": 0, "bytes": 0, "first": None, "last": None, "evidence": []})
            st["count"] += 1
            st["bytes"] += nb
            if ev.ts is not None:
                st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
            if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        # 2) 单 IP 单日总量
        day = None
        if ev.ts is not None:
            import time as _t
            day = _t.strftime("%Y-%m-%d", _t.localtime(ev.ts))
        st = self.daily.setdefault(ip, {"bytes": 0, "day": day, "count": 0, "evidence": []})
        if day == st["day"]:
            st["bytes"] += nb
            st["count"] += 1
        else:  # 跨天重置
            st.update({"bytes": nb, "day": day, "count": 1, "evidence": []})
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        # 3) 敏感文件访问（200）
        # 流量包里 URI 常挂在 detail（响应事件刻意不写 ev.uri，避免与请求行重复计数）
        if ev.status == 200:
            low = (ev.uri or ev.detail.get("uri") or "").lower()
            if SENSITIVE_RE.search(low):
                st2 = self.sensitive.setdefault(ip, {"count": 0, "paths": set(), "evidence": []})
                st2["count"] += 1
                st2["paths"].add(low.split("?")[0])
                if len(st2["evidence"]) < self.config.evidence_sample_per_alert:
                    st2["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (ip, uri), st in sorted(self.big.items(), key=lambda kv: -kv[1]["bytes"]):
            self._alert(2, st["count"], {"src_ip": ip, "uri": uri, "total_bytes": st["bytes"]},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                f"超大下载：{ip} 下载 {uri} 共 {st['bytes'] / 1048576:.1f}MB（{st['count']} 次）")
        for ip, st in sorted(self.daily.items(), key=lambda kv: -kv[1]["bytes"]):
            if st["bytes"] >= self.config.exfil_daily_bytes:
                self._alert(2, st["count"], {"src_ip": ip, "total_bytes": st["bytes"], "day": st["day"]},
                            st["evidence"], None, None)
                self.alerts[-1].description = (
                    f"流量异常：{ip} 在 {st['day']} 通过 Web 下载 {st['bytes'] / 1048576:.0f}MB")
        for ip, st in sorted(self.sensitive.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= 5:
                self._alert(3, st["count"], {"src_ip": ip, "paths": sorted(st["paths"])[:20]},
                            st["evidence"], None, None)
                self.alerts[-1].description = f"敏感文件访问：{ip} 访问 {st['count']} 次敏感路径"
        return self.alerts

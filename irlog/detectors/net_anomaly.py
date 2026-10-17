"""流量异常检测：端口/主机扫描、C2 心跳信标、DNS 隧道与 DGA、明文凭据、可疑外联。

消费事件：
- A_NETWORK_CONN（pcap 解析器，以及 Windows 网络连接类日志归一化后的同类事件）
- A_NET_DNS / A_NET_TLS / A_NET_CRED / A_NET_FLOW

设计取舍（避免误报）：
- 扫描判定看「窗口内去重后的端口/主机数」，不是包数——重传与正常大流量不会误伤
- 信标要求同时满足：连接次数达标 + 平均间隔达标 + 间隔变异系数（CV）足够小；
  突发重连或人工操作间隔不规律，CV 大，不告警
- 外传只在「流向非内网地址」且字节量/出入比达标时才报
"""
from __future__ import annotations

import ipaddress
import math
from collections import deque

from ..models import (
    A_NETWORK_CONN, A_NET_DNS, A_NET_CRED, A_NET_FLOW, Event,
)
from .base import Detector

# 已知远控/后门常见端口（低危线索，需人工确认）
SUSPICIOUS_PORTS = {
    4444: "Metasploit 默认反向 shell",
    6666: "常见后门端口",
    6667: "IRC（僵尸网络 C2 常见）",
    9001: "Tor 目录/OR 端口",
    1337: "常见后门端口",
    12345: "NetBus 后门",
    27374: "Sub7 后门",
    31337: "Back Orifice",
}

# DNS 查询类型
QTYPE_LABELS = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT",
                28: "AAAA", 33: "SRV", 65: "HTTPS"}


# 内网判定：RFC1918 / 回环 / 链路本地 / CGNAT / IPv6 ULA 与链路本地。
# 不用 ipaddress.is_private —— 它把文档保留段（203.0.113.0/24 等）也算作私有，
# 会导致夹具与真实用例中的外部地址被误判为内网。
_INTERNAL_NETS = None


def _internal_nets() -> list:
    global _INTERNAL_NETS
    if _INTERNAL_NETS is None:
        _INTERNAL_NETS = [ipaddress.ip_network(c) for c in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
            "fc00::/7", "fe80::/10", "::1/128",
        )]
    return _INTERNAL_NETS


def _is_internal(ip: Optional[str]) -> bool:
    """是否为内网地址（外传判定用）。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _internal_nets():
        if addr.version == net.version and addr in net:
            return True
    return False


def _entropy(s: str) -> float:
    """香农熵（bits/char）。"""
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class NetAnomalyDetector(Detector):
    rule_id = "net-anomaly"
    title = "流量异常 / 扫描探测 / C2 通信"
    description = "发现端口或主机扫描、周期性信标（C2 心跳）、DNS 隧道/DGA、明文凭据传输或可疑外联"
    mitre = "T1046 Network Service Discovery / T1071 Application Layer Protocol / T1041 Exfiltration Over C2"
    recommendation = "1) 结合防火墙/EDR 确认该源主机是否已失陷；2) 对信标目标域名/IP 做情报比对并阻断；3) 排查明文协议并改为加密传输；4) 核对外传数据量与业务必要性"

    def __init__(self, config):
        super().__init__(config)
        self.conn_ts: dict = {}      # (src, dst, dport) -> deque[ts]
        self.port_scan: dict = {}    # src -> {"dq": deque[(ts,port)], "best": int}
        self.host_scan: dict = {}    # (src, dport) -> {"dq": deque[(ts,dst)], "best": int}
        self.dns_nx: dict = {}       # src -> {"dq": deque[ts], "samples": []}
        self.dns_tun: dict = {}      # src -> {"count":, "samples": [], "max_ent":}
        self.creds: dict = {}        # (src, dst, proto) -> {...}
        self.flows: dict = {}        # (src, dst, dport) -> {"out":, "in":, "count":}
        self.susp: dict = {}         # (src, dst, dport) -> {...}

    # ------------------------------------------------------------------
    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return
        if ev.action == A_NETWORK_CONN:
            self._feed_conn(ev)
        elif ev.action == A_NET_DNS:
            self._feed_dns(ev)
        elif ev.action == A_NET_CRED:
            self._feed_cred(ev)
        elif ev.action == A_NET_FLOW:
            self._feed_flow(ev)

    # ---- 连接：扫描 / 信标 ----
    def _feed_conn(self, ev: Event) -> None:
        src, dst = ev.src_ip, ev.dst_ip
        if not src or not dst:
            return
        dport = ev.detail.get("dst_port") or 0
        flags = ev.detail.get("flags") or ""
        ts = ev.ts if ev.ts is not None else 0.0

        # 信标：只统计客户端发起的连接（SYN / UDP 新流），避免服务端响应污染间隔
        if flags in ("SYN", "UDP"):
            key = (src, dst, dport)
            # 信标需要长周期历史，不做时间窗裁剪（由 deque maxlen 限幅）
            self._track(self.conn_ts, key, ts, maxlen=32, window=None)
            if key in self.conn_ts:
                self._sample(self.conn_ts, key, ev)

        # 端口扫描：单源 → 不同目的端口
        self._track_dq(self.port_scan, src, ts, dport)
        self._sample(self.port_scan, src, ev)

        # 主机扫描：单源 + 同端口 → 不同目的主机
        self._track_dq(self.host_scan, (src, dport), ts, dst)
        self._sample(self.host_scan, (src, dport), ev)

        # 已知远控端口
        if dport in SUSPICIOUS_PORTS:
            k = (src, dst, dport)
            s = self.susp.setdefault(k, {"count": 0, "note": SUSPICIOUS_PORTS[dport],
                                         "first": None, "last": None, "evidence": []})
            s["count"] += 1
            if ev.ts is not None:
                s["first"] = ev.ts if s["first"] is None else min(s["first"], ev.ts)
                s["last"] = ev.ts if s["last"] is None else max(s["last"], ev.ts)
            self._sample(self.susp, k, ev)

    # ---- DNS：DGA / 隧道 ----
    def _feed_dns(self, ev: Event) -> None:
        qname = ev.detail.get("qname") or ev.domain
        if not qname:
            return
        src = ev.src_ip or "-"
        ts = ev.ts if ev.ts is not None else 0.0

        # NXDOMAIN 风暴（DGA / 域名爆破）
        if ev.detail.get("rcode") == 3:
            self._track(self.dns_nx, src, ts, maxlen=200,
                        window=self.config.net_dns_window_sec)
            if src in self.dns_nx:
                st = self.dns_nx[src]
                if len(st["samples"]) < 20:
                    st["samples"].append(qname)
                self._sample(self.dns_nx, src, ev)

        # DNS 隧道：查询标签超长或高熵（仅看查询，不看响应）
        if not ev.detail.get("is_response"):
            label = qname.split(".")[0]
            ent = _entropy(label)
            if len(label) >= self.config.net_dns_label_len or ent >= self.config.net_dns_entropy:
                st = self.dns_tun.setdefault(src, {"count": 0, "samples": [],
                                                   "max_ent": 0.0, "first": None,
                                                   "last": None, "evidence": []})
                st["count"] += 1
                st["max_ent"] = max(st["max_ent"], ent)
                if len(st["samples"]) < 20:
                    st["samples"].append(qname[:120])
                if ev.ts is not None:
                    st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                    st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
                self._sample(self.dns_tun, src, ev)

    # ---- 明文凭据 ----
    def _feed_cred(self, ev: Event) -> None:
        k = (ev.src_ip or "-", ev.dst_ip or "-", ev.detail.get("cred_protocol") or "-")
        st = self.creds.setdefault(k, {"count": 0, "first": None, "last": None, "evidence": []})
        st["count"] += 1
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        self._sample(self.creds, k, ev)

    # ---- 流摘要：外传 ----
    def _feed_flow(self, ev: Event) -> None:
        out = ev.detail.get("bytes_out") or 0
        inn = ev.detail.get("bytes_in") or 0
        if out <= 0:
            return
        k = (ev.src_ip or "-", ev.dst_ip or "-", ev.detail.get("dst_port") or 0)
        st = self.flows.setdefault(k, {"out": 0, "in": 0, "count": 0,
                                       "first": None, "last": None, "evidence": []})
        st["out"] += out
        st["in"] += inn
        st["count"] += 1
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        self._sample(self.flows, k, ev)

    # ------------------------------------------------------------------
    # 工具：有上限的窗口聚合
    # ------------------------------------------------------------------
    def _track(self, store: dict, key, ts: float, maxlen: int = 200,
               window=None) -> dict:
        st = store.get(key)
        if st is None:
            if len(store) >= self.config.net_max_tracked:
                return {"dq": deque(), "samples": []}
            st = store[key] = {"dq": deque(maxlen=maxlen), "samples": []}
        dq = st["dq"]
        if ts and window:
            dq.append(ts)
            while dq and ts - dq[0] > window:
                dq.popleft()
        elif ts:
            dq.append(ts)
        return st

    def _track_dq(self, store: dict, key, ts: float, value) -> dict:
        st = store.get(key)
        if st is None:
            if len(store) >= self.config.net_max_tracked:
                return {"best": 0}
            st = store[key] = {"dq": deque(), "best": 0}
        dq: deque = st["dq"]
        dq.append((ts, value))
        window = self.config.net_scan_window_sec
        if ts:
            while dq and ts - dq[0][0] > window:
                dq.popleft()
        distinct = len({v for _, v in dq})
        if distinct > st["best"]:
            st["best"] = distinct
        return st

    @staticmethod
    def _distinct_best(store: dict, key) -> int:
        st = store.get(key)
        return st["best"] if st else 0

    # ------------------------------------------------------------------
    def finalize(self) -> list:
        if not self.enabled:
            return []
        self._final_port_scan()
        self._final_host_scan()
        self._final_beacon()
        self._final_dns()
        self._final_cred()
        self._final_flow()
        self._final_susp()
        return self.alerts

    def _final_port_scan(self) -> None:
        for src, st in sorted(self.port_scan.items(), key=lambda kv: -kv[1]["best"]):
            if st["best"] < self.config.net_scan_ports:
                continue
            self._alert(2, st["best"], {"src_ip": src, "distinct_ports": st["best"]},
                        st.get("evidence", []))
            self.alerts[-1].description = (
                f"端口扫描：{src} 在 {self.config.net_scan_window_sec}s 窗口内访问 "
                f"{st['best']} 个不同目的端口")
            self.alerts[-1].mitre = "T1046 Network Service Discovery"

    def _final_host_scan(self) -> None:
        for (src, dport), st in sorted(self.host_scan.items(), key=lambda kv: -kv[1]["best"]):
            if st["best"] < self.config.net_scan_hosts:
                continue
            self._alert(2, st["best"], {"src_ip": src, "dst_port": dport,
                                        "distinct_hosts": st["best"]},
                        st.get("evidence", []))
            self.alerts[-1].description = (
                f"横向扫描：{src} 在 {self.config.net_scan_window_sec}s 窗口内对 "
                f"{st['best']} 台主机的 {dport} 端口发起连接")
            self.alerts[-1].mitre = "T1046 Network Service Discovery"

    def _final_beacon(self) -> None:
        for (src, dst, dport), st in self.conn_ts.items():
            ts_list = list(st["dq"])
            if len(ts_list) < self.config.net_beacon_min:
                continue
            intervals = [b - a for a, b in zip(ts_list, ts_list[1:]) if b > a]
            if len(intervals) < self.config.net_beacon_min - 1:
                continue
            mean = sum(intervals) / len(intervals)
            if mean < self.config.net_beacon_min_interval:
                continue
            var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            cv = math.sqrt(var) / mean
            if cv > self.config.net_beacon_cv:
                continue
            sev = 1 if (len(ts_list) >= 10 and cv <= 0.2) else 2
            self._alert(sev, len(ts_list),
                        {"src_ip": src, "dst_ip": dst, "dst_port": dport,
                         "mean_interval_sec": round(mean, 2), "jitter_cv": round(cv, 3)},
                        st.get("evidence", []), ts_list[0], ts_list[-1])
            self.alerts[-1].description = (
                f"C2 心跳信标：{src} → {dst}:{dport} 连接 {len(ts_list)} 次，"
                f"平均间隔 {mean:.1f}s（抖动 CV={cv:.2f}，高度规律）")

    def _final_dns(self) -> None:
        for src, st in sorted(self.dns_nx.items(), key=lambda kv: -len(kv[1]["dq"])):
            n = len(st["dq"])
            if n < self.config.net_dns_nxdomain:
                continue
            self._alert(2, n, {"src_ip": src, "rcode": "NXDOMAIN",
                               "samples": st["samples"][:10]},
                        st.get("evidence", []))
            self.alerts[-1].description = (
                f"DNS 异常：{src} 在 {self.config.net_dns_window_sec}s 窗口内产生 {n} 次 "
                f"NXDOMAIN 查询（DGA 域名或域名爆破特征）")
            self.alerts[-1].mitre = "T1568.002 Dynamic Resolution: DGA"

        for src, st in sorted(self.dns_tun.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] < self.config.net_dns_tunnel_min:
                continue
            self._alert(2, st["count"], {"src_ip": src, "max_label_entropy": round(st["max_ent"], 2),
                                         "samples": st["samples"][:10]},
                        st.get("evidence", []), st["first"], st["last"])
            self.alerts[-1].description = (
                f"疑似 DNS 隧道：{src} 发起 {st['count']} 次超长/高熵标签查询"
                f"（最高熵 {st['max_ent']:.2f}）")
            self.alerts[-1].mitre = "T1071.004 Application Layer Protocol: DNS"

    def _final_cred(self) -> None:
        for (src, dst, proto), st in sorted(self.creds.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(2, st["count"], {"src_ip": src, "dst_ip": dst, "protocol": proto},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                f"明文凭据传输：{src} → {dst} 使用 {proto} 明文协议传输凭据 {st['count']} 次")
            self.alerts[-1].mitre = "T1040 Network Sniffing / T1071 Application Layer Protocol"

    def _final_flow(self) -> None:
        for (src, dst, dport), st in sorted(self.flows.items(), key=lambda kv: -kv[1]["out"]):
            out_mb = st["out"] / 1048576.0
            external = not _is_internal(dst)
            ratio = st["out"] / max(st["in"], 1)
            if external and st["out"] >= self.config.net_exfil_bytes:
                sev = 2
                why = f"向外部地址 {dst} 传出 {out_mb:.1f}MB（阈值 {self.config.net_exfil_bytes // 1048576}MB）"
            elif external and st["out"] >= 1048576 and ratio >= self.config.net_exfil_ratio:
                sev = 2
                why = f"向外部地址 {dst} 传出 {out_mb:.1f}MB，出入比 {ratio:.0f}:1（典型外传特征）"
            else:
                continue
            self._alert(sev, st["count"], {"src_ip": src, "dst_ip": dst, "dst_port": dport,
                                           "bytes_out": st["out"], "bytes_in": st["in"],
                                           "ratio": round(ratio, 1)},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = f"可疑外传：{src} " + why
            self.alerts[-1].mitre = "T1041 Exfiltration Over C2 Channel"

    def _final_susp(self) -> None:
        for (src, dst, dport), st in sorted(self.susp.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(3, st["count"], {"src_ip": src, "dst_ip": dst, "dst_port": dport,
                                         "note": st["note"]},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                f"可疑端口通信：{src} → {dst}:{dport}（{st['note']}）{st['count']} 次")

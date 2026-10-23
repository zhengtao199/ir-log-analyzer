"""Web 攻击检测：SQL 注入、XSS、路径遍历、敏感文件探测、扫描器识别。

- URI（含 URL 解码后的形式）匹配注入/遍历 payload 特征
- UA 命中已知扫描器（sqlmap/nikto/nessus/acunetix/nmap/wpscan/gobuster 等）
- 单 IP 404 次数超过阈值（目录扫描行为）
- URI 长度异常（溢出/混淆 payload 特征）
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from ..models import A_HTTP_REQUEST, Event
from .base import Detector

SQLI_RE = re.compile(
    r"union\s+select|union\s+all\s+select|'\s*or\s+1\s*=\s*1|\"\s*or\s+1\s*=\s*1|"
    r"or\s+'1'\s*=\s*'1|or\s+1\s*=\s*1\s*-|'\s*and|sleep\s*\(|benchmark\s*\(|"
    r"information_schema|load_file\s*\(|into\s+outfile|@@version|extractvalue\s*\(|"
    r"updatexml\s*\(|%27|%20or%20|waitfor\s+delay|pg_sleep\s*\(", re.I)
XSS_RE = re.compile(
    r"<\s*script|</\s*script|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|"
    r"document\.cookie|eval\s*\(|fromcharcode|%3c\s*script", re.I)
TRAVERSAL_RE = re.compile(
    r"\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|"
    r"/proc/self|web\.config|appsettings\.json|\.env|\.git/|id_rsa", re.I)
SCANNER_UA_RE = re.compile(
    r"sqlmap|nikto|nessus|acunetix|netsparker|nmap|masscan|dirbuster|gobuster|dirb|"
    r"wpscan|joomscan|havij|hydra|zmeu|paros|webscarab|qualys|openvas|arachni|nuclei", re.I)
SENSITIVE_RE = re.compile(
    r"/\.env|/\.git/|/web\.config|/appsettings\.json|/backup|\.zip|\.sql|\.bak|\.old|"
    r"\.tar\.gz|/etc/passwd|id_rsa|/phpmyadmin|/manager/html|/jmx-console|/actuator/env", re.I)


class WebAttackDetector(Detector):
    rule_id = "web-attack"
    ACTIONS = {A_HTTP_REQUEST}
    title = "Web 攻击 / 扫描探测"
    description = "发现 SQL 注入、XSS、路径遍历、敏感文件探测或扫描器行为"
    mitre = "T1190 Exploit Public-Facing Application / T1595 Active Scanning"
    recommendation = "1) 分析来源 IP 全部请求，定位利用入口；2) 检查 WAF/中间件日志是否被绕过；3) 修复对应漏洞并封禁来源"

    def __init__(self, config):
        super().__init__(config)
        self.attacks: dict = {}    # (ip, kind) -> {...}
        self.notfound: dict = {}   # ip -> {...}
        self.scanner_uas: dict = {}  # ip -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST:
            return
        # 请求体：单包解析只有请求行与头部，POST 的注入载荷要靠 TCP 重组补齐。
        # 重组事件只带 http_body（uri 留空），避免同一次请求被 URI 与请求体重复计数。
        body = ev.detail.get("http_body") or ""
        body_only = bool(ev.detail.get("http_body_only"))
        uri = ev.uri or body
        low = uri.lower()
        # URL 编码 payload（%27/%20/+ 等）解码后再匹配一次
        dec = unquote_plus(low) if ("%" in low or "+" in low) else low
        ip = ev.src_ip or "-"

        # 1) payload 特征
        kinds = []
        if SQLI_RE.search(low) or SQLI_RE.search(dec):
            kinds.append("SQL注入")
        if XSS_RE.search(low) or XSS_RE.search(dec):
            kinds.append("XSS")
        if TRAVERSAL_RE.search(low) or TRAVERSAL_RE.search(dec):
            kinds.append("路径遍历/敏感文件探测")
        # 请求体长度受业务影响很大，不用超长 URI 的口径判定
        if not body_only and len(uri) > self.config.web_attack_path_len:
            kinds.append("超长URI(疑似溢出/混淆)")
        if kinds:
            key = (ip, "+".join(sorted(set(kinds))))
            self._hit(self.attacks, key, ev, kinds)

        # 2) 扫描器 UA
        if SCANNER_UA_RE.search(ev.user_agent or ""):
            self._hit(self.scanner_uas, ip, ev, ["扫描器UA"])

        # 3) 404 扫描
        if ev.status == 404:
            st = self.notfound.setdefault(ip, {"count": 0, "first": None, "last": None, "evidence": []})
            st["count"] += 1
            if ev.ts is not None:
                st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
            if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def _hit(self, store: dict, key, ev: Event, kinds: list) -> None:
        st = store.setdefault(key, {"count": 0, "reasons": set(), "first": None, "last": None, "evidence": []})
        st["count"] += 1
        st["reasons"].update(kinds)
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (ip, kind), st in sorted(self.attacks.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(2, st["count"], {"src_ip": ip, "attack_type": kind, "reasons": sorted(st["reasons"])},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = f"Web 攻击：{ip} 触发 {kind} 特征 {st['count']} 次"
        for ip, st in sorted(self.scanner_uas.items(), key=lambda kv: -kv[1]["count"]):
            ua = st["evidence"][0][2] if st["evidence"] else ""
            m = SCANNER_UA_RE.search(ua)
            self._alert(3, st["count"], {"src_ip": ip, "reasons": [f"扫描器UA({m.group(0) if m else '?'})"]},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = f"扫描器行为：{ip} 使用 {m.group(0) if m else '扫描器'} UA"
        for ip, st in sorted(self.notfound.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= self.config.web_attack_404_burst:
                self._alert(3, st["count"], {"src_ip": ip, "reasons": ["404 扫描"]},
                            st["evidence"], st["first"], st["last"])
                self.alerts[-1].description = f"目录扫描：{ip} 产生 {st['count']} 次 404（疑似漏洞/目录扫描）"
        return self.alerts

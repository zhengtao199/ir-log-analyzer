"""攻击工具与 Webshell 客户端指纹识别。

UA 指纹是最廉价的"敌我识别"手段：
- 扫描/爆破器（ffuf / sqlmap / nikto / nuclei / awvs / nessus / masscan / gobuster ...）
  出现即说明资产已被自动化测绘，属于攻击前置阶段，需封禁 + 加固。
- Webshell 客户端（中国菜刀 / 冰蝎 / 哥斯拉 / 蚁剑）UA 出现即证明**已有后门在通信**，
  属紧急事件，必须按失陷处置。

同时叠加行为指纹：单 IP 大量 404（目录爆破）。
"""
from __future__ import annotations

import re

from ..models import Event, A_HTTP_REQUEST
from ..quiz import CHINA_CHOPPER_UAS, _ua_norm
from .base import Detector

# (正则, 类别, 名称)
UA_SIGNATURES = [
    (r"Fuzz Faster U Fool|ffuf", "扫描器", "ffuf"),
    (r"sqlmap", "注入工具", "sqlmap"),
    (r"Nikto", "扫描器", "Nikto"),
    (r"nuclei", "扫描器", "Nuclei"),
    (r"AWVS|Acunetix", "扫描器", "AWVS/Acunetix"),
    (r"nessus|Nessus", "扫描器", "Nessus"),
    (r"masscan|nmap|Nmap Scripting Engine", "扫描器", "masscan/nmap"),
    (r"gobuster|dirbuster|DirBuster|dirb", "扫描器", "目录爆破器"),
    (r"WPScan", "扫描器", "WPScan"),
    (r"hydra|Hydra", "爆破工具", "Hydra"),
    (r"Burp|ZAP", "渗透代理", "Burp/ZAP"),
    (r"curl/|Wget/|python-requests|Go-http-client|libwww-perl", "脚本化请求", "curl/wget/脚本"),
    (r"ZmEu|Morfeus|Zollard|w00tw00t", "蠕虫扫描", "已知漏洞蠕虫"),
    (r"antSword|AntSword", "Webshell客户端", "蚁剑 AntSword"),
    (r"behinder|Behinder", "Webshell客户端", "冰蝎 Behinder"),
    (r"godzilla|Godzilla", "Webshell客户端", "哥斯拉 Godzilla"),
]
# 合并为单条正则（一次扫描命中全部指纹，比逐条 search 快一个数量级）
_PARTS = []
_META = []
for _i, (_p, _cat, _name) in enumerate(UA_SIGNATURES):
    _PARTS.append(f"(?P<g{_i}>{_p})")
    _META.append((_cat, _name))
UA_COMBINED = re.compile("|".join(_PARTS), re.I)

# 中国菜刀客户端默认 UA（整串精确匹配，避免误判正常浏览器）
CC_SET = set(CHINA_CHOPPER_UAS)


class ToolingDetector(Detector):
    rule_id = "tooling"
    ACTIONS = {A_HTTP_REQUEST}
    title = "攻击工具 / Webshell 客户端指纹"
    description = "请求 User-Agent 命中扫描器、注入工具或 Webshell 客户端指纹，说明资产正被自动化攻击或已被控制"
    mitre = "T1595 Active Scanning / T1213 Data from Information Repositories"
    recommendation = ("1) 封禁来源 IP 并在边界/WAF 侧加限流；"
                      "2) 若为 Webshell 客户端 → 按失陷主机处置：隔离、排查落盘文件与命令执行痕迹；"
                      "3) 排查该 IP 的全部成功请求，确认是否有接口被攻破")

    def __init__(self, config):
        super().__init__(config)
        self.hits: dict = {}        # (ip, name, cat) -> {...}
        self.not_found: dict = {}   # ip -> 404 计数
        self._ua_cache: dict = {}   # UA 原文 -> 指纹结果（UA 种类远少于请求数，缓存收益极大）

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST:
            return
        ip = ev.src_ip or "-"
        if ev.status == 404:
            self.not_found[ip] = self.not_found.get(ip, 0) + 1
        ua = ev.user_agent
        if not ua:
            return
        fp = self._ua_cache.get(ua)
        if fp is None:
            low = _ua_norm(ua)
            name, cat = None, None
            if low in CC_SET:
                name, cat = "中国菜刀 China Chopper", "Webshell客户端"
            else:
                m = UA_COMBINED.search(ua)
                if m is not None and m.lastgroup:
                    cat, name = _META[int(m.lastgroup[1:])]
            fp = (name, cat)
            if len(self._ua_cache) < 20000:
                self._ua_cache[ua] = fp
        name, cat = fp
        if not name:
            return
        key = (ip, name, cat)
        st = self.hits.setdefault(key, {"count": 0, "first": None, "last": None,
                                        "evidence": [], "ua_sample": ua[:200]})
        st["count"] += 1
        st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
        st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < 5:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (ip, name, cat), st in sorted(self.hits.items(), key=lambda kv: -kv[1]["count"]):
            sev = 1 if cat == "Webshell客户端" else (2 if cat in ("注入工具", "爆破工具") else 3)
            self._alert(
                severity=sev,
                count=st["count"],
                entities={"src_ip": ip, "工具": name, "类别": cat, "UA样本": st["ua_sample"]},
                evidence=st["evidence"],
                first_ts=st["first"], last_ts=st["last"],
            )
            self.alerts[-1].description = (
                f"{ip} 使用 {name}（{cat}）发起 {st['count']} 次请求"
                + (f"，其中 404 {self.not_found.get(ip, 0)} 次" if ip in self.not_found else ""))
        # 行为指纹：404 爆发（目录/文件爆破）
        for ip, cnt in sorted(self.not_found.items(), key=lambda kv: -kv[1]):
            if cnt >= self.config.web_attack_404_burst and ip not in {k[0] for k in self.hits}:
                self._alert(
                    severity=3,
                    count=cnt,
                    entities={"src_ip": ip, "类型": "404 爆发（目录/文件爆破）"},
                    evidence=[],
                )
                self.alerts[-1].description = f"{ip} 产生 {cnt} 次 404（疑似目录或文件爆破）"
        return self.alerts

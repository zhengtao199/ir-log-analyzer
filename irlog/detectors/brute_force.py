"""暴力破解检测：SSH / RDP / SMB / Web 登录 / Kerberos 预认证失败。

触发条件（满足其一）：
- 同一源 IP 在 brute_force_window_sec 内失败 >= brute_force_threshold 次
- 同一源 IP 失败中命中 >= brute_force_min_users 个不同账号（密码喷洒，高危）
"""
from __future__ import annotations

from ..models import A_LOGON_FAILED, Event
from .base import Detector


class BruteForceDetector(Detector):
    rule_id = "brute-force"
    title = "暴力破解攻击"
    description = "短时间内大量登录失败，疑似暴力破解/密码喷洒攻击"
    mitre = "T1110 Brute Force / T1110.003 Password Spraying"
    recommendation = "1) 封禁来源 IP 并核查是否已登录成功；2) 重置受影响账号密码并启用 MFA；3) 核查失败账号是否为管理员/服务账号"

    def __init__(self, config):
        super().__init__(config)
        # key=(src_ip) -> {"users": set, "first": ts, "last": ts, "count": n}
        self.state: dict = {}

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_LOGON_FAILED or not ev.src_ip:
            return
        ip = ev.src_ip
        st = self.state.setdefault(ip, {"users": set(), "hosts": set(), "count": 0,
                                        "first": None, "last": None, "evidence": []})
        st["count"] += 1
        if ev.user:
            st["users"].add(ev.user)
        if ev.host:
            st["hosts"].add(ev.host)
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        thr = self.config.brute_force_threshold
        for ip, st in sorted(self.state.items(), key=lambda kv: -kv[1]["count"]):
            users = sorted(st["users"])
            spray = len(users) >= self.config.brute_force_min_users and self.config.brute_force_min_users > 1
            if st["count"] < thr and not spray:
                continue
            severity = 2
            extra = ""
            if spray:
                severity = 1
                extra = f"；命中 {len(users)} 个不同账号（密码喷洒特征）"
            self._alert(
                severity=severity,
                count=st["count"],
                entities={"src_ip": ip, "target_users": users,
                          "hosts": sorted(h for h in st["hosts"] if h)[:5]},
                evidence=st["evidence"],
                first_ts=st["first"],
                last_ts=st["last"],
            )
            a = self.alerts[-1]
            a.description = f"{self.description}：源 IP {ip} 共 {st['count']} 次失败登录{extra}"
        return self.alerts

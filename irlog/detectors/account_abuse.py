"""账号滥用检测：权限提升、横向移动、异常登录。

- 提权链路：短时间内「新建账号 -> 加入管理员组」（4720 后接 4732/4728/4756）
- 横向移动：单 IP 远程交互登录（LogonType 3）突增；单账号登录主机数超限
- 破解成功：同一 IP 先大量失败、随后登录成功（暴力破解得手，紧急）
- 特权异常：非标准账号获得特殊权限（4672）
"""
from __future__ import annotations

from ..models import (
    A_LOGON_FAILED, A_LOGON_SUCCESS, A_LOGON_SPECIAL,
    A_USER_CREATED, A_GROUP_MEMBER_ADDED, Event,
)
from .base import Detector

PRIV_ESC_WINDOW = 3600  # 新建账号到加入管理员组的最大间隔（秒）
CORRELATE_WINDOW = 3600  # 失败到成功关联窗口
ADMIN_GROUPS = ("administrators", "domain admins", "enterprise admins", "schema admins", "admins")


class AccountAbuseDetector(Detector):
    rule_id = "account-abuse"
    title = "权限提升 / 横向移动 / 异常登录"
    description = "发现账号提权链路、横向移动或异常登录行为"
    mitre = "T1078 Valid Accounts / T1021 Remote Services / T1098 Account Manipulation"
    recommendation = "1) 禁用可疑账号并核查其所有操作；2) 检查域管组变更记录与登录源；3) 重置相关凭据，排查持久化（计划任务/服务/启动项）"

    def __init__(self, config):
        super().__init__(config)
        self.created: dict = {}          # user -> {"ts":, "host":, "evidence":[]}
        self.group_adds: list = []       # [(ts, user, host, raw, source)]
        self.type3: dict = {}            # ip -> {...}
        self.user_hosts: dict = {}       # user -> set(hosts)
        self.failed_ips: dict = {}       # ip -> {"count":, "last_ts":, "first_ts":}
        self.success_after_fail: dict = {}  # ip -> {...}
        self.special_priv: dict = {}     # user -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return
        act = ev.action

        if act == A_USER_CREATED and ev.user:
            self.created[ev.user] = {
                "ts": ev.ts, "host": ev.host,
                "evidence": [(ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len])],
            }

        elif act == A_GROUP_MEMBER_ADDED and ev.user:
            self.group_adds.append((ev.ts, ev.user, ev.host,
                                    ev.raw[: self.config.raw_line_max_len], ev.source))

        elif act == A_LOGON_FAILED and ev.src_ip:
            st = self.failed_ips.setdefault(ev.src_ip, {"count": 0, "first": None, "last": None})
            st["count"] += 1
            if ev.ts is not None:
                st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)

        elif act == A_LOGON_SUCCESS:
            user = ev.user or "-"
            if ev.host:
                self.user_hosts.setdefault(user, set()).add(ev.host)
            lt = ev.logon_type or ev.detail.get("LogonType")
            if lt == "3" and ev.src_ip:
                st = self.type3.setdefault(ev.src_ip, {"count": 0, "users": set(), "first": None, "last": None, "evidence": []})
                st["count"] += 1
                st["users"].add(user)
                if ev.ts is not None:
                    st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                    st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
                if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                    st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))
            # 失败后成功（破解得手）
            if ev.src_ip and ev.src_ip in self.failed_ips:
                fs = self.failed_ips[ev.src_ip]
                if fs["count"] >= self.config.brute_force_threshold:
                    near = fs["last"] is None or ev.ts is None or (ev.ts - fs["last"]) <= CORRELATE_WINDOW
                    if near:
                        st = self.success_after_fail.setdefault(ev.src_ip, {"user": user, "ts": ev.ts, "evidence": [], "fail_count": fs["count"]})
                        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        elif act == A_LOGON_SPECIAL and ev.user:
            st = self.special_priv.setdefault(ev.user, {"count": 0, "hosts": set(), "first": None, "last": None, "evidence": []})
            st["count"] += 1
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

        # 1) 新建账号 -> 加入管理组
        for ts, user, host, raw, source in self.group_adds:
            created = self.created.get(user)
            if not created:
                continue
            if ts is None or created["ts"] is None or not (0 <= ts - created["ts"] <= PRIV_ESC_WINDOW):
                continue
            self._alert(1, 1, {"user": user, "host": host},
                        created["evidence"] + [(ts, source, raw)], created["ts"], ts)
            self.alerts[-1].description = f"提权链路：账号 {user} 被新建后 {int(ts - created['ts'])}s 内加入管理组（{host}）"

        # 2) 横向移动：LogonType3 突增
        for ip, st in sorted(self.type3.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= self.config.lateral_type3_burst:
                self._alert(2, st["count"], {"src_ip": ip, "users": sorted(st["users"])},
                            st["evidence"], st["first"], st["last"])
                self.alerts[-1].description = f"横向移动：{ip} 产生 {st['count']} 次远程交互登录（LogonType 3）"

        # 3) 单账号多主机
        for user, hosts in sorted(self.user_hosts.items(), key=lambda kv: -len(kv[1])):
            if len(hosts) > self.config.lateral_max_hosts and user != "-":
                self._alert(3, len(hosts), {"user": user, "hosts": sorted(hosts)}, [], None, None)
                self.alerts[-1].description = f"异常登录：账号 {user} 登录了 {len(hosts)} 台主机（阈值 {self.config.lateral_max_hosts}）"

        # 4) 暴力破解后成功
        for ip, st in self.success_after_fail.items():
            self._alert(1, st["fail_count"], {"src_ip": ip, "user": st["user"]},
                        st["evidence"], None, st["ts"])
            self.alerts[-1].description = f"暴力破解可能已得手：{ip} 在 {st['fail_count']} 次失败后成功登录账号 {st['user']}"

        # 5) 特殊权限账号（仅主机管理员常规持有，数量过多时提示）
        if len(self.special_priv) > 5:
            top = sorted(self.special_priv.items(), key=lambda kv: -kv[1]["count"])[:10]
            ev_all = [e for _u, st in top for e in st["evidence"][:3]]
            self._alert(3, len(self.special_priv), {"users": [u for u, _ in top]},
                        ev_all, None, None)
            self.alerts[-1].description = f"特权账号面偏大：{len(self.special_priv)} 个账号获得特殊权限（4672），请核对是否为后门账号"
        return self.alerts

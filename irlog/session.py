"""会话归属：把「无源 IP 的命令执行」回溯到发起它的登录会话。

背景
----
auditd EXECVE / Sysmon 进程创建等事件本身不带源 IP，告警只能定位到主机，
无法回答"是谁执行的"。应急响应里真正要的是：**哪条会话、哪个 IP 干了这个操作**。

做法（流式、常量内存）
----------------------
1. 维护每主机的**活跃会话表**：成功登录（A_LOGON_SUCCESS）开会话，
   session closed / Disconnected（A_SESSION_END）关会话，超时空闲自动关闭。
2. 命令执行事件（A_COMMAND_EXEC / A_SUDO_COMMAND）若无 src_ip，
   在其执行时刻的活跃会话中挑选来源。
3. 多会话并发时按可疑度打分排序，并**如实标注置信度**——宁可给候选集，
   也不伪造唯一结论（取证要求：结论必须可复核）。

打分维度（高→低）：
- 该 IP 在本主机上有前置登录失败（暴破后得手）——最强信号
- 外网 IP（非 RFC1918 / 非 loopback）——内网运维 vs 外部入侵
- 会话越新越可能（近期活动）
- 用户匹配（命令事件自带 user 时优先同用户会话）
"""
from __future__ import annotations

import ipaddress
import time
from typing import Optional

from .models import (
    A_LOGON_FAILED, A_LOGON_SUCCESS, A_SESSION_END,
    A_COMMAND_EXEC, A_SUDO_COMMAND, Event,
)

# 归属适用的动作（这些事件常常缺失源 IP）
ATTRIBUTABLE = (A_COMMAND_EXEC, A_SUDO_COMMAND)


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_unspecified)


class SessionTracker:
    """流式会话追踪器：只保留活跃会话，内存与输入规模无关。"""

    def __init__(self, idle_timeout: float = 1800.0,
                 max_sessions_per_host: int = 200,
                 fail_score_cap: int = 40) -> None:
        self.idle_timeout = idle_timeout
        self.max_sessions_per_host = max_sessions_per_host
        self.fail_score_cap = fail_score_cap
        self.sessions: dict[str, list[dict]] = {}   # host -> [session]
        self.fails: dict[tuple[str, str], int] = {}  # (host, ip) -> 失败次数
    # ---- 会话表维护 ----
    def _close(self, host: str, ev: Event) -> None:
        lst = self.sessions.get(host)
        if not lst:
            return
        # 优先精确匹配 (ip, user)；否则按 user 关最近打开的一条（LIFO）
        for s in reversed(lst):
            if s["closed"]:
                continue
            if ev.src_ip and s["ip"] == ev.src_ip and (ev.user is None or s["user"] == ev.user):
                s["closed"] = True
                return
        if ev.user:
            for s in reversed(lst):
                if not s["closed"] and s["user"] == ev.user:
                    s["closed"] = True
                    return

    def active(self, host: str, ts: float) -> list[dict]:
        """指定时刻仍活跃的会话（惰性判定空闲超时，无需逐事件扫描）。"""
        return [s for s in self.sessions.get(host, ())
                if not s["closed"] and s["open_ts"] <= ts + 1
                and (ts - s["last_ts"]) <= self.idle_timeout]

    # ---- 归属 ----
    def attribute(self, ev: Event) -> Optional[dict]:
        """为缺失源 IP 的命令执行事件推断来源；已有 IP 则不作推断。"""
        if ev.action not in ATTRIBUTABLE or ev.src_ip:
            return None
        host = ev.host or "-"
        ts = ev.ts if ev.ts is not None else 0.0
        cands = [s for s in self.active(host, ts) if s["ip"]]
        if not cands:
            return None

        scored = []
        for s in cands:
            score = 0.0
            fails = self.fails.get((host, s["ip"]), 0)
            if fails:
                score += 50 + min(fails, self.fail_score_cap)   # 暴破后得手：最强信号
            if not _is_private(s["ip"]):
                score += 30                                      # 外网来源
            if ev.user and s["user"] == ev.user:
                score += 15                                      # 用户一致
            score += max(0.0, 10.0 - (ts - s["open_ts"]) / 600.0)  # 越新越可能
            scored.append((score, s, fails))
        scored.sort(key=lambda x: x[0], reverse=True)

        best_score, best, fails = scored[0]
        uniq_ips = sorted({s["ip"] for _sc, s, _f in scored})
        if len(uniq_ips) == 1:
            confidence, basis = "高", "该时刻仅一个活动会话"
        else:
            confidence, basis = "中", f"{len(uniq_ips)} 个并发会话，按可疑度推断"

        return {
            "ip": best["ip"],
            "user": best["user"] or ev.user,
            "confidence": confidence,
            "basis": basis,
            "candidate_ips": uniq_ips,
            "prior_failures": fails,
            "session_opened": time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(best["open_ts"]))
            if best["open_ts"] else None,
            "score": round(best_score, 1),
        }

    def enrich(self, ev: Event) -> Optional[dict]:
        """更新会话表并为无源 IP 的命令执行回填归属（单入口，减少逐事件调用开销）。

        热路径优化：绝大多数事件（HTTP 请求、进程创建等）与会话无关，
        先按动作分流，只对登录/会话/命令执行三类做实质处理。
        """
        a = ev.action
        host = ev.host or "-"
        ts = ev.ts if ev.ts is not None else 0.0
        lst = self.sessions.get(host)

        if a == A_LOGON_SUCCESS:
            if lst is None:
                lst = self.sessions[host] = []
            lst.append({"ip": ev.src_ip, "user": ev.user, "open_ts": ts,
                        "last_ts": ts, "closed": False})
            if len(lst) > self.max_sessions_per_host:
                del lst[: len(lst) - self.max_sessions_per_host]
            return None

        if a == A_LOGON_FAILED:
            if ev.src_ip:
                k = (host, ev.src_ip)
                self.fails[k] = self.fails.get(k, 0) + 1
            return None

        if a == A_SESSION_END:
            self._close(host, ev)
            return None

        # 会话保活：仅当该主机确有会话且事件带源 IP 时才遍历（Web 日志零开销）
        if lst and ev.src_ip:
            for s in lst:
                if not s["closed"] and s["ip"] == ev.src_ip and s["last_ts"] < ts:
                    s["last_ts"] = ts

        if a in ATTRIBUTABLE and not ev.src_ip:
            attr = self.attribute(ev)
            if attr:
                ev.src_ip = attr["ip"]
                if not ev.user:
                    ev.user = attr["user"]
                ev.detail["attribution"] = attr
                return attr
        return None


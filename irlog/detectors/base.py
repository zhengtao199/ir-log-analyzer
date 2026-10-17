"""检测器基类：流式消费事件，finalize() 时产出告警。"""
from __future__ import annotations

import time
from collections import deque
from typing import Optional

from ..models import Alert, Event


class Detector:
    """所有检测器继承此类。

    规则过滤：config.rules 为 "all" 或逗号分隔的 rule_id 列表。
    内存控制：所有聚合结构按 key 累计计数 + 采样证据（有上限），
    不缓存全量事件；时间窗口用 deque 滑动。
    """

    rule_id: str = "base"
    title: str = "基础规则"
    description: str = ""
    mitre: str = ""
    recommendation: str = ""

    def __init__(self, config) -> None:
        self.config = config
        self.enabled = config.rules == "all" or self.rule_id in [
            r.strip() for r in config.rules.split(",") if r.strip()
        ]
        self.alerts: list[Alert] = []

    # ---- 子类实现 ----
    def feed(self, ev: Event) -> None:  # pragma: no cover - 抽象
        raise NotImplementedError

    def finalize(self) -> list[Alert]:  # pragma: no cover - 抽象
        raise NotImplementedError

    # ---- 公共工具 ----
    def _sample(self, store: dict, key, ev: Event, limit_key: str = "n") -> None:
        """把事件加入证据采样（每个 key 最多保留 config.evidence_sample_per_alert 条）。"""
        entry = store.get(key)
        if entry is None:
            entry = store.setdefault(key, {"evidence": []})
        if "evidence" not in entry:      # 兼容自带统计字段的聚合结构
            entry["evidence"] = []
        if len(entry["evidence"]) < self.config.evidence_sample_per_alert:
            entry["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    @staticmethod
    def _window_push(windows: dict, key, ts: Optional[float], window_sec: int) -> int:
        """滑动窗口计数：返回当前窗口内事件数（ts 为 None 时按单 bucket 累计）。"""
        if ts is None:
            entry = windows.setdefault(key, {"count": 0, "events": deque()})
            entry["count"] += 1
            return entry["count"]
        entry = windows.setdefault(key, {"count": 0, "events": deque()})
        dq: deque = entry["events"]
        dq.append(ts)
        while dq and ts - dq[0] > window_sec:
            dq.popleft()
        entry["count"] = len(dq)
        return entry["count"]

    def _alert(self, severity: int, count: int, entities: dict,
               evidence: list, first_ts=None, last_ts=None) -> Alert:
        a = Alert(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity,
            first_ts=first_ts,
            last_ts=last_ts,
            count=count,
            entities=entities,
            evidence=evidence,
            description=self.description,
            mitre=self.mitre,
            recommendation=self.recommendation,
        )
        self.alerts.append(a)
        return a

    @staticmethod
    def _human_ts(ts: Optional[float]) -> str:
        if ts is None:
            return "未知时间"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

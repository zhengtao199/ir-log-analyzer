"""自定义规则运行时检测器。

把用户通过「规则库」工作台配置的自定义规则（独立新规则 + 挂在内置规则下的
附加特征 attaches_to）编译成运行时检测器，与内置检测器一起流式跑。

设计要点
--------
- 每条自定义规则独立聚合成一条告警（按 rule_id 分组，常量内存：证据采样有上限）。
- ``attaches_to`` 的附加特征命中后，告警归入目标内置规则的 ID/标题，
  相当于「给某条内置规则加了一条 payload」。
- 正则无法编译的规则在实例化阶段跳过，不会让整个分析崩掉。
"""
from __future__ import annotations

import re
from typing import Optional

from .base import Detector
from ..models import Alert, Event


class CustomRuleDetector(Detector):
    """消费自定义规则库，产出用户侧告警。

    注意：本检测器没有固定 rule_id —— 每条告警的 rule_id 取自其所属规则，
    以便与内置告警在「规则」维度上自然合并/对照。
    """

    rule_id = "custom-rules"
    title = "自定义规则"

    def __init__(self, config, pack) -> None:
        super().__init__(config)
        self.enabled = True
        self.rules: list = []
        for rule in pack.enabled_rules():
            compiled = []
            bad = False
            for p in rule.active_patterns():
                try:
                    compiled.append((p.id, p.compile()))
                except re.error:
                    bad = True
                    break
            if bad or not compiled:
                continue
            self.rules.append((rule, compiled))
        from . import ALL_DETECTORS
        self._builtin_titles = {c.rule_id: c.title for c in ALL_DETECTORS}
        self._builtin_meta = {c.rule_id: c for c in ALL_DETECTORS}
        self._hits: dict = {}

    def feed(self, ev: Event) -> None:
        for rule, pats in self.rules:
            text = rule.match_text(ev)
            if not text:
                continue
            hit = False
            for _pid, rx in pats:
                if rx.search(text):
                    hit = True
                    break
            if hit:
                self._record(rule, ev)

    def _record(self, rule, ev: Event) -> None:
        h = self._hits.get(rule.rule_id)
        if h is None:
            h = {"count": 0, "evidence": [], "first_ts": None,
                 "last_ts": None, "ips": set()}
            self._hits[rule.rule_id] = h
        h["count"] += 1
        if ev.ts is not None:
            if h["first_ts"] is None or ev.ts < h["first_ts"]:
                h["first_ts"] = ev.ts
            if h["last_ts"] is None or ev.ts > h["last_ts"]:
                h["last_ts"] = ev.ts
        if ev.src_ip:
            h["ips"].add(ev.src_ip)
        if len(h["evidence"]) < self.config.evidence_sample_per_alert:
            h["evidence"].append((ev.ts, ev.source,
                                 ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list[Alert]:
        for rule, _pats in self.rules:
            h = self._hits.get(rule.rule_id)
            if not h or not h["count"]:
                continue
            if rule.attaches_to:
                rid = rule.attaches_to
                base = self._builtin_meta.get(rid)
                title = rule.title or (base.title if base else rid)
                desc = (rule.description or "") + (f"（自定义附加特征，归集到内置规则 {rid}）"
                                                   if not rule.description else "")
                mitre = rule.mitre or (base.mitre if base else "")
                rec = rule.recommendation or (base.recommendation if base else "")
            else:
                rid = rule.rule_id
                title = rule.title
                desc = rule.description
                mitre = rule.mitre
                rec = rule.recommendation
            entities = {}
            if h["ips"]:
                entities["src_ip"] = sorted(h["ips"])[:10]
            alert = self._alert(
                severity=rule.severity,
                count=h["count"],
                entities=entities,
                evidence=h["evidence"],
                first_ts=h["first_ts"],
                last_ts=h["last_ts"],
            )
            # 覆盖规则级信息（_alert 默认用类属性）
            alert.rule_id = rid
            alert.title = title
            alert.description = desc or f"命中自定义规则 {rule.rule_id} 的特征"
            alert.mitre = mitre or ""
            alert.recommendation = rec or "结合命中原始日志评估影响，必要时隔离相关来源并取证。"
        return self.alerts


def test_rule_against_text(rule, text: str) -> list[dict]:
    """供「特征试测」用：在给定文本上跑一条规则的活跃特征，返回命中片段。"""
    out = []
    for p in rule.active_patterns():
        try:
            rx = p.compile()
        except re.error as exc:
            out.append({"pattern": p.id, "kind": p.kind, "ok": False, "error": str(exc)})
            continue
        m = rx.search(text)
        if m:
            snippet = text[max(0, m.start() - 40): m.end() + 40]
            out.append({"pattern": p.id, "kind": p.kind, "ok": True,
                        "match": m.group(0), "context": snippet})
        else:
            out.append({"pattern": p.id, "kind": p.kind, "ok": False, "match": None})
    return out

"""分析引擎：流式消费全部证据 -> 检测器 -> 时间线 -> 结果。

内存策略：
- 逐行/逐事件流式处理，GB 级文件不整体载入
- 检测器内部只存聚合计数与采样证据（有上限）
- 时间线事件数达上限后二分抽稀（保留首尾），不会无限增长
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import Config
from .detectors import build_detectors, IOCStore
from .models import Event, SEVERITY_LABELS
from .parsers import iter_events, detect_parser, is_probably_log
from .session import SessionTracker


class Timeline:
    """统一时间线统计（小时直方图 + 分类型计数）。

    内存策略：只保留聚合统计，不缓存事件对象 —— 内存占用与输入规模无关，
    任意大的日志文件都能在常量内存下完成分析。事件级证据由各检测器
    按需采样（有上限）后随告警输出。
    """

    def __init__(self, max_events: int = 200000) -> None:
        self.max_events = max_events
        self.hour_hist: dict[str, int] = {}
        self.by_type: dict[str, int] = {}
        self.total_seen = 0
        self._hour_cache: dict[int, str] = {}

    def _hour_key(self, ts: float) -> str:
        bucket = int(ts) // 3600 * 3600
        key = self._hour_cache.get(bucket)
        if key is None:
            key = time.strftime("%Y-%m-%d %H", time.localtime(bucket))
            if len(self._hour_cache) > 100000:  # 防缓存膨胀
                self._hour_cache.clear()
            self._hour_cache[bucket] = key
        return key

    def add(self, ev: Event) -> None:
        self.total_seen += 1
        self.by_type[ev.log_type] = self.by_type.get(ev.log_type, 0) + 1
        if ev.ts is not None:
            key = self._hour_key(ev.ts)
            self.hour_hist[key] = self.hour_hist.get(key, 0) + 1

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_seen,
            "by_log_type": self.by_type,
            "hour_histogram": dict(sorted(self.hour_hist.items())),
        }


@dataclass
class AnalysisResult:
    run_id: str
    started: float
    finished: float
    files: list = field(default_factory=list)        # [{"path", "log_type", "events", "skipped_reason"}]
    alerts: list = field(default_factory=list)       # [Alert]
    timeline: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def alerts_sorted(self) -> list:
        return sorted(self.alerts, key=lambda a: (a.severity, -(a.count or 0)))

    def severity_summary(self) -> dict:
        out = {}
        for a in self.alerts:
            out[a.severity] = out.get(a.severity, 0) + 1
        return out

    def to_dict(self, include_evidence: bool = True) -> dict:
        return {
            "run_id": self.run_id,
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started)),
            "finished": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.finished)),
            "duration_sec": round(self.finished - self.started, 2),
            "stats": self.stats,
            "severity_summary": {SEVERITY_LABELS.get(k, str(k)): v for k, v in self.severity_summary().items()},
            "files": self.files,
            "timeline": self.timeline,
            "alerts": [a.to_dict() for a in self.alerts_sorted()],
            "errors": self.errors,
        }


ProgressCB = Optional[Callable[[str, float], None]]


def run_analysis(paths: list[str], config: Config | None = None,
                 ioc_store: IOCStore | None = None,
                 progress: ProgressCB = None) -> AnalysisResult:
    """分析一批证据文件（只读）。"""
    cfg = config or Config()
    started = time.time()
    run_id = time.strftime("IR-%Y%m%d-%H%M%S", time.localtime(started))
    detectors = build_detectors(cfg, ioc_store)
    timeline = Timeline(cfg.timeline_max_events)
    # 会话归属：把无源 IP 的命令执行回填到发起它的登录会话（跨文件共享会话表）
    tracker = SessionTracker(cfg.session_idle_timeout) if cfg.attribution_enabled else None
    result = AnalysisResult(run_id=run_id, started=started, finished=started)

    total_events = 0
    for idx, path in enumerate(paths):
        def _p(msg: str, frac: float) -> None:
            if progress:
                progress(f"[{idx + 1}/{len(paths)}] {path}: {msg}", frac)

        try:
            if not is_probably_log(path):
                result.files.append({"path": path, "log_type": None, "events": 0,
                                     "skipped_reason": "二进制或超过大小上限，已跳过"})
                continue
            parser = detect_parser(path)
            log_type = parser.name if parser else "generic"
            n = 0
            for ev in iter_events(path):
                n += 1
                if tracker is not None:
                    tracker.enrich(ev)
                timeline.add(ev)
                for d in detectors:
                    d.feed(ev)
                if n % 50000 == 0:
                    _p(f"已处理 {n} 条", 0.5)
            total_events += n
            result.files.append({"path": path, "log_type": log_type, "events": n, "skipped_reason": None})
            _p(f"完成（{log_type}，{n} 条）", 1.0)
        except Exception as exc:  # 单文件失败不影响整体
            result.errors.append(f"{path}: {type(exc).__name__}: {exc}")
            result.files.append({"path": path, "log_type": None, "events": 0,
                                 "skipped_reason": f"解析异常: {exc}"})

    for d in detectors:
        try:
            d.finalize()
        except Exception as exc:
            result.errors.append(f"检测器 {d.rule_id} 异常: {type(exc).__name__}: {exc}")
        result.alerts.extend(d.alerts)

    result.timeline = timeline.to_dict()
    result.stats = {
        "total_events": total_events,
        "total_files": len(paths),
        "alert_count": len(result.alerts),
        "ioc_count": len(ioc_store.items) if ioc_store else 0,
    }
    result.finished = time.time()
    return result

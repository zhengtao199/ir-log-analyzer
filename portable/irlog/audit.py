"""审计留痕：所有分析操作追加写入 JSONL 审计日志（append-only）。

审计日志独立存放于工作目录，任何分析动作（启动分析、上传证据、
导出报告、修改 IOC 等）均留痕，满足应急响应操作可追溯要求。
"""
from __future__ import annotations

import json
import os
import time
import uuid


def new_run_id() -> str:
    return time.strftime("IR-%Y%m%d-%H%M%S-", time.localtime()) + uuid.uuid4().hex[:6]


class AuditLog:
    def __init__(self, workdir: str) -> None:
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.path = os.path.join(workdir, "audit.jsonl")

    def record(self, actor: str, action: str, **detail) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "actor": actor,
            "action": action,
            "detail": detail,
        }
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with open(self.path, "a", encoding="utf-8") as f:  # append-only
            f.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not os.path.isfile(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return out

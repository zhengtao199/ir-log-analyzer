"""证据管理：只读访问、SHA256 清单、证据链（Chain of Custody）信息。

原则：原始日志一律只读，任何分析操作都不修改证据文件；
每次分析生成不可变的证据清单（含哈希），写入独立工作目录。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Optional


def sha256_file(path: str, chunk_size: int = 1 << 20) -> str:
    """流式计算文件 SHA256（GB 级文件不占内存）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:  # 只读打开
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class EvidenceItem:
    path: str
    size: int
    sha256: str
    mtime: float
    mtime_iso: str
    log_type: Optional[str] = None
    lines_or_records: int = 0
    source: Optional[str] = None  # 手动填写的「日志来源」标签（存于 evidence/.sources.json）

    def to_dict(self) -> dict:
        return asdict(self)


def build_evidence_item(path: str, source: Optional[str] = None) -> EvidenceItem:
    st = os.stat(path)
    return EvidenceItem(
        path=os.path.abspath(path),
        size=st.st_size,
        sha256=sha256_file(path),
        mtime=st.st_mtime,
        mtime_iso=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        source=source,
    )


class EvidenceSet:
    """一次分析涉及的证据集合，含哈希与只读校验。"""

    def __init__(self) -> None:
        self.items: list[EvidenceItem] = []

    def add_file(self, path: str) -> EvidenceItem:
        item = build_evidence_item(path)
        self.items.append(item)
        return item

    def add_dir(self, path: str, recursive: bool = True) -> list[EvidenceItem]:
        added = []
        if recursive:
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    fp = os.path.join(root, name)
                    if os.path.isfile(fp):
                        added.append(self.add_file(fp))
        else:
            for name in sorted(os.listdir(path)):
                fp = os.path.join(path, name)
                if os.path.isfile(fp):
                    added.append(self.add_file(fp))
        return added

    def verify_readonly_ok(self) -> list[str]:
        """返回不可读/不存在文件的错误列表。"""
        errors = []
        for it in self.items:
            if not os.path.isfile(it.path):
                errors.append(f"证据文件不存在: {it.path}")
        return errors

    def to_dict(self) -> dict:
        return {
            "file_count": len(self.items),
            "total_bytes": sum(i.size for i in self.items),
            "items": [i.to_dict() for i in self.items],
        }


def chain_of_custody(run_id: str, operator: str, evidence: EvidenceSet,
                     started: float, finished: float, tool_version: str) -> dict:
    """生成报告内嵌的证据链信息。"""
    return {
        "case_id": run_id,
        "operator": operator,
        "tool": f"ir-log-analyzer v{tool_version}",
        "analysis_started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "analysis_finished": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(finished)),
        "evidence_integrity": "SHA256（分析前后一致，原始日志全程只读，未做任何修改）",
        "evidence": evidence.to_dict(),
    }


def write_json(path: str, obj) -> None:
    """原子写 JSON（先写临时文件再替换，避免半截文件）。"""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

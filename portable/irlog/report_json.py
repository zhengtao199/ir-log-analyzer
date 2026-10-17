"""JSON 报告输出（含证据链信息）。"""
from __future__ import annotations

from .evidence import write_json


def write_json_report(path: str, result, custody: dict) -> None:
    payload = result.to_dict()
    payload["chain_of_custody"] = custody
    write_json(path, payload)

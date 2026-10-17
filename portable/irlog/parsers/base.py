"""解析器基类与注册表。

新增日志源只需：
1. 继承 LogParser，实现 name/detect/parse
2. 在 parsers/__init__.py 的 PARSERS 列表登记
"""
from __future__ import annotations

import os
from typing import Generator, Iterable, Optional

from ..models import Event


class LogParser:
    """日志解析器接口。parse() 必须是生成器（流式，不全量读入内存）。"""

    name: str = "base"

    def detect(self, sample_lines: list[str]) -> bool:
        """根据文件头部若干行判断是否适用本解析器。"""
        raise NotImplementedError

    def detect_bytes(self, head: bytes, path: str = "") -> bool:
        """二进制魔数嗅探（可选实现）。返回 True 时优先于文本嗅探命中。"""
        return False

    def parse(self, path: str) -> Generator[Event, None, None]:
        raise NotImplementedError

    # ---- 公共工具 ----
    @staticmethod
    def read_lines(path: str, encoding: str = "utf-8", errors: str = "replace") -> Generator[str, None, None]:
        """逐行流式读取（自动跳过 BOM）。"""
        with open(path, "r", encoding=encoding, errors=errors, newline="") as f:
            first = True
            for line in f:
                if first:
                    if line.startswith("\ufeff"):
                        line = line[1:]
                    first = False
                yield line.rstrip("\r\n")

    @staticmethod
    def read_head(path: str, n: int = 4096) -> bytes:
        """读取文件头部二进制（用于魔数嗅探）。"""
        with open(path, "rb") as f:
            return f.read(n)

    @staticmethod
    def sniff(path: str, count: int = 20, max_bytes: int = 65536) -> list[str]:
        """文本嗅探：最多读 64KB，避免无换行的二进制文件被整行读入内存。"""
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
        except OSError:
            return []
        lines = []
        for line in data.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            lines.append(line)
            if len(lines) >= count:
                break
        return lines


_REGISTRY: list[LogParser] = []


def register(parser: LogParser) -> LogParser:
    _REGISTRY.append(parser)
    return parser


def registered() -> list[LogParser]:
    return list(_REGISTRY)


def detect_parser(path: str) -> Optional[LogParser]:
    """按注册顺序嗅探，返回第一个命中的解析器；无命中返回 None（generic）。

    两阶段：先做二进制魔数嗅探（流量包等二进制证据），失败再走文本嗅探。
    """
    try:
        head = LogParser.read_head(path)
    except OSError:
        return None
    for p in _REGISTRY:
        try:
            if p.detect_bytes(head, path):
                return p
        except Exception:
            continue
    try:
        sample = LogParser.sniff(path)
    except OSError:
        return None
    if not sample:
        return None
    for p in _REGISTRY:
        try:
            if p.detect(sample):
                return p
        except Exception:
            continue
    return None


def iter_events(path: str) -> Generator[Event, None, None]:
    """自动识别并流式解析单个文件。"""
    parser = detect_parser(path)
    if parser is None:
        from .generic import GenericParser
        parser = GenericParser()
    for ev in parser.parse(path):
        ev.source = path
        yield ev


# 允许作为证据分析的二进制格式魔数（pcap 大小端/纳秒变体、pcapng）
BINARY_MAGICS = (
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
)


def is_probably_log(path: str, max_size: int = 8 << 30) -> bool:
    """粗过滤：跳过明显非证据的文件（未知二进制/超大）。

    pcap / pcapng（含 gzip 压缩）是合法二进制证据，按魔数放行。
    """
    try:
        if os.path.getsize(path) > max_size:
            return False
        with open(path, "rb") as f:
            head = f.read(1024)
    except OSError:
        return False
    if head[:4] in BINARY_MAGICS:
        return True
    if head[:2] == b"\x1f\x8b":          # gzip：解出前 4 字节看是否为流量包
        try:
            import gzip
            with gzip.open(path, "rb") as g:
                return g.read(4) in BINARY_MAGICS
        except Exception:
            return False
    if b"\x00" in head:
        return False
    return True

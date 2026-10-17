"""HTTP 应用层解码：消息切分、chunked 解码、内容编码解压。

pcap 里的 HTTP 与 Web 访问日志不是一回事：
- 一次请求/响应可能被切成多个 TCP 报文（请求体常在后续报文）
- 一条长连接上会承载多条请求（pipelining / keep-alive）
- 响应体常用 chunked 分块，或 gzip/deflate 压缩

不做这些解码，注入载荷、Webshell 的执行回显、被拖走的敏感文件内容
在流量包里都是"看不见"的（前面几版只有请求行与状态码，就是这个原因）。

设计约束（与项目其余部分一致）：
- 纯标准库（gzip / zlib），离线内网可用
- 所有环节有上限：单方向消息条数、解码字节数，保证常量内存（防 zip bomb）
- 任何异常一律降级为原始字节，绝不向上抛
"""
from __future__ import annotations

import zlib
from typing import Iterator, Optional

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")

MAX_MESSAGES = 16              # 单方向最多切分多少条 HTTP 消息
MAX_HEAD = 8192                # 头部的最大长度（超长头一律放弃该条消息）
DECODE_LIMIT = 65536           # 解压后字节上限
MAX_CHUNKS = 512               # chunked 最多解多少块

# 这些响应类型解码出来是二进制，做文本匹配只会制造噪声
BINARY_CTYPE = ("image/", "video/", "audio/", "font/", "application/pdf",
                "application/zip", "application/gzip", "application/octet-stream",
                "application/x-msdownload", "application/x-shockwave-flash")

# 常见可执行文件/归档魔数（用于"下载了什么"的判定，不解码）
MAGIC_SIGNATURES = (
    (b"MZ", "Windows 可执行文件（PE/DOS 头 MZ）"),
    (b"\x7fELF", "Linux ELF 可执行文件"),
    (b"PK\x03\x04", "ZIP 压缩包"),
    (b"Rar!", "RAR 压缩包"),
    (b"\x1f\x8b", "GZIP 压缩包（未解压）"),
    (b"#!/bin/sh", "Shell 脚本"),
    (b"#!/bin/bash", "Shell 脚本"),
)


# ---------------------------------------------------------------- 头部
def _find_head_end(buf: bytes, start: int) -> Optional[tuple[int, int]]:
    """返回 (头部结束位置, 分隔符长度)；未找到返回 None。"""
    i = buf.find(b"\r\n\r\n", start)
    if 0 <= i <= start + MAX_HEAD:
        return i, 4
    j = buf.find(b"\n\n", start)
    if 0 <= j <= start + MAX_HEAD:
        return j, 2
    return None


def parse_headers(head: bytes) -> dict:
    """解析 HTTP 头（key 小写；多值头用逗号合并）。"""
    out: dict = {}
    try:
        text = head.decode("utf-8", "replace")
    except Exception:
        return out
    for line in text.replace("\r\n", "\n").split("\n")[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        out[k] = (out[k] + ", " + v) if k in out else v
    return out


def _start_line(buf: bytes, pos: int) -> Optional[bytes]:
    n = len(buf)
    limit = min(n, pos + MAX_HEAD)
    i = buf.find(b"\r\n", pos, limit)
    j = buf.find(b"\n", pos, limit)
    eol = min(x for x in (i, j) if x >= 0) if (i >= 0 or j >= 0) else -1
    return buf[pos:eol] if eol >= 0 else None


def _valid_start(line: bytes, kind: str) -> bool:
    if kind == "request":
        return line.split(b" ")[0] in HTTP_METHODS
    # 响应行必须是 "HTTP/1.1 200 ..."：只出现 "HTTP/1.1"（请求行尾部的协议串）
    # 不是响应起始行，否则会把请求当成响应解析
    if not line.startswith(b"HTTP/"):
        return False
    parts = line.split()
    return len(parts) >= 2 and parts[1].isdigit()


def _next_start(buf: bytes, pos: int, kind: str) -> Optional[int]:
    """流首部可能是残片（抓包从中间开始）：找下一个合法起始行位置。"""
    if kind == "response":
        k = buf.find(b"HTTP/", pos + 1)
        while k >= 0:
            if k == 0 or buf[k - 1:k] == b"\n":     # 必须是行首
                return k
            k = buf.find(b"HTTP/", k + 1)
        return None
    best = None
    for m in HTTP_METHODS:
        pat = m + b" "
        k = buf.find(pat, pos + 1)
        while k >= 0:
            if k == 0 or buf[k - 1:k] == b"\n":     # 必须是行首
                if best is None or k < best:
                    best = k
                break
            k = buf.find(pat, k + 1)
    return best


# ---------------------------------------------------------------- 分块与压缩
def dechunk(body: bytes) -> tuple[bytes, bool, int]:
    """chunked 解码：返回 (数据, 是否收全, 消耗掉的原始字节数)。"""
    out = bytearray()
    i = 0
    n = len(body)
    complete = False
    for _ in range(MAX_CHUNKS):
        eol = body.find(b"\r\n", i)
        if eol < 0:
            break
        raw = body[i:eol].split(b";")[0].strip() or b"0"
        try:
            size = int(raw, 16)
        except ValueError:
            break
        i = eol + 2
        if size == 0:
            complete = True
            k = body.find(b"\r\n", i)            # trailer 结束行
            i = (k + 2) if k >= 0 else n
            break
        if size > n - i:                          # 数据未收全（抓包截断）
            out += body[i:]
            i = n
            break
        out += body[i:i + size]
        i += size + 2
        if len(out) >= DECODE_LIMIT:
            break
    return bytes(out), complete, i


def _inflate(data: bytes, wbits: int) -> Optional[bytes]:
    try:
        d = zlib.decompressobj(wbits)
        return d.decompress(data, DECODE_LIMIT)
    except zlib.error:
        try:                                       # 截断流：不带上限再试一次
            return zlib.decompressobj(wbits).decompress(data)
        except Exception:
            return None
    except Exception:
        return None


def decode_content(body: bytes, encoding: str) -> tuple[bytes, str]:
    """按 Content-Encoding 解压：返回 (数据, 实际生效的编码名)。"""
    enc = (encoding or "").lower()
    if not body:
        return body, ""
    if "gzip" in enc or "x-gzip" in enc:
        out = _inflate(body, 16 + zlib.MAX_WBITS)
        if out:
            return out[:DECODE_LIMIT], "gzip"
    elif "deflate" in enc:
        for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
            out = _inflate(body, wbits)
            if out:
                return out[:DECODE_LIMIT], "deflate"
    return body, ""


def body_magic(data: bytes) -> str:
    """返回 body 前 4 字节的十六进制（供"下载了什么"判定，不解码内容）。"""
    return data[:4].hex() if data else ""


def magic_label(data: bytes) -> Optional[str]:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    return None


def to_text(data: bytes, limit: int = 8192) -> tuple[str, bool]:
    """解码 body 文本：返回 (文本, 是否疑似二进制)。"""
    if not data:
        return "", False
    sample = data[:limit]
    nul = sample.count(b"\x00")
    return sample.decode("utf-8", "replace"), nul > max(4, len(sample) // 32)


# ---------------------------------------------------------------- 消息切分
def _one_message(buf: bytes, start: int, kind: str) -> Optional[dict]:
    n = len(buf)
    pos = start
    line = None
    for _ in range(4):                             # 容忍流首部的残片
        cand = _start_line(buf, pos)
        if cand is not None and _valid_start(cand, kind):
            line = cand
            break
        nxt = _next_start(buf, pos, kind)
        if nxt is None:
            return None
        pos = nxt
    if line is None:
        return None

    he = _find_head_end(buf, pos)
    if he is None:
        return None
    idx, sep = he
    head = buf[pos:idx]
    headers = parse_headers(head)
    body_start = idx + sep

    status = None
    method = None
    uri = None
    if kind == "request":
        parts = line.split(b" ")
        method = parts[0].decode("ascii", "replace")
        uri = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
        host = headers.get("host", "")
        if host and uri.startswith("/"):
            uri = "http://" + host + uri
    else:
        parts = line.split(b" ")
        try:
            status = int(parts[1]) if len(parts) > 1 else None
        except ValueError:
            status = None

    te = headers.get("transfer-encoding", "").lower()
    try:
        clen = int(headers.get("content-length", "0") or 0)
    except ValueError:
        clen = 0

    enc_used: list = []
    if "chunked" in te:
        data, complete, used = dechunk(buf[body_start:])
        end = body_start + used
        enc_used.append("chunked")
    elif clen > 0:
        avail = n - body_start
        take = min(clen, avail)
        data = buf[body_start:body_start + take]
        end = body_start + take
        complete = avail >= clen
    elif kind == "response" and status not in (204, 304, 301, 302) and body_start < n:
        # 无长度声明（连接关闭式 / 抓包到缓冲末尾）：吃到末尾，标记不完整
        data = buf[body_start:]
        end = n
        complete = False
        enc_used.append("to-eof")
    else:
        data = b""
        end = body_start
        complete = True

    content, applied = decode_content(data, headers.get("content-encoding", ""))
    if applied:
        enc_used.append(applied)

    msg = {
        "kind": kind,
        "start_line": line.decode("utf-8", "replace"),
        "headers": headers,
        "method": method, "uri": uri, "status": status,
        "host": headers.get("host", ""),
        "ua": headers.get("user-agent", ""),
        "auth": headers.get("authorization", ""),
        "referer": headers.get("referer", ""),
        "cookie": headers.get("cookie", ""),
        "ctype": headers.get("content-type", ""),
        "body": data[:DECODE_LIMIT],
        "content": content[:DECODE_LIMIT],
        "body_len": len(data),
        "content_len": len(content),
        "encoding": enc_used,
        "complete": complete,
        "truncated": not complete,
        "end": end,
    }
    return msg


def iter_http_messages(buf: bytes, kind: str) -> Iterator[dict]:
    """在（已重组的）单方向字节流上切分 HTTP 消息。

    kind: "request"（客户端方向）或 "response"（服务端方向）。
    只产出起始行合法、且头部完整的消息；尾部残缺的一条不产出（等不到完整内容）。
    """
    if not buf:
        return
    n = len(buf)
    i = 0
    count = 0
    while count < MAX_MESSAGES and i < n:
        msg = _one_message(buf, i, kind)
        if msg is None:
            return
        yield msg
        nxt = msg["end"]
        i = nxt if nxt > i else i + 1              # 防死循环
        count += 1

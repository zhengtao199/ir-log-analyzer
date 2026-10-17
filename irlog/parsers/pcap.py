"""pcap / pcapng 流量包解析（纯标准库，流式常量内存）。

不依赖 scapy / dpdk 等第三方库（离线内网不可用）：
- pcap  ：libpcap 经典格式（大小端 + 微秒/纳秒变体）
- pcapng：SHB / IDB / EPB / SPB / PB（NRB 等无关块跳过）
- 两者均支持 gzip 压缩（.pcap.gz，标准库 gzip 流式解压）

链路层：Ethernet(1) / RAW(12,14,101) / NULL(0) / Linux SLL(113) / VLAN 标签剥离
输出归一化事件（复用既有动作常量，让已有规则直接生效）：
- A_NETWORK_CONN  TCP SYN / SYN-ACK / RST、UDP 新流
- A_NET_DNS       DNS 查询与响应（qname / qtype / rcode）
- A_HTTP_REQUEST  HTTP 请求行与响应行（→ 复用 web-attack / webshell / exfiltration）
- A_NET_TLS       TLS ClientHello（SNI + JA3 指纹）
- A_NET_CRED      明文协议凭据（FTP / Telnet / HTTP-Basic / POP3 / IMAP / SMTP）
- A_NET_STREAM    TCP 重组流（追踪流）：跨报文还原的双向应用层内容

内存策略：只维护有上限的流表（MAX_FLOWS），逐包处理不缓存报文本身。
"""
from __future__ import annotations

import gzip
import hashlib
import socket
import struct
from typing import Generator, Iterator, Optional

from ..models import (
    Event,
    A_NETWORK_CONN, A_NET_DNS, A_NET_TLS, A_NET_CRED, A_NET_FLOW, A_NET_STREAM,
    A_HTTP_REQUEST,
)
from .base import LogParser, register
from .tcpstream import TCPStreamReassembler
from .httpproto import (
    BINARY_CTYPE, iter_http_messages, to_text as http_to_text,
    body_magic, magic_label,
)

# ---- 魔数 ----
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"      # 大端，微秒
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"      # 小端，微秒
PCAP_MAGIC_BE_NS = b"\xa1\xb2\xcd\x34"   # 大端，纳秒
PCAP_MAGIC_LE_NS = b"\x34\xcd\xb2\xa1"   # 小端，纳秒
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
GZIP_MAGIC = b"\x1f\x8b"

# ---- 链路层类型 ----
DLT_NULL = 0
DLT_ETHERNET = 1
DLT_RAW = 12
DLT_RAW_ALT = 14
DLT_RAW_101 = 101
DLT_LINUX_SLL = 113

# 流表上限：超出后不再登记新流（只保留已有流的计数），保证常量内存
MAX_FLOWS = 50000

# TCP 重组（追踪流）上限：并发流数与每方向缓冲字节数共同封住内存
# （最坏约 1000 × 2 × 25KB ≈ 50MB；绝大多数会话远小于此，超出的部分标记 truncated）
STREAM_MAX_STREAMS = 1000
STREAM_MAX_BYTES = 16384
# 重组内容转文本时的取样长度（超出部分仍计入字节数，但不参与文本匹配）
STREAM_TEXT_LIMIT = 8192
# HTTP 请求体 / 响应体取样长度
HTTP_BODY_LIMIT = 4096
# 单包已解析过的请求行/响应行计数上限（超出后不再登记，退化为"重组后补发"）
HTTP_SEEN_CAP = 50000

# HTTP 方法（用于识别请求行）
HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")

# 明文凭据协议特征
CRED_PATTERNS = (
    (b"USER ", "FTP"),
    (b"PASS ", "FTP"),
    (b"Authorization: Basic ", "HTTP-Basic"),
    (b"authorization: basic ", "HTTP-Basic"),
    (b"AUTH LOGIN", "SMTP"),
    (b"AUTH PLAIN", "SMTP"),
    (b"login:", "Telnet"),
    (b"Login:", "Telnet"),
    (b"assword:", "Telnet"),
)

# 已知远控/后门常见端口（仅作辅助线索，低危）
SUSPICIOUS_PORTS = {
    4444: "Metasploit 默认反向 shell",
    5555: "常见后门/ADB 调试",
    6666: "常见后门/IRC 僵尸网络",
    6667: "IRC（僵尸网络 C2 常见）",
    9001: "Tor 目录/OR 端口",
    9030: "Tor OR 端口",
    1337: "常见后门端口",
    12345: "NetBus 后门",
    27374: "Sub7 后门",
    31337: "Back Orifice / Elite",
}


# ==========================================================================
# 文件格式读取
# ==========================================================================
def _iter_pcap(fh, head: bytes) -> Iterator[tuple[float, bytes, int]]:
    """经典 pcap：产出 (ts, packet_bytes, linktype)。"""
    magic = head[:4]
    if magic == PCAP_MAGIC_BE:
        endian, tsdiv = ">", 1_000_000.0
    elif magic == PCAP_MAGIC_LE:
        endian, tsdiv = "<", 1_000_000.0
    elif magic == PCAP_MAGIC_BE_NS:
        endian, tsdiv = ">", 1_000_000_000.0
    elif magic == PCAP_MAGIC_LE_NS:
        endian, tsdiv = "<", 1_000_000_000.0
    else:
        return
    if len(head) < 24:
        return
    linktype = struct.unpack(endian + "I", head[20:24])[0]
    rec = struct.Struct(endian + "IIII")
    read = fh.read
    while True:
        hdr = read(16)
        if len(hdr) < 16:
            return
        ts_sec, ts_frac, incl, _orig = rec.unpack(hdr)
        if incl > 0x40000000:            # 异常长度，视为文件损坏
            return
        data = read(incl)
        if len(data) < incl:
            return
        yield ts_sec + ts_frac / tsdiv, data, linktype


def _parse_pcapng_options(body: bytes, endian: str, start: int) -> dict:
    """解析 pcapng 选项（code,len,value 的 TLV，4 字节对齐）。"""
    opts: dict = {}
    i = start
    n = len(body)
    while i + 4 <= n:
        code, length = struct.unpack_from(endian + "HH", body, i)
        i += 4
        if code == 0:                    # opt_endofopt
            break
        opts[code] = body[i:i + length]
        i += length + ((4 - length % 4) % 4)
    return opts


def _iter_pcapng(fh, head: bytes) -> Iterator[tuple[float, bytes, int]]:
    """pcapng：按块解析，产出 (ts, packet_bytes, linktype)。head 为已读出的前若干字节。"""
    if len(head) < 12:
        return
    _btype, blen = struct.unpack("<II", head[:8])     # SHB 魔数大小端同形
    if blen < 12:
        return
    endian = "<" if head[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    rest = blen - len(head)                            # 跳过 SHB 剩余（含块尾长度）
    if rest > 0:
        fh.read(rest)

    if_tsresol: list = []                # 每个接口的时间戳分辨率（秒）
    if_link: list = []

    while True:
        h = fh.read(8)
        if len(h) < 8:
            return
        btype, blen = struct.unpack(endian + "II", h)
        if blen < 12:
            return
        # 块布局：type(4) + total_len(4) + body + padding + trailing_len(4)
        # 即 blen - 12 为 body+padding，需再吞掉尾部 4 字节
        raw = fh.read(blen - 8)
        if len(raw) < blen - 8:
            return
        body = raw[:blen - 12]

        if btype == 0x00000001:          # Interface Description Block
            if len(body) >= 8:
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
                if_link.append(linktype)
                opts = _parse_pcapng_options(body, endian, 8)
                raw = opts.get(9)                   # if_tsresol
                if raw:
                    b = raw[0]
                    if_tsresol.append(2.0 ** -(b & 0x7F) if (b & 0x80) else 10.0 ** -b)
                else:
                    if_tsresol.append(1e-6)
        elif btype == 0x00000006:        # Enhanced Packet Block
            if len(body) < 20:
                continue
            ifid, tsh, tsl, caplen, _origlen = struct.unpack_from(endian + "IIIII", body, 0)
            data = body[20:20 + caplen]
            res = if_tsresol[ifid] if ifid < len(if_tsresol) else 1e-6
            linktype = if_link[ifid] if ifid < len(if_link) else DLT_ETHERNET
            yield ((tsh << 32) | tsl) * res, data, linktype
        elif btype == 0x00000003:        # Simple Packet Block
            if len(body) < 4:
                continue
            data = body[4:]
            yield 0.0, data, (if_link[0] if if_link else DLT_ETHERNET)
        elif btype == 0x00000002:        # Packet Block（已废弃）
            if len(body) < 20:
                continue
            ifid = struct.unpack_from(endian + "H", body, 0)[0]
            tsh, tsl, caplen = struct.unpack_from(endian + "III", body, 4)
            data = body[16:16 + caplen]
            res = if_tsresol[ifid] if ifid < len(if_tsresol) else 1e-6
            yield ((tsh << 32) | tsl) * res, data, (if_link[ifid] if ifid else DLT_ETHERNET)


# ==========================================================================
# 协议解码
# ==========================================================================
def _decode_packet(linktype: int, data: bytes) -> Optional[dict]:
    """链路层 → IP → TCP/UDP，返回归一化字典；非 IP 或格式异常返回 None。"""
    n = len(data)
    if n < 14:
        return None
    try:
        if linktype == DLT_ETHERNET:
            etype = struct.unpack_from("!H", data, 12)[0]
            off = 14
            for _ in range(3):                      # 剥离 VLAN / QinQ 标签
                if etype in (0x8100, 0x88A8, 0x9100):
                    if n < off + 4:
                        return None
                    etype = struct.unpack_from("!H", data, off + 2)[0]
                    off += 4
                else:
                    break
            if etype == 0x0800:
                ip_ver = 4
            elif etype == 0x86DD:
                ip_ver = 6
            else:
                return None
        elif linktype in (DLT_RAW, DLT_RAW_ALT, DLT_RAW_101):
            ip_ver = data[0] >> 4
            off = 0
        elif linktype == DLT_NULL:
            ip_ver = data[4] >> 4
            off = 4
        elif linktype == DLT_LINUX_SLL:
            if n < 16:
                return None
            proto = struct.unpack_from("!H", data, 14)[0]
            if proto != 0x0800:                     # SLL 仅处理 IPv4
                return None
            ip_ver = 4
            off = 16
        else:
            return None

        if ip_ver == 4:
            if n < off + 20:
                return None
            ihl = (data[off] & 0x0F) * 4
            if ihl < 20:
                return None
            total_len = struct.unpack_from("!H", data, off + 2)[0]
            proto = data[off + 9]
            src = socket.inet_ntoa(data[off + 12:off + 16])
            dst = socket.inet_ntoa(data[off + 16:off + 20])
            p0 = off + ihl
            end = off + total_len if total_len else n
        elif ip_ver == 6:
            if n < off + 40:
                return None
            proto = data[off + 6]
            plen = struct.unpack_from("!H", data, off + 4)[0]
            src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
            p0 = off + 40
            end = min(p0 + plen, n)
            for _ in range(8):                      # 跳过扩展头
                if proto in (0, 43, 44, 50, 51, 60):
                    if p0 + 2 > end:
                        return None
                    if proto == 44:                 # 分片头固定 8 字节
                        proto = data[p0]
                        p0 += 8
                    else:
                        proto = data[p0]
                        p0 += 8 + data[p0 + 1] * 8
                else:
                    break
        else:
            return None

        if end > n:
            end = n
        out = {"version": ip_ver, "src": src, "dst": dst, "proto": proto}

        if proto == 6:                              # TCP
            if p0 + 20 > end:
                return None
            sport, dport = struct.unpack_from("!HH", data, p0)
            seq, ack = struct.unpack_from("!II", data, p0 + 4)
            doff = (data[p0 + 12] >> 4) * 4
            flags = data[p0 + 13]
            payload = data[p0 + doff:end] if doff >= 20 else b""
            out.update({"sport": sport, "dport": dport, "seq": seq, "ack": ack,
                        "flags": flags, "payload": payload})
        elif proto == 17:                           # UDP
            if p0 + 8 > end:
                return None
            sport, dport, ulen = struct.unpack_from("!HHH", data, p0)
            payload = data[p0 + 8:end]
            out.update({"sport": sport, "dport": dport, "flags": 0,
                        "payload": payload, "ulen": ulen})
        else:
            out.update({"sport": 0, "dport": 0, "flags": 0, "payload": b""})
        out["ip_payload_len"] = max(0, end - p0)
        return out
    except Exception:
        return None


def _tcp_flags(pkt: dict) -> str:
    f = pkt["flags"]
    names = []
    if f & 0x02:
        names.append("SYN")
    if f & 0x10:
        names.append("ACK")
    if f & 0x01:
        names.append("FIN")
    if f & 0x04:
        names.append("RST")
    if f & 0x08:
        names.append("PSH")
    return "".join(names) or "-"


# ==========================================================================
# 应用层解析
# ==========================================================================
def _read_dns_name(buf: bytes, off: int) -> tuple[Optional[str], int]:
    """解析 DNS 域名（支持压缩指针），返回 (name, 下一个偏移)。"""
    labels = []
    end = off
    jumped = False
    for _ in range(32):
        if off >= len(buf):
            return None, off
        ln = buf[off]
        if ln & 0xC0 == 0xC0:                       # 压缩指针
            if off + 1 >= len(buf):
                return None, off
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        labels.append(buf[off + 1:off + 1 + ln])
        off += ln + 1
        if not jumped:
            end = off
    try:
        return b".".join(labels).decode("utf-8", "replace"), end
    except Exception:
        return None, end


def _parse_dns(payload: bytes) -> Optional[dict]:
    if len(payload) < 12:
        return None
    try:
        _tid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", payload, 0)
        qr = (flags >> 15) & 1
        rcode = flags & 0xF
        i = 12
        qname = None
        qtype = None
        for _ in range(min(qd, 3)):
            name, i = _read_dns_name(payload, i)
            if name is None:
                break
            if qname is None:
                qname = name
            if i + 4 <= len(payload):
                qtype = struct.unpack_from("!H", payload, i)[0]
                i += 4
        return {"qr": qr, "rcode": rcode, "qname": qname,
                "qtype": qtype, "answers": an, "questions": qd}
    except Exception:
        return None


def _parse_headers(raw: bytes) -> dict:
    """解析 HTTP 头（不区分大小写，key 小写）。"""
    out: dict = {}
    try:
        text = raw.decode("utf-8", "replace")
        for line in text.split("\r\n")[1:]:
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return out


def _parse_http(payload: bytes) -> Optional[dict]:
    """识别 HTTP 请求行 / 响应行（不做 TCP 重组，仅单包识别）。"""
    if len(payload) < 8:
        return None
    idx = payload.find(b"\r\n")
    if idx < 0:
        return None
    line = payload[:idx]
    parts = line.split(b" ")
    stop = payload.find(b"\r\n\r\n")
    head = payload[:stop + 4] if stop > 0 else payload[:2000]
    headers = _parse_headers(head)

    if parts[0] in HTTP_METHODS and len(parts) >= 2:
        uri = parts[1].decode("utf-8", "replace")
        host = headers.get("host", "")
        if host and uri.startswith("/"):
            uri = "http://" + host + uri
        try:
            clen = int(headers.get("content-length", "0") or 0)
        except ValueError:
            clen = 0
        return {"direction": "request",
                "method": parts[0].decode("ascii", "replace"),
                "uri": uri[:4000],
                "host": host,
                "ua": headers.get("user-agent", ""),
                "auth": headers.get("authorization", ""),
                "content_length": clen}

    if line.startswith(b"HTTP/") and len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = None
        try:
            clen = int(headers.get("content-length", "0") or 0)
        except ValueError:
            clen = 0
        return {"direction": "response", "status": status,
                "content_length": clen, "ctype": headers.get("content-type", "")}
    return None


def _u16_list(buf: bytes) -> list:
    return [struct.unpack_from("!H", buf, k)[0] for k in range(0, len(buf) - 1, 2)]


def _sni_from_ext(b: bytes) -> Optional[str]:
    try:
        i = 2                                       # 跳过 server_name_list 长度
        while i + 3 <= len(b):
            ntype = b[i]
            i += 1
            nlen = struct.unpack_from("!H", b, i)[0]
            i += 2
            val = b[i:i + nlen]
            i += nlen
            if ntype == 0:
                return val.decode("utf-8", "replace")
    except Exception:
        return None
    return None


def _parse_tls(payload: bytes) -> Optional[dict]:
    """解析 TLS ClientHello：SNI + JA3 指纹。"""
    try:
        if len(payload) < 11 or payload[0] != 0x16:
            return None
        rlen = struct.unpack_from("!H", payload, 3)[0]
        body = payload[5:5 + rlen]
        if len(body) < 40 or body[0] != 0x01:       # 仅 ClientHello
            return None
        i = 4
        cver = struct.unpack_from("!H", body, i)[0]
        i += 2 + 32                                 # 版本 + random
        sid_len = body[i]
        i += 1 + sid_len
        cs_len = struct.unpack_from("!H", body, i)[0]
        i += 2
        ciphers = body[i:i + cs_len]
        i += cs_len
        comp_len = body[i]
        i += 1 + comp_len

        sni = None
        ja3_exts: list = []
        curves = ""
        ec_fmt = ""
        if i + 2 <= len(body):
            ext_total = struct.unpack_from("!H", body, i)[0]
            i += 2
            end = min(i + ext_total, len(body))
            while i + 4 <= end:
                etype, elen = struct.unpack_from("!HH", body, i)
                i += 4
                val = body[i:i + elen]
                i += elen
                ja3_exts.append(str(etype))
                if etype == 0x0000:
                    sni = _sni_from_ext(val)
                elif etype == 0x000A and len(val) >= 2:      # supported_groups
                    curves = "-".join(str(x) for x in _u16_list(val[2:]))
                elif etype == 0x000B and val:
                    ec_fmt = str(val[0])
        ciphers_s = "-".join(str(x) for x in _u16_list(ciphers))
        ja3_str = "%d,%s,%s,%s,%s" % (cver, ciphers_s, "-".join(ja3_exts), curves, ec_fmt)
        return {"sni": sni, "ja3": hashlib.md5(ja3_str.encode()).hexdigest(),
                "version": cver}
    except Exception:
        return None


def _match_cred(payload: bytes) -> Optional[tuple]:
    """识别明文协议凭据，返回 (协议, 关键字)。"""
    if not payload:
        return None
    head = payload[:1200]
    for pat, proto in CRED_PATTERNS:
        if pat in head:
            return proto, pat.decode("utf-8", "replace").strip()
    return None


def _to_text(b: bytes, limit: int = STREAM_TEXT_LIMIT) -> tuple[str, bool]:
    """重组字节流转文本：返回 (文本, 是否疑似二进制)。

    二进制流（TLS/压缩内容）解码出来是乱码，交给文本规则只会制造噪声；
    这里只做标记，具体内容仍保留在事件中供人工复核。
    """
    if not b:
        return "", False
    sample = b[:limit]
    nul = sample.count(b"\x00")
    return sample.decode("utf-8", "replace"), nul > max(4, len(sample) // 32)


# ==========================================================================
# 解析器
# ==========================================================================
class PcapParser(LogParser):
    name = "pcap"

    def detect(self, sample_lines: list[str]) -> bool:
        return False                                 # 二进制格式，文本嗅探无意义

    def detect_bytes(self, head: bytes, path: str = "") -> bool:
        if head[:4] in (PCAP_MAGIC_BE, PCAP_MAGIC_LE,
                        PCAP_MAGIC_BE_NS, PCAP_MAGIC_LE_NS, PCAPNG_MAGIC):
            return True
        if head[:2] == GZIP_MAGIC and path:
            try:                                    # 需解压后看内部魔数
                with gzip.open(path, "rb") as g:
                    return g.read(4) in (PCAP_MAGIC_BE, PCAP_MAGIC_LE,
                                         PCAP_MAGIC_BE_NS, PCAP_MAGIC_LE_NS,
                                         PCAPNG_MAGIC)
            except Exception:
                return False
        return False

    def parse(self, path: str) -> Generator[Event, None, None]:
        # 先探测是否 gzip 压缩，再打开同一个句柄顺序读取（避免偏移错乱）
        try:
            with open(path, "rb") as probe:
                magic2 = probe.read(2)
        except OSError:
            return
        fh = gzip.open(path, "rb") if magic2 == GZIP_MAGIC else open(path, "rb")
        head = fh.read(24)

        try:
            if head[:4] == PCAPNG_MAGIC:
                packets = _iter_pcapng(fh, head)
            else:
                packets = _iter_pcap(fh, head)

            flows: dict = {}
            # 单包已产出的请求行/响应行计数：重组后不再重复发同样的行事件，
            # 只补单包看不到的部分（请求体、响应体、被切开的请求行）
            http_seen: dict = {"req": {}, "resp": {}}
            reasm = TCPStreamReassembler(max_streams=STREAM_MAX_STREAMS,
                                         max_bytes=STREAM_MAX_BYTES)
            for ts, data, linktype in packets:
                pkt = _decode_packet(linktype, data)
                if pkt is None:
                    continue
                for ev in self._emit(ts, pkt, flows, http_seen):
                    yield ev
                # TCP 重组：所有 TCP 报文都过一遍——纯握手用于记录 ISN（乱序
                # 重排要靠它）与关闭方向，带载荷的段进入重排
                if pkt["proto"] == 6:
                    done = reasm.feed(ts, pkt["src"], pkt["sport"],
                                      pkt["dst"], pkt["dport"],
                                      pkt.get("seq") or 0, pkt.get("payload") or b"",
                                      pkt.get("flags") or 0)
                    if done is not None:
                        for ev in self._stream_event(done, http_seen):
                            yield ev
                    for extra in reasm.drain():
                        for ev in self._stream_event(extra, http_seen):
                            yield ev
            for s in reasm.finish():
                for ev in self._stream_event(s, http_seen):
                    yield ev
            for ev in self._flow_events(flows):
                yield ev
        finally:
            try:
                fh.close()
            except Exception:
                pass

    # ---- 单包事件 ----
    def _emit(self, ts: float, pkt: dict, flows: dict,
              http_seen: Optional[dict] = None) -> Generator[Event, None, None]:
        src, dst = pkt["src"], pkt["dst"]
        sport, dport = pkt["sport"], pkt["dport"]
        proto = "TCP" if pkt["proto"] == 6 else ("UDP" if pkt["proto"] == 17 else str(pkt["proto"]))
        payload = pkt.get("payload") or b""
        plen = len(payload)

        # 流表（有上限）：用于 UDP 新流识别与 EOF 汇总
        fkey = (src, sport, dst, dport, proto)
        rkey = (dst, dport, src, sport, proto)
        flow = flows.get(fkey) or flows.get(rkey)
        is_new = False
        if flow is None:
            if len(flows) < MAX_FLOWS:
                flow = {"ts": ts, "last": ts, "out": 0, "in": 0,
                        "pkts": 0, "uri": None}
                flows[fkey] = flow
                is_new = True
        if flow is not None:
            flow["last"] = ts
            flow["pkts"] += 1
            if flow is flows.get(fkey):
                flow["out"] += plen
            else:
                flow["in"] += plen

        # 1) 连接事件：TCP SYN / SYN-ACK / RST，UDP 新流
        if proto == "TCP":
            f = pkt["flags"]
            if f & 0x02 and not (f & 0x10):          # SYN
                yield self._conn(ts, pkt, "SYN", plen)
            elif f & 0x02 and f & 0x10:              # SYN-ACK
                yield self._conn(ts, pkt, "SYN-ACK", plen)
            elif f & 0x04:                           # RST
                yield self._conn(ts, pkt, "RST", plen)
        elif is_new:
            yield self._conn(ts, pkt, "UDP", plen)

        if not payload:
            return

        # 2) DNS
        if sport == 53 or dport == 53:
            dns = _parse_dns(payload)
            if dns and dns.get("qname"):
                yield self._dns(ts, pkt, dns)
            return

        # 3) HTTP（请求行 / 响应行）
        http = _parse_http(payload)
        if http:
            ev = self._http(ts, pkt, http, flow)
            if ev is not None:
                yield ev
            if http_seen is not None:
                self._mark_seen(http_seen, http["direction"], src, sport, dst, dport)
            if http["direction"] == "request" and flow is not None:
                flow["uri"] = http["uri"]
            return

        # 4) TLS ClientHello
        if dport == 443 or (payload[0] == 0x16):
            tls = _parse_tls(payload)
            if tls and (tls["sni"] or tls["ja3"]):
                yield self._tls(ts, pkt, tls)
                return

        # 5) 明文凭据
        cred = _match_cred(payload)
        if cred:
            yield self._cred(ts, pkt, cred[0], cred[1])

    # ---- 事件构造 ----
    @staticmethod
    def _base(ts: float, pkt: dict) -> Event:
        ev = Event(ts=ts, log_type="pcap")
        ev.src_ip = pkt["src"]
        ev.dst_ip = pkt["dst"]
        ev.detail["src_port"] = pkt["sport"]
        ev.detail["dst_port"] = pkt["dport"]
        ev.detail["proto"] = "TCP" if pkt["proto"] == 6 else (
            "UDP" if pkt["proto"] == 17 else str(pkt["proto"]))
        ev.detail["ip_version"] = pkt["version"]
        return ev

    def _conn(self, ts: float, pkt: dict, flags: str, plen: int) -> Event:
        ev = self._base(ts, pkt)
        ev.action = A_NETWORK_CONN
        ev.detail["flags"] = flags
        ev.detail["payload_len"] = plen
        note = SUSPICIOUS_PORTS.get(pkt["dport"])
        if note:
            ev.detail["suspicious_port_note"] = note
        ev.raw = "%s %s:%d -> %s:%d %s len=%d" % (
            ev.detail["proto"], pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"],
            flags, plen)
        return ev

    def _dns(self, ts: float, pkt: dict, dns: dict) -> Event:
        ev = self._base(ts, pkt)
        ev.action = A_NET_DNS
        ev.domain = dns.get("qname")
        ev.detail.update({"qname": dns.get("qname"), "qtype": dns.get("qtype"),
                          "rcode": dns.get("rcode"), "is_response": bool(dns.get("qr")),
                          "answers": dns.get("answers")})
        if dns.get("qr"):
            # 响应：src_ip 记为查询方（客户端），与 HTTP 响应事件保持同一语义
            ev.src_ip, ev.dst_ip = pkt["dst"], pkt["src"]
            ev.detail["src_port"], ev.detail["dst_port"] = pkt["dport"], pkt["sport"]
        ev.raw = "DNS %s -> %s %s %s (qtype=%s rcode=%s answers=%s)" % (
            pkt["src"], pkt["dst"], "响应" if dns.get("qr") else "查询",
            dns.get("qname"), dns.get("qtype"), dns.get("rcode"), dns.get("answers"))
        return ev

    def _http(self, ts: float, pkt: dict, http: dict, flow: Optional[dict]) -> Optional[Event]:
        ev = self._base(ts, pkt)
        ev.action = A_HTTP_REQUEST
        ev.detail["direction"] = http["direction"]
        if http["direction"] == "request":
            # 语义对齐 Web 访问日志：src_ip = 客户端
            ev.method = http["method"]
            ev.uri = http["uri"]
            ev.user_agent = http["ua"] or None
            ev.domain = http["host"] or None
            ev.detail["host"] = http["host"]
            ev.bytes_sent = http["content_length"] or None
            ev.raw = "HTTP %s -> %s %s %s UA=%s" % (
                pkt["src"], pkt["dst"], http["method"], http["uri"], http["ua"][:80])
        else:
            # 响应：src_ip 记为客户端（下载方），便于外传类规则按客户端聚合。
            # uri 只放进 detail：响应行不含攻击 payload，若写入 ev.uri 会让
            # web-attack 对同一次请求重复计数。
            ev.src_ip, ev.dst_ip = pkt["dst"], pkt["src"]
            ev.detail["src_port"], ev.detail["dst_port"] = pkt["dport"], pkt["sport"]
            ev.status = http["status"]
            ev.bytes_sent = http["content_length"] or None
            ev.detail["uri"] = (flow or {}).get("uri")
            ev.detail["content_type"] = http["ctype"]
            ev.raw = "HTTP %s <- %s %s %s 响应 %s字节" % (
                pkt["dst"], pkt["src"], ev.detail["uri"] or "-", http["status"],
                http["content_length"])
        return ev

    def _tls(self, ts: float, pkt: dict, tls: dict) -> Event:
        ev = self._base(ts, pkt)
        ev.action = A_NET_TLS
        ev.domain = tls.get("sni")
        ev.hashes = tls.get("ja3")
        ev.detail.update({"sni": tls.get("sni"), "ja3": tls.get("ja3"),
                          "tls_version": tls.get("version")})
        ev.raw = "TLS %s -> %s SNI=%s JA3=%s" % (
            pkt["src"], pkt["dst"], tls.get("sni"), tls.get("ja3"))
        return ev

    def _cred(self, ts: float, pkt: dict, proto: str, keyword: str) -> Event:
        ev = self._base(ts, pkt)
        ev.action = A_NET_CRED
        ev.detail.update({"cred_protocol": proto, "keyword": keyword})
        snippet = (pkt.get("payload") or b"")[:120].decode("utf-8", "replace")
        ev.raw = "明文凭据[%s] %s -> %s : %s" % (proto, pkt["src"], pkt["dst"], snippet)
        return ev

    # ---- 重组流（追踪流） ----
    @staticmethod
    def _skey(src: str, sport: int, dst: str, dport: int) -> tuple:
        a, b = (src, sport), (dst, dport)
        return (a, b) if a <= b else (b, a)

    @staticmethod
    def _mark_seen(http_seen: dict, direction: str,
                   src: str, sport: int, dst: str, dport: int) -> None:
        """登记单包已解析过的请求行/响应行，供重组阶段去重。"""
        bucket = http_seen["req" if direction == "request" else "resp"]
        if len(bucket) >= HTTP_SEEN_CAP:
            return
        k = PcapParser._skey(src, sport, dst, dport)
        bucket[k] = bucket.get(k, 0) + 1

    def _stream_event(self, s: dict, http_seen: Optional[dict] = None) -> Generator[Event, None, None]:
        # 纯握手（FIN 关闭但无载荷）不产出事件：没有可分析的内容
        if not s["client_len"] and not s["server_len"]:
            return
        ctext, cbin = _to_text(s["client_data"])
        stext, sbin = _to_text(s["server_data"])
        c_ip, c_port = s["src"], s["sport"]
        s_ip, s_port = s["dst"], s["dport"]

        ev = Event(ts=s["first"], log_type="pcap", action=A_NET_STREAM,
                   src_ip=c_ip, dst_ip=s_ip)
        ev.detail.update({
            "src_port": c_port, "dst_port": s_port, "proto": "TCP",
            "client_text": ctext, "server_text": stext,
            "client_bytes": s["client_len"], "server_bytes": s["server_len"],
            "packets": s["packets"],
            "duration_sec": round(max(0.0, s["last"] - s["first"]), 3),
            "retransmits": s["retransmits"], "out_of_order": s["out_of_order"],
            "truncated": s["truncated"], "reset": s["reset"],
            "complete": s["complete"], "partial": s.get("partial", False),
            "client_binary": cbin, "server_binary": sbin,
        })
        ev.bytes_sent = s["client_len"] + s["server_len"]
        ev.raw = ("TCP流 %s:%d <-> %s:%d 客户端%d字节/服务端%d字节 "
                  "%d包 时长%.1fs%s") % (
            c_ip, c_port, s_ip, s_port, s["client_len"], s["server_len"],
            s["packets"], max(0.0, s["last"] - s["first"]),
            "（截断）" if s["truncated"] else "")
        yield ev

        # HTTP：单包只能看到请求行/响应行，请求体与响应体（注入载荷、Webshell
        # 回显、被拖走的文件内容）必须靠重组 + chunked/gzip 解码才能拿到
        for bev in self._http_stream_events(s, http_seen):
            yield bev

    def _http_stream_events(self, s: dict, http_seen: Optional[dict]) -> Generator[Event, None, None]:
        """把重组后的双向缓冲切成 HTTP 消息，补齐单包看不到的部分。

        去重口径：单包已发过的请求行/响应行不再重复发（否则同一次请求会被
        检测器计数两次），只补「单包没解析到」的行 + 全部请求体/响应体。
        """
        reqs = list(iter_http_messages(s["client_data"], "request")) if s["client_data"] else []
        resps = list(iter_http_messages(s["server_data"], "response")) if s["server_data"] else []
        if not reqs and not resps:
            return

        req_seen = resp_seen = 0
        if http_seen is not None:
            req_seen = http_seen["req"].pop(s["key"], 0)
            resp_seen = http_seen["resp"].pop(s["key"], 0)

        # 1) 请求行：仅在单包完全没解析到时补发（请求行被切开 / 非 80 端口等）
        if req_seen == 0:
            for m in reqs:
                yield self._http_req_event(s, m)
        # 2) 请求体：单包永远拿不到，一律产出（uri 留空，避免与请求行重复计数）
        for m in reqs:
            bev = self._http_body_event(s, m, "request")
            if bev is not None:
                yield bev

        # 3) 响应行：同理，只在单包没解析到时补发（404 扫描要靠状态码）
        if resp_seen == 0:
            for m in resps:
                yield self._http_resp_event(s, m)
        # 4) 响应体：外传内容、命令回显、恶意脚本都在里面
        for i, m in enumerate(resps):
            uri = reqs[i]["uri"] if i < len(reqs) else None
            bev = self._http_body_event(s, m, "response", uri=uri)
            if bev is not None:
                yield bev

    def _http_req_event(self, s: dict, m: dict) -> Event:
        ev = Event(ts=s["first"], log_type="pcap", action=A_HTTP_REQUEST,
                   src_ip=s["src"], dst_ip=s["dst"])
        ev.method = m["method"]
        ev.uri = m["uri"]
        ev.user_agent = m["ua"] or None
        ev.domain = m["host"] or None
        ev.detail.update({
            "direction": "request", "proto": "TCP",
            "src_port": s["sport"], "dst_port": s["dport"],
            "host": m["host"], "reassembled": True,
            "referer": m["referer"] or None, "cookie": m["cookie"] or None,
        })
        ev.raw = "HTTP(重组) %s -> %s %s %s UA=%s" % (
            s["src"], s["dst"], m["method"], m["uri"], m["ua"][:80])
        return ev

    def _http_resp_event(self, s: dict, m: dict) -> Event:
        # 与单包响应事件同一语义：src_ip 记为客户端（下载方）
        ev = Event(ts=s["first"], log_type="pcap", action=A_HTTP_REQUEST,
                   src_ip=s["src"], dst_ip=s["dst"])
        ev.status = m["status"]
        ev.detail.update({
            "direction": "response", "proto": "TCP",
            "src_port": s["sport"], "dst_port": s["dport"],
            "content_type": m["ctype"], "reassembled": True,
        })
        ev.raw = "HTTP(重组) %s <- %s 响应 %s %s" % (s["src"], s["dst"], m["status"], m["ctype"])
        return ev

    def _http_body_event(self, s: dict, m: dict, direction: str,
                         uri: Optional[str] = None) -> Optional[Event]:
        raw = m["content"]
        if not raw:
            return None
        ctype = (m["ctype"] or "").split(";")[0].strip().lower()
        binary = any(ctype.startswith(p) for p in BINARY_CTYPE)
        text, looks_binary = http_to_text(raw, HTTP_BODY_LIMIT)
        if binary or looks_binary:
            text = ""                      # 图片/压缩包解码成文本只会制造噪声
        magic = magic_label(raw)

        is_req = direction == "request"
        ev = Event(ts=s["first"], log_type="pcap", action=A_HTTP_REQUEST,
                   src_ip=s["src"], dst_ip=s["dst"])
        # 请求行/响应行的字段已由对应事件覆盖，这里只承载 body，避免重复计数：
        # ev.uri 留空，靠 detail["http_body"] 参与内容匹配
        if is_req:
            ev.method = m["method"]
            ev.domain = m["host"] or None
        else:
            ev.status = m["status"]
        ev.detail.update({
            "direction": direction, "proto": "TCP",
            "src_port": s["sport"], "dst_port": s["dport"],
            "host": m["host"] or None,
            "http_body": text,
            "http_body_len": m["content_len"],
            "http_body_raw_len": m["body_len"],
            "http_body_encoding": m["encoding"],
            "http_body_truncated": m["truncated"],
            "http_body_binary": bool(binary or looks_binary),
            "http_body_magic": body_magic(raw),
            "http_body_magic_label": magic,
            "http_content_type": ctype or None,
            "http_body_only": is_req,
            "http_resp_body": not is_req,
            "uri": uri,
            "reassembled": True,
        })
        ev.raw = "HTTP %s %s %s 体 %d 字节%s: %s" % (
            "请求" if is_req else "响应",
            s["src"] if is_req else s["dst"], s["dst"] if is_req else s["src"],
            m["content_len"],
            "(%s)" % ",".join(m["encoding"]) if m["encoding"] else "",
            (text or (magic or "<二进制 %s>" % ctype))[:200].replace("\r\n", " "))
        return ev

    # ---- EOF：流摘要 ----
    def _flow_events(self, flows: dict) -> Generator[Event, None, None]:
        for (src, sport, dst, dport, proto), f in flows.items():
            dur = max(0.0, (f["last"] - f["ts"]))
            ev = Event(ts=f["ts"], log_type="pcap", action=A_NET_FLOW,
                       src_ip=src, dst_ip=dst)
            ev.detail.update({"src_port": sport, "dst_port": dport, "proto": proto,
                              "packets": f["pkts"], "bytes_out": f["out"],
                              "bytes_in": f["in"], "duration_sec": round(dur, 3),
                              "uri": f.get("uri")})
            ev.bytes_sent = f["out"]
            ev.raw = "FLOW %s %s:%d -> %s:%d 出%d字节/入%d字节 %d包 时长%.1fs" % (
                proto, src, sport, dst, dport, f["out"], f["in"], f["pkts"], dur)
            yield ev

register(PcapParser())

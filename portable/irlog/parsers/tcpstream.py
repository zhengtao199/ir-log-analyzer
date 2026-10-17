"""TCP 流重组（对应 Wireshark 的「追踪流 / Follow TCP Stream」）。

单包解析只能看到被切分的应用层数据片段：HTTP POST 的请求体常在后续报文、
FTP/Telnet 的用户名与密码常分属两个报文、反向 shell 的命令可能被拆成多段。
本模块把这些片段按序列号还原成完整的双向会话内容，再交给检测器分析。

设计约束（GB 级抓包 / 常量内存）：
- 只跟踪「真正带载荷」的 TCP 流，纯握手不占内存
- 每方向缓冲有字节上限，超出即截断并立刻吐出（不等 FIN）
- 流数量有上限，超出时淘汰最久未更新的流
- 支持乱序（gap 暂存）、重传/重叠（按已有进度裁剪）、32 位序列号回绕
- 不做 IP 分片重组：分片场景需先由抓包工具或 Zeek 预处理

产出的流对象是一个 dict，字段见 `TCPStreamReassembler._flush()`。
"""
from __future__ import annotations

from collections import OrderedDict, deque
from typing import Iterator, Optional

MASK32 = 0xFFFFFFFF

# 位掩码
FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10


class _Dir:
    """单方向的重组装状态。"""
    __slots__ = ("isn", "buf", "next_rel", "segs", "dups", "gaps",
                 "closed", "truncated", "bytes_total", "from_syn", "partial")

    def __init__(self) -> None:
        self.isn: Optional[int] = None      # 初始序列号（相对偏移基准）
        self.buf = bytearray()              # 已连续的数据
        self.next_rel: int = 0              # 下一个期望的相对偏移
        self.segs: dict = {}                # 乱序暂存：rel -> bytes
        self.dups: int = 0                  # 重传/重叠次数
        self.gaps: int = 0                  # 乱序次数
        self.closed: bool = False           # 收到 FIN/RST
        self.truncated: bool = False        # 达到字节上限被截断
        self.bytes_total: int = 0           # 该方向实际写入的字节数（去重后）
        self.from_syn: bool = False         # 基准是否来自握手（可正确重排乱序）
        self.partial: bool = False          # 基准不可信，内容按偏移尽力拼接


class TCPStreamReassembler:
    """双向 TCP 流重组器。"""

    def __init__(self, max_streams: int = 2000, max_bytes: int = 32768,
                 max_pending: int = 64, isn_cap: int = 20000) -> None:
        self.max_streams = max_streams
        self.max_bytes = max_bytes
        self.max_pending = max_pending
        self.isn_cap = isn_cap
        self.streams: "OrderedDict[tuple, dict]" = OrderedDict()   # LRU，淘汰 O(1)
        # SYN 序号缓存：握手指纹，有了它才能正确重排乱序段。
        # 单独存放是为了让「纯 SYN 不占用流槽位」——SYN Flood 不会撑爆流表。
        self.isn: dict = {}
        # 握手里「谁先发起」决定了哪一端是客户端。不能按 IP 字典序猜：
        # 外网攻击 IP（203.0.113.x）连内网服务器（10.0.0.x）时字典序会把方向判反，
        # 于是请求体被当成响应体、外传方向也跟着反。
        self.syn_side: dict = {}
        self.pending: deque = deque()      # 同一次 feed 里产生的额外完成流
        # 统计（供报告/自检）
        self.stats = {"streams": 0, "flushed": 0, "evicted": 0}

    # ---- 键：按 (ip,port) 字典序归一化，使正反方向归为同一条流 ----
    @staticmethod
    def _key(src: str, sport: int, dst: str, dport: int) -> tuple:
        a, b = (src, sport), (dst, dport)
        return (a, b) if a <= b else (b, a)

    @staticmethod
    def _new_stream(key: tuple, ts: float) -> dict:
        return {"key": key, "a": _Dir(), "b": _Dir(),
                "a_ep": key[0], "b_ep": key[1], "client": None,
                "first": ts, "last": ts, "pkts": 0, "reset": False}

    @staticmethod
    def _guess_client(a: tuple, b: tuple) -> tuple:
        """没有握手时的兜底：服务端口通常低且固定，客户端口是随机高位端口。"""
        (_aip, ap), (_bip, bp) = a, b
        if ap < 1024 <= bp:
            return b
        if bp < 1024 <= ap:
            return a
        return b if bp > ap else a

    # ---- 主入口 ----
    def feed(self, ts: float, src: str, sport: int, dst: str, dport: int,
             seq: int, payload: bytes, flags: int) -> Optional[dict]:
        """写入一个 TCP 报文（含纯握手的空载荷报文，用于记录 ISN / 关闭方向）。

        返回：本次完成/被淘汰/被截断的流对象（dict），否则 None。
        一次 feed 可能同时产生多个（如淘汰旧流后又截断新流），统一压入
        pending 由本方法与 drain() 逐个吐出，保证不丢。
        """
        self._feed(ts, src, sport, dst, dport, seq, payload, flags or 0)
        return self.pending.popleft() if self.pending else None

    def _feed(self, ts: float, src: str, sport: int, dst: str, dport: int,
              seq: int, payload: bytes, flags: int) -> None:
        key = self._key(src, sport, dst, dport)

        # 握手：只记指纹，不占流槽位（SYN Flood 不会撑爆流表）
        if flags & SYN and not (flags & ACK):
            self._remember_isn(src, sport, dst, dport, seq)

        st = self.streams.get(key)
        if st is None:
            if not payload:
                return
            if len(self.streams) >= self.max_streams:
                old = self._evict_oldest()
                if old is not None:
                    self.stats["evicted"] += 1
                    self.pending.append(old)
            st = self._new_stream(key, ts)
            st["client"] = self.syn_side.pop(key, None)
            self.streams[key] = st
            self.stats["streams"] += 1
        else:
            self.streams.move_to_end(key)          # LRU：最近活跃的排到末尾

        st["last"] = ts
        st["pkts"] += 1
        d = st["a"] if (src, sport) == st["a_ep"] else st["b"]

        if flags & (FIN | RST):
            d.closed = True
        if flags & RST:
            st["reset"] = True

        if not payload:
            if st["a"].closed and st["b"].closed:
                self._emit_flush(key)
            return

        n = len(payload)
        if d.isn is None:
            cached = self.isn.pop((src, sport, dst, dport), None)
            if cached is not None:
                # 握手可见：SYN 占用一个序号，数据从 rel=1 起，乱序可被正确重排
                d.isn = cached
                d.next_rel = 1
                d.from_syn = True
            else:
                # 抓包缺握手（如已过滤只剩数据）：以首个数据段为基准顺序拼接
                d.isn = seq
                d.buf += payload
                d.bytes_total += n
                d.next_rel = n
                self._drain(d)
                self._after_data(key, st, d)
                return

        rel = (seq - d.isn) & MASK32             # 处理 32 位序列号回绕
        if rel < d.next_rel:
            # 重传或与已有数据重叠：只补齐尾部新字节
            d.dups += 1
            end = rel + n
            if end > d.next_rel:
                d.buf += payload[d.next_rel - rel:]
                d.bytes_total += end - d.next_rel
                d.next_rel = end
                self._drain(d)
        elif rel == d.next_rel:
            d.buf += payload
            d.bytes_total += n
            d.next_rel = rel + n
            self._drain(d)
        else:
            # 乱序：暂存，等缺口补齐后再拼接
            d.gaps += 1
            if len(d.segs) < self.max_pending and rel not in d.segs:
                d.segs[rel] = payload
        self._after_data(key, st, d)

    def _emit_flush(self, key: tuple) -> None:
        s = self._flush(key)
        if s is not None:
            self.pending.append(s)

    def _after_data(self, key: tuple, st: dict, d: _Dir) -> None:
        if len(d.buf) >= self.max_bytes:
            d.truncated = True
            self._emit_flush(key)
            return
        if st["a"].closed and st["b"].closed:
            self._emit_flush(key)

    def drain(self) -> Iterator[dict]:
        """取走 feed 未能一次返回的完成流（淘汰与新流同时完成的场景）。"""
        while self.pending:
            yield self.pending.popleft()

    def _remember_isn(self, src: str, sport: int, dst: str, dport: int,
                      seq: int) -> None:
        if len(self.isn) >= self.isn_cap:        # 丢最早的一批，避免无限增长
            for k in list(self.isn)[: self.isn_cap // 4]:
                del self.isn[k]
        self.isn[(src, sport, dst, dport)] = seq
        if len(self.syn_side) >= self.isn_cap:
            for k in list(self.syn_side)[: self.isn_cap // 4]:
                del self.syn_side[k]
        self.syn_side[self._key(src, sport, dst, dport)] = (src, sport)

    def _drain(self, d: _Dir) -> None:
        """缺口补齐后，把暂存段按序拼接。"""
        segs = d.segs
        while d.next_rel in segs:
            seg = segs.pop(d.next_rel)
            d.buf += seg
            d.bytes_total += len(seg)
            d.next_rel += len(seg)

    def _evict_oldest(self) -> Optional[dict]:
        """淘汰最久未更新的流（OrderedDict 头部，O(1)）。"""
        if not self.streams:
            return None
        key = next(iter(self.streams))
        return self._flush(key)

    @staticmethod
    def _materialize(d: _Dir) -> None:
        """基准不可信时的兜底：按偏移顺序尽力拼接暂存段。

        仅在「一个连续字节都没拼出来」时触发（例如抓包里 SYN 与实际数据
        不属于同一次连接），拼接结果标记 partial，提示内容可能不完整。
        """
        if d.buf or not d.segs:
            return
        d.buf = bytearray(b"".join(d.segs[k] for k in sorted(d.segs)))
        d.bytes_total += len(d.buf)
        d.partial = True

    def _flush(self, key: tuple) -> Optional[dict]:
        st = self.streams.pop(key, None)
        if st is None:
            return None
        self.stats["flushed"] += 1
        a, b = st["a"], st["b"]
        self._materialize(a)
        self._materialize(b)
        client = st.get("client")
        a_ep, b_ep = st["a_ep"], st["b_ep"]
        if client not in (a_ep, b_ep):
            client = self._guess_client(a_ep, b_ep)
        (c_ip, c_port), (s_ip, s_port) = (client, b_ep if client == a_ep else a_ep)
        # 方向 a/b 与客户端/服务端不是一回事（键按字典序归一化，客户端可能排在后面）
        c_dir, s_dir = (a, b) if client == a_ep else (b, a)
        return {
            "key": key,
            "src": c_ip, "sport": c_port,          # 发起方（客户端）
            "dst": s_ip, "dport": s_port,
            "client_data": bytes(c_dir.buf), "server_data": bytes(s_dir.buf),
            "client_len": c_dir.bytes_total, "server_len": s_dir.bytes_total,
            "packets": st["pkts"], "first": st["first"], "last": st["last"],
            "retransmits": a.dups + b.dups,
            "out_of_order": a.gaps + b.gaps,
            "truncated": a.truncated or b.truncated,
            "reset": st["reset"],
            "complete": a.closed and b.closed,
            "partial": a.partial or b.partial,
        }

    def finish(self) -> Iterator[dict]:
        """抓包结束：吐出所有未完成的流（乱序/无 FIN 的场景靠这里收尾）。"""
        for key in list(self.streams.keys()):
            s = self._flush(key)
            if s is not None:
                yield s

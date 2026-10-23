"""TCP 重组流内容检测（"追踪流"里到底发生了什么）。

消费 A_NET_STREAM（pcap 解析器经 TCP 重组还原的双向会话内容）。

单包解析看不到这些，只有重组后才能判定：
- 反向 shell：命令被拆在多个报文里，或命令与回显分属两个方向
- POST 请求体里的注入载荷（由 A_HTTP_REQUEST 的 http_body 交给 web-attack 处理，
  本规则聚焦流层面的会话语义）
- FTP/Telnet 的「用户名」与「密码」分属两个报文 → 这里配成完整凭据对
- 敏感文件外传：/etc/passwd、私钥、shadow 等内容只有重组后才连成完整文本
- 会话内传输的编码载荷（base64/hex），沿用 command-obfuscation 的解码口径

误报控制：
- 二进制流（TLS 等）跳过文本规则，只保留原始字节供人工复核
- 反向 shell 需要「客户端命令特征」；仅出现 whoami 等弱特征不单独告警
- 敏感内容只认结构化特征（root:x:0:0 / BEGIN PRIVATE KEY / uid=0(root)）
"""
from __future__ import annotations

import re

from ..models import A_NET_STREAM, Event
from .base import Detector
from .command_obfuscation import (
    PAYLOAD_KEYWORDS, B64_TOKEN_RE, HEX_TOKEN_RE, PIPE_EXEC_RE,
    decode_b64_token, decode_hex_token,
)

# ---- L1 反向 shell / 交互式命令执行（客户端方向） ----
REVERSE_SHELL_PATTERNS = (
    (r"/dev/tcp/[0-9.]+/\d+", "bash /dev/tcp 反向连接"),
    (r"\b(?:ba|z|da)?sh\s+-i\b", "交互式 shell（-i）"),
    (r"\bmkfifo\s+/tmp/\S+", "mkfifo 命名管道反弹"),
    (r"0<&\s*\d+\s*;?\s*exec\s+\d+<>/dev/tcp/", "bash 文件描述符反弹"),
    (r"\bnc\s+\S+\s+\d+\s+-e\b", "netcat -e 绑定 shell"),
    (r"\bncat\s+\S+\s+\d+\s+-e\b", "ncat -e 绑定 shell"),
    (r"\bpython[0-9.]*\s+-c\s+['\"].*?(?:socket|pty|subprocess)", "Python 反弹 shell"),
    (r"\bperl\s+-e\s+['\"].*?socket", "Perl 反弹 shell"),
    (r"\bphp\s+-r\s+['\"].*?fsockopen", "PHP 反弹 shell"),
    (r"\bruby\s+-rsocket\s+-e", "Ruby 反弹 shell"),
    (r"powershell[^\n]{0,80}-(?:nop|noprofile)[^\n]{0,80}-(?:exec|e)\s+bypass",
     "PowerShell 隐蔽执行"),
    (r"IEX\s*\(\s*New-Object\s+Net\.WebClient", "PowerShell 下载执行"),
)
REVERSE_SHELL_RE = [(re.compile(p, re.I), d) for p, d in REVERSE_SHELL_PATTERNS]

# 交互确认：服务端回显里出现这些，说明命令真的被执行了
SHELL_ECHO_RE = re.compile(
    r"(?:uid=\d+\((?:root|[\w-]+)\)|root:x:0:0:|/bin/(?:ba|z|da)?sh|"
    r"Linux\s+\S+\s+\d+\.\d+|cannot\s+access|No\s+such\s+file\s+or\s+directory|"
    r"command\s+not\s+found)", re.I)

# 弱特征：单独出现不足以定性，需与服务端回显组合
WEAK_CMD_RE = re.compile(
    r"\b(?:whoami|hostname|uname\s+-a|ifconfig|ip\s+addr|cat\s+/etc/passwd|"
    r"id\s*;|netstat\s+-an|ps\s+aux)\b", re.I)

# ---- L2 敏感文件内容外传（服务端方向 = 下载方拿到的数据） ----
SENSITIVE_CONTENT_PATTERNS = (
    (r"root:x:0:0:", "/etc/passwd 内容"),
    (r"[\w.-]+:\$6\$[A-Za-z0-9./]{20,}", "/etc/shadow 哈希"),
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----", "私钥文件"),
    (r"\bBEGIN OPENSSH PRIVATE KEY\b", "SSH 私钥"),
    (r"(?:aws_secret_access_key|AKIA[0-9A-Z]{16})", "云凭据"),
    (r"jdbc:[a-z]+://[^\s]+:[^\s@]+@", "数据库连接串（含口令）"),
)
SENSITIVE_CONTENT_RE = [(re.compile(p, re.I), d) for p, d in SENSITIVE_CONTENT_PATTERNS]

# ---- L3 完整凭据对（跨报文，单包检测只能拿到一半） ----
FTP_USER_RE = re.compile(r"\bUSER\s+(\S+)")
FTP_PASS_RE = re.compile(r"\bPASS\s+(\S+)")
TELNET_LOGIN_RE = re.compile(r"(?:login|Login|username)[:：]\s*(\S+)")
TELNET_PASS_RE = re.compile(r"(?:assword)[:：]\s*(\S+)")
SMTP_AUTH_RE = re.compile(r"\bAUTH\s+(?:LOGIN|PLAIN)\s+([A-Za-z0-9+/=]{8,})")

# ---- L4 Webshell 交互（HTTP 参数里下命令，回显里有执行结果） ----
WEBSHELL_PARAM_RE = re.compile(r"(?:cmd|exec|command|c|act|pass|do)\s*=", re.I)

# 凭据脱敏：报告里不落明文口令
def _mask(s: str) -> str:
    if len(s) <= 2:
        return "*" * len(s)
    return s[:1] + "*" * (len(s) - 2) + s[-1:]


class StreamContentDetector(Detector):
    rule_id = "stream-content"
    ACTIONS = {A_NET_STREAM}
    title = "TCP 流内容异常"
    description = ("重组 TCP 会话后发现反向 shell、敏感文件外传、跨报文凭据对"
                   "或会话内编码载荷")
    mitre = ("T1059 Command and Scripting Interpreter / T1071 Application Layer Protocol "
             "/ T1020 Automated Exfiltration / T1552 Unsecured Credentials")
    recommendation = ("1) 按流的两端定位受害主机与 C2 地址，立即隔离并抓内存；"
                      "2) 凭据对涉及的账号强制改密并排查复用；"
                      "3) 还原完整会话内容确认执行了哪些命令；"
                      "4) 在边界封禁 C2 地址与端口")

    def __init__(self, config):
        super().__init__(config)
        self.hits: dict = {}          # (key, kind) -> 聚合

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_NET_STREAM:
            return
        ctext = ev.detail.get("client_text") or ""
        stext = ev.detail.get("server_text") or ""
        # 二进制流（TLS/压缩）解码后是乱码，文本规则只制造噪声
        cbin = bool(ev.detail.get("client_binary"))
        sbin = bool(ev.detail.get("server_binary"))
        client = "" if cbin else ctext
        server = "" if sbin else stext

        src = ev.src_ip or "-"
        dst = ev.dst_ip or "-"
        dport = ev.detail.get("dst_port")     # 键左侧为客户端，右侧端口即服务端口

        reasons: list[str] = []
        severity = 3

        # ---- L1 反向 shell ----
        if client:
            for rx, label in REVERSE_SHELL_RE:
                m = rx.search(client)
                if m:
                    echo = SHELL_ECHO_RE.search(server) if server else None
                    if echo:
                        reasons.append("反向 shell 已确认执行：%s（服务端回显 %s）"
                                       % (label, echo.group(0)[:60]))
                        severity = 1
                    else:
                        reasons.append("疑似反向 shell：%s（片段：%s）"
                                       % (label, m.group(0)[:60]))
                        severity = min(severity, 2)
                    break
            else:
                # 弱特征 + 服务端命令回显 = 交互式命令执行
                m = WEAK_CMD_RE.search(client)
                echo = SHELL_ECHO_RE.search(server) if server else None
                if m and echo:
                    reasons.append("交互式命令执行：客户端 %s，服务端回显 %s"
                                   % (m.group(0)[:40], echo.group(0)[:60]))
                    severity = min(severity, 2)

        # ---- L2 敏感文件内容 ----
        for rx, label in SENSITIVE_CONTENT_RE:
            hit = rx.search(server) or rx.search(client)
            if hit:
                reasons.append("流内传输敏感内容：%s" % label)
                severity = 1
                break

        # ---- L3 完整凭据对 ----
        pair = self._cred_pair(client, server)
        if pair:
            reasons.append("明文协议完整凭据对：%s 用户 %s / 口令 %s"
                           % (pair[0], pair[1], _mask(pair[2])))
            severity = min(severity, 2)

        # ---- L4 Webshell 交互 ----
        if client and WEBSHELL_PARAM_RE.search(client[:400]) and \
                SHELL_ECHO_RE.search(server or ""):
            reasons.append("Webshell 交互式执行：请求参数含命令字段且响应回显执行结果")
            severity = min(severity, 1)

        # ---- L5 会话内编码载荷 ----
        enc = self._encoded_payload(client)
        if enc:
            reasons.append(enc)
            severity = min(severity, 1 if "管道执行" in enc else 2)

        if not reasons:
            return

        key = (src, dst, dport, reasons[0][:40])
        st = self.hits.setdefault(key, {
            "count": 0, "reasons": set(), "severity": 3,
            "first": None, "last": None, "evidence": [],
            "src": src, "dst": dst, "dport": dport,
        })
        st["count"] += 1
        st["reasons"].update(reasons)
        st["severity"] = min(st["severity"], severity)
        st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
        st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        self._sample(self.hits, key, ev)

    # ---- 凭据对：用户名与口令分属不同报文时，只有重组后才能配对 ----
    @staticmethod
    def _cred_pair(client: str, server: str) -> Optional[tuple]:
        text = client + "\n" + (server or "")
        for proto, ur, pr in (("FTP", FTP_USER_RE, FTP_PASS_RE),
                              ("Telnet", TELNET_LOGIN_RE, TELNET_PASS_RE)):
            um, pm = ur.search(client), pr.search(client)
            if um and pm:
                return (proto, um.group(1), pm.group(1))
        m = SMTP_AUTH_RE.search(text)
        if m:
            return ("SMTP", "-", m.group(1)[:64])
        return None

    # ---- 编码载荷：沿用 command-obfuscation 的解码口径 ----
    @staticmethod
    def _encoded_payload(client: str) -> str:
        if not client or len(client) < 24:
            return ""
        for m in B64_TOKEN_RE.finditer(client):
            dec, _ = decode_b64_token(m.group(0))
            if dec and PAYLOAD_KEYWORDS.search(dec):
                tail = "并管道执行" if PIPE_EXEC_RE.search(client) else ""
                return "流内 Base64 载荷已解码%s：%s" % (tail, dec[:120])
        for m in HEX_TOKEN_RE.finditer(client):
            dec = decode_hex_token(m.group(0))
            if dec and PAYLOAD_KEYWORDS.search(dec):
                tail = "并管道执行" if PIPE_EXEC_RE.search(client) else ""
                return "流内 Hex 载荷已解码%s：%s" % (tail, dec[:120])
        return ""

    def finalize(self) -> list:
        for key, st in sorted(self.hits.items(), key=lambda kv: kv[1]["severity"]):
            reasons = sorted(st["reasons"])
            self._alert(
                st["severity"], st["count"],
                {"src_ip": st["src"], "dst_ip": st["dst"], "dst_port": st["dport"],
                 "reasons": reasons},
                st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                "TCP 流内容异常：%s -> %s:%s 检出 %s"
                % (st["src"], st["dst"], st["dport"],
                   "；".join(r[:70] for r in reasons[:2])))
        return self.alerts

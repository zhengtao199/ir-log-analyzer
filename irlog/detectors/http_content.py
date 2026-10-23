"""HTTP 请求体 / 响应体内容检测（流量包侧）。

Web 访问日志与 pcap 单包解析都只有「请求行 + 状态码」，真正能定性的内容在
body 里，而这些只有做 TCP 重组 + chunked/gzip 解码之后才拿得到：

请求体：
- Webshell 交互：cmd=/exec= 参数里带系统命令
- 上传木马：multipart 里 filename="*.php/.jsp/.aspx"
- 一句话木马本体（被写入/上传的内容）

响应体：
- 命令执行回显（uid=0(root)、Windows IP 配置、卷序列号）→ 确认被打穿
- 敏感文件内容（/etc/passwd、私钥、云密钥）→ 确认数据已被拖走
- 服务端返回的木马源码 / 恶意脚本
- 下载的可执行文件（PE/ELF/脚本）→ 后续落地执行的线索

误报控制（与 stream-content 同一口径）：
- 只认结构化特征，不做"看着可疑"的模糊判定
- 图片/压缩包等二进制 body 不参与文本匹配，只用魔数判断"下载了什么"
- 编码载荷必须解码后命中攻击关键词才算
"""
from __future__ import annotations

import re

from ..models import A_HTTP_REQUEST, Event
from .base import Detector
from .command_obfuscation import (
    PAYLOAD_KEYWORDS, B64_TOKEN_RE, HEX_TOKEN_RE, PIPE_EXEC_RE,
    decode_b64_token, decode_hex_token,
)

# ---- 请求体：Webshell 交互参数 ----
CMD_PARAM_RE = re.compile(
    r"(?:^|[?&;\s])(cmd|exec|command|code|payload|c|act|action|do|func|shell)\s*=", re.I)
CMD_TOKEN_RE = re.compile(
    r"\b(whoami|ipconfig|ifconfig|systeminfo|net\s+user|net\s+localgroup|tasklist|"
    r"netstat\s+-an|uname\s+-a|ps\s+aux|cat\s+/etc/(passwd|shadow)|type\s+c:\\\\|"
    r"dir\s+c:\\\\|/bin/(ba)?sh\s+-c|certutil|schtasks)\b", re.I)

# ---- 上传的可疑脚本文件名 ----
UPLOAD_FILE_RE = re.compile(
    r'filename\s*=\s*"?[^"\'\r\n;]{0,120}?\.(php|phtml|php[0-9]|phar|jsp|jspx|'
    r'asp|aspx|ashx|asmx|asa|cer|cdx|war|jspa)\b', re.I)

# ---- 一句话木马本体 / 服务端脚本后门 ----
WEBSHELL_SRC_RE = re.compile(
    r"eval\s*\(\s*\$(?:_POST|_GET|_REQUEST|_SERVER)|@eval\s*\(|assert\s*\(\s*\$_|"
    r"base64_decode\s*\(\s*\$_|system\s*\(\s*\$_|passthru\s*\(\s*\$_|"
    r"shell_exec\s*\(\s*\$_|preg_replace\s*\(\s*['\"]/.*?/e|"
    r"Runtime\.getRuntime\(\)\s*\.\s*exec|new\s+ProcessBuilder|"
    r"<\s*%\s*eval\s+request|<%\s*execute\s+request", re.I)

# ---- 响应体：命令执行的回显（确认命令真的跑了） ----
SHELL_ECHO_RE = re.compile(
    r"uid=\d+\((?:root|[\w-]+)\)\s+gid=|root:x:0:0:|"
    r"Windows\s+IP\s+[Cc]onfiguration|卷序列号|"
    r"[A-Za-z]:\\(?:Windows|Users|inetpub)\\|"
    r"command\s+not\s+found|No\s+such\s+file\s+or\s+directory|"
    r"sh:\s+\d+:\s+|cannot\s+access\s+'", re.I)

# ---- 响应体：敏感文件内容（确认数据被拖走） ----
SENSITIVE_CONTENT_PATTERNS = (
    (r"root:x:0:0:", "/etc/passwd 内容"),
    (r"[\w.-]+:\$(?:1|6|2[aby])\$[A-Za-z0-9./]{16,}", "/etc/shadow 哈希"),
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----", "私钥文件"),
    (r"\bAKIA[0-9A-Z]{16}\b", "云密钥（AWS Access Key）"),
    (r"aws_secret_access_key\s*[=:]", "云密钥（AWS Secret）"),
    (r"jdbc:[a-z]+://[^\s]+:[^\s@]+@", "数据库连接串（含口令）"),
    (r"BEGIN\s+PGP\s+MESSAGE|ssh-rsa\s+AAAA[0-9A-Za-z+/=]{40,}", "SSH 公钥/密钥材料"),
)
SENSITIVE_CONTENT_RE = [(re.compile(p, re.I), d) for p, d in SENSITIVE_CONTENT_PATTERNS]

# ---- 响应体：恶意脚本内容（下载即执行类） ----
SCRIPT_CONTENT_RE = re.compile(
    r"powershell[^\n]{0,80}-(?:enc|encodedcommand)|IEX\s*\(|Invoke-Expression|"
    r"certutil[^\n]{0,40}-decode|bitsadmin[^\n]{0,40}/transfer|"
    r"curl\s+[^\n|]{0,80}\|\s*(?:ba|z|da)?sh|wget\s+[^\n|]{0,80}\|\s*(?:ba|z|da)?sh|"
    r"/dev/tcp/[0-9.]+/\d+|mshta\s+https?://", re.I)


class HttpContentDetector(Detector):
    rule_id = "http-content"
    ACTIONS = {A_HTTP_REQUEST}
    title = "HTTP 内容异常（请求体/响应体）"
    description = ("重组并解码 HTTP 内容后发现命令执行回显、敏感文件外传、"
                   "Webshell 交互或恶意载荷下载")
    mitre = ("T1505.003 Web Shell / T1190 Exploit Public-Facing Application / "
             "T1020 Automated Exfiltration / T1105 Ingress Tool Transfer")
    recommendation = ("1) 定位对应 URL 与服务端文件，确认是否为 Webshell 并提取样本；"
                      "2) 若出现命令回显，按失陷处理：隔离主机、抓内存、排查持久化；"
                      "3) 若外传敏感文件，评估泄露范围并强制轮换密钥/口令；"
                      "4) 封堵来源 IP 并检索同期同 URL 的其他来源")

    def __init__(self, config):
        super().__init__(config)
        self.hits: dict = {}

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST:
            return
        is_resp = bool(ev.detail.get("http_resp_body"))
        body = ev.detail.get("http_body") or ""
        magic = ev.detail.get("http_body_magic_label")
        ctype = ev.detail.get("http_content_type") or ""
        uri = ev.uri or ev.detail.get("uri") or ""
        if not body and not magic:
            return

        src = ev.src_ip or "-"          # 请求体：客户端；响应体：下载方
        dst = ev.dst_ip or "-"
        port = ev.detail.get("dst_port")
        reasons: list[str] = []
        severity = 3

        if is_resp:
            # 1) 命令执行回显
            m = SHELL_ECHO_RE.search(body)
            if m:
                reasons.append("HTTP 响应体含命令执行回显：%s" % m.group(0)[:60])
                severity = 1
            # 2) 敏感文件内容
            for rx, label in SENSITIVE_CONTENT_RE:
                if rx.search(body):
                    reasons.append("HTTP 响应体含敏感内容：%s" % label)
                    severity = 1
                    break
            # 3) 木马源码
            m = WEBSHELL_SRC_RE.search(body)
            if m:
                reasons.append("HTTP 响应体含一句话木马特征：%s" % m.group(0)[:60])
                severity = 1
            # 4) 恶意脚本内容（下载即执行）
            if not reasons or severity > 2:
                m = SCRIPT_CONTENT_RE.search(body)
                if m:
                    reasons.append("HTTP 响应体含下载执行类脚本：%s" % m.group(0)[:60])
                    severity = min(severity, 2)
            # 5) 可执行文件/脚本下载（弱线索）
            if magic and severity > 2:
                reasons.append("HTTP 下载可执行文件/脚本：%s（%s）" % (magic, ctype or "-"))
                severity = 3
        else:
            # 1) Webshell 交互：命令参数 + 系统命令
            if CMD_PARAM_RE.search(body) and CMD_TOKEN_RE.search(body):
                m = CMD_TOKEN_RE.search(body)
                reasons.append("Webshell 交互：请求体含命令参数并执行 %s" % m.group(0)[:40])
                severity = 1
            # 2) 上传木马文件
            m = UPLOAD_FILE_RE.search(body)
            if m:
                reasons.append("上传可疑脚本文件：%s" % m.group(0)[:80])
                severity = 1
            # 3) 木马本体（写入/上传的内容）
            m = WEBSHELL_SRC_RE.search(body)
            if m:
                reasons.append("请求体含一句话木马代码：%s" % m.group(0)[:60])
                severity = 1
            # 4) 编码载荷（沿用 command-obfuscation 的解码口径）
            enc = self._encoded_payload(body)
            if enc:
                reasons.append(enc)
                severity = min(severity, 1 if "管道执行" in enc else 2)

        if not reasons:
            return

        key = (src, dst, port, "响应体" if is_resp else "请求体")
        st = self.hits.setdefault(key, {
            "count": 0, "reasons": set(), "severity": 3,
            "first": None, "last": None, "evidence": [],
            "src": src, "dst": dst, "port": port, "uri": uri,
            "direction": "响应体" if is_resp else "请求体",
        })
        st["count"] += 1
        st["reasons"].update(reasons)
        st["severity"] = min(st["severity"], severity)
        if not st["uri"] and uri:
            st["uri"] = uri
        st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
        st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        self._sample(self.hits, key, ev)

    # ---- 编码载荷：解码后必须命中攻击关键词才算，避免把 base64 图片当告警 ----
    @staticmethod
    def _encoded_payload(text: str) -> str:
        if not text or len(text) < 24:
            return ""
        for m in B64_TOKEN_RE.finditer(text):
            dec, _ = decode_b64_token(m.group(0))
            if dec and PAYLOAD_KEYWORDS.search(dec):
                tail = "并管道执行" if PIPE_EXEC_RE.search(text) else ""
                return "HTTP 内容含 Base64 载荷已解码%s：%s" % (tail, dec[:120])
        for m in HEX_TOKEN_RE.finditer(text):
            dec = decode_hex_token(m.group(0))
            if dec and PAYLOAD_KEYWORDS.search(dec):
                tail = "并管道执行" if PIPE_EXEC_RE.search(text) else ""
                return "HTTP 内容含 Hex 载荷已解码%s：%s" % (tail, dec[:120])
        return ""

    def finalize(self) -> list:
        for key, st in sorted(self.hits.items(), key=lambda kv: kv[1]["severity"]):
            reasons = sorted(st["reasons"])
            self._alert(
                st["severity"], st["count"],
                {"src_ip": st["src"], "dst_ip": st["dst"], "dst_port": st["port"],
                 "uri": st["uri"], "direction": st["direction"], "reasons": reasons},
                st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = (
                "HTTP %s异常：%s <-> %s:%s 检出 %s"
                % (st["direction"], st["src"], st["dst"], st["port"],
                   "；".join(r[:70] for r in reasons[:2])))
        return self.alerts

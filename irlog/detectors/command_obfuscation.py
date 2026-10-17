"""命令混淆 / 编码载荷识别：攻击者得手后最常用的隐蔽执行手段。

背景：特征黑名单（如 vssadmin、whoami）对**编码/混淆后的命令**完全失效——
PowerShell ``-enc <Base64(UTF-16LE)>``、cmd ``^`` 插入、空引号插入、
``certutil -decode`` 等手法在原始命令行里看不到任何明文恶意词。
本规则不依赖黑名单，直接对命令行做结构识别与解码：

- L1 PowerShell 编码参数：``-enc / -encodedcommand / -e`` 后接 Base64，
  自动尝试 UTF-16LE 与 Latin-1 两种解码，取可打印比例高者
- L2 隐式 Base64 载荷：命令行中长度、字符集、Shannon 熵三重过滤的长串
  （熵阈值避开 GUID/十六进制指纹等良性长参数）
- L3 命令行混淆：cmd ``^`` 插入（who^oami）、空引号插入（ev""entvwr）、
  环境变量片段截取（%COMSPEC:~0,5%）、$env: 拼接
- L4 LOLBAS / 解码下载工具：certutil -urlcache/-decode、bitsadmin、
  FromBase64String、mshta、regsvr32 /i:、rundll32 javascript:
- L5 Hex 编码载荷：40+ 位连续十六进制串，bytes.fromhex 解码后可打印且含
  命令/URL 关键词才报（避开日志中常见的 SHA 指纹/MAC——随机字节不可打印，
  且要求关键词双保险）；与 `| sh`/`| bash` 管道组合为紧急
- L6 下载-落地-执行链：同一条命令行内出现「下载工具 + 写入临时/可写目录 +
  赋权或执行」三步（T1105）；`curl|bash` 类下载即执行为紧急
- L7 解码器管道：xxd -r / base64 -d / openssl enc -d 等在命令行内还原载荷（T1140）

适用事件：Windows 进程创建（4688/Sysmon 1）、Linux 命令执行
（sshd execute / sudo COMMAND / auditd EXECVE，A_COMMAND_EXEC / A_SUDO_COMMAND）。

严重度：
- 解码成功且载荷含执行/网络关键词（iex/downloadstring/http 等）→ 紧急
- 编码载荷 / 混淆 / LOLBAS → 高危
- 仅高熵长串（无关键词）→ 中危
"""
from __future__ import annotations

import base64
import binascii
import math
import re

from ..models import A_PROCESS_CREATE, A_COMMAND_EXEC, A_SUDO_COMMAND, Event
from .base import Detector

# ---- L1: PowerShell 编码参数 ----
# 完整参数名（-enc/-encodedcommand）门槛低：该参数本身就是强特征
ENC_PARAM_RE = re.compile(
    r"(?:-{1,2})(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{12,})", re.I)
# 单字母 -e 门槛高：-e 是常见短参数，需长 Base64 才认定
ENC_SHORT_RE = re.compile(r"(?:-{1,2})e\s+([A-Za-z0-9+/=]{16,})", re.I)
# 解码后载荷中的高危关键词（命中即紧急）
PAYLOAD_KEYWORDS = re.compile(
    r"(iex|invoke-expression|invoke-command|downloadstring|downloadfile|downloaddata|"
    r"net\.webclient|webrequest|start-process|frombase64string|to-base64string|"
    r"http://|https://|ftp://|bypass|-w\s*hidden|-nop|noprofile|new-object|"
    r"mimikatz|invoke-shellcode|invoke-mimikatz|sekurlsa|"
    r"whoami|/groups|net\s+user|net\s+localgroup|systeminfo|vssadmin|"
    r"reg(add|save)|schtasks|sc\s+create|wmic\s+process\s+call)",
    re.I)

# ---- L2: 隐式 Base64 ----
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
# ---- L3: 混淆特征 ----
CARET_RE = re.compile(r"[A-Za-z0-9]\^[A-Za-z0-9]")           # who^oami
EMPTY_QUOTE_RE = re.compile(r'[A-Za-z]""[A-Za-z]')      # ev""entvwr（单引号包双引号，避免隐式拼接）
ENV_SLICE_RE = re.compile(                                   # %COMSPEC:~0,5%
    r"%[A-Za-z_]+:~?\d*(?:,\d+)?%|\$env:[A-Za-z_]+\s*\+|\$env:comspec", re.I)
# ---- L4: LOLBAS / 解码下载 ----
LOLBAS_RE = re.compile(
    r"(certutil(?:\.exe)?\s+.*(?:-urlcache|-decode|-encode)|"
    r"bitsadmin(?:\.exe)?\s+/transfer|"
    r"frombase64string|"
    r"mshta(?:\.exe)?\s+(?:javascript|vbscript|http)|"
    r"regsvr32\s+/[si]\s*[^\s]*(?:http|javascript|scrobj)|"
    r"rundll32(?:\.exe)?\s+javascript:|"
    r"installutil(?:\.exe)?\s+/logfile=|"
    r"msbuild(?:\.exe)?\s+.*\.(?:xml|csproj)\b|"
    r"wmic\s+process\s+call\s+create)",
    re.I)
# ---- L5: Hex 编码载荷 ----
# 40+ 位连续 hex（前后不接 hex 字符，避免从更长串中误切）。
# 不要求偶数长度：真实日志中载荷常被截断或编码实现不保证偶数。
HEX_TOKEN_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])")
# 解码后必须含命令/URL 关键词（避开日志中常见的 SHA 指纹/MAC 等良性 hex）。
# `://` 与域名模式用于载荷中段被插入/损坏、仅前缀可读的场景
# （如 ...://evil.domain/ 干净、后半段错位成乱码的真实攻击日志）。
HEX_PAYLOAD_KEYWORDS = re.compile(
    r"(https?://|ftp://|://|[a-z0-9\-]{3,}\.[a-z]{2,6}/|"
    r"/tmp/|/bin/|/usr/|/dev/shm|/etc/|/var/|"
    r"wget|curl|chmod|chown|chattr|crontab|systemctl|service\s|"
    r"&&|\|\||\|\s*(?:ba|z|da)?sh\b|bash|python[23]?|perl|ruby|php|nc\s|"
    r"base64|shadow|passwd|authorized_keys|\.sh\b|\.elf\b|iptables|useradd)",
    re.I)
# 同行管道执行：| sh / | bash（hex 载荷的经典落地方式）
PIPE_EXEC_RE = re.compile(r"\|\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.I)
# ---- L6: 下载-落地-执行链（T1105 Ingress Tool Transfer）----
# 攻击者得手后最常见的三步：远程下载 → 写入可写临时目录 → 赋权并执行。
# 单看任一步都是正常运维，同一条命令行里串起来即为强特征。
DL_TOOL_RE = re.compile(r"\b(wget|curl|busybox\s+wget|fetch|aria2c|lwp-download)\b", re.I)
DL_OUTFILE_RE = re.compile(
    r"(?:-O|--output-document|-o)\s+(\S+)|>\s*(\S+)|-o\s+(\S+)", re.I)
WRITABLE_DIR_RE = re.compile(r"^/?(?:tmp|var/tmp|dev/shm|run|home/[^/]+|\.)/", re.I)
CHMOD_EXEC_RE = re.compile(r"\b(chmod\s+(?:\+?[0-7]*[1-7][0-7]{2}|[ugoa]*\+x)|\+x\b)", re.I)
EXEC_AFTER_RE = re.compile(r"(&&|\|\||;)\s*(\./|sh\s|bash\s|/bin/(?:ba)?sh\s|source\s)", re.I)
# 下载即执行：curl http://x | bash —— 无落地文件，直接管道喂给解释器（更隐蔽）
DL_PIPE_EXEC_RE = re.compile(
    r"\b(wget|curl)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b", re.I)
# ---- L7: 编码/解码器管道落地（T1140）----
DECODER_PIPE_RE = re.compile(
    r"\b(xxd\s+-[pr]|base64\s+-(?:d|di)|openssl\s+enc\s+-d|"
    r"perl\s+-e\s+.*pack|python[23]?\s+-c\s+.*b64decode|tr\s+-d\s)", re.I)


def _try_decode_hex(token: str) -> str:
    """hex 解码，容忍奇数长度（真实日志常见）：补 '0' 与截尾各试一次。"""
    candidates = [token] if len(token) % 2 == 0 else [token + "0", token[:-1]]
    fallback = ""
    for cand in candidates:
        try:
            dec = bytes.fromhex(cand).decode("latin-1", "replace")
        except ValueError:
            continue
        if _printable_ratio(dec) >= 0.85:
            return dec
        if not fallback:
            fallback = dec
    return fallback


def _shannon(s: str) -> float:
    """字符分布的 Shannon 熵（bits/char）。"""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return ok / len(s)


def _ascii_ratio(s: str) -> float:
    """ASCII 可打印字符（0x20-0x7E）占比。"""
    if not s:
        return 0.0
    ok = sum(1 for ch in s if 0x20 <= ord(ch) <= 0x7E or ch in "\r\n\t")
    return ok / len(s)


def _try_decode(token: str) -> tuple[str, str]:
    """尝试 Base64 解码。返回 (解码文本, 编码方式)；失败返回 ("", "")。

    PowerShell -enc 载荷几乎都是 UTF-16LE 编码的 ASCII 脚本，因此 UTF-16LE
    分支额外要求解码结果为 ASCII 可打印——否则任意字节按 UTF-16LE 解出的
    CJK 乱码也会“可打印”，把 latin-1 可解的串抢先误判。
    """
    raw = token.rstrip("=")
    pad = token + "=" * (-len(raw) % 4)
    for enc, label in (("utf-16-le", "utf-16le"), ("latin-1", "latin-1")):
        try:
            dec = base64.b64decode(pad, validate=False).decode(enc, "replace")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(dec) >= 4 and _printable_ratio(dec) >= 0.85:
            if enc == "utf-16-le" and _ascii_ratio(dec) < 0.9:
                continue
            return dec, label
    return "", ""


# 供其他检测器复用的公开别名（流内容检测沿用同一套解码口径，避免两处实现漂移）
decode_b64_token = _try_decode
decode_hex_token = _try_decode_hex


class CommandObfuscationDetector(Detector):
    rule_id = "command-obfuscation"
    title = "命令混淆 / 编码载荷"
    description = "发现 Base64 编码命令、命令行混淆或 LOLBAS 隐蔽执行行为"
    mitre = ("T1027 Obfuscated Files or Information / T1059.001 PowerShell / "
             "T1218 System Binary Proxy Execution / T1140 Deobfuscate/Decode Files")
    recommendation = ("1) 对告警中的解码结果还原完整攻击链（下载地址、落地文件）；"
                      "2) 检查父进程（邮件附件/办公软件/Web 服务）定位入口；"
                      "3) 全网排查同源 IP/同哈希文件，隔离受影响主机")

    def __init__(self, config):
        super().__init__(config)
        self.hits: dict = {}          # (host, kind) -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return
        if ev.action not in (A_PROCESS_CREATE, A_COMMAND_EXEC, A_SUDO_COMMAND):
            return
        cmdline = (ev.detail.get("CommandLine") or ev.detail.get("command")
                   or ev.detail.get("cmd") or ev.detail.get("message") or "")
        if not cmdline or len(cmdline) < 16:
            return
        host = ev.host or "-"
        reasons: list[str] = []
        severity = 2

        # sshd execute 行本身即异常痕迹（正常 OpenSSH 不产生，-e 参数执行/旧版后门）
        if ev.detail.get("sshd_execute"):
            reasons.append("sshd execute 痕迹：-e 参数远程命令执行（疑似旧版 SSH 后门利用）")

        # ---- L1 编码参数 ----
        for rx in (ENC_PARAM_RE, ENC_SHORT_RE):
            for m in rx.finditer(cmdline):
                dec, enc_label = _try_decode(m.group(1))
                if dec:
                    hit_kw = PAYLOAD_KEYWORDS.search(dec)
                    if hit_kw:
                        reasons.append(f"编码命令已解码（{enc_label}，命中关键词 "
                                       f"{hit_kw.group(0)[:24]!r}）：{dec[:160]}")
                        severity = 1
                    else:
                        reasons.append(f"编码命令已解码（{enc_label}）：{dec[:160]}")

        # ---- L2 隐式 Base64 长串 ----
        seen: set[str] = set()
        for tok in B64_TOKEN_RE.findall(cmdline):
            if tok in seen:
                continue
            seen.add(tok)
            if len(tok) < self.config.obf_b64_min_len:
                continue
            ent = _shannon(tok)
            if ent < self.config.obf_entropy_min:
                continue
            dec, enc_label = _try_decode(tok)
            if dec and PAYLOAD_KEYWORDS.search(dec):
                reasons.append(f"高熵编码串已解码（{enc_label}，熵 {ent:.2f}）：{dec[:160]}")
                severity = 1
            elif dec:
                reasons.append(f"高熵编码串已解码（{enc_label}，熵 {ent:.2f}）：{dec[:120]}")
            else:
                reasons.append(f"不可解码高熵串（长度 {len(tok)}，熵 {ent:.2f}，疑似加密/自定义编码载荷）")
                severity = max(severity, 3)

        # ---- L3 混淆 ----
        carets = CARET_RE.findall(cmdline)
        if len(carets) >= self.config.obf_caret_min:
            reasons.append(f"cmd ^ 插入混淆 ×{len(carets)}（如 {'^'.join(carets[:3])}）")
        # 空引号插入是高特异性手法（合法命令行几乎不存在 字母""字母），1 处即报
        quotes = EMPTY_QUOTE_RE.findall(cmdline)
        if quotes:
            reasons.append(f"空引号插入混淆 ×{len(quotes)}（如 {''.join(quotes[:2])}）")
        if ENV_SLICE_RE.search(cmdline):
            reasons.append("环境变量片段截取/拼接（%VAR:~x,y% 或 $env: 拼接）")

        # ---- L4 LOLBAS ----
        m = LOLBAS_RE.search(cmdline)
        if m:
            reasons.append(f"LOLBAS/解码下载工具：{m.group(0)[:80]}")

        # ---- L5 Hex 编码载荷（echo '<hex>' | sh 的典型落地方式）----
        # 判据：解码含命令/URL 关键词为主 + 可打印比例兜底。
        # 真实载荷常混入污染字节（比例可能低至 0.6），而随机 SHA 指纹/MAC
        # 同时满足"关键词命中 + 比例≥0.6"的概率趋近于零。
        pipe_exec = bool(PIPE_EXEC_RE.search(cmdline))
        seen_hex: set[str] = set()
        for tok in HEX_TOKEN_RE.findall(cmdline):
            if tok in seen_hex:
                continue
            seen_hex.add(tok)
            dec = _try_decode_hex(tok)
            if not dec or _printable_ratio(dec) < 0.6:
                continue
            if not HEX_PAYLOAD_KEYWORDS.search(dec):
                continue  # 无命令/URL 关键词的 hex 不报，避开良性长 hex
            if pipe_exec:
                reasons.append(f"Hex 编码载荷已解码并经管道执行：{dec[:160]}")
                severity = 1
            else:
                reasons.append(f"Hex 编码载荷已解码：{dec[:160]}")
                severity = max(severity, 2)

        # ---- L6 下载-落地-执行链 ----
        if DL_PIPE_EXEC_RE.search(cmdline):
            # 下载即执行：无落地文件、不留痕，最隐蔽的一种
            reasons.append(f"远程下载并直接管道执行（无落地文件）：{cmdline[:120]}")
            severity = 1
        elif DL_TOOL_RE.search(cmdline):
            out = DL_OUTFILE_RE.search(cmdline)
            out_path = next((g for g in out.groups() if g), "") if out else ""
            landed_tmp = bool(out_path) and bool(WRITABLE_DIR_RE.search(out_path))
            if landed_tmp and (CHMOD_EXEC_RE.search(cmdline) or EXEC_AFTER_RE.search(cmdline)):
                # 完整链：下载 → 落到临时目录 → 赋权/执行
                reasons.append(
                    f"下载-落地-执行链：{DL_TOOL_RE.search(cmdline).group(1)} 下载至 "
                    f"{out_path} 后赋权/执行（{cmdline[:100]}）")
                severity = 1
            elif landed_tmp:
                reasons.append(f"下载至可写临时目录 {out_path}（{cmdline[:100]}）")
                severity = max(severity, 2)

        # ---- L7 解码器管道（把编码内容还原成文件/脚本）----
        dm = DECODER_PIPE_RE.search(cmdline)
        if dm:
            if pipe_exec or PIPE_EXEC_RE.search(cmdline):
                reasons.append(f"解码器还原后管道执行（{dm.group(1)}）：{cmdline[:120]}")
                severity = 1
            else:
                reasons.append(f"命令行内使用解码器还原载荷（{dm.group(1)}）：{cmdline[:120]}")
                severity = max(severity, 2)

        if not reasons:
            return
        key = (host, reasons[0][:60])
        st = self.hits.setdefault(key, {"count": 0, "reasons": set(),
                                        "first": None, "last": None, "severity": 3,
                                        "evidence": [], "attribution": None})
        # 归属：优先保留置信度高 / 更可疑（前置失败更多）的那条，供结论可复核
        attr = ev.detail.get("attribution")
        if attr:
            cur = st["attribution"]
            if cur is None or (attr.get("score", 0), attr.get("prior_failures", 0)) > \
                    (cur.get("score", 0), cur.get("prior_failures", 0)):
                st["attribution"] = attr
        st["count"] += 1
        st["reasons"].update(reasons)
        st["severity"] = min(st["severity"], severity)
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (host, _kind), st in sorted(self.hits.items(), key=lambda kv: kv[1]["severity"]):
            proc_reasons = sorted(st["reasons"])
            entities = {"host": host, "reasons": proc_reasons}
            attr = st.get("attribution")
            if attr:
                entities.update({
                    "src_ip": attr["ip"],
                    "user": attr["user"],
                    "attribution_confidence": attr["confidence"],
                    "attribution_basis": attr["basis"],
                    "candidate_ips": attr["candidate_ips"],
                    "prior_failures": attr["prior_failures"],
                    "session_opened": attr["session_opened"],
                })
            self._alert(st["severity"], st["count"], entities,
                        st["evidence"], st["first"], st["last"])
            desc = (f"命令混淆/编码载荷：{host} 上 {st['count']} 次可疑执行"
                    f"（{'；'.join(r[:80] for r in proc_reasons[:2])}）")
            if attr:
                desc = (f"[归属 {attr['ip']}｜置信度{attr['confidence']}｜{attr['basis']}] "
                        + desc)
            self.alerts[-1].description = desc
        return self.alerts

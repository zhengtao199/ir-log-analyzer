"""Linux 日志解析器：auth.log / secure（SSH、sudo）与 syslog 通用格式。

覆盖典型行：
    Jan 15 09:30:01 host sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 52134 ssh2
    Jan 15 09:30:05 host sshd[1234]: Accepted password for root from 10.0.0.5 port 52135 ssh2
    Jan 15 09:31:00 host sudo:  user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
    Jan 15 09:32:00 host sshd[1234]: POSSIBLE BREAK-IN ATTEMPT!
syslog 无年份，按当前年补全（跨年场景取日志中 1 月但当前 12 月时回退一年）。
"""
from __future__ import annotations

import re
import time
from typing import Generator, Optional

from ..models import (
    Event,
    A_LOGON_FAILED, A_LOGON_SUCCESS, A_SUDO_COMMAND, A_GENERIC,
    A_COMMAND_EXEC, A_SESSION_END, A_NETWORK_CONN,
)
from .base import LogParser, register

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)"
)

FAILED_PW_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive\S*) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
# sshd 的 execute 行：正常 OpenSSH 不会产生，多为 -e 参数执行/旧版后门利用痕迹
SSHD_EXECUTE_RE = re.compile(
    r"error:\s*execute:\s*(?P<cmd>/usr/bin/ssh\b.*|.*)", re.I | re.S)
# auditd EXECVE：type=EXECVE msg=audit(...): a0="ls" a1="-la" ...
# 攻击者入侵后的实际命令轨迹（含 hex 编码参数），必须归一为命令执行
EXECVE_RE = re.compile(r"type=EXECVE\s+msg=audit\([^)]*\):\s*(?P<args>.*)$")
EXECVE_ARG_RE = re.compile(r'a(\d+)="([^"]*)"')
AUDIT_HEX_RE = re.compile(r"[0-9A-Fa-f]+$")
SUDO_RE = re.compile(
    r"(?P<user>[\w\-.]+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<runas>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
BREAKIN_RE = re.compile(r"POSSIBLE BREAK-IN ATTEMPT", re.I)
# 会话关闭：用于界定登录会话的结束，从而把命令执行归属到正确的源 IP
SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)", re.I)
DISCONNECT_RE = re.compile(
    r"(?:Disconnected|Connection closed) (?:from|by)"
    r"(?:\s+(?:invalid user\s+)?(?P<user>\S+))?"
    r"(?:\s+(?P<ip>\d+\.\d+\.\d+\.\d+))?", re.I)
# 防火墙（UFW/iptables front-end）连接记录：[UFW ALLOW] ... SRC=x.x.x.x DST=... PROTO=TCP SPT=52341 DPT=22
# 用途：与 sshd Accepted 的源端口做精确匹配，把命令执行归属到"同一条 TCP 连接"的来源 IP
FIREWALL_RE = re.compile(r"\[UFW\s+(?P<fwaction>[A-Z ]+)\]")
FW_KV_RE = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=([^\s]+)")


def _ts(mon: str, day: int, hh: int, mm: int, ss: int) -> float:
    year = time.localtime().tm_year
    # 跨年修正：日志是 1 月但当前已到 12 月，说明日志属于上一年
    if MONTHS.get(mon, 1) == 1 and time.localtime().tm_mon >= 11:
        year -= 1
    return time.mktime((year, MONTHS.get(mon, 1), day, hh, mm, ss, 0, 0, -1))


def _decode_audit_arg(val: str) -> str:
    """auditd 对含特殊字符的参数以 hex 编码输出：解码可读的 hex 参数。

    判据：纯 hex、偶数长度、解码后 ASCII 可打印比例高。其余（如以 + 开头的
    payload 参数、明文 ls/-la）原样保留。
    """
    if len(val) < 4 or len(val) % 2 != 0 or not AUDIT_HEX_RE.fullmatch(val):
        return val
    try:
        dec = bytes.fromhex(val).decode("latin-1", "replace")
    except ValueError:
        return val
    ok = sum(1 for ch in dec if 0x20 <= ord(ch) <= 0x7E or ch in "\r\n\t")
    return dec if len(dec) and ok / len(dec) >= 0.9 else val


class LinuxAuthParser(LogParser):
    name = "linux-auth"

    def detect(self, sample_lines: list[str]) -> bool:
        text = "\n".join(sample_lines[:10])
        if not SYSLOG_RE.search(text):
            return False
        # auditd 记录（type=EXECVE/SYSCALL 等）也是本解析器的管辖范围：
        # 纯 audit.log 里没有 sshd/sudo，不能因此退回 syslog 丢掉命令执行
        if re.search(r"type=[A-Z_]+\s+msg=audit|\baudit\[\d+\]:", text):
            return True
        return bool(re.search(r"sshd|sudo|su\[|login|polkitd|CRON|systemd-logind", text))

    def parse(self, path: str) -> Generator[Event, None, None]:
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            ts = _ts(m.group("mon"), int(m.group("day")), hh, mm, ss)
            proc = m.group("proc")
            msg = m.group("msg")

            action = A_GENERIC
            user = src_ip = None
            detail = {"process": proc, "pid": m.group("pid"), "message": msg}

            fm = FAILED_PW_RE.search(msg)
            am = ACCEPTED_RE.search(msg)
            im = INVALID_USER_RE.search(msg)
            sm = SUDO_RE.search(msg)
            em = SSHD_EXECUTE_RE.search(msg) if proc.startswith("sshd") else None
            xv = EXECVE_RE.search(msg)
            fwm = FIREWALL_RE.search(msg) if proc.startswith("kernel") else None

            if fwm:
                # 防火墙连接记录：归一为网络连接事件，供会话归属做源端口精确关联
                action = A_NETWORK_CONN
                kv = dict(FW_KV_RE.findall(msg))
                src_ip = kv.get("SRC")
                detail["firewall"] = True
                detail["fw_action"] = fwm.group("fwaction").strip()
                if kv.get("SPT"):
                    detail["sport"] = kv["SPT"]
                if kv.get("DPT"):
                    detail["dport"] = kv["DPT"]
                if kv.get("PROTO"):
                    detail["proto"] = kv["PROTO"]
                if kv.get("DST"):
                    detail["dst_ip"] = kv["DST"]
            elif fm:
                action = A_LOGON_FAILED
                user, src_ip = fm.group("user"), fm.group("ip")
            elif am:
                action = A_LOGON_SUCCESS
                user, src_ip = am.group("user"), am.group("ip")
                detail["sport"] = am.group("port")  # 供防火墙 SRC/SPT 精确关联
            elif im:
                action = A_LOGON_FAILED
                user, src_ip = im.group("user"), im.group("ip")
                detail["invalid_user"] = True
            elif xv:
                # auditd EXECVE：命令参数逐个解码后拼接（a0 为程序名）
                pairs = sorted((int(n), v) for n, v in EXECVE_ARG_RE.findall(xv.group("args")))
                if pairs:
                    action = A_COMMAND_EXEC
                    detail["command"] = " ".join(_decode_audit_arg(v) for _n, v in pairs)
                    detail["execve"] = True
                else:
                    action = A_GENERIC
            elif em:
                # sshd execute 行：归一为命令执行，保留完整命令行供解码分析
                action = A_COMMAND_EXEC
                detail["command"] = em.group("cmd").strip()
                detail["sshd_execute"] = True
            elif sm:
                action = A_SUDO_COMMAND
                user = sm.group("user")
                detail["runas"] = sm.group("runas")
                detail["command"] = sm.group("cmd")
            elif BREAKIN_RE.search(msg):
                action = A_LOGON_FAILED
                detail["break_in_attempt"] = True
            elif SESSION_CLOSED_RE.search(msg):
                action = A_SESSION_END
                user = SESSION_CLOSED_RE.search(msg).group("user")
                detail["session_closed"] = True
            elif DISCONNECT_RE.search(msg):
                dm = DISCONNECT_RE.search(msg)
                action = A_SESSION_END
                user = dm.group("user")
                src_ip = dm.group("ip")
                detail["disconnected"] = True
            elif "authentication failure" in msg.lower():
                action = A_LOGON_FAILED
                um = re.search(r"user=(\S+)", msg)
                if um:
                    user = um.group(1)
                rm = re.search(r"rhost=(\S+)", msg)
                if rm:
                    src_ip = rm.group(1)

            yield Event(
                ts=ts,
                log_type="linux-auth",
                source=path,
                action=action,
                host=m.group("host"),
                user=user,
                src_ip=src_ip,
                detail=detail,
                raw=line[:2000],
            )


class LinuxSyslogParser(LogParser):
    """非认证类 syslog（放行 generic 之前的通用解析）。"""

    name = "linux-syslog"

    def detect(self, sample_lines: list[str]) -> bool:
        return bool(SYSLOG_RE.search("\n".join(sample_lines[:10])))

    def parse(self, path: str) -> Generator[Event, None, None]:
        for line in self.read_lines(path, errors="replace"):
            if not line.strip():
                continue
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            ts = _ts(m.group("mon"), int(m.group("day")), hh, mm, ss)
            yield Event(
                ts=ts,
                log_type="linux-syslog",
                source=path,
                action=A_GENERIC,
                host=m.group("host"),
                detail={"process": m.group("proc"), "pid": m.group("pid"), "message": m.group("msg")},
                raw=line[:2000],
            )


register(LinuxAuthParser())
register(LinuxSyslogParser())

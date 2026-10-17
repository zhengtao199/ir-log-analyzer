"""Webshell 与后门检测。

Web 侧（Nginx/Apache/IIS 访问日志）：
- 请求可疑脚本后缀（php/jsp/asp/aspx 等）且位于常见上传目录（uploads/images/files 等）
- POST 到可疑脚本后缀（疑似一句话木马交互）
- URI 含 webshell 典型参数（cmd=, exec=, whoami, system(, passthru, eval( 等）
- 短 URI + 小响应体的可疑脚本访问

主机侧（Windows 4688 / Sysmon 1）：
- Web 服务进程（w3wp/httpd/apache2/php-cgi/tomcat/java-catalina）派生命令行解释器
  （cmd.exe / powershell / bash / sh）或可疑工具
"""
from __future__ import annotations

import os
import re
from urllib.parse import unquote_plus

from ..models import A_PROCESS_CREATE, A_HTTP_REQUEST, Event
from .base import Detector

UPLOAD_DIRS_RE = re.compile(
    r"/upload|/uploads|/images|/img|/files|/attachments|/attachment|/media|/res|"
    r"/static/upload|/editor|/ueditor", re.I)
SUSPICIOUS_PARAMS = re.compile(
    r"(?:^|[?&])(cmd|exec|command|code|payload|eval|system|passthru|shell_exec|"
    r"assert|base64_decode|call_user_func|preg_replace)\s*=", re.I)
SHELL_TOKENS = re.compile(
    r"\b(whoami|net\s+user|net\s+localgroup|ipconfig|/etc/passwd|systeminfo|"
    r"tasklist|netstat|type\s+c:\\|cat\s+/etc|powershell|base64_decode|eval\(|assert\()\b", re.I)

# Web 服务进程 -> 派生即高危
WEB_SERVER_PROCS = ("w3wp.exe", "httpd.exe", "apache2", "nginx.exe", "php-cgi.exe",
                    "tomcat", "catalina", "java.exe", "inetinfo.exe", "w3wp")
INTERPRETERS = ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "/bin/sh",
                "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe")


class WebshellDetector(Detector):
    rule_id = "webshell"
    title = "Webshell / 后门"
    description = "发现疑似 Webshell 行为：上传目录中的可执行脚本或 Web 进程派生命令执行"
    mitre = "T1505.003 Server Software Component: Web Shell / T1190 Exploit Public-Facing Application"
    recommendation = "1) 隔离主机，排查对应文件（哈希、创建时间、内容）；2) 复盘上传入口（文件上传漏洞/弱口令后台）；3) 全盘扫描同类文件并检查计划任务/启动项持久化"

    def __init__(self, config):
        super().__init__(config)
        self.web_hits: dict = {}      # (ip, uri) -> {...}
        self.proc_hits: dict = {}     # (host, process) -> {...}

    # ---- Web 侧 ----
    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return
        if ev.action == A_HTTP_REQUEST and (ev.uri or ev.detail.get("http_body")):
            self._check_web(ev)
        elif ev.action == A_PROCESS_CREATE and ev.process:
            self._check_process(ev)

    def _check_web(self, ev: Event) -> None:
        uri = ev.uri or ""
        # 流量包里 POST 的命令常只在请求体里（重组后才能拿到），
        # 此时 uri 为空 —— 用请求体补齐，否则 Webshell 交互会整类漏掉
        body = ev.detail.get("http_body") or ""
        low = (uri + " " + body).lower() if body else uri.lower()
        dec = unquote_plus(low) if ("%" in low or "+" in low) else low
        ulow = uri.lower()
        path = ulow.split("?", 1)[0]
        ext = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
        in_upload_dir = bool(UPLOAD_DIRS_RE.search(low))
        suspicious_ext = ext in self.config.webshell_suspicious_exts
        post = (ev.method or "").upper() == "POST"
        reasons = []
        if suspicious_ext and in_upload_dir:
            reasons.append(f"上传目录中的脚本文件（{ext}）")
        if suspicious_ext and post:
            reasons.append(f"POST 提交到 {ext} 脚本（疑似木马交互）")
        if SUSPICIOUS_PARAMS.search(low) or SUSPICIOUS_PARAMS.search(dec):
            reasons.append("URI 含命令执行类参数")
        if SHELL_TOKENS.search(low) or SHELL_TOKENS.search(dec):
            reasons.append("URI 含系统命令特征" if not body else "请求体含系统命令特征")
        if not reasons:
            return
        key = (ev.src_ip or "-", path or "(仅请求体)")
        st = self.web_hits.setdefault(key, {"count": 0, "reasons": set(), "first": None, "last": None, "evidence": []})
        st["count"] += 1
        st["reasons"].update(reasons)
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    # ---- 主机侧 ----
    def _check_process(self, ev: Event) -> None:
        parent = (ev.parent_process or "").lower()
        proc = (ev.process or "").lower()
        if not any(w in parent for w in WEB_SERVER_PROCS):
            return
        base = os.path.basename(proc)
        if not any(i in proc for i in INTERPRETERS):
            return
        cmdline = ev.detail.get("CommandLine") or ev.detail.get("command") or ""
        key = (ev.host or "-", ev.process or "-")
        st = self.proc_hits.setdefault(key, {"count": 0, "first": None, "last": None, "evidence": []})
        st["count"] += 1
        if ev.ts is not None:
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
        if len(st["evidence"]) < self.config.evidence_sample_per_alert:
            st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (ip, path), st in sorted(self.web_hits.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(
                severity=1,
                count=st["count"],
                entities={"src_ip": ip, "uri": path, "reasons": sorted(st["reasons"])},
                evidence=st["evidence"],
                first_ts=st["first"], last_ts=st["last"],
            )
            self.alerts[-1].description = (
                f"Webshell 行为：{ip} 访问 {path}（{'；'.join(sorted(st['reasons']))}）")
        for (host, proc), st in sorted(self.proc_hits.items(), key=lambda kv: -kv[1]["count"]):
            self._alert(
                severity=1,
                count=st["count"],
                entities={"host": host, "process": proc},
                evidence=st["evidence"],
                first_ts=st["first"], last_ts=st["last"],
            )
            self.alerts[-1].description = (
                f"Web 进程派生命令执行（疑似 Webshell 执行链）：{host} 上 {proc}")
        return self.alerts

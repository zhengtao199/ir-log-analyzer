"""后台/管理入口登录成功检测。

Web 日志里"登录成功"通常是：
    POST 到 login/signin/auth 类接口 -> 302 跳转到后台首页（或 200 带凭证）
紧接着往往能看到后台功能页的 200 请求，可作为"已拿到后台权限"的佐证。

应急意义：失陷事件里后台权限来源有三类 —— 弱口令、凭据泄露、利用漏洞绕过鉴权，
无论哪种都必须立即重置口令并核查账号列表。
"""
from __future__ import annotations

import re

from ..models import Event, A_HTTP_REQUEST
from .base import Detector

LOGIN_PATH_RE = re.compile(
    r"(login|signin|sign-in|doSignin|dosignin|auth|session|authenticate|"
    r"account\.php|admin/index|cp\.php|user/login|member\.php)", re.I)
LOGIN_QUERY_RE = re.compile(r"(action=(login|signin|dosignin|dologin|auth))", re.I)
ADMIN_PATH_RE = re.compile(r"/(admin|manage|manager|backend|webadmin|wp-admin|administrator)/", re.I)


class AdminLoginDetector(Detector):
    rule_id = "admin_login"
    ACTIONS = {A_HTTP_REQUEST}
    title = "后台登录成功"
    description = "检测到管理入口登录成功的请求（POST 登录接口返回 302/200），需核实是否为授权运维行为"
    mitre = "T1078 Valid Accounts"
    recommendation = ("1) 与管理员确认是否为本人操作，非授权即视为失陷；"
                      "2) 立即重置后台口令与所有管理员账号口令，启用 MFA；"
                      "3) 检查用户表是否被新增/提权账号，核查登录后的操作（插件上传、模板编辑、数据导出）")

    def __init__(self, config):
        super().__init__(config)
        self.logins: dict = {}     # (ip, path) -> {...}
        self.after: dict = {}      # ip -> {admin_pages: set, first, last}

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST or not ev.uri:
            return
        path = ev.uri.split("?", 1)[0]
        query = ev.uri.split("?", 1)[1] if "?" in ev.uri else ""
        method = (ev.method or "").upper()
        ip = ev.src_ip or "-"

        if method == "POST" and (LOGIN_PATH_RE.search(path) or LOGIN_QUERY_RE.search(query)) \
                and ev.status is not None and ev.status in (200, 301, 302, 303):
            rec = self.logins.setdefault((ip, path), {
                "count": 0, "first": None, "last": None, "evidence": [], "statuses": {},
            })
            rec["count"] += 1
            rec["statuses"][ev.status] = rec["statuses"].get(ev.status, 0) + 1
            rec["first"] = ev.ts if rec["first"] is None else min(rec["first"], ev.ts)
            rec["last"] = ev.ts if rec["last"] is None else max(rec["last"], ev.ts)
            if len(rec["evidence"]) < 5:
                rec["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        # 登录后的后台访问（佐证）
        if ADMIN_PATH_RE.search(path) and ev.status is not None and 200 <= ev.status < 300:
            st = self.after.setdefault(ip, {"pages": set(), "first": None, "last": None})
            if len(st["pages"]) < 40:
                st["pages"].add(path)
            st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
            st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (ip, path), rec in sorted(self.logins.items(), key=lambda kv: -kv[1]["count"]):
            follow = self.after.get(ip)
            pages = sorted(follow["pages"])[:6] if follow else []
            sev = 2 if (follow and len(follow["pages"]) >= 3) else 3
            self._alert(
                severity=sev,
                count=rec["count"],
                entities={
                    "src_ip": ip,
                    "登录接口": path,
                    "响应状态": sorted(rec["statuses"]),
                    "登录后访问后台页数": len(follow["pages"]) if follow else 0,
                    "后台页面样本": pages,
                },
                evidence=rec["evidence"],
                first_ts=rec["first"], last_ts=rec["last"],
            )
            self.alerts[-1].description = (
                f"{ip} 于 {self._human_ts(rec['first'])} 对 {path} 发起登录并获成功响应"
                f"（{rec['count']} 次）" + (f"，随后访问后台页面 {len(follow['pages'])} 个" if follow else ""))
        return self.alerts

"""攻击链还原检测：后台登录成功、文件上传漏洞利用、上传后 webshell 落地。

与 `web-attack`（关注单条请求的攻击特征）不同，本规则关注**跨请求的关联**：
攻击者先登录后台 → 通过上传接口落地文件 → 反复 POST 该文件完成交互。
这类链路在单看一条日志时都不"像"攻击，只有串起来才能定性。

对应 MITRE ATT&CK：
- T1078 Valid Accounts（登录成功）
- T1505.003 Server Software Component: Web Shell（后门落地）
- T1190 Exploit Public-Facing Application（上传漏洞）
"""
from __future__ import annotations

from typing import Optional

from ..models import A_HTTP_REQUEST, Event
from ..stats import (WRITABLE_DIRS_RE, LOGIN_ACTION_RE, UPLOAD_ACTION_RE,
                     script_ext_of, param_count, PARAM_FUZZ_MIN)
from .base import Detector


class AttackChainDetector(Detector):
    rule_id = "attack-chain"
    title = "攻击链还原（登录 / 上传 / 后门落地）"
    description = ("发现跨请求的攻击链：后台登录成功、文件上传漏洞被利用、"
                   "上传后才出现的脚本被反复 POST 交互（疑似 webshell）")
    mitre = ("T1078 Valid Accounts / T1190 Exploit Public-Facing Application / "
             "T1505.003 Server Software Component: Web Shell")
    recommendation = (
        "1) 立即隔离该 Web 主机，保留磁盘与内存镜像；"
        "2) 核对上传接口的鉴权与文件类型白名单，删除落地脚本并比对文件哈希；"
        "3) 轮换后台全部账号口令与 Web 会话密钥，排查同目录其他新增文件；"
        "4) 复盘上传漏洞入口（插件/主题安装、附件上传、编辑器接口）并打补丁")

    def __init__(self, config):
        super().__init__(config)
        self.logins: list[dict] = []
        self.uploads: list[dict] = []
        self.post_scripts: dict = {}       # (ip, path) -> {"count","first","last","evidence"}
        self.path_first: dict = {}         # path -> 首次出现 ts
        self.seen_upload_ts: Optional[float] = None
        self._cap = 200

    # ------------------------------------------------------------ feed

    def feed(self, ev: Event) -> None:
        if not self.enabled or ev.action != A_HTTP_REQUEST:
            return
        uri = ev.uri or ""
        if not uri:
            return
        path = uri.split("?", 1)[0]
        method = (ev.method or "").upper()
        status = ev.status
        ip = ev.src_ip or "-"

        # 记录脚本路径首次出现时间（有上限）
        if script_ext_of(path) is not None:
            if path in self.path_first or len(self.path_first) < 8000:
                prev = self.path_first.get(path)
                if prev is None or (ev.ts is not None and ev.ts < prev):
                    self.path_first[path] = ev.ts if ev.ts is not None else prev or 0.0

        # 1) 后台登录成功
        if method == "POST" and status in (200, 302) and LOGIN_ACTION_RE.search(uri):
            if len(self.logins) < self._cap:
                self.logins.append(self._rec(ev, ip, uri, method, status))

        # 2) 文件上传漏洞利用
        if method in ("POST", "PUT") and status in (200, 201, 204, 302) \
                and UPLOAD_ACTION_RE.search(uri):
            if len(self.uploads) < self._cap:
                self.uploads.append(self._rec(ev, ip, uri, method, status))
            if ev.ts is not None:
                if self.seen_upload_ts is None or ev.ts < self.seen_upload_ts:
                    self.seen_upload_ts = ev.ts

        # 3) POST 成功到脚本（webshell 交互特征）
        if method == "POST" and status == 200 and script_ext_of(path) is not None:
            key = (ip, path)
            st = self.post_scripts.get(key)
            if st is None:
                if len(self.post_scripts) >= 8000:
                    return
                st = {"count": 0, "first": None, "last": None, "evidence": []}
                self.post_scripts[key] = st
            st["count"] += 1
            if ev.ts is not None:
                st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
            if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def _rec(self, ev: Event, ip: str, uri: str, method: str, status) -> dict:
        return {"ts": ev.ts, "ip": ip, "uri": uri, "method": method,
                "status": status, "user_agent": ev.user_agent,
                "source": ev.source,
                "raw": ev.raw[: self.config.raw_line_max_len]}

    # ------------------------------------------------------------ finalize

    def finalize(self) -> list:
        if not self.enabled:
            return []

        # (a) 后台登录成功
        if self.logins:
            self._emit_login()

        # (b) 文件上传漏洞利用
        if self.uploads:
            self._emit_upload()

        # (c) 上传后落地的脚本 + POST 交互（webshell）
        self._emit_webshell()

        return self.alerts

    def _emit_login(self) -> None:
        ips = sorted({e["ip"] for e in self.logins})
        uris = sorted({e["uri"].split("?", 1)[0] for e in self.logins})
        ev = [ (e["ts"], e["source"], e["raw"]) for e in self.logins[: self.config.evidence_sample_per_alert] ]
        first = min((e["ts"] for e in self.logins if e["ts"] is not None), default=None)
        last = max((e["ts"] for e in self.logins if e["ts"] is not None), default=None)
        self._alert(
            severity=2,
            count=len(self.logins),
            entities={"src_ip": ips[0] if len(ips) == 1 else ",".join(ips[:5]),
                      "candidate_ips": ips,
                      "uri": uris[0] if len(uris) == 1 else ",".join(uris[:3]),
                      "users": []},
            evidence=ev,
            first_ts=first, last_ts=last,
        )
        self.alerts[-1].description = (
            f"后台登录成功 {len(self.logins)} 次：{ips[0] if len(ips)==1 else ','.join(ips[:5])}"
            f" 访问 {uris[0] if len(uris)==1 else ','.join(uris[:3])}"
            f"（POST 后返回 200/302，说明口令正确并已进入后台）")

    def _emit_upload(self) -> None:
        ips = sorted({e["ip"] for e in self.uploads})
        uris = sorted({e["uri"].split("?", 1)[0] for e in self.uploads})
        ev = [(e["ts"], e["source"], e["raw"]) for e in self.uploads[: self.config.evidence_sample_per_alert]]
        first = min((e["ts"] for e in self.uploads if e["ts"] is not None), default=None)
        last = max((e["ts"] for e in self.uploads if e["ts"] is not None), default=None)
        self._alert(
            severity=2,
            count=len(self.uploads),
            entities={"src_ip": ips[0] if len(ips) == 1 else ",".join(ips[:5]),
                      "candidate_ips": ips,
                      "uri": uris[0] if len(uris) == 1 else ",".join(uris[:3])},
            evidence=ev,
            first_ts=first, last_ts=last,
        )
        self.alerts[-1].description = (
            f"文件上传接口被调用 {len(self.uploads)} 次：{ips[0] if len(ips)==1 else ','.join(ips[:5])}"
            f" POST/PUT {uris[0] if len(uris)==1 else ','.join(uris[:3])}"
            f"（返回成功状态，若该接口未做鉴权或类型校验即为上传漏洞）")

    def _emit_webshell(self) -> None:
        # 上传之后才首次出现的脚本路径
        landed = []
        for (ip, path), st in self.post_scripts.items():
            first = self.path_first.get(path)
            if self.seen_upload_ts is None or first is None or first < self.seen_upload_ts:
                continue
            landed.append((ip, path, st, first))
        landed.sort(key=lambda x: -x[2]["count"])

        if landed:
            ip, path, st, first = landed[0]
            ev = list(st["evidence"])
            self._alert(
                severity=1,
                count=st["count"],
                entities={"src_ip": ip, "uri": path,
                          "writable_dir": bool(WRITABLE_DIRS_RE.search(path))},
                evidence=ev,
                first_ts=st["first"], last_ts=st["last"],
            )
            extra = "，位于 Web 可写目录" if WRITABLE_DIRS_RE.search(path) else ""
            self.alerts[-1].description = (
                f"上传后落地的脚本 {path}：该文件在文件上传动作之后才首次出现，"
                f"并被 {ip} POST 成功访问 {st['count']} 次{extra}（高度疑似 webshell）")
        elif self.post_scripts:
            # 没有上传上下文时，只对「可写目录 + 多次 POST 成功」报线索
            hot = [(k, v) for k, v in self.post_scripts.items()
                   if v["count"] >= 3 and WRITABLE_DIRS_RE.search(k[1])]
            hot.sort(key=lambda kv: -kv[1]["count"])
            for (ip, path), st in hot[:5]:
                self._alert(
                    severity=2,
                    count=st["count"],
                    entities={"src_ip": ip, "uri": path,
                              "writable_dir": True},
                    evidence=list(st["evidence"]),
                    first_ts=st["first"], last_ts=st["last"],
                )
                self.alerts[-1].description = (
                    f"Web 可写目录中的脚本被反复 POST：{ip} → {path}"
                    f"（{st['count']} 次且均返回 200，符合 webshell 交互特征）")

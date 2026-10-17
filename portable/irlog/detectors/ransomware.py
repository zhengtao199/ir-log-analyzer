"""勒索软件痕迹检测：影子副本删除、恢复禁用、勒索扩展名批量创建、批量删除。"""
from __future__ import annotations

import re

from ..models import A_PROCESS_CREATE, A_FILE_CREATE, A_OBJECT_DELETE, Event
from .base import Detector

RANSOM_CMDS = re.compile(
    r"(vssadmin(?:\.exe)?\s+delete\s+shadows|"
    r"wbadmin(?:\.exe)?\s+delete\s+(catalog|systemstatebackup)|"
    r"bcdedit(?:\.exe)?\s+/set.*recoveryenabled\s+no|"
    r"wevtutil(?:\.exe)?\s+(cl|clear-log)|"
    r"cipher(?:\.exe)?\s+/w|"
    r"powershell.*(?:disable-windowsoptionalfeature|remove-item.*-force.*shadow))", re.I)

EXT_RE = re.compile(r"\.([a-z0-9]{1,10})$", re.I)


class RansomwareDetector(Detector):
    rule_id = "ransomware"
    title = "勒索软件痕迹"
    description = "发现卷影副本删除、恢复禁用或勒索扩展名批量文件创建等勒索行为"
    mitre = "T1486 Data Encrypted for Impact / T1490 Inhibit System Recovery"
    recommendation = "1) 立即隔离主机（断网，保留内存镜像）；2) 勿关机，排查进程与持久化；3) 从备份恢复并核查是否已外传"

    def __init__(self, config):
        super().__init__(config)
        self.cmd_hits: dict = {}       # (host, cmd) -> {...}
        self.fileburst: dict = {}      # (host, process) -> {"events": deque, "count"}
        self.ransom_ext: dict = {}     # (host, process) -> {...}
        self.deleteburst: dict = {}    # (host, process) -> {...}

    def feed(self, ev: Event) -> None:
        if not self.enabled:
            return

        if ev.action == A_PROCESS_CREATE:
            cmdline = ev.detail.get("CommandLine") or ev.detail.get("command") or ev.raw
            if RANSOM_CMDS.search(cmdline or ""):
                key = (ev.host or "-", (ev.process or "?")[:80])
                st = self.cmd_hits.setdefault(key, {"count": 0, "first": None, "last": None, "evidence": []})
                st["count"] += 1
                if ev.ts is not None:
                    st["first"] = ev.ts if st["first"] is None else min(st["first"], ev.ts)
                    st["last"] = ev.ts if st["last"] is None else max(st["last"], ev.ts)
                if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                    st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        elif ev.action == A_FILE_CREATE:
            proc = ev.process or ev.detail.get("Image") or "-"
            host = ev.host or "-"
            # 滑动窗口文件创建突发
            st = self.fileburst.setdefault((host, proc), {"events": [], "count": 0})
            if ev.ts is not None:
                st["events"].append(ev.ts)
                w = self.config.ransomware_filecreate_window_sec
                st["events"] = [t for t in st["events"] if ev.ts - t <= w]
                st["count"] = len(st["events"])
            else:
                st["count"] += 1
            # 勒索扩展名
            fp = ev.file_path or ev.detail.get("TargetFilename") or ""
            m = EXT_RE.search(fp)
            if m and m.group(1).lower() in self.config.ransomware_exts:
                st2 = self.ransom_ext.setdefault((host, proc), {"count": 0, "exts": set(), "evidence": []})
                st2["count"] += 1
                st2["exts"].add(m.group(1).lower())
                if len(st2["evidence"]) < self.config.evidence_sample_per_alert:
                    st2["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

        elif ev.action == A_OBJECT_DELETE:
            proc = ev.process or "-"
            st = self.deleteburst.setdefault((ev.host or "-", proc), {"count": 0, "evidence": []})
            st["count"] += 1
            if len(st["evidence"]) < self.config.evidence_sample_per_alert:
                st["evidence"].append((ev.ts, ev.source, ev.raw[: self.config.raw_line_max_len]))

    def finalize(self) -> list:
        if not self.enabled:
            return []
        for (host, cmd), st in self.cmd_hits.items():
            self._alert(1, st["count"], {"host": host, "process": cmd},
                        st["evidence"], st["first"], st["last"])
            self.alerts[-1].description = f"勒索预执行行为：{host} 上执行恢复破坏命令（{cmd}）"

        for (host, proc), st in sorted(self.fileburst.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= self.config.ransomware_filecreate_burst:
                self._alert(1, st["count"], {"host": host, "process": proc}, [], None, None)
                self.alerts[-1].description = (
                    f"文件创建突发：{host} 上 {proc} 在 {self.config.ransomware_filecreate_window_sec}s 内创建 "
                    f"{st['count']} 个文件（加密行为特征）")

        for (host, proc), st in sorted(self.ransom_ext.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= 3:
                self._alert(1, st["count"], {"host": host, "process": proc, "exts": sorted(st["exts"])},
                            st["evidence"], None, None)
                self.alerts[-1].description = (
                    f"勒索扩展名：{host} 上 {proc} 创建 {st['count']} 个 "
                    f"{'/'.join('.' + e for e in sorted(st['exts']))} 文件")

        for (host, proc), st in sorted(self.deleteburst.items(), key=lambda kv: -kv[1]["count"]):
            if st["count"] >= self.config.ransomware_filecreate_burst:
                self._alert(2, st["count"], {"host": host, "process": proc}, st["evidence"], None, None)
                self.alerts[-1].description = f"批量删除：{host} 上 {proc} 删除 {st['count']} 个对象"
        return self.alerts

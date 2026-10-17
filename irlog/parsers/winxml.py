"""Windows 安全事件 / Sysmon 解析器（Get-WinEvent 导出的 XML 格式）。

导出命令（在目标机上执行，取证只读）：
    Get-WinEvent -FilterHashtable @{LogName='Security','System';Id=...} |
      Export-Clixml -Path security.xml
或直接导出原生 XML：
    Get-WinEvent -LogName Security | ForEach-Object { $_.ToXml() } > security.xml

XML 中多个 <Event> 顺序拼接（无根节点），本解析器按边界增量流式解析，
不一次性载入整个文件。

事件 ID 归一化动作映射覆盖应急响应常用事件：
登录类 4624/4625/4634/4647/4648/4771；特权 4672；账号 4720/4722/4725/4726；
组变更 4728/4732/4756；进程 4688/4689；对象访问 4656/4663/4660/4670；
共享 5140；服务 4697/7045；计划任务 4698/4702。
Sysmon：1 进程创建 / 3 网络连接 / 7 镜像加载 / 10 进程访问 / 11 文件创建 / 12/13/14 注册表。
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Generator, Optional

from ..models import (
    Event,
    A_LOGON_FAILED, A_LOGON_SUCCESS, A_LOGON_SPECIAL, A_USER_CREATED,
    A_GROUP_MEMBER_ADDED, A_PROCESS_CREATE, A_FILE_CREATE, A_OBJECT_ACCESS,
    A_OBJECT_DELETE, A_SHARE_ACCESS, A_SERVICE_INSTALL, A_SCHEDULED_TASK,
    A_NETWORK_CONN, A_GENERIC,
)
from .base import LogParser, register

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# EventID -> (action, 简要说明)
EVENT_ACTIONS = {
    "4624": (A_LOGON_SUCCESS, "登录成功"),
    "4625": (A_LOGON_FAILED, "登录失败"),
    "4634": ("logon-logoff", "注销"),
    "4647": ("logon-logoff", "用户主动注销"),
    "4648": ("explicit-cred-logon", "显式凭据登录"),
    "4771": (A_LOGON_FAILED, "Kerberos 预认证失败"),
    "4672": (A_LOGON_SPECIAL, "分配特殊权限"),
    "4720": (A_USER_CREATED, "创建用户"),
    "4722": ("user-enabled", "启用用户"),
    "4725": ("user-disabled", "禁用用户"),
    "4726": ("user-deleted", "删除用户"),
    "4728": (A_GROUP_MEMBER_ADDED, "添加到全局组"),
    "4732": (A_GROUP_MEMBER_ADDED, "添加到本地组"),
    "4756": (A_GROUP_MEMBER_ADDED, "添加到通用组"),
    "4688": (A_PROCESS_CREATE, "进程创建"),
    "4689": ("process-exit", "进程退出"),
    "4656": (A_OBJECT_ACCESS, "请求对象句柄"),
    "4663": (A_OBJECT_ACCESS, "访问对象"),
    "4660": (A_OBJECT_DELETE, "删除对象"),
    "4670": ("permission-change", "修改对象权限"),
    "5140": (A_SHARE_ACCESS, "访问网络共享"),
    "4697": (A_SERVICE_INSTALL, "安装服务"),
    "7045": (A_SERVICE_INSTALL, "安装服务(系统日志)"),
    "4698": (A_SCHEDULED_TASK, "创建计划任务"),
    "4702": (A_SCHEDULED_TASK, "计划任务更新"),
    # Sysmon
    "1": (A_PROCESS_CREATE, "进程创建(Sysmon)"),
    "3": (A_NETWORK_CONN, "网络连接(Sysmon)"),
    "7": ("image-load", "镜像加载(Sysmon)"),
    "8": ("remote-thread", "远程线程注入(Sysmon)"),
    "10": ("process-access", "进程访问(Sysmon)"),
    "11": (A_FILE_CREATE, "文件创建(Sysmon)"),
    "12": ("registry-add", "注册表新增(Sysmon)"),
    "13": ("registry-set", "注册表修改(Sysmon)"),
    "14": ("registry-rename", "注册表重命名(Sysmon)"),
}


def _text(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None or elem.text is None:
        return None
    t = elem.text.strip()
    return t or None


def _to_ts(system_time: str) -> Optional[float]:
    """'2024-01-01T12:00:00.123456Z' -> unix 秒。"""
    if not system_time:
        return None
    try:
        import datetime as _dt
        s = system_time.strip()
        if s.endswith("Z"):
            s = s[:-1]
        # 处理纳秒/微秒段
        if "." in s:
            base, frac = s.split(".", 1)
            frac = (frac + "000000")[:6]
            s = base + "." + frac
        dt = _dt.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _parse_event_xml(xml_text: str, source: str) -> Optional[Event]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    # 兼容带/不带命名空间的导出
    system = root.find(f"{NS}System")
    if system is None:
        system = root.find("System")
    if system is None:
        return None

    def _sys(tag: str) -> Optional[ET.Element]:
        el = system.find(f"{NS}{tag}")
        return el if el is not None else system.find(tag)

    event_id = _text(_sys("EventID")) or ""
    tc = _sys("TimeCreated")
    ts = _to_ts(tc.get("SystemTime") if tc is not None else None)
    computer = _text(_sys("Computer"))
    channel = _text(_sys("Channel"))

    data: dict[str, str] = {}
    ed = root.find(f"{NS}EventData")
    if ed is None:
        ed = root.find("EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data") or ed.findall("Data"):
            name = d.get("Name")
            val = _text(d)
            if name:
                data[name] = val or ""
            elif val:  # 无名 Data 按序号存
                data[f"_d{len(data)}"] = val

    action, desc = EVENT_ACTIONS.get(event_id, (A_GENERIC, f"事件 {event_id}"))
    ev = Event(
        ts=ts,
        log_type="sysmon" if event_id in ("1", "3", "7", "8", "10", "11", "12", "13", "14") else "winsec",
        source=source,
        event_id=event_id,
        action=action,
        host=computer or channel,
        detail=data,
        raw=xml_text[:4000],
    )

    # 常用字段抽取
    ev.user = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User")
    ev.src_ip = data.get("IpAddress") or data.get("SourceIp") or data.get("SourceAddress")
    if ev.src_ip in ("-", "::1", "127.0.0.1", ""):
        ev.src_ip = None if ev.src_ip in ("-", "") else ev.src_ip
    ev.dst_ip = data.get("DestinationIp") or data.get("DestAddress")
    ev.logon_type = data.get("LogonType") or data.get("Logon_Type")
    ev.process = data.get("NewProcessName") or data.get("Image") or data.get("ProcessName")
    ev.parent_process = data.get("ParentProcessName") or data.get("ParentImage")
    ev.file_path = data.get("TargetFilename") or data.get("ObjectName") or data.get("TargetObject")
    ev.hashes = data.get("Hashes")
    ev.uri = data.get("RequestURL") or data.get("Uri")
    ev.detail["_desc"] = desc
    return ev


class WindowsXmlParser(LogParser):
    """支持多个 <Event> 拼接的 XML 流（Get-WinEvent ToXml 导出）。"""

    name = "winxml"

    def detect(self, sample_lines: list[str]) -> bool:
        head = "\n".join(sample_lines[:50])
        return "<Event" in head and "xmlns" in head and ("EventID" in head or "<System>" in head)

    def parse(self, path: str) -> Generator[Event, None, None]:
        """按 <Event> ... </Event> 边界增量切分流式解析。

        支持一行内多个事件（Export-Clixml 常见）与多行单事件。
        """
        pending = ""
        started = False
        for line in self.read_lines(path):
            rest = line
            while rest:
                if not started:
                    i = rest.find("<Event")
                    if i == -1:
                        break
                    rest = rest[i:]
                    started = True
                    pending = ""
                j = rest.find("</Event>")
                if j == -1:
                    pending += rest + "\n"
                    break
                pending += rest[:j] + "</Event>"
                ev = _parse_event_xml(pending, path)
                if ev is not None:
                    yield ev
                started = False
                pending = ""
                rest = rest[j + len("</Event>"):]
        # 容忍文件末尾被截断的事件
        if started and pending.strip():
            ev = _parse_event_xml(pending + "</Event>", path)
            if ev is not None:
                yield ev


register(WindowsXmlParser())

"""应急响应处置方案生成器。

把"检测结论"翻译成"可执行的动作" —— 应急处置最怕报告写完了没人知道下一步做什么，
因此本模块输出的是分阶段、带优先级、带具体命令、并注明依据（来自哪条告警）的行动清单。

阶段划分遵循国标 GB/T 30276 / NIST SP 800-61 的四段式：
    准备与确认 -> 遏制（Containment）-> 根除（Eradication）-> 恢复（Recovery）-> 加固复盘
"""
from __future__ import annotations

import re
import time
from typing import Optional

PHASES = [
    ("confirm", "第 0 阶段 · 事件确认与取证保全", "确认攻击是否真实成功，固化证据，避免破坏现场"),
    ("contain", "第 1 阶段 · 紧急遏制（0~2 小时）", "切断攻击者当前的控制与横向通道，止血"),
    ("eradicate", "第 2 阶段 · 根除清除（2~24 小时）", "清除后门、漏洞入口与持久化，夺回控制权"),
    ("recover", "第 3 阶段 · 恢复与验证（24~72 小时）", "恢复业务并验证无残留后门"),
    ("harden", "第 4 阶段 · 加固与复盘（事后）", "补齐防护短板，形成检测与响应闭环"),
]

P_LABEL = {0: "P0-立即", 1: "P1-2小时内", 2: "P2-24小时内", 3: "P3-一周内"}


def _fmt_ts(ts) -> str:
    if ts is None:
        return "未知时间"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (ValueError, OverflowError, OSError, TypeError):
        return str(ts)


class Facts:
    """从分析结果中抽取的研判事实（供动作生成条件判断）。"""

    def __init__(self, result) -> None:
        self.result = result
        alerts = result.alerts
        q = result.quiz or {}
        self.quiz = q
        self.top_shell = q.get("top_shell")
        self.top_upload = q.get("top_upload")
        self.web = result.web_stats or {}

        self.webshells = [a for a in alerts if a.rule_id in ("webshell", "upload_exploit")]
        self.upload_chain = [a for a in alerts if a.rule_id == "upload_exploit"]
        self.shell_clients = [a for a in alerts
                              if a.rule_id == "tooling"
                              and a.entities.get("类别") == "Webshell客户端"]
        self.scanners = [a for a in alerts
                         if a.rule_id == "tooling" and a.entities.get("类别") != "Webshell客户端"]
        self.admin_logins = [a for a in alerts if a.rule_id == "admin_login"]
        self.web_attacks = [a for a in alerts if a.rule_id == "web-attack"]
        self.brutes = [a for a in alerts if a.rule_id == "brute-force"]
        self.account_abuse = [a for a in alerts if a.rule_id == "account-abuse"]
        self.exfil = [a for a in alerts if a.rule_id == "exfiltration"]
        self.ransom = [a for a in alerts if a.rule_id == "ransomware"]

        # 攻击者 IP：优先取"已成功控制"的来源，其次取最活跃的
        ips = {}
        for a in self.shell_clients + self.upload_chain + self.webshells:
            ip = a.entities.get("src_ip") or a.entities.get("来源IP")
            if isinstance(ip, list):
                for x in ip:
                    ips[x] = ips.get(x, 0) + 1000
            elif ip:
                ips[ip] = ips.get(ip, 0) + 1000
        for a in self.scanners + self.web_attacks + self.admin_logins:
            ip = a.entities.get("src_ip")
            if ip:
                ips[ip] = ips.get(ip, 0) + a.count
        for item in self.web.get("top_src_ip", [])[:10]:
            ips[item["ip"]] = ips.get(item["ip"], 0) + item["count"] // 1000
        self.attacker_ips = [ip for ip, _ in sorted(ips.items(), key=lambda kv: -kv[1])]

        self.hosts = []
        for a in alerts:
            h = a.entities.get("host")
            if h and h not in self.hosts:
                self.hosts.append(h)

    # ---- 结论级判断 ----
    @property
    def compromised(self) -> bool:
        return bool(self.upload_chain or self.shell_clients)

    @property
    def severity(self) -> str:
        if self.compromised:
            return "特别重大（已确认失陷：存在 Webshell/上传利用链）"
        if self.webshells or self.admin_logins:
            return "重大（高度疑似失陷，需人工确认）"
        if self.scanners or self.web_attacks:
            return "较大（存在自动化攻击与漏洞探测）"
        return "一般（未发现明确攻击成功迹象）"


def _cmds(*items: str) -> list:
    return [c for c in items if c]


def build_plan(result) -> dict:
    f = Facts(result)
    actions: list = []

    def add(phase: str, prio: int, title: str, detail: str,
            commands: Optional[list] = None, basis: Optional[list] = None) -> None:
        actions.append({
            "phase": phase, "priority": prio, "priority_label": P_LABEL.get(prio, str(prio)),
            "title": title, "detail": detail,
            "commands": commands or [], "basis": basis or [],
        })

    # ---------------- 第 0 阶段 ----------------
    add("confirm", 0, "固化证据并保全日志",
        "在动手清理前先固化证据：对原始日志、Web 目录、数据库做只读快照并计算哈希，"
        "确保后续溯源与司法取证可用；全程只读，禁止在原盘上直接删改。",
        _cmds("# 计算证据哈希（工具自带）",
              "python -m irlog hash <日志文件> <Web根目录副本>",
              "# Windows 目录快照（只读复制，保留时间戳）",
              "robocopy C:\\inetpub\\wwwroot D:\\IR\\snapshot\\wwwroot /E /COPY:DAT /R:0 /W:0 /LOG:D:\\IR\\copy.log",
              "# 导出 IIS 配置与站点清单",
              "%windir%\\system32\\inetsrv\\appcmd.exe list site /config /xml > D:\\IR\\iis-sites.xml"),
        ["取证保全（GB/T 30276 取证要求）"])

    if f.compromised:
        shell = f.top_shell or {}
        add("confirm", 0, "确认 Webshell 是否真实落盘并执行成功",
            (f"日志判定落盘脚本为 {shell.get('path', '未知')}（判定依据：{('；'.join(shell.get('reasons', [])) or '上传后首次出现且被交互')}）。"
             "需到服务器上核实文件是否存在、内容是否为木马、创建时间是否与日志吻合；"
             "若文件已不存在，需确认是被攻击者清理还是从未落盘成功。"),
            _cmds("# 定位文件（把日志里的 URL 路径换成物理路径后执行）",
                  "dir /a /t:c " + shell.get("path", "").replace("/", "\\") + "   # 按实际站点根目录替换",
                  "Get-ChildItem -Path C:\\inetpub\\wwwroot -Recurse -Include *.php,*.aspx,*.jsp "
                  "-File | Sort-Object CreationTime -Descending | Select-Object -First 50 "
                  "FullName,CreationTime,LastWriteTime,Length",
                  "# 计算哈希并留档",
                  "Get-FileHash -Algorithm SHA256 <文件路径> | Tee-Object -FilePath D:\\IR\\shell-hash.txt",
                  "# 查看内容（先复制副本再看，不要在原文件上用编辑器打开）",
                  "type <文件路径> | more"),
            [f"取证问答 Q4：{shell.get('file', '未知')}"] + [a.title for a in f.upload_chain][:3])
    else:
        add("confirm", 1, "人工复核是否存在攻击成功迹象",
            "未检测到「上传→落盘→利用」完整链路，但仍需结合主机侧日志（进程创建、计划任务、账号变更）"
            "与 Web 目录文件清单做一次交叉确认，排除漏报。",
            _cmds("# 排查近期新增/修改的脚本文件",
                  "Get-ChildItem C:\\inetpub\\wwwroot -Recurse -File | "
                  "Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | "
                  "Select-Object FullName,CreationTime,LastWriteTime"),
            ["检测结论：未发现完整利用链"])

    # ---------------- 第 1 阶段 ----------------
    if f.attacker_ips:
        add("contain", 0, "封禁攻击者来源 IP 并保留会话证据",
            "在防火墙/边界/主机防火墙三处同时封禁，防止清理期间攻击者继续操作或销毁痕迹；"
            "同时保留现有 TCP 连接与进程列表作为证据。",
            _cmds("# 查看当前连接（先取证）",
                  "netstat -ano | findstr /R \"" + " ".join(f.attacker_ips[:5]) + "\"",
                  "# Windows 防火墙入站封禁",
                  *[f"netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block "
                    f"remoteip={ip}" for ip in f.attacker_ips[:5]],
                  "# 临时下线站点（若业务允许）",
                  "%windir%\\system32\\inetsrv\\appcmd.exe stop site /site.name:\"<站点名>\""),
            [f"来源 IP：{', '.join(f.attacker_ips[:8])}"])

    if f.compromised:
        add("contain", 0, "隔离失陷主机并切断 Web 目录执行能力",
            "在确认落盘脚本后，优先用「禁用执行 + 保留文件」的方式止血（便于取证），"
            "不要直接删除——删早了会丢失证据且无法确认完整性；"
            "若业务可中断，直接隔离主机接入内网隔离区。",
            _cmds("# IIS 中移除该目录的脚本映射（禁止执行，保留文件）",
                  "%windir%\\system32\\inetsrv\\appcmd.exe set config \"<站点>/content/plugins\" "
                  "-section:system.webServer/handlers /-[name='PHP_via_FastCGI']",
                  "# 或临时改为只读 + 拒绝 Everyone 写入",
                  "icacls \"C:\\inetpub\\wwwroot\\content\\plugins\" /deny Everyone:(W) /T",
                  "# 抓取当时进程与子进程（WebShell 常派生 cmd/powershell）",
                  "wmic process where \"name='w3wp.exe' or name='php-cgi.exe'\" get "
                  "ProcessId,ParentProcessId,CommandLine",
                  "Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -in "
                  "(Get-Process w3wp,php-cgi -ErrorAction SilentlyContinue).Id } | "
                  "Select-Object ProcessId,Name,CommandLine"),
            [a.title for a in f.upload_chain][:3] or ["Webshell 检测"])

    if f.admin_logins:
        add("contain", 0, "重置后台与管理账号口令",
            "日志显示存在登录后台并访问管理页面的行为，需立即确认是否为授权运维；"
            "非授权则重置全部管理员口令、踢出在线会话并检查是否被新增/提权账号。",
            _cmds("# 强制下线全部会话（IIS/应用层按实际实现）",
                  "重启应用池：%windir%\\system32\\inetsrv\\appcmd.exe recycle apppool /apppool.name:<池名>",
                  "# 检查近期账号变更（Windows）",
                  "net user",
                  "wevtutil qe Security \"/q:*[System[(EventID=4720 or EventID=4726 or EventID=4732)]]\" "
                  "/f:text /c:50",
                  "# 应用后台用户表核查（emlog 为例）",
                  "SELECT uid,username,email,role FROM emlog_user ORDER BY uid DESC LIMIT 20;"),
            [a.description for a in f.admin_logins][:2])

    if f.scanners or f.web_attacks:
        add("contain", 1, "阻断自动化扫描与注入探测",
            "对扫描器/注入工具来源做限流或封禁，并在 WAF 侧开启对应规则集，"
            "避免清理期间被二次利用。",
            _cmds("# WAF/中间件：开启 SQLi、XSS、路径遍历、文件上传规则集",
                  "# 无 WAF 时在 IIS 用请求筛选阻断典型特征",
                  "%windir%\\system32\\inetsrv\\appcmd.exe set config /section:requestFiltering "
                  "/+denyUrlSequences.[sequence='../']",
                  "# 对单 IP 限速（IIS 动态 IP 限制）",
                  "%windir%\\system32\\inetsrv\\appcmd.exe set config -section:system.webServer/"
                  "security/dynamicIpSecurity /denyAction:Forbidden /maxRequests:30 /requestIntervalInMilliseconds:5000"),
            [a.description for a in (f.scanners + f.web_attacks)[:3]])

    # ---------------- 第 2 阶段 ----------------
    if f.compromised:
        shell = f.top_shell or {}
        add("eradicate", 0, "清除 Webshell 与攻击者落盘文件",
            f"删除 {shell.get('path', '落盘脚本')} 及其同目录可疑文件，删除前先备份副本并留哈希；"
            "随后全盘排查同类文件（按创建时间、按内容特征、按大小异常三种维度）。",
            _cmds("# 备份后删除",
                  "copy <文件路径> D:\\IR\\evidence\\  &&  del /f <文件路径>",
                  "# 按内容特征全盘排查一句话木马",
                  "findstr /S /M /I /C:\"eval(\" /C:\"assert(\" /C:\"base64_decode\" "
                  "/C:\"system(\" /C:\"passthru(\" C:\\inetpub\\wwwroot\\*.php",
                  "# PowerShell 版本（含 asp/aspx/jsp）",
                  "Get-ChildItem C:\\inetpub\\wwwroot -Recurse -File -Include *.php,*.asp,*.aspx,*.jsp | "
                  "Select-String -Pattern 'eval\\(|assert\\(|base64_decode|system\\(|passthru\\(|Runtime\\.|ProcessBuilder' "
                  "| Select-Object Path,LineNumber"),
            [f"取证问答 Q4：{shell.get('file', '未知')}"])

        add("eradicate", 0, "排查持久化与命令执行痕迹",
            "Webshell 落地后通常会做持久化：计划任务、服务、启动项、Web 目录外的可执行文件、"
            "以及 w3wp/php-cgi 派生的 cmd/powershell。此步不能省，否则删了马也会被重新种植。",
            _cmds("schtasks /query /fo LIST /v | findstr /I \"TaskName Status Author\"",
                  "Get-ScheduledTask | Where-Object { $_.Principal.UserId -match 'SYSTEM|Users' } | "
                  "Select-Object TaskName,TaskPath,State",
                  "sc query type= service state= all | findstr /I \"SERVICE_NAME\"",
                  "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location",
                  "wevtutil qe Security \"/q:*[System[(EventID=4688)]]\" /f:text /c:200 | findstr /I \"cmd.exe powershell\"",
                  "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ["Webshell 落地后的常见持久化路径"])

    if f.top_upload:
        up = f.top_upload
        add("eradicate", 0, "修复文件上传漏洞入口",
            f"上传漏洞路径判定为 {up.get('path', '未知')}（{('；'.join(up.get('reasons', []))[:120])}）。"
            "修复要点：关闭不必要的插件/模板在线安装功能；上传目录禁止脚本执行；"
            "强制白名单后缀 + 随机重命名 + 内容检测；并对上传接口加鉴权与速率限制。",
            _cmds("# 1) 关闭 CMS 的插件/模板在线安装（首选，能立刻止血）",
                  "# emlog：后台「插件」-> 禁用在线安装；或直接限制该接口访问",
                  "icacls \"C:\\inetpub\\wwwroot\\content\\plugins\" /deny \"IIS_IUSRS:(W)\" /T",
                  "# 2) 上传目录去执行权限（IIS 移除处理器映射）",
                  "%windir%\\system32\\inetsrv\\appcmd.exe set config \"<站点>/content\" "
                  "-section:system.webServer/handlers /-[name='PHP_via_FastCGI']",
                  "# 3) 升级 CMS 与插件到官方最新版，核对补丁说明是否覆盖该上传点",
                  "# 4) WAF 侧对上传接口加白名单校验与频率限制"),
            [f"取证问答 Q3：{up.get('path', '未知')}"] + [a.title for a in f.upload_chain][:2])

    if f.account_abuse or f.brutes:
        add("eradicate", 1, "核查账号与凭据安全",
            "对可疑账号做禁用/重置，检查是否存在新增管理员、隐藏账号、凭据复用，"
            "并推动口令策略与多因素认证。",
            _cmds("net user", "net localgroup administrators",
                  "wevtutil qe Security \"/q:*[System[(EventID=4720 or EventID=4728 or EventID=4732)]]\" /f:text /c:100"),
            [a.title for a in (f.account_abuse + f.brutes)[:3]])

    # ---------------- 第 3 阶段 ----------------
    add("recover", 1, "从可信备份恢复并验证业务",
        "优先用攻击发生前的时间点备份恢复 Web 目录与数据库；恢复后立即做完整性校验，"
        "确认无 Webshell 残留、无异常账号、无异常计划任务。",
        _cmds("# 校验恢复后目录（与已知干净基线比对）",
              "Get-ChildItem C:\\inetpub\\wwwroot -Recurse -File | Get-FileHash -Algorithm SHA256 | "
              "Export-Csv D:\\IR\\after-restore.csv -NoTypeInformation",
              "# 对比：fc D:\\IR\\baseline.csv D:\\IR\\after-restore.csv",
              "# 恢复后重启服务并观察",
              "%windir%\\system32\\inetsrv\\appcmd.exe start site /site.name:\"<站点名>\""),
        ["恢复验证"])

    add("recover", 2, "全量复查日志，确认无二次入侵",
        "恢复后重新跑一次日志分析，确认攻击者 IP 不再出现、上传接口不再被调用、"
        "落盘脚本不再被访问；同时把本次 IOC 加入长期监控。",
        _cmds("# 把 IOC 落库后重新分析",
              "python -m irlog scan <日志目录> --ioc ioc.txt --format cli,json,html",
              "# 定向复查关键词",
              "findstr /I /C:\"" + (f.top_shell or {}).get('file', 'shell') + "\" <日志文件>"),
        ["复查与监控"])

    # ---------------- 第 4 阶段 ----------------
    add("harden", 2, "补齐防护短板（上传/后台/WAF/日志）",
        "针对本次成因做针对性加固：上传白名单与去执行、后台强口令 + MFA + IP 白名单、"
        "WAF 规则集、目录权限最小化、PHP/中间件禁用危险函数。",
        _cmds("# PHP 禁用危险函数（php.ini）",
              "disable_functions = eval,assert,system,exec,passthru,shell_exec,popen,proc_open,pcntl_exec",
              "# 后台仅允许内网访问（IIS IP 限制）",
              "%windir%\\system32\\inetsrv\\appcmd.exe set config \"<站点>/admin\" "
              "-section:system.webServer/security/ipSecurity /allowUnlisted:false "
              "/+[ipAddress='192.168.0.0',subnetMask='255.255.0.0',allowed='true']",
              "# 目录权限最小化",
              "icacls \"C:\\inetpub\\wwwroot\" /inheritance:r /grant:r \"IIS_IUSRS:(RX)\""),
        ["加固基线"])

    add("harden", 3, "建立检测与响应闭环",
        "把本次攻击特征沉淀为检测规则与应急预案：日志集中留存不少于 6 个月、"
        "Web 目录文件完整性监控、上传接口告警、定期复盘演练。",
        _cmds("# 文件完整性监控（示例）",
              "Get-ChildItem C:\\inetpub\\wwwroot -Recurse -File | Get-FileHash | "
              "Export-Csv D:\\IR\\baseline.csv -NoTypeInformation",
              "# 定期基线比对（计划任务每日执行）",
              "schtasks /create /tn IR-FIM /tr \"powershell -File D:\\IR\\fim-diff.ps1\" /sc daily /st 02:00"),
        ["持续改进"])

    # ---- IOC 清单 ----
    iocs = []
    for ip in f.attacker_ips[:20]:
        iocs.append({"type": "ip", "value": ip, "note": "攻击来源 IP（按威胁度排序）"})
    if f.top_shell:
        iocs.append({"type": "file", "value": f.top_shell["path"],
                     "note": "疑似 Webshell 落盘路径"})
        for ua in f.top_shell.get("uas", [])[:4]:
            iocs.append({"type": "user-agent", "value": ua, "note": "Webshell 客户端 UA"})
    if f.top_upload:
        iocs.append({"type": "path", "value": f.top_upload["path"], "note": "存在上传漏洞的接口"})
    for a in f.scanners[:10]:
        iocs.append({"type": "user-agent", "value": str(a.entities.get("UA样本", "")),
                     "note": f"扫描器/工具 UA（{a.entities.get('工具', '')}）"})
    seen = set()
    uniq = []
    for i in iocs:
        k = (i["type"], i["value"])
        if k in seen or not i["value"]:
            continue
        seen.add(k)
        uniq.append(i)

    # ---- 关键时间线 ----
    milestones = []
    for a in (f.upload_chain + f.shell_clients)[:5]:
        milestones.append({"time": _fmt_ts(a.first_ts), "event": a.title,
                           "detail": a.description, "severity": a.severity})
    if f.admin_logins:
        a = f.admin_logins[0]
        milestones.append({"time": _fmt_ts(a.first_ts), "event": "后台登录成功",
                           "detail": a.description, "severity": a.severity})
    if f.top_upload and f.top_upload.get("first_ts"):
        milestones.append({"time": _fmt_ts(f.top_upload["first_ts"]),
                           "event": "首次出现上传动作", "detail": f.top_upload["path"],
                           "severity": 1})
    if f.top_shell and f.top_shell.get("first_ts"):
        milestones.append({"time": _fmt_ts(f.top_shell["first_ts"]),
                           "event": "Webshell 首次被访问", "detail": f.top_shell["path"],
                           "severity": 1})
    milestones.sort(key=lambda m: m["time"])

    phases = []
    for key, title, goal in PHASES:
        items = sorted([a for a in actions if a["phase"] == key], key=lambda x: x["priority"])
        if not items:
            continue
        phases.append({"key": key, "title": title, "goal": goal, "actions": items})

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "run_id": result.run_id,
        "severity": f.severity,
        "compromised": f.compromised,
        "summary": {
            "攻击是否成功": "是（存在完整上传利用链 / Webshell 通信）" if f.compromised
                       else ("待确认（有攻击行为但未确认利用成功）" if (f.webshells or f.admin_logins) else "未发现"),
            "攻击者IP": f.attacker_ips[:10],
            "上传漏洞路径": (f.top_upload or {}).get("path"),
            "Webshell文件": (f.top_shell or {}).get("file"),
            "Webshell路径": (f.top_shell or {}).get("path"),
            "告警总数": len(result.alerts),
            "分析事件数": result.stats.get("total_events", 0),
        },
        "ioc": uniq,
        "milestones": milestones,
        "phases": phases,
    }

"""应急响应处置知识库（Playbook）。

把检测告警转成「可执行的响应动作」：
    告警 → 平台判定 → 四阶段剧本（核查 / 遏制 / 证据固定 / 根除）→ 实体回填

设计原则：
- **纯数据驱动**：命令全部在 PLAYBOOKS 里，改命令不动代码，方便自行扩充
- **只读定位**：本模块只产出「给人复制执行的命令文本」，工具自身绝不执行
- **实体回填**：模板用 {ip} {user} {host} {uri} {file} {port} {process} 占位，
  按告警 entities 自动填充；取不到时填 <IP> 等占位提示，由分析人员替换
- **四阶段顺序不可颠倒**：先核查（防误报误处置）→ 再遏制（止血）→ 再固定证据
  （否则直接杀进程/删文件会毁掉溯源线索）→ 最后根除恢复

占位符一览：
    {ip}       攻击源 IP / 外联 IP
    {user}     涉事账号
    {host}     涉事主机
    {uri}      URL / 文件路径
    {file}     文件路径
    {process}  进程名 / 进程路径
    {port}     端口
    {domain}   域名
"""
from __future__ import annotations

from typing import Optional

from .models import Alert

# ---------------------------------------------------------------------------
# 阶段定义
# ---------------------------------------------------------------------------
STAGES = [
    ("verify", "阶段① 核查确认",
     "先确认告警是真实命中还是误报。没核实就断网/禁账号，业务部门会来找你。"),
    ("contain", "阶段② 遏止血",
     "确认后立刻限制影响面。顺序：断外联 → 禁账号 → 隔离主机；除勒索扩散外，别先关机。"),
    ("preserve", "阶段③ 证据固定",
     "处置动作会毁掉内存与日志线索，动之前先把易失证据取走（内存镜像、进程列表、日志导出）。"),
    ("eradicate", "阶段④ 根除恢复",
     "清后门、补漏洞、重置凭据。凭据一律按「已泄露」处理，全量轮换。"),
]

STAGE_LABELS = {k: label for k, label, _hint in STAGES}
STAGE_HINTS = {k: hint for k, _label, hint in STAGES}

# 平台标签
PLATFORM_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "web": "Web / 中间件",
    "db": "数据库",
    "net": "网络",
}

# 日志类型 → 平台
LOG_TYPE_PLATFORMS = {
    "winxml": {"windows"},
    "sysmon": {"windows"},
    "linux-auth": {"linux"},
    "linux-syslog": {"linux"},
    "iis": {"web"},
    "web-access": {"web"},
    "database": {"db"},
    "pcap": {"net"},
}

# 已知占位符 → 取不到时的提示文本
PLACEHOLDERS = {
    "ip": "<IP>", "user": "<账号>", "host": "<主机名>", "uri": "<URL>",
    "file": "<文件路径>", "process": "<进程>", "port": "<端口>",
    "domain": "<域名>", "dst": "<外联IP>",
}


# ---------------------------------------------------------------------------
# 知识库：rule_id -> 平台 -> 阶段 -> [{"cmd": ..., "note": ...}]
# ---------------------------------------------------------------------------
PLAYBOOKS: dict = {

    # =====================================================================
    # 1. 暴破
    # =====================================================================
    "brute-force": {
        "windows": {
            "verify": [
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 | "
                         "Where-Object {$_.Message -match '{ip}'} | "
                         "Select-Object TimeCreated, @{n='账号';e={$_.Properties[5].Value}}, "
                         "@{n='来源IP';e={$_.Properties[19].Value}}",
                 "note": "确认 4625 失败登录是否全部来自同一 IP；同时看有没有夹带 4624 成功登录"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 | "
                         "Where-Object {$_.Message -match '{ip}'}",
                 "note": "**关键**：若同一 IP 先大量 4625 后出现 4624，说明口令已被打穿，按入侵处置"},
            ],
            "contain": [
                {"cmd": "netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block remoteip={ip}",
                 "note": "在边界/主机防火墙封禁来源 IP，先止血"},
                {"cmd": "Disable-ADAccount -Identity '{user}'",
                 "note": "命中账号先禁用（不是删除，删除会丢 SID 与审计关联）；确认是正常用户再恢复"},
                {"cmd": "net localgroup administrators",
                 "note": "查看本机管理员组成员是否被塞进了陌生账号"},
            ],
            "preserve": [
                {"cmd": "wevtutil epl Security C:\\ir\\{host}-security.evtx",
                 "note": "导出安全日志留证；随后拷贝到取证盘，别只留在染毒主机上"},
                {"cmd": "Get-Process | Out-File C:\\ir\\{host}-proclist.txt",
                 "note": "快照进程列表，作为后续比对基线"},
            ],
            "eradicate": [
                {"cmd": "Set-ADAccountPassword -Identity '{user}' -Reset",
                 "note": "命中账号改密；若命中域管，按域内全量失陷处理"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732,4728} | "
                         "Where-Object {$_.Message -match '{ip}'}",
                 "note": "查暴破成功后是否被加进管理员组/特权组"},
                {"cmd": "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable",
                 "note": "确保登录审计已开，避免下次无日志可查"},
            ],
        },
        "linux": {
            "verify": [
                {"cmd": "grep -E 'Failed password.*{ip}' /var/log/auth.log /var/log/secure 2>/dev/null | tail -50",
                 "note": "统计失败登录次数与目标账号"},
                {"cmd": "grep -E 'Accepted (password|publickey).*{ip}' /var/log/auth.log /var/log/secure 2>/dev/null",
                 "note": "**关键**：同一 IP 出现 Accepted 即视为口令失陷"},
            ],
            "contain": [
                {"cmd": "iptables -A INPUT -s {ip} -j DROP",
                 "note": "封禁来源 IP（持久化需再写入 iptables-save / firewalld）"},
                {"cmd": "passwd -l '{user}'",
                 "note": "锁定涉事账号；若为服务账号需先确认影响面"},
                {"cmd": "who && w",
                 "note": "看当前是否仍在线，在线的话先踢会话"},
            ],
            "preserve": [
                {"cmd": "mkdir -p /var/tmp/ir && cp /var/log/auth.log* /var/tmp/ir/",
                 "note": "先拷贝认证日志再清理，避免轮转覆盖"},
                {"cmd": "ss -tunap > /var/tmp/ir/{host}-ss.txt; ps auxww > /var/tmp/ir/{host}-ps.txt",
                 "note": "网络连接与进程快照，供后续溯源"},
            ],
            "eradicate": [
                {"cmd": "grep -E '{user}' /etc/passwd /etc/shadow",
                 "note": "确认账号是否被新建/改写；陌生 UID 0 账号 = 后门"},
                {"cmd": "cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null",
                 "note": "清理 SSH 公钥后门，这是 Linux 横向移动最常见入口"},
                {"cmd": "awk -F: '$3==0 {print}' /etc/passwd",
                 "note": "查 UID 0 的隐藏管理员账号"},
            ],
        },
    },

    # =====================================================================
    # 2. Webshell
    # =====================================================================
    "webshell": {
        "web": {
            "verify": [
                {"cmd": "grep -rn '{uri}' /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | tail -30",
                 "note": "看该 URI 的访问记录：谁访问的、UA 是什么、返回码与响应大小"},
                {"cmd": "find / -path /proc -prune -o -newermt '-7 days' -name '*.php' -print 2>/dev/null | head -50",
                 "note": "按时间找 Web 目录下最近新增的 PHP 文件，比对发布时间与上线时间"},
            ],
            "contain": [
                {"cmd": "chmod 000 <webshell文件路径>",
                 "note": "先摘权限而不是直接删——文件内容是溯源攻击者意图的关键证据"},
                {"cmd": "iptables -A INPUT -s {ip} -j DROP",
                 "note": "封禁确认的攻击来源 IP"},
            ],
            "preserve": [
                {"cmd": "cp <webshell文件路径> /var/tmp/ir/webshell-$(date +%F).php && sha256sum /var/tmp/ir/webshell-*.php",
                 "note": "留存 Webshell 本体并算哈希，用于 IOC 比对与后续举证"},
            ],
            "eradicate": [
                {"cmd": "rm -f <webshell文件路径>",
                 "note": "取证完成后再删除"},
                {"cmd": "grep -rn 'eval\\|assert\\|system\\|passthru\\|shell_exec' <web根目录> --include='*.php' 2>/dev/null | head -30",
                 "note": "全站扫一遍同类函数，攻击者通常不只丢一个"},
                {"cmd": "find <web根目录> -name '*.php' -perm -o+w -ls",
                 "note": "查可写目录，确认上传点是否收敛"},
            ],
        },
        "windows": {
            "verify": [
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 300 | "
                         "Where-Object {$_.Message -match '{process}'} | "
                         "Select-Object TimeCreated, @{n='新进程';e={$_.Properties[8].Value}}, "
                         "@{n='命令行';e={$_.Properties[8].Value}}",
                 "note": "确认 Web 进程（w3wp/IIS 应用池）是否真的派生了 shell"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040,7045} | Select-Object -Last 30",
                 "note": "看是否注册了可疑服务做持久化"},
            ],
            "contain": [
                {"cmd": "Stop-WebAppPool -Name '<应用池名>'",
                 "note": "先停应用池切断 Webshell 执行入口，保留站点静态页面"},
                {"cmd": "netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block remoteip={ip}",
                 "note": "封禁来源 IP"},
            ],
            "preserve": [
                {"cmd": "Get-CimInstance Win32_Process | Where-Object {$_.Name -match '{process}'} | "
                         "Select-Object ProcessId, Name, CommandLine | Format-List",
                 "note": "记录 Webshell 进程与完整命令行，删除前先取证"},
                {"cmd": "wevtutil epl Security C:\\ir\\{host}-security.evtx; wevtutil epl System C:\\ir\\{host}-system.evtx",
                 "note": "导出安全与系统日志"},
            ],
            "eradicate": [
                {"cmd": "Get-ChildItem -Recurse <web根目录> -Include *.aspx,*.ashx,*.asmx | "
                         "Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-14)}",
                 "note": "IIS 下按时间找近期新增的 aspx/ashx 处理文件"},
                {"cmd": "Remove-Item <webshell文件路径> -Force",
                 "note": "取证完成后删除文件"},
                {"cmd": "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}",
                 "note": "清理计划任务持久化"},
            ],
        },
    },

    # =====================================================================
    # 3. Web 攻击（注入 / 扫描 / 路径穿越）
    # =====================================================================
    "web-attack": {
        "web": {
            "verify": [
                {"cmd": "grep -F '{uri}' /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | tail -30",
                 "note": "看请求量、UA、返回码：404 居多=扫描器，200 且返回异常大=可能真打进去了"},
                {"cmd": "awk '{print $9}' <access.log> | sort | uniq -c | sort -rn | head",
                 "note": "统计响应码分布，快速判断扫描与成功边界"},
            ],
            "contain": [
                {"cmd": "iptables -A INPUT -s {ip} -j DROP",
                 "note": "封禁扫描/注入来源"},
                {"cmd": "nginx -t && nginx -s reload",
                 "note": "加载 WAF 规则后重载（先确认配置无误）"},
            ],
            "preserve": [
                {"cmd": "cp <access.log> /var/tmp/ir/access-$(date +%F).log",
                 "note": "原始访问日志留证，别在机器上直接清"},
            ],
            "eradicate": [
                {"cmd": "grep -rn \" UNION \\| SELECT \\| or 1=1 \\| sleep(\\| benchmark(\" <access.log> | wc -l",
                 "note": "量化注入尝试规模，确认是否已被利用"},
                {"cmd": "mysql -e \"SELECT * FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys');\"",
                 "note": "数据库侧确认是否有多余表（注入常见落地）"},
                {"cmd": "补丁/升级受影响组件，并开启参数化查询与统一错误页",
                 "note": "根因修复：关闭详细报错、禁用危险函数、收敛权限"},
            ],
        },
    },

    # =====================================================================
    # 3b. 多阶段攻击链（登录 → 上传 → 后门落地 → 交互）
    # =====================================================================
    "attack-chain": {
        "web": {
            "verify": [
                {"cmd": "grep -F '{uri}' /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | tail -50",
                 "note": "还原整条链：登录成功 → 上传接口 → 落地的脚本文件被反复 POST"},
                {"cmd": "grep -E 'POST .*(upload|admin)' <access.log> | tail -30",
                 "note": "圈出上传动作与后台管理请求，定位落地文件与攻击时间窗口"},
            ],
            "contain": [
                {"cmd": "iptables -A INPUT -s {ip} -j DROP",
                 "note": "封禁攻击来源 IP，先止血"},
                {"cmd": "chmod 000 <webshell文件路径>; mv <webshell文件路径> /var/tmp/ir/webshell-$(date +%F).bak",
                 "note": "把落地的脚本文件立刻降权并移出 web 目录（先留证再处理）"},
            ],
            "preserve": [
                {"cmd": "cp <access.log> /var/tmp/ir/access-$(date +%F).log && sha256sum /var/tmp/ir/access-*.log",
                 "note": "原始访问日志留证，记录攻击者 IP 与落地时间窗"},
                {"cmd": "cp <webshell文件路径> /var/tmp/ir/webshell-$(date +%F).php && sha256sum /var/tmp/ir/webshell-*.php",
                 "note": "webshell 本体留证（切勿在 web 目录内直接删除）"},
            ],
            "eradicate": [
                {"cmd": "rm -f <webshell文件路径>",
                 "note": "确认已留证后彻底移除后门文件"},
                {"cmd": "grep -Rin 'eval(\\|base64_decode\\|assert(' <webroot>/ 2>/dev/null | head",
                 "note": "排查是否还有其它后门/一句话木马"},
                {"cmd": "重置后台/数据库账号口令，并审计近期所有上传与会话记录",
                 "note": "根因修复：修补上传功能（限制类型/落地目录/鉴权），复核后台鉴权逻辑"},
            ],
        },
        "windows": {
            "verify": [
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 500 | "
                         "Where-Object {$_.Message -match '{ip}'}",
                 "note": "若链路上出现 Windows 主机，确认该 IP 是否登录成功"},
            ],
            "contain": [
                {"cmd": "netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block remoteip={ip}",
                 "note": "在边界/主机防火墙封禁来源 IP"},
            ],
            "preserve": [
                {"cmd": "wevtutil epl Security C:\\var\\tmp\\ir\\Sec-$(Get-Date -Format yyyyMMdd).evtx",
                 "note": "安全日志留证"},
            ],
            "eradicate": [
                {"cmd": "撤销被加入特权组的账号，并重置相关凭据",
                 "note": "根因修复：收敛后台入口与上传权限"},
            ],
        },
    },

    # =====================================================================
    # 4. 异常账号
    # =====================================================================
    "account-abuse": {
        "windows": {
            "verify": [
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4728,4732,4756} -MaxEvents 100",
                 "note": "看账号是否被新建/启用/加入特权组"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 300 | "
                         "Where-Object {$_.Message -match '{ip}'}",
                 "note": "若告警带来源 IP，查该 IP 是否成功登录过（成功登录=凭据已失陷）"},
                {"cmd": "Get-ADUser -Filter * -Properties LastLogonDate,WhenCreated | "
                         "Sort-Object LastLogonDate -Descending | Select -First 20",
                 "note": "列出最近活跃与最新创建的账号"},
            ],
            "contain": [
                {"cmd": "Disable-ADAccount -Identity '{user}'",
                 "note": "禁用账号（保留对象以便取证）"},
                {"cmd": "Get-ADGroupMember -Identity 'Domain Admins' | Select Name,SamAccountName",
                 "note": "核对域管组成员，逐条确认是否合理"},
            ],
            "preserve": [
                {"cmd": "Get-ADUser -Identity '{user}' -Properties * | Export-Clixml C:\\ir\\{user}-ad.xml",
                 "note": "导出账号属性快照，含最后登录时间与密码策略"},
                {"cmd": "wevtutil epl Security C:\\ir\\{host}-security.evtx",
                 "note": "导出安全日志"},
            ],
            "eradicate": [
                {"cmd": "Remove-ADUser -Identity '{user}' -Confirm:$false",
                 "note": "确认非业务账号后删除"},
                {"cmd": "Set-ADAccountPassword -Identity '{user}' -Reset -ChangePasswordAtLogon $true",
                 "note": "所有涉事账号强制改密并要求下次登录修改"},
                {"cmd": "Get-ADObject -Filter * -SearchBase 'CN=AdminSDHolder,CN=System,DC=<域名>' | fl",
                 "note": "检查 AdminSDHolder 是否被篡改（域控持久化常用手法）"},
            ],
        },
        "linux": {
            "verify": [
                {"cmd": "lastlog | head -30; last '{user}' | head -20",
                 "note": "看账号最近登录时间与来源"},
                {"cmd": "awk -F: '$3==0 || $3>=1000 {print $1, $3, $7}' /etc/passwd",
                 "note": "列出可登录账号，重点看 shell 非 nologin 的"},
            ],
            "contain": [
                {"cmd": "usermod -L '{user}' && usermod -s /sbin/nologin '{user}'",
                 "note": "锁账号并禁登录 shell"},
            ],
            "preserve": [
                {"cmd": "getent passwd > /var/tmp/ir/passwd.txt; getent shadow > /var/tmp/ir/shadow.txt; chmod 600 /var/tmp/ir/shadow.txt",
                 "note": "账号数据库快照（shadow 权限收紧）"},
            ],
            "eradicate": [
                {"cmd": "userdel -r '{user}'",
                 "note": "确认非业务账号后连同家目录删除"},
                {"cmd": "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#'",
                 "note": "清理 sudo 提权后门"},
            ],
        },
    },

    # =====================================================================
    # 5. 数据外传
    # =====================================================================
    "exfiltration": {
        "net": {
            "verify": [
                {"cmd": "tshark -r <抓包文件> -q -z conv,tcp 2>/dev/null | sort -k3 -rn | head -20",
                 "note": "看哪些会话传输字节数最大，定位外联目标"},
                {"cmd": "tshark -r <抓包文件> -Y 'ip.addr=={dst}' -T fields -e frame.time -e tcp.len 2>/dev/null | head -30",
                 "note": "确认该 IP 的传输量与时间分布，判断是业务同步还是外传"},
            ],
            "contain": [
                {"cmd": "在边界防火墙/交换机 ACL 拒绝到外联目标 {dst} 的出向连接",
                 "note": "先断外联通道；若该外联 IP 是云存储，需确认是否为业务 API"},
                {"cmd": "tshark -r <抓包文件> -Y 'ip.addr=={dst} && http.request' -T fields -e http.host -e http.request.uri | head",
                 "note": "看请求的 Host 与路径，判断上传目的地"},
            ],
            "preserve": [
                {"cmd": "cp <抓包文件> /var/tmp/ir/exfil-$(date +%F).pcap && sha256sum /var/tmp/ir/exfil-*.pcap",
                 "note": "抓包文件是外传定性的核心证据，务必留存并算哈希"},
            ],
            "eradicate": [
                {"cmd": "对 {dst} 做威胁情报比对（微步 / VirusTotal / 内部 IOC 库）",
                 "note": "确认 IP 归属与恶意标签"},
                {"cmd": "全面排查失陷主机上的外传通道：DNS 隧道、云盘、邮件、Rclone",
                 "note": "外传通常不止一条通道，需逐条封堵"},
            ],
        },
        "linux": {
            "verify": [
                {"cmd": "ss -tunap | grep -E '{ip}|ESTAB' | head -20",
                 "note": "查当前到可疑 IP 的连接与所属进程"},
                {"cmd": "grep -rn '{ip}' /var/log/ 2>/dev/null | head -20",
                 "note": "在系统与中间件日志中定位该 IP 的痕迹"},
            ],
            "contain": [
                {"cmd": "iptables -A OUTPUT -d {ip} -j DROP",
                 "note": "阻断出向连接"},
            ],
            "preserve": [
                {"cmd": "tar czf /var/tmp/ir/{host}-logs.tgz /var/log 2>/dev/null",
                 "note": "打包日志留证"},
            ],
            "eradicate": [
                {"cmd": "crontab -l; ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null",
                 "note": "清理用于持续外传的定时任务"},
                {"cmd": "轮换该主机所有凭据（含数据库口令、API Key、SSH 私钥）",
                 "note": "外传意味着凭据可能已泄露"},
            ],
        },
    },

    # =====================================================================
    # 6. 勒索
    # =====================================================================
    "ransomware": {
        "windows": {
            "verify": [
                {"cmd": "Get-ChildItem -Recurse <受影响目录> -Include *.{加密后缀} | Measure-Object | Select Count",
                 "note": "统计加密文件规模，确认是否已大规模扩散"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 | "
                         "Where-Object {$_.Message -match 'vssadmin|wbadmin|bcdedit|wmic.*shadowcopy'}",
                 "note": "查是否执行过删卷影/破坏备份的命令，这是勒索典型前置动作"},
            ],
            "contain": [
                {"cmd": "立即隔离主机：拔网线 / 交换机端口 shutdown / 防火墙入向全禁",
                 "note": "**最高优先级**：勒索靠 SMB/域内横向扩散，晚一分钟多一批机器中招"},
                {"cmd": "Disable-ADAccount -Identity '<横向移动所用账号>'",
                 "note": "禁用被利用的域账号，切断域内扩散路径"},
                {"cmd": "停止并禁用受影响服务器的 SQL/文件服务共享，仅保留取证所需端口",
                 "note": "收敛横向移动面"},
            ],
            "preserve": [
                {"cmd": "Get-Process | Out-File C:\\ir\\{host}-proclist.txt; "
                         "Get-CimInstance Win32_Process | Select ProcessId,CommandLine | "
                         "Export-Csv C:\\ir\\{host}-cmdline.csv",
                 "note": "勒索进程与命令行是识别家族的关键"},
                {"cmd": "Copy-Item '<勒索信文件>' C:\\ir\\ ; Copy-Item <加密样本文件> C:\\ir\\sample-encrypted",
                 "note": "留存勒索信与一个加密样本（**不要**急着删，解密与溯源都要用）"},
                {"cmd": "winpmem_mini_x64.exe C:\\ir\\{host}-mem.raw  （或按预案采集内存镜像）",
                 "note": "内存中可能残留密钥或未加密载荷"},
            ],
            "eradicate": [
                {"cmd": "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}; "
                         "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                 "note": "清理持久化启动项"},
                {"cmd": "用备份恢复：先断网恢复 → 打补丁 → 再上线",
                 "note": "恢复顺序不能反，否则刚恢复又被感染"},
                {"cmd": "全量轮换域内所有账号口令与计算机账号口令",
                 "note": "勒索意味着域凭据已失陷"},
            ],
        },
    },

    # =====================================================================
    # 7. 命令混淆 / 编码命令
    # =====================================================================
    "command-obfuscation": {
        "windows": {
            "verify": [
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 | "
                         "Where-Object {$_.Message -match '{process}'} | "
                         "Select TimeCreated, @{n='命令行';e={$_.Properties[8].Value}}",
                 "note": "看完整命令行与父进程：父进程是 winword/outlook 基本可确认是钓鱼"},
                {"cmd": "Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -match '-enc|-e \\|FromBase64String|iex|Invoke-Expression'}",
                 "note": "当前仍在运行的混淆命令进程"},
            ],
            "contain": [
                {"cmd": "Stop-Process -Id <PID> -Force",
                 "note": "先终止进程，再查落地文件"},
                {"cmd": "netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block remoteip={ip}",
                 "note": "封禁关联 C2 IP"},
            ],
            "preserve": [
                {"cmd": "Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine | "
                         "Export-Csv C:\\ir\\{host}-proc.csv",
                 "note": "完整进程与父子关系快照，用于还原执行链"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} | "
                         "Where-Object {$_.Message -match '{process}'}",
                 "note": "PowerShell 脚本块日志能拿到解码后的真实命令"},
            ],
            "eradicate": [
                {"cmd": "Get-ChildItem -Recurse $env:TEMP,C:\\Users\\Public,<web目录> -Include *.ps1,*.bat,*.vbs,*.hta | "
                         "Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}",
                 "note": "清理落地载荷"},
                {"cmd": "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}; "
                         "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                 "note": "清理持久化"},
                {"cmd": "启用并集中收集 PowerShell 脚本块日志与命令行审计（4688 含命令行）",
                 "note": "根因加固：没开这两个日志，下次照样看不见"},
            ],
        },
        "linux": {
            "verify": [
                {"cmd": "grep -rn '{process}' /var/log/auth.log /var/log/syslog /var/log/audit/audit.log 2>/dev/null | tail -20",
                 "note": "从认证/系统/审计日志还原完整命令"},
                {"cmd": "ps auxww | grep -E 'bash -i|/dev/tcp/|nc |curl|wget' | grep -v grep",
                 "note": "查反弹 shell 与下载执行进程"},
            ],
            "contain": [
                {"cmd": "kill -9 <PID>",
                 "note": "终止可疑进程"},
                {"cmd": "iptables -A OUTPUT -d {ip} -j DROP",
                 "note": "阻断出向 C2"},
            ],
            "preserve": [
                {"cmd": "ps auxww > /var/tmp/ir/{host}-ps.txt; cat /proc/<PID>/cmdline | tr '\\0' ' ' > /var/tmp/ir/cmdline.txt",
                 "note": "进程与完整命令行留证"},
                {"cmd": "ausearch -ts recent -i > /var/tmp/ir/audit-recent.txt 2>/dev/null",
                 "note": "auditd 明细日志是还原攻击链的最佳来源"},
            ],
            "eradicate": [
                {"cmd": "ls -la /tmp /var/tmp /dev/shm; find /tmp /var/tmp -type f -mtime -3 2>/dev/null",
                 "note": "清理临时目录落地载荷"},
                {"cmd": "crontab -l; ls /etc/cron.* /var/spool/cron/crontabs 2>/dev/null",
                 "note": "清理定时任务持久化"},
            ],
        },
    },

    # =====================================================================
    # 8. 数据库攻击
    # =====================================================================
    "db-attack": {
        "db": {
            "verify": [
                {"cmd": "SELECT * FROM performance_schema.processlist WHERE Info IS NOT NULL ORDER BY TIME DESC;",
                 "note": "看当前正在执行的语句，是否存在拖库/删表"},
                {"cmd": "SELECT user, host, db, command, time, state, info FROM information_schema.processlist;",
                 "note": "确认异常语句来源账号与主机"},
            ],
            "contain": [
                {"cmd": "KILL <进程ID>;",
                 "note": "先杀掉破坏性语句，保留 general_log 记录"},
                {"cmd": "ALTER USER '{user}'@'%' ACCOUNT LOCK;   -- PostgreSQL: ALTER ROLE ... WITH LOGIN NOLOGIN",
                 "note": "锁定涉事数据库账号"},
                {"cmd": "REVOKE ALL PRIVILEGES ON *.* FROM '{user}'@'%';",
                 "note": "回收权限（按需只回收 DROP/FILE/SUPER 等高危权限）"},
            ],
            "preserve": [
                {"cmd": "导出 general_log / slow_query_log / PostgreSQL csvlog 到取证盘",
                 "note": "数据库日志是注入与拖库定性的唯一依据"},
                {"cmd": "SELECT * FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema');",
                 "note": "记录现有表结构快照，便于判断是否被建后门表"},
            ],
            "eradicate": [
                {"cmd": "DROP TABLE IF EXISTS <后门表>;",
                 "note": "清理注入落地的后门表（先确认不是业务表）"},
                {"cmd": "SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR File_priv='Y';",
                 "note": "审计高危权限账号，回收不必要的 SUPER/FILE 权限"},
                {"cmd": "应用层改参数化查询；数据库账号按最小权限拆分（应用账号不给 DDL）",
                 "note": "根因修复：注入的根在应用，不在数据库"},
            ],
        },
    },

    # =====================================================================
    # 9. 流量异常（扫描 / 信标 / DNS 隧道 / DGA）
    # =====================================================================
    "net-anomaly": {
        "net": {
            "verify": [
                {"cmd": "tshark -r <抓包文件> -q -z endpoints,ip 2>/dev/null | sort -k2 -rn | head -20",
                 "note": "按流量定位最活跃主机，判断扫描源与失陷主机"},
                {"cmd": "tshark -r <抓包文件> -Y 'ip.addr=={ip}' -T fields -e frame.time_relative -e ip.proto | head -40",
                 "note": "看该 IP 的通信节奏：等间隔小包 = 信标，杂乱大包 = 扫描/外传"},
                {"cmd": "tshark -r <抓包文件> -Y 'dns' -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -20",
                 "note": "看高频/异常长域名，判断 DNS 隧道与 DGA"},
            ],
            "contain": [
                {"cmd": "在边界封禁外联目标 {dst} 与 {domain}（DNS 类威胁优先用 DNS 沉洞）",
                 "note": "告警里的源 IP 若为内网主机即为失陷主机，先断网再排查"},
                {"cmd": "对失陷主机先断网再排查",
                 "note": "C2 在线期间清理容易被打断或木马反复重连"},
            ],
            "preserve": [
                {"cmd": "cp <抓包文件> /var/tmp/ir/net-$(date +%F).pcap && sha256sum /var/tmp/ir/net-*.pcap",
                 "note": "抓包留存并算哈希"},
                {"cmd": "tshark -r <抓包文件> -Y 'ip.addr=={ip}' -w /var/tmp/ir/{ip}-filtered.pcap",
                 "note": "单独抽出可疑会话，方便移交分析"},
            ],
            "eradicate": [
                {"cmd": "对失陷主机 {ip} 做全盘查杀与补丁，并核对该主机上所有计划任务和服务",
                 "note": "C2 通常带持久化，不清理干净会再次上线"},
                {"cmd": "在 DNS 与出口防火墙上加入 {domain} 及同族域名规则",
                 "note": "防同族域名换 IP 复活"},
            ],
        },
    },

    # =====================================================================
    # 10. 追踪流内容（反向 shell / 凭据 / 文件外传）
    # =====================================================================
    "stream-content": {
        "net": {
            "verify": [
                {"cmd": "tshark -r <抓包文件> -q -z follow,tcp,raw,<流索引> 2>/dev/null | head -60",
                 "note": "直接看该 TCP 流的双向内容，确认是反向 shell 还是正常管理会话"},
                {"cmd": "tshark -r <抓包文件> -Y 'tcp.port=={port}' -T fields -e ip.src -e tcp.payload | head -20",
                 "note": "按端口看载荷，反向 shell 的载荷以命令与回显为主"},
            ],
            "contain": [
                {"cmd": "阻断失陷主机 {ip} 到外联目标 {dst}:{port} 的出向连接",
                 "note": "反向 shell 是**出向**连接，只加入向 ACL 拦不住，必须做出向封禁"},
                {"cmd": "定位 {ip} 对应主机并断网排查",
                 "note": "反向 shell 说明该主机已被控"},
            ],
            "preserve": [
                {"cmd": "tshark -r <抓包文件> -Y 'tcp.stream eq <流索引>' -w /var/tmp/ir/stream-<流索引>.pcap",
                 "note": "单独抽出该流留证"},
                {"cmd": "对失陷主机采集内存镜像与进程列表",
                 "note": "反向 shell 的木马进程常只在内存中"},
            ],
            "eradicate": [
                {"cmd": "轮换该流中出现过的所有账号口令（含明文 FTP/数据库口令）",
                 "note": "**明文协议流里出现过的口令一律视为已泄露**"},
                {"cmd": "排查失陷主机持久化：计划任务、服务、启动项、SSH authorized_keys",
                 "note": "反向 shell 只是入口，持久化才是复发根源"},
                {"cmd": "推动明文协议改造为 SSH/SFTP/TLS",
                 "note": "根因：明文传输让凭据在流里裸奔"},
            ],
        },
    },

    # =====================================================================
    # 11. HTTP 内容（响应体回显 / 上传木马 / 下载执行）
    # =====================================================================
    "http-content": {
        "web": {
            "verify": [
                {"cmd": "tshark -r <抓包文件> -Y 'http.response && ip.addr=={ip}' -T fields -e http.response.code -e http.file_data | head -20",
                 "note": "看响应体内容，确认是否真是命令回显/敏感文件内容"},
                {"cmd": "grep -F '{uri}' <access.log> | tail -30",
                 "note": "关联访问日志，确认请求来源、UA 与时间"},
            ],
            "contain": [
                {"cmd": "封禁 {ip}；若为正常外网用户，先限流并核实身份",
                 "note": "先断攻击面"},
                {"cmd": "停用被上传的可执行文件：chmod 000 <文件路径> / 移除 IIS 处理程序映射",
                 "note": "上传的木马先摘权限再取证"},
            ],
            "preserve": [
                {"cmd": "tshark -r <抓包文件> -Y 'http.request && ip.addr=={ip}' -w /var/tmp/ir/http-{ip}.pcap",
                 "note": "抽出该主机的 HTTP 会话留证"},
                {"cmd": "cp <被上传文件> /var/tmp/ir/ && sha256sum /var/tmp/ir/*",
                 "note": "木马本体留证并算哈希，便于关联 IOC"},
            ],
            "eradicate": [
                {"cmd": "删除木马文件；全站扫描同类文件（同名前缀、同大小、同上传时间窗）",
                 "note": "攻击者常批量上传"},
                {"cmd": "收敛上传点：白名单扩展名、禁执行权限、上传目录独立且不可解析",
                 "note": "根因修复：上传点是最大暴露面"},
                {"cmd": "轮换 Web 服务所用数据库账号与 API 密钥",
                 "note": "回显内容中若出现配置，一律按泄露处理"},
            ],
        },
    },

    # =====================================================================
    # 12. IOC 命中
    # =====================================================================
    "ioc": {
        "windows": {
            "verify": [
                {"cmd": "Get-CimInstance Win32_Process | Where-Object {$_.Name -match '{process}' -or $_.CommandLine -match '{ip}'}",
                 "note": "确认命中 IOC 的进程是否仍在运行"},
                {"cmd": "Get-FileHash -Algorithm SHA256 '<文件路径>'",
                 "note": "比对文件哈希与 IOC 是否一致（注意排除正常同名文件）"},
                {"cmd": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 200 | Where-Object {$_.Message -match '{ip}'}",
                 "note": "看该 IP 是否有成功登录"},
            ],
            "contain": [
                {"cmd": "netsh advfirewall firewall add rule name=\"IR-Block-{ip}\" dir=in action=block remoteip={ip}",
                 "note": "双向封禁 IOC IP（入向 + 出向各一条）"},
                {"cmd": "Stop-Process -Name '{process}' -Force -ErrorAction SilentlyContinue",
                 "note": "终止命中进程"},
            ],
            "preserve": [
                {"cmd": "Get-FileHash '<文件路径>' | Out-File C:\\ir\\{host}-ioc-hash.txt",
                 "note": "哈希入档，作为命中证据"},
                {"cmd": "wevtutil epl Security C:\\ir\\{host}-security.evtx; wevtutil epl System C:\\ir\\{host}-system.evtx",
                 "note": "导出日志"},
            ],
            "eradicate": [
                {"cmd": "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}; Get-Service | Where-Object {$_.Status -eq 'Running'}",
                 "note": "清理持久化（IOC 命中通常意味着已有持久化）"},
                {"cmd": "全盘扫描同哈希文件，删除并提交样本到威胁平台",
                 "note": "确认横向移动范围"},
                {"cmd": "轮换该主机所有凭据",
                 "note": "按已失陷标准处理"},
            ],
        },
        "linux": {
            "verify": [
                {"cmd": "grep -rn '{ip}' /var/log/ 2>/dev/null | head -20",
                 "note": "在系统日志中定位 IOC 痕迹"},
                {"cmd": "ps auxww | grep -E '{process}' | grep -v grep",
                 "note": "确认命中进程"},
            ],
            "contain": [
                {"cmd": "iptables -A INPUT -s {ip} -j DROP; iptables -A OUTPUT -d {ip} -j DROP",
                 "note": "双向封禁"},
            ],
            "preserve": [
                {"cmd": "cp /var/log/auth.log* /var/tmp/ir/ 2>/dev/null; ss -tunap > /var/tmp/ir/{host}-ss.txt",
                 "note": "日志与连接快照留证"},
            ],
            "eradicate": [
                {"cmd": "find / -path /proc -prune -o -name '{process}' -print 2>/dev/null",
                 "note": "定位并清除命中文件"},
                {"cmd": "crontab -l; ls /etc/cron.* 2>/dev/null",
                 "note": "清理定时任务"},
            ],
        },
    },
}


# ---------------------------------------------------------------------------
# 渲染引擎
# ---------------------------------------------------------------------------
def _first(entities: dict, *keys: str) -> Optional[str]:
    """按优先级取实体值，支持 list/set（取首个）。"""
    for k in keys:
        v = entities.get(k)
        if isinstance(v, (list, tuple, set)):
            v = next(iter(v), None) if v else None
        if v not in (None, "", []):
            return str(v)
    return None


def _is_path_like(v: Optional[str]) -> bool:
    """判断值是否其实是个文件路径/文件名（防止把 source 文件名当主机名用）。"""
    if not v:
        return True
    if "/" in v or "\\" in v:
        return True
    return v.lower().endswith((".xml", ".log", ".pcap", ".pcapng", ".json",
                               ".jsonl", ".csv", ".txt", ".evtx", ".gz"))


def _clean_host(v: Optional[str]) -> Optional[str]:
    return None if _is_path_like(v) else v


def _evidence_text(alert: Alert) -> str:
    """reasons + 证据原文拼接，供兜底正则提取。"""
    parts = []
    for r in (alert.entities or {}).get("reasons", []) or []:
        parts.append(str(r))
    for ev in (alert.evidence or []):
        if len(ev) > 2 and ev[2]:
            parts.append(str(ev[2]))
    return "\n".join(parts)


def _from_evidence(alert: Alert, pattern: str) -> Optional[str]:
    """实体里没有时，从 evidence/reasons 兜底提取（如 HTTP 请求行里的 URL）。"""
    import re
    m = re.compile(pattern).search(_evidence_text(alert))
    if not m:
        return None
    # 有分组取分组，无分组（如纯 IP 匹配）取整段
    val = m.group(1) if m.groups() else m.group(0)
    return val.strip().strip('"\'')


def extract_vars(alert: Alert) -> dict:
    """从告警实体提取模板变量；不足时从证据原文回补。"""
    e = alert.entities or {}

    user = _first(e, "user", "target_users", "account")
    hosts = _clean_host(_first(e, "hosts"))
    ip = _first(e, "src_ip", "ip", "candidate_ips", "remote_ip")
    if not ip:                      # 从证据原文里的第一个公网/内网 IP 回补
        ip = _from_evidence(alert, r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
                                   r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
    dst = _first(e, "dst_ip", "remote_ip", "c2_ip", "external_ip")
    if not dst:
        dst = ip

    uri = _first(e, "uri", "url", "path")
    if not uri:
        uri = _from_evidence(alert, r'(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+(/\S+)')
    if not user:
        user = _from_evidence(alert, r'(?:账号|user|account|User)\s*[=:：]\s*["\']?([A-Za-z0-9._$\-\\]+)')
    proc = _first(e, "process", "proc", "image", "command")
    if not proc:                    # Sysmon XML 的 <Data Name='Image'>
        proc = _from_evidence(alert, r"Name=['\"]Image['\"]>([^<]+)<")
    domain = _first(e, "domain", "dns", "query")
    port = _first(e, "port", "dst_port", "sport", "src_port")

    v = {
        "ip": ip, "dst": dst, "user": user,
        "host": _clean_host(_first(e, "host", "hostname")) or hosts,
        "uri": uri, "file": uri, "process": proc, "domain": domain,
        "port": port,
    }
    return v


def _fill(cmd: str, vars_: dict) -> tuple[str, list[str]]:
    """替换 {占位符}；取不到的填 <提示> 并记录 missing。"""
    missing = []
    out = cmd
    for key, hint in PLACEHOLDERS.items():
        val = vars_.get(key)
        token = "{%s}" % key
        if token in out:
            if val:
                out = out.replace(token, val)
            else:
                out = out.replace(token, hint)
                missing.append(key)
    return out, missing


def platforms_for(alert: Alert, files: Optional[list] = None) -> list:
    """根据告警证据来源推断应给出哪些平台的命令。"""
    plats: set = set()
    srcs = {str(e[1]) for e in (alert.evidence or []) if len(e) > 1 and e[1]}
    # 文件级日志类型
    for f in (files or []):
        lt = f.get("log_type")
        if not lt:
            continue
        base = (f.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
        if not srcs or base in srcs or not srcs:
            plats |= LOG_TYPE_PLATFORMS.get(lt, set())
    # 文件名兜底
    for s in srcs:
        low = s.lower()
        if "security" in low or "sysmon" in low or "win" in low or "iis" in low:
            plats |= {"windows"}
        if "auth" in low or "syslog" in low or "secure" in low or "audit" in low:
            plats |= {"linux"}
        if "access" in low or "nginx" in low or "apache" in low:
            plats |= {"web"}
        if "mysql" in low or "pg" in low or "postgres" in low or "mongo" in low or "redis" in low or "sql" in low:
            plats |= {"db"}
        if ".pcap" in low:
            plats |= {"net"}
    if not plats:
        plats = {"windows", "linux", "web"}
    return [p for p in ("windows", "linux", "web", "db", "net") if p in plats]


def build_playbook(alert: Alert, files: Optional[list] = None) -> dict:
    """为一条告警生成四阶段处置剧本（含回填后的命令）。"""
    vars_ = extract_vars(alert)
    plats = platforms_for(alert, files)
    kb = PLAYBOOKS.get(alert.rule_id, {})

    # 该规则没有专属剧本时，给一份通用四阶段骨架，避免用户看到空白
    if not kb:
        return {
            "rule_id": alert.rule_id,
            "platforms": plats,
            "generic": True,
            "stages": [{
                "key": key, "label": label, "hint": hint,
                "cmds": [{"cmd": "（该规则暂无专属命令，请按下面通用步骤处理）",
                          "note": "核查告警真伪 → 遏制影响面 → 固定证据 → 根除并轮换凭据"}],
            } for key, label, hint in STAGES],
        }

    # 只保留本告警实际有内容的平台；没有则退回第一个可用平台
    avail = [p for p in plats if p in kb]
    if not avail:
        avail = [next(iter(kb))]

    stages = []
    for key, label, hint in STAGES:
        cmds = []
        seen = set()
        for p in avail:
            for c in kb.get(p, {}).get(key, []):
                cmd, missing = _fill(c["cmd"], vars_)
                if cmd in seen:
                    continue
                seen.add(cmd)
                cmds.append({"cmd": cmd, "note": c.get("note", ""),
                             "platform": p, "missing": missing})
        if cmds:
            stages.append({"key": key, "label": label, "hint": hint, "cmds": cmds})

    missing_all = sorted({m for s in stages for c in s["cmds"] for m in c.get("missing", [])})
    return {
        "rule_id": alert.rule_id,
        "platforms": avail,
        "platform_labels": [PLATFORM_LABELS.get(p, p) for p in avail],
        "generic": False,
        "missing_vars": missing_all,
        "stages": stages,
    }


def attach_playbooks(result) -> None:
    """给分析结果里的每条告警附加处置剧本。"""
    for a in result.alerts:
        try:
            a.playbook = build_playbook(a, result.files)
        except Exception as exc:               # 知识库异常不能拖垮分析
            result.errors.append(
                f"处置剧本生成异常({a.rule_id}): {type(exc).__name__}: {exc}")
            a.playbook = {"rule_id": a.rule_id, "platforms": [], "generic": True,
                          "stages": []}


def playbook_markdown(result) -> str:
    """导出 Markdown 版《应急响应处置手册》。"""
    d = result.to_dict()
    L = []
    L.append(f"# 应急响应处置手册\n")
    L.append(f"- 案件编号：{result.run_id}")
    L.append(f"- 生成时间：{d['finished']}")
    L.append(f"- 告警总数：{len(d['alerts'])} 条（按严重程度排序）")
    L.append(f"- 说明：以下命令**由分析人员复制后自行执行**，本工具不执行任何命令；"
             f"`<尖括号>` 为需按现场情况替换的占位值。\n")
    L.append("---\n")

    for i, a in enumerate(d["alerts"], 1):
        pb = a.get("playbook") or {}
        L.append(f"## {i}. [{a['severity_label']}] {a['title']}\n")
        L.append(f"- 规则：`{a['rule_id']}`")
        L.append(f"- 时间：{a.get('first_time')} ~ {a.get('last_time')}（{a['count']} 次）")
        L.append(f"- 说明：{a.get('description') or '-'}")
        if a.get("mitre"):
            L.append(f"- ATT&CK：{a['mitre']}")
        ent = "；".join(
            f"{k}={v if not isinstance(v, (list, set)) else ','.join(map(str, v))}"
            for k, v in (a.get("entities") or {}).items()
        )
        if ent:
            L.append(f"- 关联实体：{ent}")
        plats = pb.get("platform_labels") or []
        if plats:
            L.append(f"- 适用平台：{' / '.join(plats)}")
        L.append("")
        for st in pb.get("stages", []):
            L.append(f"### {st['label']}\n")
            L.append(f"> {st['hint']}\n")
            for c in st["cmds"]:
                L.append(f"```bash\n{c['cmd']}\n```")
                if c.get("note"):
                    L.append(f"* {c['note']}")
                L.append("")
        L.append("---\n")
    return "\n".join(L)

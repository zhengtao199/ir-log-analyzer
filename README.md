# ir-log-analyzer — 应急响应日志分析工具

面向**应急响应（Incident Response）**场景的日志分析工具：多源日志归一化解析 → 12 大类威胁检测（含命令混淆/编码载荷解码、数据库攻击、TCP 流重组） → 时间线还原 → 三模报告输出（CLI / JSON / HTML）+ 本地 Web 展示层。

**核心特性**

- **零依赖**：纯 Python 标准库，无第三方包，离线内网拷走即用（Python 3.10+，Windows/Linux 均可）
- **取证合规**：原始日志全程只读；分析前计算 SHA256 证据清单；全程操作审计留痕（append-only JSONL）；报告内嵌证据链（Chain of Custody）信息
- **流式处理**：逐行/逐事件解析，内存占用与日志规模无关（实测 50 万行峰值内存约 1MB，耗时约 30s）
- **插件式架构**：解析器、检测器均为注册表模式，新增日志源/规则只需加一个模块

---

## 1. 快速开始

```bash
# 进入项目目录
cd ir-log-analyzer

# 分析一批证据（文件或目录），生成 CLI 时间线 + JSON + HTML 报告
python -m irlog scan <文件或目录> [--ioc ioc.txt] [--operator 分析人]

# 启动 Web 展示层（默认 http://127.0.0.1:8611）
python -m irlog serve [--port 8611] [--evidence-dir 证据目录]

# 仅计算证据 SHA256（取证固定）
python -m irlog hash <文件...>

# 查看全部检测规则与阈值
python -m irlog rules
```

> Windows 上若 `python` 未配置，使用完整路径，如：
> `C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python.exe -m irlog scan ...`

**scan 退出码**（可用于脚本联动）：`0` 无告警 / `1` 仅低中危 / `2` 存在高危或紧急 / `3` 执行出错。

**scan 常用参数**

| 参数 | 说明 |
| --- | --- |
| `--ioc FILE` | IOC 列表（txt 每行一条 / csv 首列，`#` 开头为注释） |
| `--out PREFIX` | 报告输出前缀（默认 `irlog-output/<案件编号>`） |
| `--format cli,json,html` | 输出格式，默认全部；加 `md` 可额外导出 Markdown 版处置手册 |
| `--no-playbook` | 不生成《应急响应处置手册》（默认随报告一起产出） |
| `--set key=value` | 覆盖阈值，可多次（如 `--set brute_force_threshold=3`） |
| `--operator NAME` | 分析人，写入证据链 |
| `--workdir DIR` | 工作目录（报告/IOC/审计日志落盘处，默认 `irlog-output`） |
| `--no-recursive` | 目录不递归 |

---

## 2. 系统要求与跨机器部署

**系统要求**

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10/11、Windows Server 2016+（Linux/macOS 亦可） |
| Python | **3.10 或更高**（无第三方依赖，不需要 `pip install` 任何包） |
| 内存 | 流式处理，峰值约 1MB，与日志规模无关 |
| 网络 | 完全离线可用；Web 控制台默认仅监听 127.0.0.1（本机） |

**为什么能直接在别的 Windows 电脑上跑**

- 纯标准库：不存在"目标机缺依赖"问题
- 所有文本读写显式 `encoding="utf-8"`：不受目标机系统代码页（GBK 等）影响
- 零外部命令调用（无 `subprocess`/`os.system`）：不需要目标机预装任何工具链
- 未使用 3.12+ 限定语法：同一代码库已在 **Python 3.10.10 与 3.13.12 双版本实测通过**（单元测试 26/26、Web E2E 42/42、CLI 扫描一致）

**三种部署方式（按目标机环境选择）**

| 目标机环境 | 方式 | 操作 |
| --- | --- | --- |
| 已装 Python 3.10+ | 拷贝即用 | 复制 `ir-log-analyzer` 目录 → `python -m irlog scan <证据路径>` |
| 没装 Python / 版本太老 / 不确定 | **绿色免安装包**（推荐） | 复制 `ir-log-analyzer-portable` 目录 → 双击 `启动Web控制台.bat` 或把日志文件**拖到** `启动命令行分析.bat` 图标上（内置 Python 3.10 运行时，共约 83MB） |
| 需要单文件分发 | 自行打包 | 在有网机器上 `pip install pyinstaller` 后 `pyinstaller -F -n irlog --add-data "irlog/web;irlog/web" --hidden-import irlog.server ...`（本仓库不内置，保持离线零依赖） |

绿色免安装包结构：

```
ir-log-analyzer-portable/
├── 启动Web控制台.bat      # 双击启动，自动打开 http://127.0.0.1:8611
├── 启动命令行分析.bat      # 拖拽日志文件/文件夹到图标即可分析
├── python/                # 内置 Python 3.10.10 运行时（拷贝即用，无需安装）
├── irlog/                 # 工具代码（与主仓库一致）
├── evidence/              # 证据目录（Web 上传落盘处，预置 2 个示例日志）
└── output/                # 报告输出目录
```

> 已验证：便携包使用**内置运行时**完成 CLI 扫描（告警 + HTML/JSON 报告生成）与 Web 控制台全流程。
> 目标机首次运行时如杀毒软件拦截 `python.exe` 监听端口，属误报，将目录加白即可。

---

## 3. Windows 事件日志（EVTX）如何接入

EVTX 是二进制专有格式，本工具通过**官方导出**的 XML 接入（保证解析可靠性，导出过程对原始文件只读）。在目标机上执行（建议在取证镜像/应急响应优盘环境中运行）：

```powershell
# 导出 Security 日志全部事件为 XML（每事件一个 <Event> 块）
Get-WinEvent -LogName Security | ForEach-Object { $_.ToXml() } |
  Out-File -FilePath security_export.xml -Encoding utf8

# 或按事件 ID 过滤导出（更小更快）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4672,4720,4732,4688,5140} |
  ForEach-Object { $_.ToXml() } | Out-File -FilePath security_filtered.xml -Encoding utf8

# Sysmon 同理
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  ForEach-Object { $_.ToXml() } | Out-File -FilePath sysmon_export.xml -Encoding utf8
```

然后把导出的 `.xml` 文件（连同 Linux/Web 日志）一起交给 `irlog scan` 即可。解析器注册表预留了 EVTX 原生二进制解析的扩展位（`irlog/parsers/` 下新增一个 `LogParser` 实现并注册即可被自动识别）。

---

## 4. 支持的日志格式（自动识别，无需指定）

| 类型 | 格式 | 典型来源 |
| --- | --- | --- |
| `pcap` | **pcap / pcapng 流量包**（含 `.pcap.gz`，见下节） | tcpdump、Wireshark、Zeek、防火墙抓包 |
| `winxml` | Get-WinEvent `ToXml()` 导出的多 `<Event>` XML 流 | Windows Security / System / Sysmon |
| `database` | **MySQL / PostgreSQL / SQL Server / MongoDB / Redis**（见下节） | 错误日志、general log、慢查询、csvlog、Mongo JSON、Redis |
| `linux-auth` | syslog 文本（sshd/sudo/login） | Linux auth.log、secure |
| `linux-syslog` | syslog 通用格式 | syslog、messages |
| `web-access` | Nginx/Apache combined/common（含 vhost 前缀变体） | 各类 Web 服务器 |
| `iis` | IIS W3C 扩展日志（`#Fields` 动态列） | IIS |
| `jsonl` | JSON Lines（兼容 time/@timestamp/ip/user/uri 等常见字段） | 中间件、框架（经 Filebeat/Logstash 等转 JSON 后接入） |
| `generic` | 兜底：尽力提取时间与 IP，原样入时间线 | 任意文本日志 |

**中间件/框架扩展方式**：用 Filebeat/Logstash/rsyslog 把 Tomcat、MySQL、Redis、K8s Audit 等日志转成 JSON Lines 即可直接被 `jsonl` 解析器消费；也可按第 9 节添加专用解析器。

---

## 5. 检测规则（11 大类，均可配置/可裁剪）

| 规则 ID | 名称 | 触发逻辑 | 默认阈值 |
| --- | --- | --- | --- |
| `brute-force` | 暴力破解 | 窗口内登录失败次数超限；命中多账号判密码喷洒（紧急） | 300s / 5 次 |
| `webshell` | Webshell/后门 | 上传目录脚本、POST 到可疑后缀、命令执行参数；Web 进程（w3wp/httpd/php-cgi/tomcat）派生命令行解释器 | — |
| `web-attack` | Web 攻击/扫描 | SQL 注入、XSS、路径遍历、敏感文件探测（URI 自动 URL 解码后匹配）、扫描器 UA、404 突增 | 404≥50 |
| `account-abuse` | 权限提升/横向移动/异常登录 | 新建账号→加入管理组（紧急）；LogonType3 突增；单账号多主机；失败后成功登录（紧急） | 提权窗口 1h |
| `exfiltration` | 数据外传 | 单请求响应体超限、单 IP 单日流量超限、敏感文件批量下载 | 50MB / 500MB |
| `ransomware` | 勒索软件痕迹 | vssadmin/wbadmin/bcdedit/wevtutil 恢复破坏命令（紧急）；文件创建突发；勒索扩展名批量出现 | 60s 内 100 个 |
| `command-obfuscation` | 命令混淆/编码载荷 | **不依赖黑名单**，直接对命令行做结构识别与解码：① PowerShell `-enc/-encodedcommand` Base64 载荷自动解码（UTF-16LE/Latin-1，载荷含 iex/http 等关键词→紧急）② 长串高熵检测（长度+字符集+Shannon 熵，避开 GUID/hex 指纹）③ cmd `^` 插入、空引号插入（`ev""entvwr`）、`%VAR:~x,y%`/`$env:` 拼接 ④ LOLBAS/解码下载（certutil/bitsadmin/mshta/regsvr32/rundll32 javascript/wmic call create）⑤ **Hex 编码载荷**（`echo '<hex>' | sh`，容忍奇数长度与载荷中段污染，含 `://`/域名/命令关键词且管道执行→紧急）⑥ **下载-落地-执行链**（下载工具 + 写入 `/tmp` 等可写目录 + 赋权/执行，`curl|bash` 类下载即执行→紧急）⑦ **解码器管道**（`xxd -r`/`base64 -d`/`openssl enc -d` 在命令行内还原载荷）；适用 Windows 进程创建与 Linux 命令执行（sshd execute / sudo COMMAND / **auditd EXECVE**） | Base64≥40 字符且熵≥4.3；`^`×3；hex≥40 位 |
| `db-attack` | **数据库攻击/高危操作**（见下节） | SQL 注入落地、破坏性语句、提权建账号、敏感表拖库 | 敏感表 300s / 20 次 |
| `net-anomaly` | **流量异常 / 扫描 / C2 通信**（见下节） | 端口扫描、横向扫描、C2 心跳信标、DNS 隧道与 DGA、明文凭据传输、可疑外传、已知远控端口 | 端口/主机各 20；信标 6 次 |
| `stream-content` | **TCP 流内容异常**（见下节） | 重组会话内的反向 shell、敏感文件外传、跨报文凭据对、Webshell 交互、会话内编码载荷 | — |
| `http-content` | **HTTP 请求体/响应体内容异常**（见下节） | 命令执行回显、敏感文件内容外传、一句话木马本体、上传可疑脚本、下载执行类脚本、可执行文件下载 | — |
| `ioc` | IOC 命中 | 事件字段匹配 IP/域名/哈希/URL/路径情报（域名含 DNS 查询与 TLS SNI） | — |

**命令混淆规则的能力边界**（防误报取舍，必要时用 `--set` 调整）：

- **能解开的**：Base64 编码命令（解码结果直接写入告警，含 C2 地址/落地文件）、Hex 编码载荷（容忍奇数长度与中段污染字节，前缀含 `://`/域名即判可疑）、常见混淆手法、LOLBAS 离地攻击
- **解不开的**：自定义加密/XOR 编码（只报“高熵不可解串”，中危）；短于 40 字符的隐式 Base64（长度/熵不可靠，不报）；单次 `^` 插入（<3 次不报，避免误伤合法转义）
- **Linux 侧**：`sshd: error: execute: ...` 行（正常 OpenSSH 不产生，旧版 `-e` 后门/利用痕迹）会归一为命令执行并送入解码分析；sudo COMMAND 同样过检测
- **auditd**：`type=EXECVE msg=audit(...): a0="..." a1="..."` 记录会解析出完整命令行（含特殊字符的参数按 auditd 的 hex 编码还原），这是**攻击者登录后实际执行过什么**最主要的证据来源
- 若需调整：`--set obf_b64_min_len=32 --set obf_entropy_min=4.0 --set obf_caret_min=2`

### 数据库日志分析

数据库日志在应急响应里常被忽略，但它提供两类 Web 侧拿不到的证据：

**① 谁在撞库** —— 认证失败归一化为 `logon-failed`（带源 IP 与账号），**直接复用既有 brute-force / account-abuse 规则**：

| 引擎 | 日志来源 | 识别的失败特征 |
|---|---|---|
| MySQL | 错误日志 / general log | `Access denied for user 'root'@'10.0.0.5'`、`Aborted connection ... user: ... host:` |
| PostgreSQL | csvlog | `password authentication failed for user`、客户端 `IP:PORT` 字段 |
| SQL Server | 错误日志 | `Login failed for user 'sa'. [CLIENT: 10.0.0.5]` |
| MongoDB | JSON 日志 | `"c":"ACCESS","msg":"Authentication failed"` |
| Redis | 运行日志 | `Auth fail ... addr=10.0.0.5:55555` |

**② 注入到底有没有打穿** —— Web 日志只有 URL 里的可疑字符串（尝试），而 MySQL general log /
PostgreSQL `statement:` 记录的是**真正被数据库执行的 SQL**（结果）。`UNION SELECT`、
`INTO OUTFILE`、`SLEEP()` 出现在这里即代表注入已落地，处置优先级完全不同，因此单列 `db-attack` 规则：

- **L1 注入落地**：UNION SELECT、恒真条件、时间盲注（SLEEP/BENCHMARK/WAITFOR/pg_sleep）、
  报错注入（extractvalue/updatexml/cast）、系统表探测（information_schema/sysobjects）、
  文件读写与命令执行（`LOAD_FILE`/`INTO OUTFILE`/`COPY TO PROGRAM`/`xp_cmdshell`）、
  堆叠查询、hex/CHAR 编码绕过 —— 多特征组合或命中文件读写/恒真条件 → **紧急**
- **L2 破坏篡改**：`DROP DATABASE/TABLE`、`TRUNCATE`、无 WHERE 的 `DELETE`/`UPDATE` → **紧急**；
  带 WHERE 的 UPDATE/DELETE 视为正常业务，**不告警**（防误报）
- **L3 权限与账号**：`GRANT ALL`、`CREATE/ALTER USER`、`sp_configure`、
  `CREATE FUNCTION ... SONAME`（UDF 提权）→ 高危
- **L4 拖库**：窗口内对敏感表（user/account/card/password/token/…）的查询次数超阈值 → 中危
  （`--set db_dump_min_queries=10 --set db_dump_window_sec=600`）

MySQL general log 的 `Query` 行只有线程号，工具会按**线程号回溯 `Connect` 行**把 SQL 关联回账号与来源 IP，
告警因此带得动溯源（实测：`appuser` / `10.0.0.30`）。慢查询日志的 `SET timestamp` 等 MySQL 自带前缀语句
不会污染检测。

### 流量包分析（pcap / pcapng）

**零第三方依赖**：不装 scapy/dpdk（离线内网不可用），用标准库 `struct` 手解文件格式。

**支持**：经典 pcap（大小端 + 微秒/纳秒变体）、pcapng（SHB/IDB/EPB/SPB）、两者均可 gzip 压缩；
链路层 Ethernet / RAW / NULL / Linux SLL（含 VLAN 标签剥离）；IPv4 与 IPv6。

抓包不是日志，工具把报文**还原成归一化事件**，让既有规则直接生效：

| 还原出的事件 | 内容 | 复用/新增规则 |
| --- | --- | --- |
| 连接事件 | TCP SYN / SYN-ACK / RST、UDP 新流（含端口与标志位） | `net-anomaly` |
| **HTTP 请求** | 方法、URI（补全 Host）、UA、Content-Length | **复用** `web-attack` / `webshell` / `exfiltration` |
| HTTP 响应 | 状态码、Content-Length（按流关联回请求 URI） | 复用 404 扫描、外传规则 |
| **HTTP 请求体** | 重组后的真实 body（chunked 解码 + gzip/deflate 解压） | **复用** `web-attack`（注入）/`webshell`；新增 `http-content` |
| **HTTP 响应体** | 服务端返回的实际内容（外传文件、命令回显、木马源码） | `http-content` |
| **DNS** | 查询域名、qtype、`rcode`（NXDOMAIN 可判 DGA） | `net-anomaly` + `ioc` 域名匹配 |
| **TLS** | ClientHello 的 **SNI** 与 **JA3 指纹** | `ioc` 域名/哈希匹配 |
| 明文凭据 | FTP / Telnet / HTTP-Basic / POP3 / IMAP / SMTP 的 USER·PASS·Authorization | `net-anomaly` |
| 流摘要 | 每条流的包数、双向字节数、时长（EOF 汇总） | `net-anomaly` 外传判定 |
| **重组流（追踪流）** | 跨报文还原的双向会话内容（见下节） | `stream-content` + `web-attack`（POST 请求体） |

`net-anomaly` 检测逻辑与防误报取舍：

- **端口扫描 / 横向扫描**：看**窗口内去重后的端口数或主机数**（不是包数），重传和大流量不会误伤
- **C2 心跳信标**：同时满足「连接次数 ≥ 6」+「平均间隔 ≥ 1s」+「间隔变异系数 CV ≤ 0.35」才报；
  人工操作与突发重连间隔不规律（CV 大），不告警。CV ≤ 0.2 且 ≥10 次 → **紧急**
- **DNS 隧道 / DGA**：查询标签长度 ≥30 或香农熵 ≥3.6（隧道）；窗口内 NXDOMAIN ≥20（DGA/域名爆破）
- **明文凭据**：命中即高危（无论内外网），附协议名
- **可疑外传**：仅当目标为**非内网地址**且满足「≥100MB」或「≥1MB 且出入比 ≥10:1」
- **已知远控端口**（4444/6667/1337/31337 等）仅作低危线索，需人工确认

内网判定用自建 RFC1918/回环/链路本地/CGNAT 表，**不用 `ipaddress.is_private`** —— 后者把文档保留段
（203.0.113.0/24 等）也算私有，会把外部地址误判成内网而漏报外传。

### 追踪流：TCP 重组（Follow TCP Stream）

单包解析只看得到被切开的片段。这些内容**必须重组才能判定**，`irlog/parsers/tcpstream.py`
按 Wireshark「追踪流」的语义做双向还原：

| 只有重组才能看到的证据 | 说明 |
| --- | --- |
| HTTP POST 请求体 | 注入载荷常在请求行之后的报文里，请求行本身是干净的 `/login` |
| 反向 shell 命令 | 命令被拆成多段，且「命令」与「回显」分属两个方向 |
| FTP/Telnet 凭据对 | `USER` 与 `PASS` 通常是两个报文，单包只能看到一半 |
| 敏感文件内容 | `/etc/passwd`、私钥、shadow 只有连成整段才可识别 |
| 会话内编码载荷 | base64/hex 命令常随管道执行一起出现 |

重组规则：

- **定基**：优先用握手指纹（SYN 序号）作基准，因此**乱序段能被正确重排**；
  抓包缺握手时退化为「首个数据段定基 + 顺序拼接」，并在事件中标记
- **重传/重叠**：按已有进度裁剪，只补新字节——重传不会让内容重复、字节数虚高
- **序列号回绕**：32 位回绕安全
- **常量内存**：并发流上限 1000（LRU 淘汰，淘汰前先吐出内容）、每方向 16KB 缓冲，
  超限即截断并标记 `truncated`；纯握手不占流槽位（SYN Flood 撑不爆流表）

`stream-content` 规则判定：反向 shell（客户端命令特征 + 服务端回显 `uid=0(root)` 等
→ **紧急**）、敏感文件内容外传（**紧急**）、完整凭据对（报告内口令脱敏）、
Webshell 交互执行、会话内 base64/hex 载荷（沿用 `command-obfuscation` 同一套解码口径）。

### HTTP 内容解码：请求体 / 响应体

流量包里的 HTTP 与 Web 访问日志不是一回事：请求行常常是干净的 `/login`、
响应也只有状态码，**真正能定性的内容在 body 里**，而且 body 常被分块或压缩。
工具在重组后的双向字节流上做完整的应用层解码（`irlog/parsers/httpproto.py`）：

| 解码环节 | 处理内容 |
| --- | --- |
| 消息切分 | 一条长连接上的**多条请求/响应**逐条切出（pipelining / keep-alive 不再只看到第一条） |
| 长度判定 | `Content-Length` 精确截取；不足则标记 `truncated`，不静默丢内容 |
| **chunked** | `Transfer-Encoding: chunked` 分块还原（含 trailer），不解分块就看不到任何内容 |
| **压缩** | `Content-Encoding: gzip / deflate` 解压（标准库 zlib，输出有上限，防 zip bomb） |
| 二进制判定 | 图片/压缩包等不参与文本匹配，只用魔数判断「下载了什么」 |

`http-content` 规则判定（**比 Web 日志更能定性**）：

- **命令执行回显**（紧急）：响应体出现 `uid=0(root)`、`Windows IP Configuration`、
  卷序列号、`command not found` → 说明命令真的跑起来了，不只是「尝试过」
- **敏感文件内容**（紧急）：`/etc/passwd`（`root:x:0:0:`）、shadow 哈希、`BEGIN PRIVATE KEY`、
  AWS `AKIA` 密钥、含口令的 JDBC 连接串 → 数据**已被拖走**，不是「访问了可疑路径」
- **Webshell 交互/本体**（紧急）：请求体 `cmd=/exec=` 带 `whoami`/`ipconfig`/`cat /etc/passwd`；
  `eval($_POST[...])`、`Runtime.getRuntime().exec` 等一句话木马特征
- **上传可疑脚本**（紧急）：multipart 里 `filename="*.php/.jsp/.aspx"` 等可执行后缀
- **下载执行类脚本**（高危）：响应体含 `curl …|sh`、`powershell -enc`、`certutil -decode`、
  `IEX(`、`/dev/tcp/` 反弹
- **可执行文件下载**（中危线索）：按魔数识别 PE（`MZ`）、ELF、ZIP/RAR、Shell 脚本

去重口径：单包已解析过的请求行/响应行**不再重复发事件**（否则同一次请求会被计数两次），
重组阶段只补单包看不到的部分；请求体/响应体事件刻意不写 `uri`，避免与请求行重复计数。

性能与内存（纯 Python 单核实测）：连接类报文约 **14 万包/秒**；**每条流都做完整 HTTP 解码**
（切分 + chunked + 解压 + 产出请求体/响应体事件）的密集 HTTP 场景约 **2.7 万包/秒**。
流表有上限（`MAX_FLOWS=50000`），检测聚合 key 上限 `net_max_tracked`（默认 20000），
2 万条并发 HTTP 流下内存峰值约 6MB，GB 级抓包常量内存完成。

```bash
python -m irlog scan capture.pcap --workdir output
python -m irlog scan capture.pcapng --set net_scan_ports=50 --set net_beacon_min=8
python -m irlog scan capture.pcap --ioc ioc.txt      # SNI/DNS 域名直接命中情报
```

**限制**：不做 IP 分片重组；严重丢包时流会缺段（标记 `truncated`/`partial`）。
HTTP 支持到 HTTP/1.1（含 chunked 与 gzip/deflate），**HTTPS 里的 HTTP/2 与加密载荷无法解析**
（只能取到 TLS 的 SNI 与 JA3 指纹）；如需解密，请先在抓包端导出密钥或改用明文代理日志。
复杂分片场景建议先用 Zeek 转成 `conn.log`/`dns.log` 再喂给工具。

### 攻击者溯源：命令执行归属到源 IP

`auditd EXECVE`、Sysmon 进程创建这类事件**自带不带源 IP**，告警只能定位到主机。工具内置会话归属（`irlog/session.py`）：流式维护每主机的活跃登录会话，把无源 IP 的命令执行回填到发起它的会话，并**如实给出置信度**（取证要求：结论可复核，不伪造唯一性）。

- 判据优先级：① 该 IP 在本主机有前置登录失败（暴破后得手，最强信号）② 外网 IP（非 RFC1918）③ 用户一致 ④ 会话越新越可能
- 置信度**高**＝该时刻仅一个活动会话；**中**＝并发多会话，按可疑度推断，并在 `candidate_ips` 列出全部候选
- 无任何会话时不凭空造 IP；可通过 `--set attribution_enabled=false` 关闭、`--set session_idle_timeout=3600` 调整空闲超时
- 输出示例：`[归属 193.106.30.99｜置信度中｜5 个并发会话，按可疑度推断] 命令混淆/编码载荷：...`

- 全部阈值通过 `--set` 覆盖，例如：
  `--set brute_force_threshold=3 --set exfil_response_bytes=10485760 --set web_attack_404_burst=20`
- 只跑部分规则：`--set rules=brute-force,webshell`
- 每条告警均带：严重程度（紧急/高危/中危/低危）、关联实体、首次/末次时间、次数、**原始日志证据样本**、ATT&CK 映射、处置建议。

## 6. IOC 列表格式

```text
# 每行一条，# 开头为注释；类型自动识别，也可显式标注
203.0.113.66
evil.example.com
2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE
http://c2.example.com/gate.php
ip:45.33.32.156
sha256:<64位哈希>
```

匹配字段：源/目的 IP、URI、文件哈希（Sysmon Hashes 字段）、文件路径、UA、原始日志文本。

## 7. 输出产物

| 产物 | 说明 |
| --- | --- |
| CLI 时间线 | 告警汇总表 + 每小时事件数直方图，退出码可联动 |
| JSON 报告 | 全量结构化数据（告警/时间线/文件处理明细/错误），供 SIEM/SOAR 消费 |
| HTML 报告 | 自包含单文件（零外部引用，可离线打开/邮件分发）：态势概览 → **类型分析结论（按日志类型分别回答应急问题）** → **跨类型综合关联（统一攻击者画像 / 关联结论 / 全局 IOC / 跨源时间线）** → 告警明细（可展开证据 + **处置剧本命令**）→ 时间线 → 证据链（SHA256）→ 处理明细 |
| **应急响应处置手册** | `<run_id>-playbook.html`（Markdown 可选）：只保留「要动手的部分」，按 紧急/高危/中低危 分组，每条告警配四阶段命令，可直接打印或转发给一线处置人员。`--no-playbook` 可关闭 |
| 工作目录 | `audit.jsonl`（操作留痕）、案件报告、IOC 文件 |

### 7.1 处置剧本（Playbook）

每条告警自动附带**四阶段响应命令**，命令里的 IP/账号/主机/URL 已按告警实体自动回填：

| 阶段 | 作用 | 要点 |
| --- | --- | --- |
| ① 核查确认 | 先确认是真中招还是误报 | 没核实就断网/禁账号，业务部门会来找你 |
| ② 遏止血 | 限制影响面 | 顺序：断外联 → 禁账号 → 隔离主机；除勒索扩散外别先关机 |
| ③ 证据固定 | 留存易失证据 | 动之前先取内存镜像、进程列表、日志导出 |
| ④ 根除恢复 | 清后门、补漏洞 | 凭据一律按已泄露处理，全量轮换 |

- **平台自动匹配**：日志来自 Windows 就给 PowerShell/事件日志命令，来自 Linux 就给 bash/journalctl，来自 pcap 就给 tshark，来自数据库就给 SQL，来自 Web 就给 Nginx/Apache 排查命令
- **取不到的变量**显示为 `<IP>`、`<账号>` 这类占位提示，并明确告知需人工替换
- **命令只给人复制执行**：工具本身不执行任何命令、不对目标主机做写操作，与「只读分析」的取证定位一致
- 知识库在 `irlog/respond.py` 的 `PLAYBOOKS` 里**纯数据维护**，加命令不用改逻辑

**取证合规设计**：分析前对每个证据文件计算 SHA256 并写入证据链；分析过程只以只读方式打开原始日志；所有分析动作（启动/上传/下载报告/导入 IOC）追加写入审计日志。

## 8. Web 交互控制台

```bash
python -m irlog serve --evidence-dir D:\IR-CASE\evidence --workdir D:\IR-CASE\output
```

- 浏览器打开 `http://127.0.0.1:8611`（默认仅监听本机回环，不上外网；纯原生 HTML/JS，零外部依赖）
- 九个标签页构成完整交互流程：

| 标签页 | 功能 |
| --- | --- |
| 📁 证据管理 | 拖拽/点选上传（自动计算 SHA256、自动识别日志类型）、勾选待分析文件、单文件删除（二次确认 + 删除前 SHA256 留证 + 审计记录） |
| 🚀 分析中心 | 选择规则集（全部/单类）、IOC 状态、高级阈值覆盖（暴力破解窗口、外传 MB 阈值等）、一键分析、实时进度 |
| 🚨 告警看板 | 按级别/规则/关键词筛选，展开查看实体、ATT&CK、处置建议与原始日志证据样本；**每条告警附四阶段处置剧本（命令一键复制）**，可一键下载《应急响应处置手册》与导出筛选结果 |
| 📈 时间线 | 每小时事件数 SVG 柱状图（告警小时红点标记，悬停查看）+ 日志来源构成 |
| 🧩 类型分析 | 每类已加载日志一张卡片：KPI（如 Web 的 2xx 成功/独立客户端 IP、Windows 的登录失败/成功、数据库的注入语句数）+ 自动结论（回答「谁在攻击 / 谁在爆破 / 有没有打穿」）+ 取证导出提示；下方跨类型综合关联：统一攻击者 IP 画像（风险分级）、关联结论（critical/high 自动回写画像）、全局 IOC 归集、跨源告警时间线 |
| 🛠 规则库 | 查看 13 类内置规则各自在匹配什么；新增 / 编辑 / 删除自定义规则（独立新规则 或 挂载到内置规则追加特征）；特征实时试测（命中高亮）；规则包导入 / 导出（合并或整体替换，替换前自动备份） |
| 🎯 IOC 情报 | 粘贴导入 / 从 `ioc/` 文件载入 / 清空，分析时自动匹配 |
| 📄 报告中心 | 历史运行列表、HTML 报告在线预览、JSON/HTML 下载、一键载入看板复盘 |
| 🧾 审计日志 | 全程操作留痕查询（上传/分析/下载/IOC 导入/规则库变更） |

- 分析人姓名记入顶部栏（localStorage 持久化），随审计与证据链落盘
- 安全措施：静态文件与证据 API 均限制在各自目录内（防路径穿越）、上传文件名净化、操作全程留痕

## 9. 架构与扩展

```
ir-log-analyzer/
├── irlog/
│   ├── cli.py               # argparse 入口（scan/serve/hash/rules）
│   ├── server.py            # Web 交互控制台（stdlib http.server + JSON API）
│   ├── web/                 # 前端（原生 HTML/CSS/JS，零依赖）
│   │   ├── index.html app.js style.css
│   ├── engine.py            # 流式分析引擎（逐事件 → 检测器，常量内存）
│   ├── config.py            # 全部阈值（--set 可覆盖）
│   ├── models.py            # Event / Alert 归一化模型
│   ├── stats.py             # 统计门面：按日志类型分发聚合（web/windows/linux/database）
│   ├── profiles.py          # 日志类型画像：按类型回答各自的应急问题 + 跨类型综合关联
│   ├── rulepack.py          # 自定义规则库模型 + 内置规则清单 + 导入导出
│   ├── evidence.py          # SHA256 证据清单 / 证据链 / 只读保证
│   ├── audit.py             # append-only 审计留痕
│   ├── session.py           # 会话归属：无源 IP 的命令执行 → 发起会话（含置信度）
│   ├── parsers/             # 解析器注册表（pcap 走二进制魔数，其余按文本优先级）
│   │   ├── base.py pcap.py tcpstream.py winxml.py linux.py database.py
│   │   ├── webaccess.py iis.py generic.py
│   ├── detectors/           # 检测器注册表（12 大类规则）
│   │   ├── base.py brute_force.py webshell.py web_attack.py
│   │   ├── account_abuse.py exfiltration.py ransomware.py ioc_match.py
│   │   ├── command_obfuscation.py db_attack.py net_anomaly.py stream_content.py
│   │   ├── attack_chain.py   # 多阶段攻击链（登录→上传→后门落地→交互）
│   │   └── custom.py         # 自定义规则检测器（编译规则库，独立规则 + 挂载特征）
│   ├── respond.py            # 处置知识库（四阶段命令模板 + 实体回填）
│   ├── report_json.py / report_html.py
│   └── tests（tests/）：138 个单元/端到端/大规模测试
```

**新增日志源**：在 `irlog/parsers/` 新建模块，继承 `LogParser`，实现 `detect(sample_lines)` 与生成器 `parse(path)`，在 `parsers/__init__.py` 导入即注册（顺序=嗅探优先级）。

**新增检测规则**：在 `irlog/detectors/` 新建模块，继承 `Detector`，实现 `feed(ev)`（流式累计）与 `finalize()`（产出 Alert），在 `detectors/__init__.py` 的 `ALL_DETECTORS` 登记。

## 10. 运行测试

```bash
python -m unittest discover -s tests -v
```

覆盖：解析器字段抽取（8 类）、自动识别、12 类检测器触发/不触发/阈值配置（含命令混淆解码与误报边界）、**auditd EXECVE 解析与 hex 参数还原**、**会话归属（唯一会话/暴破优先/无会话不造 IP）**、**数据库日志解析（MySQL/PG/MSSQL/Mongo/Redis，含 general log 线程号关联）与注入落地/破坏/提权/拖库检测**、**pcap/pcapng 解析（双封装 + gzip、HTTP/DNS/TLS-SNI/JA3/明文凭据还原）与扫描/信标/DNS/外传检测（含正常流量零告警误报底线）**、**TCP 流重组（乱序/重传/回绕/缺握手兜底/常量内存上限、按 SYN 判定客户端方向）与流内容检测（反向 shell、跨报文凭据对、POST 请求体注入、敏感文件外传、会话内编码载荷）**、**HTTP 请求体/响应体解码（长连接多消息切分、chunked、gzip/deflate）与内容检测（命令回显、敏感文件外传、上传木马、下载执行脚本）**、IOC 匹配、**处置剧本（知识库覆盖度/阶段齐整/实体回填/占位符不残留/主机名不误填为文件名）**、证据只读哈希不变、报告与证据链、XSS 转义、50 万行计时（<60s）、内存峰值（<300MB）。

Web 控制台端到端验证（需先 `python -m irlog serve`）：

```bash
python tests/web_e2e_check.py   # 45 项检查：静态资源/上传字节保真/删除/越界拦截/规则过滤/阈值覆盖/IOC/报告/审计
```

## 11. 多类型分析、跨类型关联与规则库（本版新增）

应急现场往往同时有 Web 访问日志、Windows 安全日志、Linux 认证日志、数据库日志。把它们混在一起看容易淹没信号，强行"一套规则打天下"又会漏掉每类日志独有的应急问题。本版把分析拆成三层：**按类型回答 → 跨类型关联 → 自定义规则**。

### 11.1 类型分析结论（按日志类型分别回答应急问题）

`irlog/profiles.py` 维护一张「日志类型画像」表（`LOG_PROFILES`）。每类日志声明它关注什么 KPI、它要回答哪个应急问题、它重点看哪些规则。分析时只生成**实际加载了**的类型卡片，零样本的类型不出现（例如只导入了 Web 日志，就不会凭空冒出 Windows 卡片）。

每张类型卡片包含：

- **KPI 仪表盘**：Web 看「2xx 成功请求 / 独立客户端 IP / 4xx 错误 / 后台登录成功 / 文件上传调用」；Windows 看「登录失败 / 登录成功 / 账号变更 / 组成员变更 / 日志清除」；Linux 看「失败登录 / 成功登录 / sudo 次数 / 账号变更」；数据库看「高危语句 / 破坏性语句 / 权限变更 / 认证失败」。
- **自动结论**：用文字直接回答该类型的核心问题——Web 是「谁在攻击、打了什么漏洞、有没有 2xx 成功（攻击是否得手）」；Windows 是「谁在爆破、谁登录成功、有没有持久化与提权、日志有没有被清」；数据库是「有没有注入落地、有没有拖库、有没有权限变更」。结论会标记「🔴 反取证」「⚠ 需核查」等优先级。
- **取证导出提示**：每张卡片给出该类日志在目标机上的取证导出命令（如 `wevtutil qe Security /f:csv`、Linux 的 `/var/log/secure`），方便把"下一步要取什么证据"直接留给一线。

报告里这部分是「**二、类型分析结论**」，看板里是「🧩 类型分析」标签页。

### 11.2 跨类型综合关联（谁是同一个攻击者）

单看一类日志只能看到攻击的一个切面。`build_correlation()` 把所有类型归一化到统一的实体（IP / 账号 / 路径 / SQL / 命令）之上，产出四个视图：

- **统一攻击者 IP 画像**：同一 IP 跨 Web / Windows / Linux / 数据库的活动被合并到一张画像，标注它出现在哪些类型、各侧命中数、风险等级（low/medium/high/critical）。风险等级规则：`critical`=命中紧急告警或被 critical 关联结论点名；`high`=命中高危告警或跨 ≥3 类；`medium`=出现于多类或单类高危。
- **关联结论**：自动推导跨类型强信号，例如「Web 注入 → 数据库高危语句」（疑似注入打穿）、「Linux 先暴力后登录成功 + Windows 登录成功」（疑似横向移动）、「Windows 先大量失败随后成功 + 同期账号/组变更」（疑似爆破后提权）、「多类日志同时出现同一 IP」（单一来源跨多资产推进）、「安全日志被清除」（反取证）。critical 结论会**回写**到对应 IP 画像，保证"结论说紧急、画像也标紧急"一致。
- **全局 IOC 归集**：把所有类型的高危 IOC 分类汇总——攻击来源 IP、被攻击的目标账号、敏感路径、危险 SQL、可疑命令、扫描器 UA，一处总览。
- **跨源告警时间线**：把各类型告警按时间排成一条线，统一标注来源 IP 与规则，便于看清攻击推进顺序。

报告里这部分是「**三、跨类型综合关联视图**」，看板里位于「🧩 类型分析」标签页下方。

### 11.3 规则库工作台（把你的环境特征固化成检测）

内置 12 大类规则覆盖通用威胁，但每个环境都有自己的"专属 IOC"——自有系统路径、内部域名、业务专有名词、历史事件的指纹。规则库让使用工具的人**不改代码**就能固化这些特征：

- **查看**：内置规则清单（`builtin_inventory()`）逐条列出 13 类内置规则各自在匹配什么（特征 ID、类型、内容、说明），与检测器源码同源，由测试守护不漂移。
- **新增独立规则**：不设 `attaches_to` 就是一条全新的检测分类，自定义 ID、标题、严重度、MITRE、处置建议，分析时作为独立检测器运行。
- **挂载到内置规则**：设 `attaches_to="webshell"` 时，自定义特征命中后按 webshell 的 ID 与标题出告警——相当于"给 Webshell 规则加了一条 payload"，不破坏内置规则本体。
- **特征实时试测**：写特征时粘贴一段日志文本即可看到命中高亮，降低正则写错的成本。
- **导入 / 导出 / 合并 / 替换**：规则包以 `rules/custom.json` 持久化（不属于证据链）。导入支持「合并」（同 ID 覆盖、新 ID 追加）与「整体替换」（替换前自动备份 `*.bak-时间戳`），便于团队间分享与版本管理。
- **审计**：所有增删改写入审计日志（谁、何时、改了哪条），与取证合规定位一致。

看板里是「🛠 规则库」标签页；REST 接口为 `/api/rulepack`（GET 查看/导出、POST 新增/修改、DELETE 删除、POST /import 导入、POST /test 试测）。分析时引擎自动从工作目录加载 `rules/custom.json` 并将其中的规则编译成检测器。

## 12. 已知限制

- EVTX 二进制文件不直接解析，需按第 3 节导出 XML（可靠性优先；原生 EVTX 解析为规划中的扩展位）
- Linux syslog 文本无年份，按当前年补全（跨年 1 月日志自动回退一年）；建议分析时保证系统时间准确
- Web 访问日志无法看到 POST 请求体，数据外传检测基于响应体大小与路径特征
- 部分检测依赖日志本身是否开启对应审计策略（如 4688 进程创建需配置高级审核策略；Sysmon 需部署）
- 单 IP 单日流量等聚合维度按自然日（本地时区）统计

---

*ir-log-analyzer v1.0.0 · 应急响应专用 · 离线内网 · 纯标准库*

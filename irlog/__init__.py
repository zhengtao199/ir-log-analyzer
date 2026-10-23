"""应急响应日志分析工具（IR Log Analyzer）.

离线内网环境、纯 Python 标准库实现：
- 解析：Windows 安全事件/Sysmon（XML 导出）、Linux auth/syslog/auditd、Nginx/Apache、
  IIS W3C、JSON Lines、数据库日志、**pcap/pcapng（含 TCP 流重组）**
- 检测：暴力破解 / Webshell / Web 攻击 / 权限提升与横向移动 / 数据外传 / 勒索痕迹 /
  命令混淆与编码载荷 / 数据库攻击 / 流量异常 / 流内容 / **上传利用链 / 攻击工具指纹 /
  后台登录爆破** / 攻击链还原 / IOC 匹配
- 输出：CLI 时间线 + 结构化 JSON + 自包含 HTML 报告 + 处置手册 + 本地 Web 展示层
- 取证：原始日志只读、SHA256 证据清单、全程审计留痕、报告含证据链信息
- **靶场取证问答**：`irlog quiz` 自动求解题型（状态码计数/方法种类/上传漏洞路径/
  Webshell 文件名/4xx 条数）并拼接 flag
- **应急响应处置方案**：按「确认-遏制-根除-恢复-加固」五阶段生成带优先级的处置动作
- **会话归属增强**：防火墙（UFW）连接记录 SRC/SPT 与 sshd 登录源端口精确匹配，
  把命令执行归因到真实来源 IP（避免被爆破噪音 IP 误导）
"""

__version__ = "3.0.0"

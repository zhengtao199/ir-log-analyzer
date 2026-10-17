"""应急响应日志分析工具（IR Log Analyzer）.

离线内网环境、纯 Python 标准库实现：
- 解析：Windows 安全事件/Sysmon（XML 导出）、Linux auth/syslog、Nginx/Apache、IIS W3C、JSON Lines
- 检测：暴力破解 / Webshell / Web 攻击 / 权限提升与横向移动 / 数据外传 / 勒索痕迹 / IOC 匹配
- 输出：CLI 时间线 + 结构化 JSON + 自包含 HTML 报告 + 本地 Web 展示层
- 取证：原始日志只读、SHA256 证据清单、全程审计留痕、报告含证据链信息
"""

__version__ = "1.0.0"

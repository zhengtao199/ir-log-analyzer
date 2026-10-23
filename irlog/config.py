"""全局配置与默认阈值。

所有阈值均可通过 CLI ``--set key=value`` 覆盖，例如：
    --set brute_force_window_sec=300 --set brute_force_threshold=5
可用键名见 Config 字段（--set 传错时会列出全部可用键）。
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields


@dataclass
class Config:
    # ---- 暴力破解 ----
    brute_force_window_sec: int = 300          # 统计窗口（秒）
    brute_force_threshold: int = 5             # 窗口内失败次数阈值
    brute_force_min_users: int = 1             # 单源 IP 命中多少不同账号即高危（密码喷洒）

    # ---- Web 攻击 / 扫描器 ----
    web_attack_404_burst: int = 50             # 单 IP 404 次数（扫描器特征）
    web_attack_path_len: int = 512             # URI 长度上限

    # ---- Webshell ----
    webshell_max_uri_len: int = 300
    webshell_suspicious_exts: tuple = ("php", "php3", "php4", "php5", "phtml", "jsp", "jspx", "jspa", "asp", "aspx", "asa", "cer", "cdx", "ashx")

    # ---- 数据外传 ----
    exfil_response_bytes: int = 50 * 1024 * 1024   # 单请求响应体超过该值告警（50MB）
    exfil_daily_bytes: int = 500 * 1024 * 1024     # 单 IP 单日超过该值告警（500MB）

    # ---- 勒索软件 ----
    ransomware_filecreate_burst: int = 100     # 单进程窗口内文件创建数
    ransomware_filecreate_window_sec: int = 60
    ransomware_exts: tuple = ("locked", "enc", "encrypted", "crypt", "crypto", "wannacry", "ryuk", "lockbit", "conti", "aaa", "xyz")

    # ---- 命令混淆 / 编码载荷 ----
    obf_b64_min_len: int = 40                # Base64 候选串最小长度
    obf_entropy_min: float = 4.3             # 高熵阈值（bits/char，避开 GUID/hex）
    obf_caret_min: int = 3                   # cmd ^ 插入混淆最少出现次数
    # ---- 数据库 ----
    db_dump_window_sec: int = 300            # 拖库统计窗口（秒）
    db_dump_min_queries: int = 20            # 窗口内敏感表查询次数阈值

    # ---- 流量分析（pcap / pcapng）----
    net_scan_ports: int = 20               # 窗口内单源访问不同目的端口数（端口扫描）
    net_scan_hosts: int = 20               # 窗口内单源同端口访问不同主机数（横向扫描）
    net_scan_window_sec: int = 120         # 扫描统计窗口（秒）
    net_beacon_min: int = 6                # 相同目标的最小连接次数（C2 心跳）
    net_beacon_cv: float = 0.35            # 间隔变异系数上限（越小越规律）
    net_beacon_min_interval: float = 1.0   # 平均间隔下限（秒），排除突发重连
    net_dns_nxdomain: int = 20             # 窗口内 NXDOMAIN 次数（DGA / 域名爆破）
    net_dns_window_sec: int = 300
    net_dns_tunnel_min: int = 5            # 超长/高熵标签查询次数（DNS 隧道）
    net_dns_entropy: float = 3.6           # 单标签香农熵阈值
    net_dns_label_len: int = 30            # 单标签长度阈值
    net_exfil_bytes: int = 100 * 1024 * 1024   # 流向外部的字节阈值
    net_exfil_ratio: float = 10.0          # 出入字节比阈值
    net_max_tracked: int = 20000           # 流量聚合 key 上限（常量内存保护）

    # ---- 会话归属 ----
    attribution_enabled: bool = True         # 为无源 IP 的命令执行回填来源会话
    session_idle_timeout: float = 1800.0     # 会话空闲超时（秒），超时自动关闭

    max_alerts_per_rule: int = 80              # 单条规则最多保留多少告警（按严重度/次数取 TopN，防告警爆炸）

    # ---- 横向移动 ----
    lateral_type3_burst: int = 10              # 单 IP 远程交互登录次数
    lateral_max_hosts: int = 3                 # 单账号登录主机数上限

    # ---- 通用 ----
    evidence_sample_per_alert: int = 10        # 每条告警保留的原始证据行数上限
    timeline_max_events: int = 200000          # 时间线事件上限（防内存膨胀）
    raw_line_max_len: int = 2000               # 保留的原始日志行长度
    rules: str = "all"                         # all 或逗号分隔的规则 id

    def apply_overrides(self, items: list[str]) -> None:
        """应用 --set key=value 覆盖。"""
        valid = {f.name for f in fields(self)}
        for item in items or []:
            if "=" not in item:
                raise ValueError(f"--set 参数格式错误: {item!r}，应为 key=value")
            key, _, raw = item.partition("=")
            key = key.strip()
            if key not in valid:
                raise ValueError(f"未知配置项: {key}（可用: {sorted(valid)}）")
            cur = getattr(self, key)
            if isinstance(cur, tuple):
                setattr(self, key, tuple(x.strip() for x in raw.split(",") if x.strip()))
            elif isinstance(cur, bool):
                setattr(self, key, raw.lower() in ("1", "true", "yes"))
            else:
                try:
                    setattr(self, key, type(cur)(raw))
                except (TypeError, ValueError):
                    raise ValueError(f"配置项 {key} 值无法转换: {raw!r}")


DEFAULT_CONFIG = Config()

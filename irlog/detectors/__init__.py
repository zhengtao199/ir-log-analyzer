"""检测器注册表。"""
from .base import Detector
from .brute_force import BruteForceDetector
from .webshell import WebshellDetector
from .web_attack import WebAttackDetector
from .account_abuse import AccountAbuseDetector
from .exfiltration import ExfiltrationDetector
from .ransomware import RansomwareDetector
from .command_obfuscation import CommandObfuscationDetector
from .db_attack import DbAttackDetector
from .net_anomaly import NetAnomalyDetector
from .stream_content import StreamContentDetector
from .http_content import HttpContentDetector
from .attack_chain import AttackChainDetector
from .upload_exploit import UploadExploitDetector
from .tooling import ToolingDetector
from .admin_login import AdminLoginDetector
from .ioc_match import IOCDetector, IOCStore, classify  # noqa: F401

ALL_DETECTORS = [
    BruteForceDetector,
    WebshellDetector,
    WebAttackDetector,
    AccountAbuseDetector,
    ExfiltrationDetector,
    RansomwareDetector,
    CommandObfuscationDetector,
    DbAttackDetector,
    NetAnomalyDetector,
    StreamContentDetector,
    HttpContentDetector,
    AttackChainDetector,
    UploadExploitDetector,
    ToolingDetector,
    AdminLoginDetector,
    IOCDetector,
]


def build_detectors(config, ioc_store: IOCStore | None = None) -> list[Detector]:
    allowed = None
    if getattr(config, "rules", "all") and config.rules != "all":
        allowed = {r.strip() for r in config.rules.split(",") if r.strip()}
    out = []
    for cls in ALL_DETECTORS:
        if allowed is not None and cls.rule_id not in allowed:
            continue
        if cls is IOCDetector:
            out.append(cls(config, ioc_store))
        else:
            out.append(cls(config))
    return out


__all__ = ["ALL_DETECTORS", "build_detectors", "IOCStore", "classify"]

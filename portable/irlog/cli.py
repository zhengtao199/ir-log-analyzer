"""命令行入口。

用法：
    python -m irlog scan <文件/目录...> [选项]     # 分析并生成报告
    python -m irlog serve [--port 8611] [--evidence-dir DIR]   # 启动 Web 展示层
    python -m irlog hash <文件...>                 # 仅计算证据 SHA256
    python -m irlog rules                          # 列出全部检测规则

scan 选项：
    --ioc FILE             IOC 列表（txt 每行一条 / csv 首列）
    --out PREFIX           报告输出前缀（默认 irlog-output/<run_id>）
    --format cli,json,html 输出格式（默认全部）
    --set key=value        覆盖阈值，可多次（如 --set brute_force_threshold=3；
                           --set 传错时会列出全部可用键名）
    --operator NAME        分析人（写入证据链）
    --workdir DIR          工作目录（默认 ./irlog-output）
    --no-recursive         目录不递归
    --quiet                精简输出

退出码：0 无告警 / 1 仅低中危 / 2 存在高危或紧急 / 3 执行出错
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__
from .audit import AuditLog
from .config import Config, DEFAULT_CONFIG
from .detectors import ALL_DETECTORS, IOCStore
from .engine import run_analysis
from .evidence import EvidenceSet, chain_of_custody
from .models import SEVERITY_LABELS
from .report_html import write_html_report
from .report_json import write_json_report


def _collect_paths(paths: list[str], recursive: bool) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _d, files in os.walk(p):
                    out.extend(os.path.join(root, f) for f in sorted(files))
            else:
                out.extend(os.path.join(p, f) for f in sorted(os.listdir(p)) if os.path.isfile(os.path.join(p, f)))
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"[警告] 路径不存在，已忽略: {p}", file=sys.stderr)
    return out


def _print_alerts(result) -> None:
    alerts = result.alerts_sorted()
    if not alerts:
        print("\n[结果] 未触发任何检测规则。")
        return
    print(f"\n[结果] 共 {len(alerts)} 条告警（按严重程度排序）：\n")
    print(f"{'级别':<6}{'规则':<16}{'标题':<22}{'次数':>6}  实体/说明")
    print("-" * 100)
    for a in alerts:
        ent = ", ".join(f"{k}={v}" for k, v in list(a.entities.items())[:2])
        desc = (a.description or "")[:60]
        print(f"{SEVERITY_LABELS.get(a.severity, '?'):<6}{a.rule_id:<16}{a.title:<22}{a.count:>6}  {ent}")
        if desc:
            print(f"{'':6}{'':16}{'':22}{'':>6}  └ {desc}")
    worst = min(a.severity for a in alerts)
    print(f"\n最高严重程度: {SEVERITY_LABELS.get(worst, worst)}")


def _print_histogram(result) -> None:
    hist = result.timeline.get("hour_histogram", {})
    if not hist:
        return
    mx = max(hist.values())
    print("\n[时间线] 每小时事件数：")
    for h, c in hist.items():
        bar = "█" * max(1, int(c * 40 / mx))
        print(f"  {h}  {bar} {c}")


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = Config()
    try:
        cfg.apply_overrides(args.set)
    except ValueError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 3

    paths = _collect_paths(args.paths, not args.no_recursive)
    if not paths:
        print("[错误] 没有可分析的证据文件", file=sys.stderr)
        return 3

    workdir = args.workdir
    os.makedirs(workdir, exist_ok=True)
    audit = AuditLog(workdir)
    audit.record(args.operator or "cli", "scan-start", paths=paths, rules=cfg.rules)

    # 证据清单（哈希在全部分析之前计算，保证与磁盘一致）
    evidence = EvidenceSet()
    for p in paths:
        try:
            evidence.add_file(p)
        except OSError as exc:
            print(f"[警告] 无法读取证据: {p} ({exc})", file=sys.stderr)

    ioc_store = IOCStore()
    if args.ioc:
        n = ioc_store.load_file(args.ioc)
        print(f"[IOC] 已加载 {n} 条 IOC（来源: {args.ioc}）")
        audit.record(args.operator or "cli", "ioc-load", file=args.ioc, count=n)

    print(f"[分析] {len(paths)} 个证据文件，规则集: {cfg.rules}，工具版本 v{__version__}")
    if not args.quiet:
        print(f"[分析] 工作目录: {os.path.abspath(workdir)}")

    def progress(msg: str, _frac: float) -> None:
        if not args.quiet:
            print(f"  … {msg}")

    started = time.time()
    result = run_analysis(paths, cfg, ioc_store, progress=progress if not args.quiet else None)
    audit.record(args.operator or "cli", "scan-done", run_id=result.run_id,
                 events=result.stats.get("total_events"), alerts=len(result.alerts))

    custody = chain_of_custody(result.run_id, args.operator or "cli", evidence,
                               started, result.finished, __version__)

    out_prefix = args.out or os.path.join(workdir, result.run_id)
    fmts = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    produced = []
    if "json" in fmts:
        p = out_prefix + ".json"
        write_json_report(p, result, custody)
        produced.append(p)
    if "html" in fmts:
        p = out_prefix + ".html"
        write_html_report(p, result, custody)
        produced.append(p)

    _print_alerts(result)
    if not args.quiet:
        _print_histogram(result)
        print(f"\n[统计] 事件 {result.stats.get('total_events', 0):,} 条 / "
              f"文件 {result.stats.get('total_files', 0)} 个 / 耗时 {result.stats.get('duration_sec', 0):.1f}s")
    for p in produced:
        print(f"[报告] 已生成: {os.path.abspath(p)}")
    if result.errors:
        print(f"[注意] {len(result.errors)} 个文件/检测器出现异常（详见 JSON 报告 errors 字段）")
        for e in result.errors[:5]:
            print(f"  - {e}")

    alerts = result.alerts
    if any(a.severity <= 2 for a in alerts):
        return 2
    if alerts:
        return 1
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    from .evidence import build_evidence_item
    for p in args.paths:
        if not os.path.isfile(p):
            print(f"[警告] 不存在: {p}", file=sys.stderr)
            continue
        item = build_evidence_item(p)
        print(f"{item.sha256}  {_fmt(item.size):>10}  {p}")
    return 0


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def cmd_rules(_args: argparse.Namespace) -> int:
    print(f"检测规则（v{__version__}）：\n")
    for cls in ALL_DETECTORS:
        print(f"  {cls.rule_id:<16} {cls.title}")
        print(f"  {'':16}   {cls.description}")
        if cls.mitre:
            print(f"  {'':16}   ATT&CK: {cls.mitre}")
        print()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import run_server
    return run_server(host=args.host, port=args.port, evidence_dir=args.evidence_dir,
                      workdir=args.workdir)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="irlog",
        description="应急响应日志分析工具（离线内网 / 纯标准库）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"ir-log-analyzer v{__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="分析日志并生成报告")
    sp.add_argument("paths", nargs="+", help="证据文件或目录")
    sp.add_argument("--ioc", help="IOC 列表文件（txt/csv）")
    sp.add_argument("--out", help="报告输出前缀")
    sp.add_argument("--format", default="cli,json,html", help="输出格式（默认 cli,json,html）")
    sp.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="覆盖阈值")
    sp.add_argument("--operator", default=os.environ.get("USERNAME", "analyst"), help="分析人")
    sp.add_argument("--workdir", default="irlog-output", help="工作目录")
    sp.add_argument("--no-recursive", action="store_true", help="目录不递归")
    sp.add_argument("--quiet", action="store_true", help="精简输出")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("hash", help="计算证据文件 SHA256")
    sp.add_argument("paths", nargs="+")
    sp.set_defaults(func=cmd_hash)

    sp = sub.add_parser("rules", help="列出全部检测规则")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("serve", help="启动 Web 展示层")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8611)
    sp.add_argument("--evidence-dir", default=None, help="证据文件目录（Web 上传落盘位置）")
    sp.add_argument("--workdir", default="irlog-output", help="工作目录")
    sp.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n[中断] 用户取消", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001
        print(f"[错误] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

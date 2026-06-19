"""Command-line interface for scanning, report generation and baselines."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver
import sys
import webbrowser
from pathlib import Path
from typing import List, Optional, Sequence

from .baseline import compare_items, load_scan_items, save_baseline
from .auditlog import AuditLogger
from .collectors import CronCollector, LaunchdCollector, MacOSSystemCollector, ShellCollector
from .config import RULES
from .config import ScanConfig
from .reporters import terminal_summary, write_reports
from .scanner import Scanner
from .verifier import FileVerifier


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="persistguard",
        description="macOS 自启动持久化检测与可解释风险评分（只读）",
    )
    parser.add_argument("--version", action="version", version="PersistGuard 1.0.0")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="扫描本机或测试根目录并生成报告")
    scan.add_argument("--root", type=Path, default=Path("/"), help="扫描根目录；测试夹具可指定替代根目录")
    scan.add_argument("--home", type=Path, help="用户主目录；默认使用当前用户 HOME")
    scan.add_argument("--out", type=Path, default=Path("reports"), help="报告输出目录")
    scan.add_argument("--format", choices=["all", "html", "json", "csv"], default="all", help="报告格式")
    scan.add_argument("--stem", default="persistguard-report", help="报告文件名前缀")
    scan.add_argument("--no-system-baseline", action="store_true", help="不扫描 /System/Library 基线")
    scan.add_argument("--no-signature", action="store_true", help="跳过 codesign 校验（夹具/调试用途）")
    scan.add_argument("--baseline-out", type=Path, help="同时保存本次扫描为差异比较基线")
    scan.add_argument("--log", type=Path, help="JSONL 审计日志路径；默认写入输出目录")
    scan.add_argument("--rules", type=Path, help="自定义规则权重与阈值 JSON")
    scan.add_argument("--sources", help="限定采集器：launchd,scheduled,shell,system（逗号分隔）")
    scan.add_argument("--quiet", action="store_true", help="不输出终端摘要")

    baseline = sub.add_parser("compare", help="比较两份 JSON 扫描结果或基线")
    baseline.add_argument("baseline", type=Path)
    baseline.add_argument("current", type=Path)
    baseline.add_argument("--out", type=Path, help="差异 JSON 输出路径；默认写到标准输出")

    serve = sub.add_parser("serve", help="通过本地 HTTP 打开已生成的 HTML 报告")
    serve.add_argument("report", type=Path, nargs="?", default=Path("reports/persistguard-report.html"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-open", action="store_true")
    return parser


def _scan(args: argparse.Namespace) -> int:
    root = args.root.expanduser().resolve()
    home = args.home.expanduser().resolve() if args.home else (Path.home() if root == Path("/") else root / "Users" / "fixture")
    weights = {rule_id: rule.weight for rule_id, rule in RULES.items()}
    high_threshold, medium_threshold, recent_days = 60, 30, 7
    if args.rules:
        custom = json.loads(args.rules.read_text(encoding="utf-8"))
        configured_weights = custom.get("weights", {})
        unknown = set(configured_weights) - set(RULES)
        if unknown:
            raise ValueError(f"未知规则 ID: {', '.join(sorted(unknown))}")
        for rule_id, weight in configured_weights.items():
            if not isinstance(weight, int):
                raise ValueError(f"规则 {rule_id} 权重必须为整数")
            weights[rule_id] = weight
        high_threshold = int(custom.get("high_threshold", high_threshold))
        medium_threshold = int(custom.get("medium_threshold", medium_threshold))
        recent_days = int(custom.get("recent_days", recent_days))
        if not 0 <= medium_threshold < high_threshold <= 100:
            raise ValueError("阈值必须满足 0 <= medium_threshold < high_threshold <= 100")
    config = ScanConfig(
        root=root,
        home=home,
        include_system_baseline=not args.no_system_baseline,
        rule_weights=weights,
        high_threshold=high_threshold,
        medium_threshold=medium_threshold,
        recent_days=recent_days,
    )
    verifier = FileVerifier(config.signature_timeout, enabled=not args.no_signature)
    collector_map = {
        "launchd": LaunchdCollector(config),
        "scheduled": CronCollector(config),
        "shell": ShellCollector(config),
        "system": MacOSSystemCollector(config),
    }
    selected_collectors = None
    if args.sources:
        requested = [source.strip() for source in args.sources.split(",") if source.strip()]
        unknown_sources = set(requested) - set(collector_map)
        if unknown_sources:
            raise ValueError(f"未知采集器: {', '.join(sorted(unknown_sources))}")
        selected_collectors = [collector_map[source] for source in requested]
    log_path = args.log or (args.out / f"{args.stem}-audit.jsonl")
    result = Scanner(config=config, verifier=verifier, collectors=selected_collectors, audit_logger=AuditLogger(log_path)).scan()
    formats: Sequence[str] = ("html", "json", "csv") if args.format == "all" else (args.format,)
    outputs = write_reports(result, args.out, formats=formats, stem=args.stem)
    if args.baseline_out:
        save_baseline(result, args.baseline_out)
    if not args.quiet:
        print(terminal_summary(result, color=sys.stdout.isatty()))
        print("\n报告文件:")
        for output in outputs:
            print(f"  {output.resolve()}")
        if args.baseline_out:
            print(f"  基线: {args.baseline_out.resolve()}")
        print(f"  审计日志: {log_path.resolve()}")
    return 2 if result.summary["HIGH"] else 0


def _compare(args: argparse.Namespace) -> int:
    diff = compare_items(load_scan_items(args.baseline), load_scan_items(args.current))
    text = json.dumps(diff, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(args.out.resolve())
    else:
        print(text)
    return 1 if diff["summary"]["added"] or diff["summary"]["changed"] else 0


def _serve(args: argparse.Namespace) -> int:
    report = args.report.expanduser().resolve()
    if not report.is_file():
        print(f"报告不存在: {report}", file=sys.stderr)
        return 2
    os.chdir(report.parent)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer((args.host, args.port), handler) as server:
        url = f"http://{args.host}:{args.port}/{report.name}"
        print(f"正在提供报告: {url}")
        if not args.no_open:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n已停止。")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.command:
        args = parser.parse_args(["scan", *(argv or [])])
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "compare":
            return _compare(args)
        if args.command == "serve":
            return _serve(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 2

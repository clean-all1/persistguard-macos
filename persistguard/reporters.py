"""Terminal, JSON, CSV and self-contained HTML reporting."""

from __future__ import annotations

import csv
import io
import json
from importlib import resources
from pathlib import Path
from typing import Iterable, List, Sequence

from .models import ScanResult


CSV_FIELDS = [
    "level", "score", "source", "scope", "label", "config_path", "program",
    "arguments", "sign_status", "signer", "file_hash", "owner", "mode", "mtime_iso",
    "run_at_load", "keep_alive", "requires_privilege", "parse_error", "rule_hits",
]


def _csv_safe(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def render_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=indent)


def render_csv(result: ScanResult) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for item in result.items:
        row = item.to_dict()
        row["arguments"] = json.dumps(item.arguments, ensure_ascii=False)
        row["rule_hits"] = "; ".join(f"{hit.rule_id}:{hit.weight:+d}:{hit.reason}" for hit in item.hits)
        writer.writerow({key: _csv_safe(value) for key, value in row.items()})
    return output.getvalue()


def render_html(result: ScanResult) -> str:
    template = resources.files("persistguard").joinpath("templates/report.html").read_text(encoding="utf-8")
    data = json.dumps(result.to_dict(), ensure_ascii=False, separators=(",", ":"))
    data = data.replace("</", "<\\/")
    return template.replace("__SCAN_DATA__", data)


def write_reports(
    result: ScanResult,
    output_dir: Path,
    formats: Sequence[str] = ("html", "json", "csv"),
    stem: str = "persistguard-report",
) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: List[Path] = []
    renderers = {"html": render_html, "json": render_json, "csv": render_csv}
    for format_name in formats:
        if format_name not in renderers:
            raise ValueError(f"Unsupported report format: {format_name}")
        path = output_dir / f"{stem}.{format_name}"
        path.write_text(renderers[format_name](result), encoding="utf-8", newline="")
        outputs.append(path)
    return outputs


def terminal_summary(result: ScanResult, color: bool = True) -> str:
    summary = result.summary
    def styled(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text
    lines = [
        styled("PersistGuard 扫描完成", "1;36"),
        f"主机: {result.host}  耗时: {result.duration_seconds:.3f}s  项目: {summary['TOTAL']}",
        "  ".join([
            styled(f"高危 {summary['HIGH']}", "1;31"),
            styled(f"中危 {summary['MEDIUM']}", "1;33"),
            styled(f"低危 {summary['LOW']}", "1;32"),
            f"采集错误 {len(result.errors)}",
        ]),
    ]
    if result.items:
        lines.append("\n风险最高的项目:")
        for item in result.items[:5]:
            lines.append(f"  {item.level:<6} {item.score:>3}  {item.label or '(未命名)'}  {item.program or item.config_path}")
    return "\n".join(lines)

"""Cron and periodic-task collection."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..config import ScanConfig
from ..models import AutoStartItem, CoverageEntry, ScanError
from ..utils import expand_program, split_command
from .base import CollectionResult


class CronCollector:
    name = "scheduled_tasks"

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def _display_path(self, path: Path) -> str:
        if self.config.root == Path("/"):
            return str(path)
        try:
            return "/" + str(path.relative_to(self.config.root))
        except ValueError:
            return str(path)

    @staticmethod
    def _looks_like_environment(line: str) -> bool:
        head = line.split(None, 1)[0]
        return "=" in head and not head.startswith("@")

    def parse_crontab(self, text: str, config_path: str, system: bool) -> List[AutoStartItem]:
        items: List[AutoStartItem] = []
        for number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or self._looks_like_environment(line):
                continue
            parts = line.split()
            if line.startswith("@"):
                schedule_fields = 1
            else:
                schedule_fields = 5
            command_index = schedule_fields + (1 if system else 0)
            if len(parts) <= command_index:
                continue
            schedule = " ".join(parts[:schedule_fields])
            user = parts[schedule_fields] if system else ""
            command = " ".join(parts[command_index:])
            tokens = split_command(command)
            program = expand_program(tokens[0] if tokens else "", home=self.config.home)
            items.append(AutoStartItem(
                source="cron",
                config_path=f"{config_path}#L{number}",
                label=f"cron:{schedule}:{number}",
                program=program,
                arguments=tokens[1:],
                run_at_load=schedule == "@reboot",
                scope="system" if system else "user",
                raw={"schedule": schedule, "user": user, "line": line},
            ))
        return items

    def _read_crontab_file(self, path: Path, result: CollectionResult, coverage: CoverageEntry) -> None:
        if not path.exists():
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            parsed = self.parse_crontab(text, self._display_path(path), system=True)
            for item in parsed:
                item.mtime = path.stat().st_mtime
            result.items.extend(parsed)
            coverage.item_count += len(parsed)
        except PermissionError as exc:
            coverage.error_count += 1
            result.errors.append(ScanError("collect", self._display_path(path), str(exc), True))
        except OSError as exc:
            coverage.error_count += 1
            result.errors.append(ScanError("collect", self._display_path(path), str(exc)))

    def _collect_user_crontab(self, result: CollectionResult, coverage: CoverageEntry) -> None:
        if self.config.root != Path("/") or shutil.which("crontab") is None:
            return
        try:
            proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=self.config.command_timeout, check=False)
            if proc.returncode == 0:
                parsed = self.parse_crontab(proc.stdout, "crontab:user", system=False)
                result.items.extend(parsed)
                coverage.item_count += len(parsed)
            elif "no crontab" not in proc.stderr.lower():
                coverage.error_count += 1
                result.errors.append(ScanError("collect", "crontab:user", proc.stderr.strip() or "crontab returned an error"))
        except (subprocess.TimeoutExpired, OSError) as exc:
            coverage.error_count += 1
            result.errors.append(ScanError("collect", "crontab:user", str(exc)))

    def _collect_periodic(self, result: CollectionResult, coverage: CoverageEntry) -> None:
        for period in ("daily", "weekly", "monthly"):
            directory = self.config.rooted(f"/etc/periodic/{period}")
            if not directory.is_dir():
                continue
            try:
                paths = sorted(path for path in directory.iterdir() if path.is_file())
            except PermissionError as exc:
                coverage.error_count += 1
                result.errors.append(ScanError("collect", self._display_path(directory), str(exc), True))
                continue
            for path in paths:
                try:
                    first_line = path.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
                    interpreter = ""
                    if first_line and first_line[0].startswith("#!"):
                        interpreter = first_line[0][2:].strip().split()[0]
                    item = AutoStartItem(
                        source="periodic",
                        config_path=self._display_path(path),
                        label=f"periodic:{period}:{path.name}",
                        program=interpreter or self._display_path(path),
                        arguments=[self._display_path(path)] if interpreter else [],
                        scope="system",
                        mtime=path.stat().st_mtime,
                        raw={"period": period},
                    )
                    result.items.append(item)
                    coverage.item_count += 1
                except (PermissionError, OSError) as exc:
                    coverage.error_count += 1
                    result.errors.append(ScanError("collect", self._display_path(path), str(exc), isinstance(exc, PermissionError)))

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("scheduled_tasks", "cron 与 periodic 定时任务")
        for configured in ("/etc/crontab", "/etc/anacrontab"):
            self._read_crontab_file(self.config.rooted(configured), result, coverage)
        self._collect_user_crontab(result, coverage)
        self._collect_periodic(result, coverage)
        if coverage.item_count == 0 and coverage.error_count == 0:
            coverage.note = "未发现已配置的 cron 或 periodic 任务"
        result.coverage.append(coverage)
        return result

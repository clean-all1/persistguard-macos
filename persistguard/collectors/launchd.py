"""LaunchAgent and LaunchDaemon enumeration/parsing."""

from __future__ import annotations

import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.parsers.expat import ExpatError

from ..config import ScanConfig
from ..models import AutoStartItem, CoverageEntry, ScanError
from ..utils import expand_program, normalize_bool
from .base import CollectionResult


class LaunchdCollector:
    name = "launchd"

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def _locations(self) -> List[Tuple[Path, str, str, str]]:
        locations = [
            (self.config.home_path("Library/LaunchAgents"), "launch_agent", "user", "用户 LaunchAgents"),
            (self.config.rooted("/Library/LaunchAgents"), "launch_agent", "system", "全局 LaunchAgents"),
            (self.config.rooted("/Library/LaunchDaemons"), "launch_daemon", "system", "LaunchDaemons"),
        ]
        if self.config.include_system_baseline:
            locations.extend([
                (self.config.rooted("/System/Library/LaunchAgents"), "system_launch_agent", "system", "系统 LaunchAgents 基线"),
                (self.config.rooted("/System/Library/LaunchDaemons"), "system_launch_daemon", "system", "系统 LaunchDaemons 基线"),
            ])
        return locations

    def _display_path(self, path: Path) -> str:
        if self.config.root == Path("/"):
            return str(path)
        try:
            return "/" + str(path.relative_to(self.config.root))
        except ValueError:
            return str(path)

    def parse_plist(self, path: Path, source: str, scope: str) -> AutoStartItem:
        try:
            with path.open("rb") as handle:
                payload: Dict[str, Any] = plistlib.load(handle)
        except (plistlib.InvalidFileException, ExpatError, ValueError) as original:
            if self.config.root != Path("/") or shutil.which("plutil") is None:
                raise
            converted = subprocess.run(
                ["plutil", "-convert", "xml1", "-o", "-", str(path)],
                capture_output=True,
                timeout=self.config.command_timeout,
                check=False,
            )
            if converted.returncode != 0:
                raise original
            payload = plistlib.loads(converted.stdout)
        raw_args = payload.get("ProgramArguments")
        if isinstance(raw_args, str):
            args = [raw_args]
        elif isinstance(raw_args, list):
            args = [str(value) for value in raw_args]
        else:
            args = []
        program = str(payload.get("Program") or (args[0] if args else ""))
        arguments = args[1:] if args and program == args[0] else args
        working_directory = str(payload.get("WorkingDirectory") or "")
        program = expand_program(program, working_directory, self.config.home)
        raw = {
            "program_key": str(payload.get("Program") or ""),
            "working_directory": working_directory,
            "disabled": normalize_bool(payload.get("Disabled", False)),
            "start_interval": payload.get("StartInterval"),
            "start_calendar_interval": payload.get("StartCalendarInterval"),
            "process_type": payload.get("ProcessType", ""),
        }
        return AutoStartItem(
            source=source,
            config_path=self._display_path(path),
            label=str(payload.get("Label") or path.stem),
            program=program,
            arguments=arguments,
            run_at_load=normalize_bool(payload.get("RunAtLoad", False)),
            keep_alive=normalize_bool(payload.get("KeepAlive", False)),
            scope=scope,
            mtime=path.stat().st_mtime,
            raw=raw,
        )

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        for directory, source, scope, display_name in self._locations():
            coverage = CoverageEntry(source, display_name, available=directory.is_dir())
            if not directory.is_dir():
                coverage.note = "目录不存在，当前系统未使用该点位"
                result.coverage.append(coverage)
                continue
            try:
                paths = sorted(directory.glob("*.plist"))
            except PermissionError as exc:
                coverage.available = False
                coverage.error_count += 1
                coverage.note = "无权限读取"
                result.errors.append(ScanError("collect", self._display_path(directory), str(exc), True))
                result.coverage.append(coverage)
                continue
            for path in paths:
                try:
                    result.items.append(self.parse_plist(path, source, scope))
                    coverage.item_count += 1
                except PermissionError as exc:
                    coverage.error_count += 1
                    result.errors.append(ScanError("parse", self._display_path(path), str(exc), True))
                    result.items.append(AutoStartItem(source, self._display_path(path), path.stem, scope=scope, requires_privilege=True, parse_error=str(exc)))
                except (OSError, ValueError, plistlib.InvalidFileException, ExpatError, subprocess.TimeoutExpired) as exc:
                    coverage.error_count += 1
                    result.errors.append(ScanError("parse", self._display_path(path), str(exc)))
                    result.items.append(AutoStartItem(source, self._display_path(path), path.stem, scope=scope, parse_error=str(exc)))
            result.coverage.append(coverage)
        return result

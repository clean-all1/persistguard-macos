"""Login items, BTM records, login hooks and configuration profiles."""

from __future__ import annotations

import json
import plistlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import unquote, urlparse

from ..config import ScanConfig
from ..models import AutoStartItem, CoverageEntry, ScanError
from ..utils import expand_program, split_command
from .base import CollectionResult


class MacOSSystemCollector:
    name = "macos_system"

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def _run(self, args: List[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=self.config.command_timeout, check=False)

    @staticmethod
    def _walk_login_items(value: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(value, dict):
            if any(key in value for key in ("path", "_name", "name")):
                yield value
            for child in value.values():
                yield from MacOSSystemCollector._walk_login_items(child)
        elif isinstance(value, list):
            for child in value:
                yield from MacOSSystemCollector._walk_login_items(child)

    def _login_items(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("login_item", "登录项 / Background Items")
        if self.config.root != Path("/") or shutil.which("system_profiler") is None:
            coverage.available = self.config.root == Path("/")
            coverage.note = "夹具扫描不调用主机 system_profiler" if self.config.root != Path("/") else "system_profiler 不可用"
            result.coverage.append(coverage)
            return result
        try:
            proc = self._run(["system_profiler", "SPLoginItemDataType", "-json"])
            if proc.returncode != 0:
                raise OSError(proc.stderr.strip() or "system_profiler failed")
            payload = json.loads(proc.stdout or "{}")
            seen = set()
            for entry in self._walk_login_items(payload):
                path = str(entry.get("path") or entry.get("location") or "")
                name = str(entry.get("_name") or entry.get("name") or Path(path).name or "login-item")
                key = (name, path)
                if key in seen or (not path and name in {"SPLoginItemDataType", "login_items"}):
                    continue
                seen.add(key)
                result.items.append(AutoStartItem(
                    source="login_item",
                    config_path="system_profiler:SPLoginItemDataType",
                    label=name,
                    program=expand_program(path, home=self.config.home),
                    run_at_load=True,
                    scope="user",
                    raw={key: value for key, value in entry.items() if isinstance(value, (str, int, float, bool))},
                ))
                coverage.item_count += 1
        except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError) as exc:
            coverage.error_count += 1
            coverage.available = False
            coverage.note = "登录项查询失败，已降级继续"
            result.errors.append(ScanError("collect", "system_profiler:SPLoginItemDataType", str(exc)))
        if coverage.item_count == 0 and coverage.error_count == 0:
            coverage.note = "未发现传统登录项"
        result.coverage.append(coverage)
        return result

    def _btm(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("background_item", "BTM / SMAppService 后台项")
        if self.config.root != Path("/") or shutil.which("sfltool") is None:
            coverage.available = False
            coverage.note = "sfltool 不可用或当前为夹具扫描"
            result.coverage.append(coverage)
            return result
        try:
            proc = self._run(["sfltool", "dumpbtm"])
            if proc.returncode != 0:
                raise OSError(proc.stderr.strip() or "sfltool dumpbtm failed")
            current: Dict[str, str] = {}
            records: List[Dict[str, str]] = []
            for raw in proc.stdout.splitlines():
                line = raw.strip()
                match = re.match(r"([A-Za-z][A-Za-z ]+):\s*(.*)", line)
                if not match:
                    continue
                key, value = match.group(1).strip().lower().replace(" ", "_"), match.group(2).strip()
                if key in {"uuid", "name"} and current and ("name" in current or "url" in current):
                    records.append(current)
                    current = {}
                current[key] = value
            if current:
                records.append(current)
            seen = set()
            for record in records:
                record_type = record.get("type", "").lower()
                if not any(token in record_type for token in ("app (", "agent", "daemon", "login", "background app")):
                    continue
                raw_url = record.get("url", "")
                if raw_url == "(null)":
                    raw_url = ""
                url = unquote(urlparse(raw_url).path) if raw_url.startswith("file://") else unquote(raw_url)
                executable = record.get("executable_path", "")
                if executable == "(null)":
                    executable = ""
                program = executable or url
                name = record.get("name") or record.get("identifier") or record.get("uuid") or Path(program).name
                if name == "(null)" or not name or (name, program) in seen:
                    continue
                seen.add((name, program))
                enabled = "[enabled" in record.get("disposition", "").lower()
                result.items.append(AutoStartItem(
                    source="background_item",
                    config_path=url or "sfltool:dumpbtm",
                    label=name,
                    program=program,
                    run_at_load=enabled,
                    scope="system" if "daemon" in record_type else "user",
                    raw=record,
                ))
                coverage.item_count += 1
        except (subprocess.TimeoutExpired, OSError) as exc:
            coverage.error_count += 1
            coverage.available = False
            message = str(exc)
            needs_privilege = any(token in message.lower() for token in ("authorization", "privilege", "permission", "denied"))
            coverage.note = "BTM 查询需要管理员授权" if needs_privilege else "BTM 查询失败，已降级继续"
            result.errors.append(ScanError("collect", "sfltool:dumpbtm", message, needs_privilege))
        if coverage.item_count == 0 and coverage.error_count == 0:
            coverage.note = "未发现 BTM 后台项"
        result.coverage.append(coverage)
        return result

    def _hooks(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("login_hook", "登录 / 注销钩子")
        paths = [
            self.config.home_path("Library/Preferences/com.apple.loginwindow.plist"),
            self.config.rooted("/Library/Preferences/com.apple.loginwindow.plist"),
        ]
        for path in paths:
            if not path.is_file():
                continue
            try:
                with path.open("rb") as handle:
                    payload = plistlib.load(handle)
                for key in ("LoginHook", "LogoutHook"):
                    command = str(payload.get(key) or "").strip()
                    if not command:
                        continue
                    tokens = split_command(command)
                    result.items.append(AutoStartItem(
                        source="login_hook",
                        config_path=str(path),
                        label=key,
                        program=expand_program(tokens[0] if tokens else "", home=self.config.home),
                        arguments=tokens[1:],
                        run_at_load=key == "LoginHook",
                        scope="system" if str(path).startswith("/Library") else "user",
                        mtime=path.stat().st_mtime,
                        raw={"hook": key, "command": command},
                    ))
                    coverage.item_count += 1
            except PermissionError as exc:
                coverage.error_count += 1
                result.errors.append(ScanError("collect", str(path), str(exc), True))
            except (OSError, ValueError, plistlib.InvalidFileException) as exc:
                coverage.error_count += 1
                result.errors.append(ScanError("parse", str(path), str(exc)))
        if coverage.item_count == 0 and coverage.error_count == 0:
            coverage.note = "未配置登录或注销钩子"
        result.coverage.append(coverage)
        return result

    @staticmethod
    def _profile_records(value: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(value, dict):
            if any(key in value for key in ("PayloadIdentifier", "ProfileIdentifier", "profileIdentifier")):
                yield value
            for child in value.values():
                yield from MacOSSystemCollector._profile_records(child)
        elif isinstance(value, list):
            for child in value:
                yield from MacOSSystemCollector._profile_records(child)

    def _profiles(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("configuration_profile", "配置描述文件")
        if self.config.root != Path("/") or shutil.which("profiles") is None:
            coverage.available = False
            coverage.note = "profiles 命令不可用或当前为夹具扫描"
            result.coverage.append(coverage)
            return result
        try:
            proc = self._run(["profiles", "list", "-output", "stdout-xml"])
            if proc.returncode not in {0, 3}:
                raise OSError(proc.stderr.strip() or "profiles list failed")
            if proc.stdout.strip():
                payload = plistlib.loads(proc.stdout.encode("utf-8"))
                seen = set()
                for record in self._profile_records(payload):
                    identifier = str(record.get("PayloadIdentifier") or record.get("ProfileIdentifier") or record.get("profileIdentifier") or "")
                    if not identifier or identifier in seen:
                        continue
                    seen.add(identifier)
                    display = str(record.get("PayloadDisplayName") or record.get("ProfileDisplayName") or identifier)
                    result.items.append(AutoStartItem(
                        source="configuration_profile",
                        config_path="profiles:list",
                        label=display,
                        program="",
                        scope="system",
                        raw={"identifier": identifier, "organization": str(record.get("PayloadOrganization") or "")},
                    ))
                    coverage.item_count += 1
        except (subprocess.TimeoutExpired, OSError, ValueError, plistlib.InvalidFileException) as exc:
            coverage.error_count += 1
            coverage.available = False
            coverage.note = "描述文件查询失败，已降级继续"
            result.errors.append(ScanError("collect", "profiles:list", str(exc), "permission" in str(exc).lower()))
        if coverage.item_count == 0 and coverage.error_count == 0:
            coverage.note = "未发现配置描述文件"
        result.coverage.append(coverage)
        return result

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        for operation in (self._login_items, self._btm, self._hooks, self._profiles):
            result.extend(operation())
        return result

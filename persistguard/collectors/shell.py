"""User shell-startup script collection."""

from __future__ import annotations

from pathlib import Path
import re
from typing import List

from ..config import SHELL_RC_FILES, ScanConfig
from ..models import AutoStartItem, CoverageEntry, ScanError
from ..utils import expand_program, split_command
from .base import CollectionResult


class ShellCollector:
    name = "shell_startup"
    SKIP_PREFIXES = (
        "#", "export ", "alias ", "unalias ", "typeset ", "set ", "unset ",
        "source ", ". ", "function ", "if ", "then", "else", "elif ", "fi",
        "case ", "esac", "for ", "while ", "do", "done", "return", "bindkey ",
        "autoload ", "compinit", "PATH=", "PROMPT=", "PS1=", "[ ", "[[ ", "test ",
    )
    ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
    COMMAND_SUBSTITUTION = re.compile(r"\$\((.+)\)")
    BACKTICK_SUBSTITUTION = re.compile(r"`(.+)`")

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    @classmethod
    def _actionable(cls, line: str) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith(cls.SKIP_PREFIXES):
            return False
        if stripped.startswith("eval ") and "$(" not in stripped and "`" not in stripped:
            return False
        if cls.ASSIGNMENT.match(stripped) and "$(" not in stripped and "`" not in stripped:
            return False
        return bool(split_command(stripped))

    @classmethod
    def _command_tokens(cls, line: str) -> List[str]:
        if cls.ASSIGNMENT.match(line) or line.startswith("eval "):
            match = cls.COMMAND_SUBSTITUTION.search(line) or cls.BACKTICK_SUBSTITUTION.search(line)
            if not match:
                return []
            return split_command(match.group(1))
        return split_command(line)

    def parse(self, path: Path) -> List[AutoStartItem]:
        items: List[AutoStartItem] = []
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not self._actionable(line):
                continue
            tokens = self._command_tokens(line)
            if not tokens:
                continue
            program = expand_program(tokens[0], home=self.config.home)
            items.append(AutoStartItem(
                source="shell_rc",
                config_path=f"{path}#L{number}",
                label=f"{path.name}:{number}",
                program=program,
                arguments=tokens[1:],
                run_at_load=True,
                scope="user",
                mtime=path.stat().st_mtime,
                raw={"line": line},
            ))
        return items

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        coverage = CoverageEntry("shell_rc", "Shell 启动脚本")
        seen_files = 0
        for relative in SHELL_RC_FILES:
            path = self.config.home_path(relative)
            if not path.is_file():
                continue
            seen_files += 1
            try:
                parsed = self.parse(path)
                result.items.extend(parsed)
                coverage.item_count += len(parsed)
            except PermissionError as exc:
                coverage.error_count += 1
                result.errors.append(ScanError("collect", str(path), str(exc), True))
            except OSError as exc:
                coverage.error_count += 1
                result.errors.append(ScanError("collect", str(path), str(exc)))
        if seen_files == 0:
            coverage.note = "未找到常见 Shell 启动脚本"
        elif coverage.item_count == 0:
            coverage.note = "启动脚本存在，但未发现可执行命令"
        result.coverage.append(coverage)
        return result

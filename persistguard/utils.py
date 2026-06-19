"""Small side-effect-free helpers."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable, List


def normalize_bool(value: object) -> bool:
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def split_command(command: str) -> List[str]:
    try:
        return shlex.split(command, comments=True, posix=True)
    except ValueError:
        return command.strip().split()


def expand_program(program: str, working_directory: str = "", home: Path | None = None) -> str:
    if not program:
        return ""
    env = dict(os.environ)
    if home:
        env["HOME"] = str(home)
    expanded = program
    if home:
        expanded = expanded.replace("${HOME}", str(home)).replace("$HOME", str(home))
    expanded = os.path.expandvars(expanded)
    if expanded.startswith("~") and home:
        expanded = str(home) + expanded[1:]
    elif expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)
    if not os.path.isabs(expanded) and working_directory:
        expanded = os.path.join(working_directory, expanded)
    return os.path.normpath(expanded)


def is_hidden_path(path: str) -> bool:
    if not path:
        return False
    return any(part.startswith(".") and part not in {".", ".."} for part in Path(path).parts)


def unique_strings(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

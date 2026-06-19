"""Shared, serializable data models used across the scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class RuleHit:
    rule_id: str
    weight: int
    title: str
    reason: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AutoStartItem:
    source: str
    config_path: str
    label: str = ""
    program: str = ""
    arguments: List[str] = field(default_factory=list)
    run_at_load: bool = False
    keep_alive: bool = False
    sign_status: str = "unknown"
    signer: str = ""
    file_hash: str = ""
    owner: str = ""
    mode: str = ""
    mtime: float = 0.0
    size: int = 0
    scope: str = "user"
    requires_privilege: bool = False
    parse_error: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    hits: List[RuleHit] = field(default_factory=list)
    score: int = 0
    level: str = "LOW"
    recommendations: List[str] = field(default_factory=list)

    @property
    def command(self) -> str:
        return " ".join([self.program, *self.arguments]).strip()

    @property
    def id(self) -> str:
        return f"{self.source}:{self.config_path}:{self.label}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["command"] = self.command
        data["id"] = self.id
        data["mtime_iso"] = (
            datetime.fromtimestamp(self.mtime, tz=timezone.utc).isoformat()
            if self.mtime
            else ""
        )
        return data


@dataclass
class ScanError:
    stage: str
    path: str
    message: str
    needs_privilege: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageEntry:
    source: str
    display_name: str
    attempted: bool = True
    available: bool = True
    item_count: int = 0
    error_count: int = 0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    items: List[AutoStartItem]
    errors: List[ScanError] = field(default_factory=list)
    coverage: List[CoverageEntry] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    host: str = ""
    os_version: str = ""
    tool_version: str = "1.0.0"
    scan_root: str = "/"
    policy: Dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> Dict[str, int]:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in self.items:
            counts[item.level] = counts.get(item.level, 0) + 1
        counts["TOTAL"] = len(self.items)
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "metadata": {
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": self.duration_seconds,
                "host": self.host,
                "os_version": self.os_version,
                "tool_version": self.tool_version,
                "scan_root": self.scan_root,
            },
            "summary": self.summary,
            "policy": self.policy,
            "coverage": [entry.to_dict() for entry in self.coverage],
            "errors": [error.to_dict() for error in self.errors],
            "items": [item.to_dict() for item in self.items],
        }

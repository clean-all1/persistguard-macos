"""Five-stage collection -> parse -> verify -> score -> result pipeline."""

from __future__ import annotations

import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from . import __version__
from .collectors import CronCollector, LaunchdCollector, MacOSSystemCollector, ShellCollector
from .collectors.base import CollectionResult
from .config import ScanConfig
from .engine import RuleEngine
from .models import AutoStartItem, ScanError, ScanResult
from .verifier import FileVerifier
from .auditlog import AuditLogger


class Scanner:
    def __init__(
        self,
        config: Optional[ScanConfig] = None,
        verifier: Optional[FileVerifier] = None,
        collectors: Optional[Iterable[object]] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.verifier = verifier or FileVerifier(self.config.signature_timeout)
        self.collectors = list(collectors) if collectors is not None else [
            LaunchdCollector(self.config),
            CronCollector(self.config),
            ShellCollector(self.config),
            MacOSSystemCollector(self.config),
        ]
        self.engine = RuleEngine(
            self.config.recent_days,
            weights=self.config.rule_weights,
            high_threshold=self.config.high_threshold,
            medium_threshold=self.config.medium_threshold,
        )
        self.audit_logger = audit_logger
        self._verification_cache = {}
        self._verification_error_paths = set()
        self._verification_error_privilege = {}

    def _real_program_path(self, program: str) -> str:
        if self.config.root == Path("/") or not program.startswith("/"):
            return program
        return str(self.config.root / program.lstrip("/"))

    def _verify(self, item: AutoStartItem, errors: List[ScanError]) -> None:
        if not item.program:
            item.sign_status = "unknown"
            return
        real_program = self._real_program_path(item.program)
        try:
            if real_program not in self._verification_cache:
                signature, signer = self.verifier.check_signature(real_program)
                metadata = self.verifier.file_metadata(real_program)
                self._verification_cache[real_program] = (signature, signer, metadata)
            item.sign_status, item.signer, metadata = self._verification_cache[real_program]
            item.requires_privilege = self._verification_error_privilege.get(real_program, False)
            for key, value in metadata.items():
                setattr(item, key, value)
            if self.config.root != Path("/") and metadata:
                item.owner = "fixture"
        except PermissionError as exc:
            item.requires_privilege = True
            item.sign_status = "unknown"
            self._verification_cache[real_program] = ("unknown", "", {})
            self._verification_error_privilege[real_program] = True
            if real_program not in self._verification_error_paths:
                errors.append(ScanError("verify", item.program, str(exc), True))
                self._verification_error_paths.add(real_program)
        except OSError as exc:
            item.sign_status = "unknown"
            self._verification_cache[real_program] = ("unknown", "", {})
            self._verification_error_privilege[real_program] = False
            if real_program not in self._verification_error_paths:
                errors.append(ScanError("verify", item.program, str(exc)))
                self._verification_error_paths.add(real_program)

    def scan(self) -> ScanResult:
        wall_start = time.perf_counter()
        started = datetime.now(timezone.utc)
        if self.audit_logger:
            self.audit_logger.emit("scan_started", root=str(self.config.root), home=str(self.config.home), collectors=[collector.__class__.__name__ for collector in self.collectors])
        collected = CollectionResult()
        for collector in self.collectors:
            try:
                batch = collector.collect()  # type: ignore[attr-defined]
                collected.extend(batch)
                if self.audit_logger:
                    self.audit_logger.emit("collector_finished", collector=collector.__class__.__name__, items=len(batch.items), errors=len(batch.errors))
            except Exception as exc:  # collector isolation is a deliberate reliability boundary
                collected.errors.append(ScanError("collector", collector.__class__.__name__, str(exc)))
                if self.audit_logger:
                    self.audit_logger.emit("collector_failed", collector=collector.__class__.__name__, error=str(exc))

        deduplicated = {}
        for item in collected.items:
            deduplicated.setdefault(item.id, item)
        items = list(deduplicated.values())
        for item in items:
            self._verify(item, collected.errors)
        items = self.engine.evaluate_all(items)

        finished = datetime.now(timezone.utc)
        result = ScanResult(
            items=items,
            errors=collected.errors,
            coverage=collected.coverage,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=round(time.perf_counter() - wall_start, 3),
            host=socket.gethostname() if self.config.root == Path("/") else "fixture.local",
            os_version=platform.platform(),
            tool_version=__version__,
            scan_root=str(self.config.root),
            policy={
                "weights": dict(self.config.rule_weights),
                "high_threshold": self.config.high_threshold,
                "medium_threshold": self.config.medium_threshold,
                "recent_days": self.config.recent_days,
            },
        )
        if self.audit_logger:
            self.audit_logger.emit("scan_finished", duration_seconds=result.duration_seconds, summary=result.summary, errors=len(result.errors))
        return result

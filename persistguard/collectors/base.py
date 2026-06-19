from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..models import AutoStartItem, CoverageEntry, ScanError


@dataclass
class CollectionResult:
    items: List[AutoStartItem] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    coverage: List[CoverageEntry] = field(default_factory=list)

    def extend(self, other: "CollectionResult") -> None:
        self.items.extend(other.items)
        self.errors.extend(other.errors)
        self.coverage.extend(other.coverage)

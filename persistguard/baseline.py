"""Save and compare scan baselines without mutating the host."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .models import ScanResult


def _fingerprint(item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": item.get("id", ""),
        "label": item.get("label", ""),
        "source": item.get("source", ""),
        "config_path": item.get("config_path", ""),
        "program": item.get("program", ""),
        "arguments": item.get("arguments", []),
        "file_hash": item.get("file_hash", ""),
        "sign_status": item.get("sign_status", "unknown"),
        "score": item.get("score", 0),
        "level": item.get("level", "LOW"),
    }


def save_baseline(result: ScanResult, path: Path) -> None:
    payload = {
        "schema_version": "1.0",
        "created_at": result.finished_at,
        "host": result.host,
        "items": [_fingerprint(item.to_dict()) for item in result.items],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_scan_items(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("items")
    if not isinstance(items, list):
        raise ValueError("JSON does not contain an items array")
    return [_fingerprint(item) for item in items if isinstance(item, dict)]


def compare_items(baseline: List[Mapping[str, Any]], current: List[Mapping[str, Any]]) -> Dict[str, Any]:
    before = {str(item.get("id")): _fingerprint(item) for item in baseline}
    after = {str(item.get("id")): _fingerprint(item) for item in current}
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    changed = []
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        changes = {field: {"before": old.get(field), "after": new.get(field)} for field in new if field != "id" and old.get(field) != new.get(field)}
        if changes:
            changed.append({"id": key, "label": new.get("label", ""), "changes": changes})
    return {
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "unchanged": len(before.keys() & after.keys()) - len(changed)},
        "added": added,
        "removed": removed,
        "changed": changed,
    }

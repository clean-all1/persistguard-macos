"""Persistence-point collectors."""

from .base import CollectionResult
from .cron import CronCollector
from .launchd import LaunchdCollector
from .shell import ShellCollector
from .system import MacOSSystemCollector

__all__ = [
    "CollectionResult",
    "CronCollector",
    "LaunchdCollector",
    "ShellCollector",
    "MacOSSystemCollector",
]

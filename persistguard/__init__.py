"""PersistGuard - read-only macOS persistence risk auditing."""

from .models import AutoStartItem, RuleHit, ScanResult

__all__ = ["AutoStartItem", "RuleHit", "ScanResult"]
__version__ = "1.0.0"

import json
import tempfile
import unittest
from pathlib import Path

from persistguard.auditlog import AuditLogger


class AuditLogTests(unittest.TestCase):
    def test_jsonl_is_append_only_and_parseable(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.emit("scan_started", root="/")
            logger.emit("scan_finished", items=3)
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([record["event"] for record in records], ["scan_started", "scan_finished"])
            self.assertTrue(all("timestamp" in record for record in records))


if __name__ == "__main__":
    unittest.main()

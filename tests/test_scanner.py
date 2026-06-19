import tempfile
import unittest
from pathlib import Path

from persistguard.config import ScanConfig
from persistguard.scanner import Scanner
from persistguard.collectors.base import CollectionResult
from persistguard.models import AutoStartItem


class FakeVerifier:
    def check_signature(self, program):
        return ("unsigned", "")

    def file_metadata(self, program):
        path = Path(program)
        return {"owner": "fixture", "mode": "0o755", "mtime": path.stat().st_mtime, "size": path.stat().st_size, "file_hash": "abc123"} if path.exists() else {}


class ScannerTests(unittest.TestCase):
    def test_demo_fixture_end_to_end(self):
        fixture = Path(__file__).parent / "fixtures" / "demo_root"
        config = ScanConfig(root=fixture, home=fixture / "Users" / "fixture", include_system_baseline=False)
        result = Scanner(config=config, verifier=FakeVerifier()).scan()
        demo = next(item for item in result.items if item.label == "test.demo.persist")
        self.assertEqual(demo.level, "HIGH")
        self.assertGreaterEqual(demo.score, 65)
        self.assertEqual(demo.file_hash, "abc123")
        self.assertTrue(result.coverage)

    def test_duplicate_verification_error_is_reported_once(self):
        class Collector:
            def collect(self):
                return CollectionResult(items=[
                    AutoStartItem("launch_agent", "/a", "a", "/protected/tool"),
                    AutoStartItem("background_item", "/b", "b", "/protected/tool"),
                ])

        class DeniedVerifier:
            def check_signature(self, program):
                raise PermissionError("denied")

            def file_metadata(self, program):
                return {}

        result = Scanner(config=ScanConfig(include_system_baseline=False), verifier=DeniedVerifier(), collectors=[Collector()]).scan()
        self.assertEqual(len(result.errors), 1)
        self.assertTrue(all(item.sign_status == "unknown" for item in result.items))


if __name__ == "__main__":
    unittest.main()

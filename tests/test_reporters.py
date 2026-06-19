import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from persistguard.engine import RuleEngine
from persistguard.models import AutoStartItem, CoverageEntry, ScanResult
from persistguard.reporters import render_csv, render_html, render_json, terminal_summary, write_reports


class ReporterTests(unittest.TestCase):
    def setUp(self):
        item = RuleEngine(now=1_800_000_000).evaluate(AutoStartItem("launch_agent", "/a", "测试项", "/tmp/x", sign_status="unsigned"))
        self.result = ScanResult([item], coverage=[CoverageEntry("launch_agent", "用户 LaunchAgents", item_count=1)], host="test.local")

    def test_json_schema(self):
        payload = json.loads(render_json(self.result))
        self.assertEqual(payload["summary"]["TOTAL"], 1)
        self.assertEqual(payload["items"][0]["label"], "测试项")

    def test_csv_is_parseable(self):
        rows = list(csv.DictReader(io.StringIO(render_csv(self.result))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "launch_agent")

    def test_csv_neutralizes_formula_values(self):
        self.result.items[0].label = "=HYPERLINK(\"https://example.invalid\")"
        rows = list(csv.DictReader(io.StringIO(render_csv(self.result))))
        self.assertTrue(rows[0]["label"].startswith("'="))

    def test_html_is_self_contained_and_has_data(self):
        html = render_html(self.result)
        self.assertNotIn("__SCAN_DATA__", html)
        self.assertIn("PersistGuard", html)
        self.assertIn("测试项", html)
        self.assertNotIn("<script src=", html)

    def test_html_escapes_script_terminator_in_embedded_data(self):
        self.result.items[0].label = "</script><script>alert(1)</script>"
        html = render_html(self.result)
        self.assertNotIn('"label":"</script>', html)
        self.assertIn('"label":"<\\/script>', html)

    def test_terminal_summary(self):
        text = terminal_summary(self.result, color=False)
        self.assertIn("扫描完成", text)
        self.assertIn("测试项", text)

    def test_write_reports_creates_all_formats(self):
        with tempfile.TemporaryDirectory() as td:
            outputs = write_reports(self.result, Path(td), formats=("html", "json", "csv"), stem="scan")
            self.assertEqual([path.name for path in outputs], ["scan.html", "scan.json", "scan.csv"])
            self.assertTrue(all(path.is_file() and path.stat().st_size > 0 for path in outputs))


if __name__ == "__main__":
    unittest.main()

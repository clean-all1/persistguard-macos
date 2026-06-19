import unittest

from persistguard.models import AutoStartItem, ScanResult


class ModelTests(unittest.TestCase):
    def test_summary_and_serialization(self):
        items = [
            AutoStartItem("launch_agent", "/a", level="HIGH", score=70),
            AutoStartItem("cron", "/b", level="MEDIUM", score=40),
            AutoStartItem("shell_rc", "/c", level="LOW", score=0),
        ]
        result = ScanResult(items)
        self.assertEqual(result.summary, {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "TOTAL": 3})
        self.assertEqual(result.to_dict()["schema_version"], "1.0")

    def test_item_command_and_id(self):
        item = AutoStartItem("cron", "/etc/crontab#L1", "task", "/bin/sh", ["-c", "echo ok"])
        self.assertEqual(item.command, "/bin/sh -c echo ok")
        self.assertIn("cron:/etc/crontab#L1:task", item.id)


if __name__ == "__main__":
    unittest.main()

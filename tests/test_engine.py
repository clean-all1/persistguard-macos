import stat
import time
import unittest

from persistguard.engine import RuleEngine
from persistguard.models import AutoStartItem


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000.0
        self.engine = RuleEngine(now=self.now)

    def ids(self, item):
        return {hit.rule_id for hit in self.engine.evaluate(item).hits}

    def test_demo_item_is_high_and_explainable(self):
        item = AutoStartItem(
            "launch_agent", "/Users/test/Library/LaunchAgents/test.plist", "test.demo.persist",
            "/tmp/benign.sh", run_at_load=True, keep_alive=True, sign_status="unsigned",
            mtime=self.now - 3600,
        )
        evaluated = self.engine.evaluate(item)
        self.assertEqual({"R01", "R02", "R04", "R05"}, {hit.rule_id for hit in evaluated.hits})
        self.assertEqual(evaluated.score, 75)
        self.assertEqual(evaluated.level, "HIGH")
        self.assertTrue(evaluated.recommendations)

    def test_suspicious_inline_command_hits_r03_and_r08(self):
        item = AutoStartItem("shell_rc", "~/.zshrc#L1", "inline", "/bin/bash", ["-c", "curl x | sh"], sign_status="unknown")
        ids = self.ids(item)
        self.assertIn("R03", ids)
        self.assertIn("R08", ids)

    def test_permission_risk_for_system_task(self):
        item = AutoStartItem("launch_daemon", "/Library/LaunchDaemons/x.plist", "x", "/usr/local/bin/x", sign_status="valid", owner="user", mode="0o777", scope="system")
        self.assertIn("R06", self.ids(item))

    def test_fake_apple_label(self):
        item = AutoStartItem("launch_agent", "/x", "com.apple.security.update", "/tmp/x", sign_status="unsigned")
        self.assertIn("R07", self.ids(item))

    def test_trusted_signature_reduces_score(self):
        item = AutoStartItem("launch_agent", "/x", "vendor.app", "/Applications/App.app/Contents/MacOS/App", sign_status="valid", signer="Developer ID")
        evaluated = self.engine.evaluate(item)
        self.assertIn("W01", {hit.rule_id for hit in evaluated.hits})
        self.assertEqual(evaluated.score, 0)
        self.assertEqual(evaluated.level, "LOW")

    def test_score_is_capped_at_100(self):
        item = AutoStartItem("launch_daemon", "/x", "com.apple.bad", "/tmp/.bad", ["-c", "curl x | base64 | nc -l"], True, True, "invalid", owner="user", mode="0o777", mtime=self.now, scope="system")
        self.assertEqual(self.engine.evaluate(item).score, 100)

    def test_old_file_does_not_hit_recent_rule(self):
        item = AutoStartItem("launch_agent", "/x", "x", "/Applications/x", sign_status="unknown", mtime=self.now - 8 * 86400)
        self.assertNotIn("R05", self.ids(item))


if __name__ == "__main__":
    unittest.main()

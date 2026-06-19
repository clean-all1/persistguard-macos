import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from persistguard.collectors.system import MacOSSystemCollector
from persistguard.config import ScanConfig


BTM_SAMPLE = """
UUID: DEV
Name: Vendor Group
Type: developer (0x20)
Identifier: Vendor
URL: (null)
UUID: DAEMON
Name: ExampleDaemon
Type: legacy daemon (0x10010)
Disposition: [enabled, allowed, notified] (0xb)
Identifier: 16.com.example.daemon
URL: file:///Library/LaunchDaemons/com.example.daemon.plist
Executable Path: /Library/PrivilegedHelperTools/example-daemon
UUID: APP
Name: Example App
Type: app (0x2)
Disposition: [disabled, allowed, notified] (0xa)
Identifier: 2.com.example.app
URL: file:///Applications/Example%20App.app/
"""


class StubSystemCollector(MacOSSystemCollector):
    def _run(self, args):
        return subprocess.CompletedProcess(args, 0, BTM_SAMPLE, "")


class SystemCollectorTests(unittest.TestCase):
    @patch("persistguard.collectors.system.shutil.which", return_value="/usr/bin/sfltool")
    def test_btm_filters_group_records_and_uses_executable_path(self, _which):
        collector = StubSystemCollector(ScanConfig(root=Path("/")))
        result = collector._btm()
        self.assertEqual(len(result.items), 2)
        daemon = next(item for item in result.items if item.label == "ExampleDaemon")
        app = next(item for item in result.items if item.label == "Example App")
        self.assertEqual(daemon.program, "/Library/PrivilegedHelperTools/example-daemon")
        self.assertEqual(daemon.scope, "system")
        self.assertTrue(daemon.run_at_load)
        self.assertEqual(app.program, "/Applications/Example App.app/")
        self.assertFalse(app.run_at_load)


if __name__ == "__main__":
    unittest.main()

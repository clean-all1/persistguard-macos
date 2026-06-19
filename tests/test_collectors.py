import plistlib
import tempfile
import unittest
from pathlib import Path

from persistguard.collectors.cron import CronCollector
from persistguard.collectors.launchd import LaunchdCollector
from persistguard.collectors.shell import ShellCollector
from persistguard.config import ScanConfig


class CollectorTests(unittest.TestCase):
    def test_launchd_parses_program_arguments_and_keepalive_dict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "Users" / "alice"
            directory = home / "Library" / "LaunchAgents"
            directory.mkdir(parents=True)
            path = directory / "x.plist"
            with path.open("wb") as handle:
                plistlib.dump({"Label": "x", "ProgramArguments": ["$HOME/bin/x", "--quiet"], "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}}, handle)
            result = LaunchdCollector(ScanConfig(root=root, home=home, include_system_baseline=False)).collect()
            self.assertEqual(len(result.items), 1)
            item = result.items[0]
            self.assertEqual(item.program, str(home / "bin/x"))
            self.assertEqual(item.arguments, ["--quiet"])
            self.assertTrue(item.keep_alive)

    def test_launchd_keeps_broken_plist_as_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            directory = home / "Library" / "LaunchAgents"
            directory.mkdir(parents=True)
            (directory / "broken.plist").write_text("not a plist", encoding="utf-8")
            result = LaunchdCollector(ScanConfig(root=root, home=home, include_system_baseline=False)).collect()
            self.assertEqual(len(result.items), 1)
            self.assertTrue(result.items[0].parse_error)
            self.assertEqual(len(result.errors), 1)

    def test_launchd_expat_error_does_not_abort_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            directory = home / "Library" / "LaunchAgents"
            directory.mkdir(parents=True)
            (directory / "broken.plist").write_bytes(b'<?xml version="1.0" bad?><plist></plist>')
            with (directory / "valid.plist").open("wb") as handle:
                plistlib.dump({"Label": "valid", "Program": "/usr/bin/true"}, handle)
            result = LaunchdCollector(ScanConfig(root=root, home=home, include_system_baseline=False)).collect()
            self.assertEqual(len(result.items), 2)
            self.assertEqual(sum(bool(item.parse_error) for item in result.items), 1)
            self.assertTrue(any(item.label == "valid" for item in result.items))

    def test_cron_parser_handles_system_and_reboot(self):
        collector = CronCollector(ScanConfig())
        text = "# comment\nSHELL=/bin/sh\n@reboot root /bin/sh -c 'echo start'\n0 3 * * * root /usr/bin/true\n"
        items = collector.parse_crontab(text, "/etc/crontab", system=True)
        self.assertEqual(len(items), 2)
        self.assertTrue(items[0].run_at_load)
        self.assertEqual(items[0].raw["user"], "root")
        self.assertEqual(items[1].program, "/usr/bin/true")

    def test_shell_parser_ignores_configuration_lines(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            path = home / ".zshrc"
            path.write_text("export PATH=/opt/bin:$PATH\nalias ll='ls -l'\nJAVA_HOME=/Library/Java\neval \"$VAR\"\n/bin/bash -c 'echo hello'\n", encoding="utf-8")
            items = ShellCollector(ScanConfig(root=root, home=home)).parse(path)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].program, "/bin/bash")

    def test_shell_parser_extracts_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            path = home / ".zshrc"
            path.write_text("SETUP=$('/opt/tool' init --quiet)\neval $(/opt/homebrew/bin/brew shellenv)\n", encoding="utf-8")
            items = ShellCollector(ScanConfig(root=root, home=home)).parse(path)
            self.assertEqual([item.program for item in items], ["/opt/tool", "/opt/homebrew/bin/brew"])
            self.assertEqual(items[0].arguments, ["init", "--quiet"])


if __name__ == "__main__":
    unittest.main()

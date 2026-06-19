#!/usr/bin/env python3
"""Create a harmless, isolated fixture tree for a deterministic demo scan.

The script never writes to ~/Library/LaunchAgents and never invokes launchctl.
"""

from __future__ import annotations

import argparse
import plistlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path, nargs="?", default=Path("demo-fixture"))
    args = parser.parse_args()
    root = args.target.expanduser().resolve()
    fixture_home = root / "Users" / "fixture"
    launch_agents = fixture_home / "Library" / "LaunchAgents"
    temp = root / "tmp"
    launch_agents.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    script = temp / "benign.sh"
    script.write_text('#!/bin/sh\necho "$(date) persistguard demo" >> /tmp/persistguard-demo.log\n', encoding="utf-8")
    script.chmod(0o755)
    payload = {
        "Label": "test.demo.persist",
        "ProgramArguments": ["/tmp/benign.sh"],
        "RunAtLoad": True,
        "KeepAlive": True,
    }
    with (launch_agents / "test.demo.persist.plist").open("wb") as handle:
        plistlib.dump(payload, handle)
    print(root)
    print(f"python -m persistguard scan --root '{root}' --home '{fixture_home}' --out demo-reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

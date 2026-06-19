"""Code-signature verification and file evidence collection."""

from __future__ import annotations

import hashlib
import os
import plistlib
import pwd
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, Tuple


class FileVerifier:
    def __init__(self, timeout: float = 8.0, enabled: bool = True) -> None:
        self.timeout = timeout
        self.enabled = enabled

    @staticmethod
    def _resolve_program(program: str) -> str:
        if not program:
            return ""
        if os.path.isabs(program):
            return program
        return shutil.which(program) or program

    def check_signature(self, program: str) -> Tuple[str, str]:
        program = self._resolve_program(program)
        if not program or not os.path.exists(program):
            return "missing", ""
        if not self.enabled or shutil.which("codesign") is None:
            return "unknown", ""
        try:
            details = subprocess.run(
                ["codesign", "-dvv", program],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            detail_text = "\n".join([details.stdout, details.stderr])
            signer = ""
            for line in detail_text.splitlines():
                if line.startswith("Authority="):
                    signer = line.split("=", 1)[1].strip()
                    break

            apple = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", "-R", "=anchor apple", program],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if apple.returncode == 0:
                return "apple", signer or "Apple"

            valid = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", program],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if valid.returncode == 0:
                if "adhoc" in detail_text.lower() or "Signature=adhoc" in detail_text:
                    return "adhoc", signer
                if shutil.which("spctl") is not None:
                    assessed = subprocess.run(
                        ["spctl", "--assess", "--type", "execute", "--verbose=2", program],
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                        check=False,
                    )
                    assessment_text = f"{assessed.stdout}\n{assessed.stderr}".lower()
                    if assessed.returncode != 0 and "code is valid but does not seem to be an app" not in assessment_text:
                        return "invalid", signer
                return "valid", signer
            combined = f"{valid.stderr}\n{details.stderr}".lower()
            if "not signed" in combined or "code object is not signed" in combined:
                return "unsigned", signer
            return "invalid", signer
        except (subprocess.TimeoutExpired, OSError):
            return "unknown", ""

    @staticmethod
    def _metadata_target(program: str) -> str:
        path = Path(program)
        if path.is_dir() and path.suffix.lower() == ".app":
            info = path / "Contents" / "Info.plist"
            try:
                with info.open("rb") as handle:
                    executable = plistlib.load(handle).get("CFBundleExecutable")
                candidate = path / "Contents" / "MacOS" / str(executable)
                if executable and candidate.is_file():
                    return str(candidate)
            except (OSError, ValueError, plistlib.InvalidFileException):
                return program
        return program

    @staticmethod
    def file_metadata(program: str) -> Dict[str, object]:
        program = FileVerifier._resolve_program(program)
        program = FileVerifier._metadata_target(program)
        if not program or not os.path.isfile(program):
            return {}
        st = os.stat(program, follow_symlinks=True)
        digest = hashlib.sha256()
        with open(program, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        return {
            "file_hash": digest.hexdigest(),
            "owner": owner,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "mtime": st.st_mtime,
            "size": st.st_size,
        }

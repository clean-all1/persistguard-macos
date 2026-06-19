import plistlib
import platform
import tempfile
import unittest
from pathlib import Path

from persistguard.verifier import FileVerifier


class VerifierTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Darwin", "macOS codesign test")
    def test_apple_system_binary_is_recognized(self):
        status, signer = FileVerifier().check_signature("/bin/ls")
        self.assertEqual(status, "apple")
        self.assertTrue(signer)

    def test_app_bundle_metadata_targets_main_executable(self):
        with tempfile.TemporaryDirectory() as td:
            app = Path(td) / "Demo.app"
            executable = app / "Contents" / "MacOS" / "Demo"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"demo executable")
            with (app / "Contents" / "Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleExecutable": "Demo"}, handle)
            metadata = FileVerifier.file_metadata(str(app))
            self.assertEqual(metadata["size"], len(b"demo executable"))
            self.assertEqual(len(metadata["file_hash"]), 64)


if __name__ == "__main__":
    unittest.main()

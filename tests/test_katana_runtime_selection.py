"""The CLI and launchd launcher must select the project-owned Katana."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

WRAPPER = Path(__file__).resolve().parents[1] / "recon-monitor.sh"


class KatanaRuntimeSelectionTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> tuple[Path, Path]:
        wrapper = root / "recon-monitor.sh"
        shutil.copy2(WRAPPER, wrapper)
        wrapper.chmod(0o755)
        app = root / "app"
        app.mkdir()
        (app / "recon_monitor.py").write_text("command -v katana\n", encoding="utf-8")
        local = root / "state" / "bin"
        local.mkdir(parents=True)
        return wrapper, local

    def run_wrapper(self, wrapper: Path) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["RECON_PYTHON"] = "/bin/sh"
        return subprocess.run(
            [str(wrapper), "doctor"], env=env,
            text=True, capture_output=True, timeout=10,
        )

    def test_project_binary_precedes_global_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wrapper, local = self.make_fixture(Path(temp))
            katana = local / "katana"
            katana.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            katana.chmod(0o755)
            result = self.run_wrapper(wrapper)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(katana))

    def test_nonexecutable_project_binary_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wrapper, local = self.make_fixture(Path(temp))
            (local / "katana").write_text("not executable\n", encoding="utf-8")
            result = self.run_wrapper(wrapper)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not executable", result.stderr)

    def test_dangling_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wrapper, local = self.make_fixture(Path(temp))
            (local / "katana").symlink_to(local / "missing")
            result = self.run_wrapper(wrapper)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not executable", result.stderr)


if __name__ == "__main__":
    unittest.main()

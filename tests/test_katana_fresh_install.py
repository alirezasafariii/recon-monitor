"""The standard installer should be able to provision pinned Katana.

These tests never clone source or run any network scanner.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class KatanaFreshInstallTests(unittest.TestCase):
    def test_shell_syntax(self):
        for name in ("install.sh", "tools/install_project_katana.sh"):
            result = subprocess.run(
                ["bash", "-n", str(ROOT / name)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_flag_dispatches_to_helper_without_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(ROOT / "install.sh", root / "install.sh")
            (root / "tools").mkdir()
            (root / "tools/install_project_katana.sh").write_text(
                "#!/usr/bin/env bash\nprintf 'PINNED_KATANA_INSTALL_CALLED\\n'\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(root / "install.sh"), "--install-project-katana"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PINNED_KATANA_INSTALL_CALLED", result.stdout)

    def test_rejects_extra_arguments_without_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(ROOT / "install.sh", root / "install.sh")
            result = subprocess.run(
                ["bash", str(root / "install.sh"),
                 "--install-project-katana", "--unexpected"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Usage:", result.stderr)

    def test_install_missing_provisions_pinned_binary(self):
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('if [[ "${INSTALL_MISSING:-0}" == "1" ]]', text)
        self.assertIn('bash "$ROOT_DIR/tools/install_project_katana.sh"', text)
        script = (ROOT / "tools/install_project_katana.sh").read_text(encoding="utf-8")
        self.assertIn("35267ac5c8ff1db9694a319d0eb466ed97b0969f", script)
        self.assertIn("katana-v1.8.0-frontier.patch", script)
        self.assertIn("katana_stage_local_acceptance.py", script)
        self.assertIn("recon-checkpoint-dir", script)
        self.assertIn("recon-completion-log", script)

if __name__ == "__main__":
    unittest.main()

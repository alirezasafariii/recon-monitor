"""The standard installer should be able to provision pinned Katana.

These tests never clone source or run any network scanner.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class KatanaFreshInstallTests(unittest.TestCase):
    def test_helper_promotes_only_after_contract_and_acceptance(self):
        for outcome in ("success", "bad-contract", "acceptance-failure"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "checkout with spaces"
                for directory in ("tools", "app", "docs/prototypes", "state/bin", "fake-bin"):
                    (root / directory).mkdir(parents=True)
                for name in ("tools/install_project_katana.sh", "recon-monitor.sh",
                             "app/katana_runtime_contract.py"):
                    shutil.copy2(ROOT / name, root / name)
                (root / "docs/prototypes/katana-v1.8.0-frontier.patch").touch()
                acceptance = root / "acceptance-ran"
                (root / "tools/katana_stage_local_acceptance.py").write_text(
                    "from pathlib import Path\n"
                    f"Path({str(acceptance)!r}).touch()\n"
                    f"raise SystemExit({1 if outcome == 'acceptance-failure' else 0})\n"
                )
                candidate = root / "candidate"
                help_text = (
                    "-recon-completion-log EXPERIMENTAL v1 per-origin standard-engine completion JSONL\n"
                    "-recon-checkpoint-dir EXPERIMENTAL v1 durable standard-engine GET frontier checkpoint\n"
                    if outcome != "bad-contract" else "-recon-completion-log -recon-checkpoint-dir\n"
                )
                candidate.write_text("#!/bin/sh\ncat <<'HELP'\n" + help_text + "HELP\n")
                candidate.chmod(0o755)
                destination = root / "state/bin/katana"
                destination.write_text("#!/bin/sh\n# previous working binary\n")
                destination.chmod(0o755)
                previous = destination.read_bytes()
                fake_git = root / "fake-bin/git"
                fake_git.write_text(
                    '#!/bin/sh\ncase "$1" in\n'
                    'clone) mkdir -p "$4" ;;\n'
                    '-C) if [ "$3" = "rev-parse" ]; then '
                    'echo 35267ac5c8ff1db9694a319d0eb466ed97b0969f; fi ;;\n'
                    '*) exit 99 ;;\nesac\n'
                )
                fake_go = root / "fake-bin/go"
                fake_go.write_text(
                    '#!/bin/sh\nif [ "$1" = "version" ]; then echo "fixture Go"; exit 0; fi\n'
                    'while [ "$#" -gt 0 ]; do\n'
                    'if [ "$1" = "-o" ]; then shift; cp "$RECON_TEST_CANDIDATE" "$1"; exit; fi\n'
                    'shift\ndone\nexit 99\n'
                )
                for path in (fake_git, fake_go):
                    path.chmod(0o755)
                (root / "fake-bin/python3").symlink_to(sys.executable)
                result = subprocess.run(
                    ["bash", str(root / "tools/install_project_katana.sh")],
                    env={**os.environ, "PATH": str(root / "fake-bin") + os.pathsep + os.environ["PATH"],
                         "RECON_TEST_CANDIDATE": str(candidate)},
                    capture_output=True, text=True, timeout=15,
                )
                if outcome == "success":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(acceptance.exists())
                    self.assertEqual(destination.read_bytes(), candidate.read_bytes())
                    self.assertIn("[OK] Installed tested Katana:", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(destination.read_bytes(), previous)
                    self.assertEqual(acceptance.exists(), outcome == "acceptance-failure")

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

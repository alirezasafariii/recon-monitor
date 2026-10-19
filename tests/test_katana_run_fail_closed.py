"""CLI launcher must refuse real scans without tested Katana capabilities."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "recon-monitor.sh"


class KatanaRunFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="recon-katana-guard-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wrapper = self.root / "recon-monitor.sh"
        shutil.copy2(WRAPPER, self.wrapper)
        self.wrapper.chmod(0o755)
        app = self.root / "app"
        app.mkdir()
        (app / "recon_monitor.py").write_text(
            '#!/bin/sh\nprintf "APP_EXECUTED\\n"\n', encoding="utf-8"
        )

    def katana(self, supports_capabilities: bool) -> None:
        path = self.root / "state" / "bin" / "katana"
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = (
            'recon-checkpoint-dir recon-completion-log'
            if supports_capabilities else 'stock Katana v1.8.0'
        )
        path.write_text(
            '#!/bin/sh\n'
            'if [ "${1:-}" = "-h" ]; then\n'
            f'  printf "%s\\n" "{flags}"\n'
            'fi\n'
            'exit 0\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def invoke(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["RECON_PYTHON"] = "/bin/sh"
        return subprocess.run(
            ["bash", str(self.wrapper), *args],
            env=env, capture_output=True, text=True, timeout=12,
        )

    def test_missing_project_katana_rejects_real_run(self) -> None:
        result = self.invoke("run", "--target", "example.com")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--install-project-katana", result.stderr)
        self.assertNotIn("APP_EXECUTED", result.stdout)

    def test_stock_like_project_katana_rejected(self) -> None:
        self.katana(False)
        result = self.invoke("run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checkpoint/completion", result.stderr)
        self.assertNotIn("APP_EXECUTED", result.stdout)

    def test_capable_project_katana_allows_run(self) -> None:
        self.katana(True)
        result = self.invoke("run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("APP_EXECUTED", result.stdout)

    def test_dry_run_without_katana_is_allowed(self) -> None:
        result = self.invoke("run", "--dry-run", "--target", "example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("APP_EXECUTED", result.stdout)

    def test_doctor_without_katana_is_allowed(self) -> None:
        result = self.invoke("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("APP_EXECUTED", result.stdout)

    def test_run_help_without_katana_is_allowed(self) -> None:
        result = self.invoke("run", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("APP_EXECUTED", result.stdout)

    def test_json_plan_without_dry_run_is_not_bypass(self) -> None:
        result = self.invoke("run", "--json-plan")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("APP_EXECUTED", result.stdout)


if __name__ == "__main__":
    unittest.main()

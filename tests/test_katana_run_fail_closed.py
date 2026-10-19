"""Regression: Katana checks must respect selected policy and full contract."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
from katana_runtime_contract import (
    completion_supported, checkpoint_supported, check_binary
)

PATCHED_HELP = (
    "-recon-completion-log EXPERIMENTAL v1 per-origin standard-engine completion JSONL\n"
    "-recon-checkpoint-dir EXPERIMENTAL v1 durable standard-engine GET frontier checkpoint\n"
)


class KatanaRunFailClosedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="recon-katana-preflight-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "policies").mkdir()
        (self.root / "policies" / "targets.json").write_text(
            json.dumps({"targets": [
                {"name": "dns-only", "roots": ["dns.example.org"],
                 "modules": {"urls": False}},
                {"name": "web", "roots": ["web.example.org"],
                 "modules": {"urls": True}},
            ]}), encoding="utf-8"
        )
        self.binary = self.root / "state" / "bin" / "katana"
        self.binary.parent.mkdir(parents=True)
        self.preflight = ROOT / "app" / "katana_run_preflight.py"

    def katana(self, text: str, exit_code: int = 0):
        self.binary.write_text(
            '#!/bin/sh\n'
            'if [ "${1:-}" = "-h" ]; then\n'
            "cat <<'KATANA_HELP'\n" + text +
            "\nKATANA_HELP\nfi\n" +
            f"exit {exit_code}\n", encoding="utf-8"
        )
        self.binary.chmod(0o755)

    def preflight_run(self, *args):
        return subprocess.run(
            [sys.executable, str(self.preflight), str(self.root),
             "run", *args],
            capture_output=True, text=True, timeout=10
        )

    def test_dns_only_target_no_binary_allowed(self):
        self.assertEqual(self.preflight_run("--target", "dns-only").returncode, 0)

    def test_all_targets_requires_binary_if_one_uses_urls(self):
        result = self.preflight_run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--install-project-katana", result.stderr)

    def test_targeted_urls_requires_binary(self):
        result = self.preflight_run("--target", "web")
        self.assertNotEqual(result.returncode, 0)

    def test_stock_binary_rejected(self):
        self.katana("stock Katana 1.8.0")
        self.assertIn("completion/checkpoint", self.preflight_run("--target", "web").stderr)

    def test_flags_only_do_not_prove_contract(self):
        self.katana("-recon-completion-log -recon-checkpoint-dir")
        self.assertNotEqual(self.preflight_run("--target", "web").returncode, 0)

    def test_partial_contract_rejected(self):
        self.katana(PATCHED_HELP.splitlines()[0])
        self.assertNotEqual(self.preflight_run("--target", "web").returncode, 0)

    def test_patched_binary_accepted(self):
        self.katana(PATCHED_HELP)
        result = self.preflight_run("--target=web")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_and_dry_run_work_without_katana(self):
        self.assertEqual(self.preflight_run("--help").returncode, 0)
        self.assertEqual(self.preflight_run("--dry-run").returncode, 0)

    def test_json_plan_without_dry_run_does_not_bypass(self):
        self.assertNotEqual(self.preflight_run("--json-plan").returncode, 0)

    def test_invalid_target_does_not_bypass(self):
        self.assertNotEqual(self.preflight_run("--target", "nonexistent").returncode, 0)

    def test_failed_help_exit_rejected(self):
        self.katana(PATCHED_HELP, exit_code=2)
        self.assertNotEqual(self.preflight_run("--target", "web").returncode, 0)

    def test_contract_predicates_match_stage(self):
        self.assertTrue(completion_supported(PATCHED_HELP))
        self.assertTrue(checkpoint_supported(PATCHED_HELP))
        self.assertFalse(completion_supported("-recon-completion-log"))
        self.assertFalse(checkpoint_supported("-recon-checkpoint-dir"))

    def test_bash_launcher_integration(self):
        # A minimal checkout tests the real launcher and the actual policy parser.
        wrapper = self.root / "recon-monitor.sh"
        shutil.copy2(ROOT / "recon-monitor.sh", wrapper)
        app = self.root / "app"
        app.mkdir(exist_ok=True)
        for name in ("core.py", "javascript_normalization.py",
                     "katana_runtime_contract.py", "katana_run_preflight.py"):
            shutil.copy2(ROOT / "app" / name, app / name)
        (app / "recon_monitor.py").write_text(
            'print("APP_EXECUTED")\n', encoding="utf-8"
        )
        def run(*args):
            return subprocess.run(
                ["bash", str(wrapper), *args],
                env={**os.environ, "RECON_PYTHON": sys.executable},
                capture_output=True, text=True, timeout=15,
            )
        self.assertEqual(run("doctor").returncode, 0)
        no_web = run("run", "--target", "dns-only")
        self.assertEqual(no_web.returncode, 0, no_web.stderr)
        self.assertIn("APP_EXECUTED", no_web.stdout)
        web = run("run", "--target", "web")
        self.assertNotEqual(web.returncode, 0)
        self.assertNotIn("APP_EXECUTED", web.stdout)
        self.katana(PATCHED_HELP)
        accepted = run("run", "--target", "web")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("APP_EXECUTED", accepted.stdout)


if __name__ == "__main__":
    unittest.main()

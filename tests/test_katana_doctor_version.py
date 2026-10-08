from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from doctor import _tool_help_has


class KatanaDoctorVersionTests(unittest.TestCase):
    def check(self, version, help_text="-ct -rl"):
        with patch("doctor.shutil.which", return_value="/tools/katana"), patch(
            "doctor.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, help_text),
        ), patch("doctor.tool_version", return_value=("/tools/katana", version)):
            return _tool_help_has("katana", ["-ct", "-rl"])

    def test_flags_do_not_hide_known_cancellation_defect(self):
        ok, detail = self.check("banner | [INF] Current version: v1.6.1")
        self.assertFalse(ok)
        self.assertIn("cancellation defect", detail)

    def test_fixed_version_passes_flag_contract(self):
        self.assertTrue(self.check("Current version: v1.8.0")[0])

    def test_missing_flags_still_fail(self):
        self.assertFalse(self.check("Current version: v1.8.0", "-ct")[0])

    def test_version_match_is_exact(self):
        self.assertTrue(self.check("Current version: v1.6.10")[0])

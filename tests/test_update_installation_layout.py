from __future__ import annotations

import os
import json
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import AppPaths, Config, Database
from operations import UpdateManager

ROOT = Path(__file__).resolve().parents[1]


class LoggerStub:
    def warn(self, *args, **kwargs):
        pass


class InstalledReviewLayoutTests(unittest.TestCase):
    def test_legacy_updater_layout_runs_review_regressions_without_tools(self):
        # 8.8.3 stages these program roots but omits tools. Validate the actual
        # copied layout in a fresh interpreter, not the source checkout's path.
        with tempfile.TemporaryDirectory(prefix='legacy-update-layout-') as temp:
            paths = AppPaths.from_root(Path(temp) / 'old-install')
            paths.ensure()
            db = Database(paths.db)
            try:
                manager = UpdateManager(paths, Config(paths), db, LoggerStub())
                installed = Path(temp) / 'new-install'
                installed.mkdir()
                program_items = UpdateManager._program_items(ROOT)
                legacy_items = tuple(x for x in program_items if x != 'tools')
                with patch.object(UpdateManager, '_program_items', return_value=legacy_items):
                    manager._stage_program(ROOT, installed)
                self.assertFalse((installed / 'tools').exists())
                self.assertTrue((installed / 'app/dashboard_review_support.py').is_file())
                # Bound each regression independently. A shared 60-second
                # deadline for all 32 cases falsely fails on slower Intel hosts.
                discovery = (
                    "import sys,unittest,json;sys.path.insert(0,'app');"
                    "patterns=['test_dashboard_real_data_review.py','test_dependency_range_coverage.py','test_js_stage_isolated.py','test_js_validation.py'];"
                    "s=unittest.TestSuite(unittest.defaultTestLoader.discover('tests',pattern=p) for p in patterns);"
                    "\ndef flatten(suite):\n"
                    " for item in suite:\n"
                    "  if isinstance(item,unittest.TestSuite): yield from flatten(item)\n"
                    "  else: yield item.id()\n"
                    "print(json.dumps(list(flatten(s))))"
                )
                result = subprocess.run([sys.executable, '-I', '-c', discovery], cwd=installed,
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                case_ids = json.loads(result.stdout)
                self.assertEqual(len(case_ids), 32)
                self.assertEqual(len(set(case_ids)), 32)
                code = (
                    "import sys,unittest;sys.path[:0]=['app','tests'];"
                    "s=unittest.defaultTestLoader.loadTestsFromName(sys.argv[1]);"
                    "r=unittest.TextTestRunner(verbosity=1).run(s);"
                    "assert r.testsRun==1,r.testsRun;sys.exit(not r.wasSuccessful())"
                )
                for case_id in case_ids:
                    with self.subTest(installed_regression=case_id):
                        result = subprocess.run([sys.executable, '-I', '-c', code, case_id],
                                                cwd=installed, text=True, capture_output=True, timeout=60)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                db.close()

    def test_legacy_layout_skips_uninstalled_optional_prototype_reader(self):
        # A missing optional tools root is expected on 8.8.3 installs. Do not
        # hide import failures when tooling is present in a source checkout.
        with tempfile.TemporaryDirectory(prefix='legacy-prototype-layout-') as temp:
            installed = Path(temp)
            (installed / 'tests').mkdir()
            shutil.copy2(ROOT / 'tests/test_katana_prototype_completion_contract.py',
                         installed / 'tests/test_katana_prototype_completion_contract.py')
            code = (
                "import unittest;"
                "s=unittest.defaultTestLoader.discover('tests',pattern='test_katana_prototype_completion_contract.py');"
                "r=unittest.TextTestRunner().run(s);"
                "assert r.wasSuccessful();assert r.testsRun==1;assert len(r.skipped)==1"
            )
            result = subprocess.run([sys.executable, '-I', '-c', code], cwd=installed,
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_current_updater_tracks_tools_for_install_backup_and_rollback(self):
        self.assertIn('tools', UpdateManager._program_items(ROOT))


if __name__ == '__main__':
    unittest.main()

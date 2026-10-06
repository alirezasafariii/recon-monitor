from __future__ import annotations

import os
import subprocess
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
                code = (
                    "import sys,unittest;sys.path.insert(0,'app');"
                    "s=unittest.defaultTestLoader.discover('tests',pattern='test_dashboard_real_data_review.py');"
                    "r=unittest.TextTestRunner(verbosity=1).run(s);"
                    "assert r.testsRun==16,r.testsRun;sys.exit(not r.wasSuccessful())"
                )
                result = subprocess.run([sys.executable, '-I', '-c', code], cwd=installed,
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                db.close()

    def test_current_updater_tracks_tools_for_install_backup_and_rollback(self):
        self.assertIn('tools', UpdateManager._program_items(ROOT))


if __name__ == '__main__':
    unittest.main()

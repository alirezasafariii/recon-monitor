from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Config, Database
from operations import UpdateManager
from recon_monitor import build_parser


class LoggerStub:
    def info(self, *args, **kwargs):
        pass
    warn = info
    error = info


class UpdateV810Tests(unittest.TestCase):
    def manager(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nRECON_UPDATE_REPO="alirezasafariii/recon-monitor"\n', encoding="utf-8")
        paths.policy.write_text(json.dumps({"defaults": {}, "targets": []}), encoding="utf-8")
        db = Database(paths.db)
        return temp, paths, db, UpdateManager(paths, Config(paths), db, LoggerStub())

    def test_semantic_version_comparison(self):
        self.assertTrue(UpdateManager._is_newer("8.1.0", "8.0.2"))
        self.assertTrue(UpdateManager._is_newer("v9.0.0", "8.1.0"))
        self.assertFalse(UpdateManager._is_newer("8.0.2", "8.1.0"))
        self.assertFalse(UpdateManager._is_newer("8.1.0", "8.1.0"))

    def test_expected_private_release_assets(self):
        self.assertEqual(
            UpdateManager._expected_release_assets("v8.1.0"),
            ("recon-monitor-v8.1.0.zip", "recon-monitor-v8.1.0.zip.sha256"),
        )

    def test_check_parses_authenticated_github_release(self):
        temp, paths, db, manager = self.manager()
        try:
            release = {
                "tagName": "v8.5.0",
                "name": "Recon Monitor v8.5.0",
                "publishedAt": "2026-08-08T00:00:00Z",
                "url": "https://github.com/alirezasafariii/recon-monitor/releases/tag/v8.5.0",
                "assets": [
                    {"name": "recon-monitor-v8.5.0.zip"},
                    {"name": "recon-monitor-v8.5.0.zip.sha256"},
                ],
            }
            completed = mock.Mock(returncode=0, stdout=json.dumps(release), stderr="")
            with mock.patch("operations.shutil.which", return_value="/usr/local/bin/gh"), mock.patch("operations.subprocess.run", return_value=completed) as run:
                result = manager.check()
            self.assertEqual(result["source"], "github")
            self.assertEqual(result["repo"], "alirezasafariii/recon-monitor")
            self.assertEqual(result["available"], "8.5.0")
            self.assertTrue(result["update_available"])
            self.assertIn("recon-monitor-v8.5.0.zip", result["assets"])
            self.assertIn("--repo", run.call_args.args[0])
        finally:
            db.close(); temp.cleanup()

    def test_check_reports_missing_gh_without_throwing(self):
        temp, paths, db, manager = self.manager()
        try:
            with mock.patch("operations.shutil.which", return_value=None):
                result = manager.check()
            self.assertFalse(result["reachable"])
            self.assertFalse(result["update_available"])
            self.assertIn("GitHub CLI", result["message"])
        finally:
            db.close(); temp.cleanup()

    def test_update_cli_supports_automatic_private_release_install(self):
        parser = build_parser()
        args = parser.parse_args(["update", "install", "--repo", "alirezasafariii/recon-monitor", "--force"])
        self.assertEqual(args.action, "install")
        self.assertEqual(args.repo, "alirezasafariii/recon-monitor")
        self.assertTrue(args.force)
        self.assertIsNone(args.package)


if __name__ == "__main__":
    unittest.main()

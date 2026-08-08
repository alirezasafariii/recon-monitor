from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis import compare_runs  # noqa: E402
from core import AppPaths, Database, TargetPolicy  # noqa: E402
from setup_wizard import add_targets, list_targets, remove_target  # noqa: E402


class ManagementTests(unittest.TestCase):
    def test_target_management(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            paths.policy.write_text(json.dumps({"schema": 2, "defaults": {}, "targets": [{"name": "example.com", "roots": ["example.com"]}]}), encoding="utf-8")
            self.assertEqual(add_targets(paths, ["api.example.org"]), ["example.com", "api.example.org"])
            self.assertEqual(list_targets(paths), ["example.com", "api.example.org"])
            self.assertEqual(remove_target(paths, "api.example.org"), ["example.com"])

    def test_compare_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            db = Database(paths.db)
            try:
                policy = TargetPolicy.from_dict({"name": "example.com", "roots": ["example.com"]})
                for run_id, hosts in (("old", ["example.com"]), ("new", ["example.com", "api.example.com"])):
                    db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,?,?,?)", (run_id, "test", "success", "2026-01-01T00:00:00Z", 1))
                    run_dir = paths.output / "example.com" / "runs" / run_id
                    (run_dir / "current").mkdir(parents=True)
                    (run_dir / "current" / "subdomains.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")
                    (run_dir / "current" / "urls.jsonl").write_text('{"url":"https://example.com/"}\n', encoding="utf-8")
                    db.create_run_target(run_id, policy, run_dir, False)
                    db.finish_run_target(run_id, "example.com", "success")
                result = compare_runs(paths, db, "old", "new", "example.com")
                added = result["targets"]["example.com"]["subdomains"]["added"]
                self.assertEqual(added, ["api.example.com"])
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

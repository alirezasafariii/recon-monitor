from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import analysis_engine
from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, safe_json_loads, utc_now
from doctor import run_doctor
from operations import BackupManager
from recon_monitor import build_parser


class LoggerStub:
    def info(self, *args, **kwargs):
        pass

    warn = info
    error = info


class Stability451Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        paths = AppPaths.from_root(root)
        paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\n', encoding="utf-8")
        paths.policy.write_text(json.dumps({"defaults": {}, "targets": [{"name": "example.com", "roots": ["example.com"]}]}), encoding="utf-8")
        return temp, paths, Database(paths.db)

    def test_version_and_schema_remain_compatible(self):
        self.assertEqual(APP_VERSION, "8.4.0")
        self.assertEqual(SCHEMA_VERSION, 17)

    def test_safe_json_loads_rejects_corrupt_and_wrong_shape(self):
        self.assertEqual(safe_json_loads(None, [], expected_type=list), [])
        self.assertEqual(safe_json_loads("{broken", {}, expected_type=dict), {})
        self.assertEqual(safe_json_loads('[1,2]', {}, expected_type=dict), {})
        original = {"a": 1}
        result = safe_json_loads(original, {}, expected_type=dict)
        self.assertEqual(result, original)

    def test_analysis_failure_is_finalized(self):
        temp, paths, db = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
                ("run-fail", APP_VERSION, "success", now, now, "example.com"),
            )
            db.upsert_alert(
                "example.com", "fail-key", "changed_js", "HIGH", 80,
                "Failure fixture", "/api/accounts/{accountId}", {"method": "GET"}, "run-fail",
            )
            with mock.patch.object(analysis_engine, "generate_semantic_intelligence", side_effect=RuntimeError("fixture explosion")):
                with self.assertRaises(RuntimeError):
                    analysis_engine.run_analysis(paths, db, "run-fail", "example.com")
            row = db.one("SELECT status,finished_at,error FROM analysis_runs ORDER BY started_at DESC LIMIT 1")
            self.assertEqual(row["status"], "failed")
            self.assertTrue(row["finished_at"])
            self.assertIn("fixture explosion", row["error"])
        finally:
            db.close()
            temp.cleanup()

    def test_stale_state_preview_and_repair(self):
        temp, paths, db = self.project()
        try:
            old = "2020-01-01T00:00:00Z"
            db.execute(
                "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) VALUES(?,?,?,?,?,1)",
                ("stale-run", APP_VERSION, "running", old, "example.com"),
            )
            db.execute(
                "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,0)",
                ("stale-run", "example.com", "hash", "running", "urls", old, str(paths.output / "stale-run")),
            )
            db.execute(
                "INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,heartbeat_at) VALUES(?,?,?,?,1,?,?)",
                ("stale-run", "example.com", "urls", "running", old, old),
            )
            db.execute(
                "INSERT INTO work_items(run_id,target,stage,item_key,status,created_at,started_at,heartbeat_at) VALUES(?,?,?,?,?,?,?,?)",
                ("stale-run", "example.com", "urls", "item", "running", old, old, old),
            )
            db.execute(
                "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at) VALUES(?,?,?,?,?,?,?,?)",
                ("stale-analysis", "stale-run", "example.com", APP_VERSION, "test", "analysis", "running", old),
            )
            preview = db.repair_stale_state(1, dry_run=True)
            self.assertGreaterEqual(preview["count"], 4)
            self.assertEqual(preview["repaired"], 0)
            repaired = db.repair_stale_state(1)
            self.assertGreaterEqual(repaired["repaired"], 4)
            self.assertEqual(db.one("SELECT status FROM analysis_runs WHERE id='stale-analysis'")[0], "failed")
            self.assertEqual(db.one("SELECT status FROM stage_runs WHERE run_id='stale-run'")[0], "failed")
            self.assertEqual(db.one("SELECT status FROM work_items WHERE run_id='stale-run'")[0], "retry_pending")
            self.assertEqual(db.one("SELECT status FROM runs WHERE id='stale-run'")[0], "failed")
        finally:
            db.close()
            temp.cleanup()

    def test_json_health_detects_legacy_corruption(self):
        temp, paths, db = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("example.com", "broken-json", "test", "LOW", 10, "Broken", "/", "{broken", "new", 1, now, now),
            )
            health = db.json_health()
            self.assertGreaterEqual(health["malformed_count"], 1)
            self.assertTrue(any(item["field"] == "alerts.details_json" for item in health["malformed"]))
        finally:
            db.close()
            temp.cleanup()

    def test_backup_verify_latest_and_restore_drill(self):
        temp, paths, db = self.project()
        try:
            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()
            verified = manager.verify("latest")
            self.assertTrue(verified["ok"])
            self.assertEqual(verified["backup_id"], created["backup_id"])
            self.assertTrue(verified["checks"]["database_integrity"])
            drill = manager.drill("latest")
            self.assertTrue(drill["ok"])
            self.assertEqual(drill["schema_version"], str(SCHEMA_VERSION))
            self.assertGreater(drill["tables"], 10)
        finally:
            db.close()
            temp.cleanup()

    def test_backup_restore_replaces_database_safely(self):
        temp, paths, db = self.project()
        try:
            db.meta_set("restore_fixture", "before")
            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()
            db.meta_set("restore_fixture", "after")
            restored = manager.restore(created["backup_id"], force=True)
            self.assertEqual(restored["integrity"], "ok")
            reopened = Database(paths.db)
            try:
                self.assertEqual(reopened.meta_get("restore_fixture"), "before")
                audit = reopened.one("SELECT action FROM audit_log WHERE action='backup_restored' ORDER BY id DESC LIMIT 1")
                self.assertIsNotNone(audit)
            finally:
                reopened.close()
        finally:
            try:
                db.close()
            except Exception:
                pass
            temp.cleanup()

    def test_doctor_reports_current_schema(self):
        temp, paths, db = self.project()
        db.close()
        try:
            config = Config(paths)
            with contextlib.redirect_stdout(io.StringIO()):
                checks = run_doctor(paths, config, LoggerStub(), network=False)
            schema = next(check for check in checks if check.name == "Database schema")
            self.assertEqual(schema.level, "OK")
            self.assertIn(str(SCHEMA_VERSION), schema.detail)
        finally:
            temp.cleanup()

    def test_cli_exposes_repair_and_backup_drill(self):
        parser = build_parser()
        repair = parser.parse_args(["repair", "--dry-run", "--max-age-hours", "12", "--json-health"])
        self.assertEqual(repair.command, "repair")
        self.assertTrue(repair.dry_run)
        backup = parser.parse_args(["backup", "drill", "latest"])
        self.assertEqual(backup.action, "drill")
        self.assertEqual(backup.backup_id, "latest")


if __name__ == "__main__":
    unittest.main()

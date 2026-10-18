from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, Progress, ReconError
from core import TargetPolicy, read_jsonl, sha256_bytes
from recon_snapshot_artifacts import SNAPSHOT_OWNER_KIND
from operations import BackupManager
from run_lifecycle_state import record_target_lifecycle
from stages import StageContext, stage_javascript
from storage import ContentAddressedStore


class ExtendedComparisonSnapshotTests(unittest.TestCase):
    TARGET = "example.test"
    URL = "https://example.test/app.js"
    A = b'const version=1; const endpoint="/api/old";'
    B = b'const version=2; const endpoint="/api/new";'

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = runtime.Database(self.paths.db)
        self.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET],
            "javascript": {"download_source_maps": False},
        })

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def start(self, target=None):
        policy = self.policy if target is None else TargetPolicy.from_dict({"name": target, "roots": [target]})
        run_id = self.db.create_run(policy.name, 1, "offline")
        run_dir = self.paths.output / policy.name / run_id
        self.db.create_run_target(run_id, policy, run_dir, not self.db.target_has_history(policy.name))
        return StageContext(self.paths, Config(self.paths), policy, self.db, Logger(self.paths, verbose=False),
                            SimpleNamespace(), Progress(False), run_id, run_dir, False)

    def collect_js(self, ctx, data):
        (ctx.current / "urls.txt").write_text(self.URL + "\n")
        (ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": ctx.run_id, "target": self.TARGET,
            "metrics": {"collection_status": "completed", "url_selection": {}},
        }))
        with patch("stages._download_url", return_value={
            "url": self.URL, "data": data, "content_type": "application/javascript", "status_code": 200,
        }):
            return stage_javascript(ctx)

    def finish(self, ctx, status="success", *, complete_collection=False):
        collection = "success" if complete_collection else status
        record_target_lifecycle(
            self.db, ctx.run_id, ctx.policy.name, collection_status=collection,
            analysis_status="failed" if complete_collection else "success",
            report_status="success", notification_status="not_run" if complete_collection else "success",
            overall_status="partial" if complete_collection else status, baseline_reason="collection_" + collection,
        )
        self.db.finish_run_target(ctx.run_id, ctx.policy.name, status)

    def js_row(self):
        return dict(self.db.one("SELECT * FROM js_files WHERE target=? AND url=?", (self.TARGET, self.URL)))

    def test_failed_js_does_not_hide_next_raw_semantic_or_indicator_changes(self):
        for outcome in ("failed", "partial", "interrupted"):
            with self.subTest(outcome=outcome):
                data = self.B.replace(b"/api/new", ("/api/new-" + outcome).encode())
                a = self.start(); self.collect_js(a, self.A); self.finish(a)
                b = self.start(); self.collect_js(b, data); self.finish(b, outcome)
                # Baseline A must survive GC even though the working JS owner moved to B.
                store = ContentAddressedStore(self.paths, self.db)
                self.assertFalse(store.delete_if_unreferenced(sha256_bytes(self.A))["deleted"])
                self.db.close(); self.db = runtime.Database(self.paths.db)
                c = self.start()
                self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.A))
                result = self.collect_js(c, data)
                self.assertEqual(result["raw_changed"], 1)
                self.assertEqual(result["semantic_changed"], 1)
                events = list(read_jsonl(c.events_path))
                changed = [e for e in events if e["category"] == "changed_js"]
                self.assertEqual(changed[0]["details"]["old_raw_hash"], sha256_bytes(self.A))
                self.assertTrue(any(e["category"] == "js_indicator" and "/api/new" in e["item"] for e in events))
                self.assertEqual(len(self.db.all("SELECT * FROM js_diffs WHERE run_id=?", (b.run_id,))), 1)
                self.finish(c)

    def test_failed_only_inventory_is_new_in_next_run(self):
        a = self.start(); self.finish(a)
        for attempt in range(2):
            ctx = self.start()
            self.assertTrue(self.db.upsert_js_indicator(self.TARGET, self.URL, "endpoint", "/api/new", False, ctx.run_id))
            self.assertTrue(self.db.upsert_port(self.TARGET, self.TARGET, "8.8.8.8", 8443, "tcp", ctx.run_id))
            self.assertTrue(self.db.upsert_finding(self.TARGET, "finding", {"name": "stored finding"}, ctx.run_id))
            self.assertTrue(self.db.upsert_endpoint_intelligence(self.TARGET, "/api/new", "endpoint", {}, self.URL, ctx.run_id))
            self.assertEqual(self.collect_js(ctx, self.B)["new"], 1)
            self.finish(ctx, "failed" if attempt == 0 else "success")

    def test_failed_first_run_restarts_with_empty_extended_comparison_view(self):
        b = self.start(); self.collect_js(b, self.B); self.finish(b, "interrupted")
        c = self.start()
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertEqual(self.collect_js(c, self.B)["new"], 1)

    def test_same_run_resume_keeps_processed_bytes_and_receipts(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.collect_js(b, self.B); self.finish(b, "partial")
        self.db.close(); self.db = runtime.Database(self.paths.db); b.db = self.db
        self.db.create_run_target(b.run_id, self.policy, b.run_dir, False)
        self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.B))
        with patch("stages._download_url", side_effect=AssertionError("resume redownloaded processed bytes")):
            result = stage_javascript(b)
        self.assertEqual(result["reused_work_items"], 1)
        self.finish(b)
        c = self.start()
        self.assertEqual(self.collect_js(c, self.B)["raw_changed"], 0)

    def test_cas_handoff_restores_maps_sources_and_isolates_other_targets(self):
        store = ContentAddressedStore(self.paths, self.db)
        a = self.start(); self.collect_js(a, self.A)
        old, _, _ = store.put(b"old map/source")
        new, _, _ = store.put(b"failed map/source")
        prefix = self.TARGET + "\n" + self.URL
        store.set_reference("source_map", prefix, old)
        store.set_reference("source_map_source", prefix + "\nsource", old)
        store.set_reference("source_map", "other.test\nmap", new)
        self.finish(a)
        b = self.start(); self.collect_js(b, self.B)
        store.set_reference("source_map", prefix, new)
        store.sync_references("source_map_source", {}, owner_prefix=prefix + "\n")
        self.finish(b, "failed")
        store.gc()
        self.assertEqual(store.get(old), b"old map/source")
        c = self.start()
        refs = {(r["owner_kind"], r["owner_key"]): r["sha256"] for r in self.db.all("SELECT * FROM cas_references")}
        self.assertEqual(refs[("source_map", prefix)], old)
        self.assertEqual(refs[("source_map_source", prefix + "\nsource")], old)
        self.assertEqual(refs[("source_map", "other.test\nmap")], new)
        self.collect_js(c, self.B); self.finish(c)
        self.assertTrue(store.delete_if_unreferenced(sha256_bytes(self.A))["deleted"])

    def test_complete_collection_with_analysis_failure_commits_availability(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a, "partial", complete_collection=True)
        b = self.start()
        result = self.db.record_js_availability(b.run_id, self.TARGET, self.URL, "not_found", status_code=404)
        self.assertEqual(result["previous"]["run_id"], a.run_id)
        self.assertTrue(result["changed"])
        self.finish(b, "failed")
        c = self.start()
        result = self.db.record_js_availability(c.run_id, self.TARGET, self.URL, "live", status_code=200)
        self.assertEqual(result["previous"]["run_id"], a.run_id)
        self.assertFalse(result["changed"])
        self.assertEqual(len(self.db.all("SELECT * FROM js_availability_history")), 3)

    def test_availability_survives_unobserved_url_in_later_commit(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.finish(b)
        c = self.start()
        result = self.db.record_js_availability(c.run_id, self.TARGET, self.URL, "not_found", status_code=404)
        self.assertEqual(result["previous"]["run_id"], a.run_id)

    def test_committed_not_found_emits_reappearance_after_report_failure(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start()
        self.db.record_js_availability(b.run_id, self.TARGET, self.URL, "not_found", status_code=404)
        self.finish(b, "partial", complete_collection=True)
        c = self.start()
        self.collect_js(c, self.A)
        self.assertTrue(any(e["category"] == "js_reappeared" for e in read_jsonl(c.events_path)))

    def test_backup_includes_committed_bytes_after_failed_working_change(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.collect_js(b, self.B); self.finish(b, "failed")
        manager = BackupManager(self.paths, self.db, Logger(self.paths, verbose=False))
        created = manager.create()
        digest = sha256_bytes(self.A)
        object_path = self.paths.objects / digest[:2] / digest[2:4] / digest
        with tarfile.open(created["path"], "r:gz") as archive:
            self.assertIn(object_path.relative_to(self.paths.root).as_posix(), archive.getnames())
        self.assertTrue(manager.verify(created["backup_id"])["ok"])

    def test_snapshot_and_artifact_handoff_roll_back_together(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.collect_js(b, self.B)
        with patch("successful_snapshot.commit_artifact_snapshot", side_effect=RuntimeError("injected handoff failure")):
            with self.assertRaises(RuntimeError): self.finish(b)
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], a.run_id)
        c = self.start()
        self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.A))

    def test_resume_older_run_after_newer_target_run_is_rejected(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a, "partial")
        b = self.start(); self.collect_js(b, self.B); self.finish(b)
        with self.assertRaisesRegex(ReconError, "newer run"):
            self.db.create_run_target(a.run_id, self.policy, a.run_dir, True)
        self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.B))

    def downgrade_to_v2(self):
        self.db.execute("UPDATE successful_recon_commits SET table_count=4")
        self.db.execute("DELETE FROM successful_recon_state WHERE table_name NOT IN ('assets','dns_records','urls','fingerprints')")
        self.db.execute("DELETE FROM successful_recon_cas_state")
        self.db.execute("DELETE FROM successful_recon_js_availability")
        self.db.execute("DELETE FROM cas_references WHERE owner_kind=?", (SNAPSHOT_OWNER_KIND,))
        self.db.execute("UPDATE schema_meta SET value='2' WHERE key='successful_snapshot_schema_version'")

    def test_upgrade_untouched_v2_baseline_pins_js_and_is_idempotent(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        self.downgrade_to_v2()
        self.db.close(); self.db = runtime.Database(self.paths.db)
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["table_count"], 9)
        before = [tuple(row) for row in self.db.all("SELECT * FROM successful_recon_cas_state")]
        self.db.close(); self.db = runtime.Database(self.paths.db)
        self.assertEqual(before, [tuple(row) for row in self.db.all("SELECT * FROM successful_recon_cas_state")])
        self.assertEqual(self.db._previous_js_availability("next", self.TARGET, self.URL)["run_id"], a.run_id)

    def test_upgrade_polluted_v2_preserves_evidence_and_requires_rebaseline(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.collect_js(b, self.B); self.finish(b, "failed")
        self.downgrade_to_v2()
        self.db.close(); self.db = runtime.Database(self.paths.db)
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.B))
        self.assertEqual(len(self.db.all("SELECT * FROM js_availability_history")), 2)
        with self.assertRaisesRegex(ReconError, "fresh baseline"):
            self.db.create_run_target(b.run_id, self.policy, b.run_dir, False)
        c = self.start()
        self.assertEqual(self.collect_js(c, self.B)["new"], 1)
        self.assertEqual(self.db.one("SELECT baseline FROM run_targets WHERE run_id=?", (c.run_id,))[0], 1)
        self.finish(c)
        self.assertTrue(self.db.target_has_history(self.TARGET))

    def test_upgrade_seeds_unobserved_urls_from_valid_history_only(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a, "partial", complete_collection=True)
        b = self.start()
        self.db.record_js_availability(b.run_id, self.TARGET, self.URL, "not_found", status_code=404)
        self.finish(b, "failed")
        c = self.start(); self.finish(c)
        self.downgrade_to_v2()
        self.db.close(); self.db = runtime.Database(self.paths.db)
        self.assertTrue(self.db.target_has_history(self.TARGET))
        previous = self.db._previous_js_availability("next", self.TARGET, self.URL)
        self.assertEqual(previous["run_id"], a.run_id)
        self.assertEqual(previous["state"], "live")

    def test_failed_restore_rolls_back_inventory_and_current_cas_owners(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        b = self.start(); self.collect_js(b, self.B); self.finish(b, "failed")
        digest = sha256_bytes(self.A)
        self.db.execute("UPDATE object_store SET relative_path='../../outside' WHERE sha256=?", (digest,))
        refs = [tuple(row) for row in self.db.all("SELECT * FROM cas_references ORDER BY owner_kind,owner_key")]
        with self.assertRaisesRegex(ReconError, "outside the object store"):
            self.start()
        self.assertEqual(self.js_row()["raw_hash"], sha256_bytes(self.B))
        self.assertEqual(refs, [tuple(row) for row in self.db.all("SELECT * FROM cas_references ORDER BY owner_kind,owner_key")])

    def test_orchestrator_failure_after_js_does_not_consume_next_run_change(self):
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
        self.policy.limits.retries = 0
        policies = runtime.PolicySet({}, [self.policy], self.paths.policy)
        collected = []

        def js_stage(ctx):
            collected.append(ctx)
            return self.collect_js(ctx, payload)

        def fingerprint_stage(ctx):
            if fail:
                raise RuntimeError("controlled failure after JavaScript")
            return {}

        functions = {name: (lambda ctx: {}) for name, _ in runtime.STAGES if name != "report"}
        functions.update(javascript=js_stage, fingerprint=fingerprint_stage)
        for payload, fail, expected in ((self.A, False, 0), (self.B, True, 2), (self.B, False, 0)):
            runner = runtime.Orchestrator(self.paths, Config(self.paths), Logger(self.paths, verbose=False),
                                          self.db, progress=False, allow_active=False)
            with patch.dict(runtime.STAGE_FUNCTIONS, functions), patch.object(runner, "_record_versions"), \
                    patch.object(runner, "install_signal_handlers"), patch.object(runner, "_update_latest_pointers"), \
                    patch("recon_monitor_core.stage_report", return_value={
                        "analysis": {"analysis_id": "offline"},
                        "finding_notifications": {"queued": 0, "delivery": {"queued": 0, "delivered": 0}},
                    }), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(policies), expected)
        change = next(e for e in read_jsonl(collected[-1].events_path) if e["category"] == "changed_js")
        self.assertEqual(change["details"]["old_raw_hash"], sha256_bytes(self.A))

    def test_snapshot_js_path_rebases_after_copying_project(self):
        a = self.start(); self.collect_js(a, self.A); self.finish(a)
        self.db.close()
        try:
            with tempfile.TemporaryDirectory() as dest:
                copied = AppPaths.from_root(Path(dest) / "moved")
                shutil.copytree(self.paths.root, copied.root)
                moved = runtime.Database(copied.db)
                try:
                    run = moved.create_run(self.TARGET, 1, "offline")
                    moved.create_run_target(run, self.policy, copied.output / run, False)
                    path = Path(moved.one("SELECT blob_path FROM js_files")[0])
                    self.assertTrue(path.is_relative_to(copied.objects))
                    self.assertEqual(path.read_bytes(), self.A)
                finally:
                    moved.close()
        finally:
            self.db = runtime.Database(self.paths.db)


if __name__ == "__main__":
    unittest.main()

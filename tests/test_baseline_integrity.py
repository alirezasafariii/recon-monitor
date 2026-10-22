from __future__ import annotations

import json
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import recon_monitor_core as runtime
from baseline_integrity import baseline_review, repair_baselines, review_committed_baseline
from core import APP_VERSION, AppPaths, Database as BaseDatabase, ReconError, TargetPolicy, json_dumps
from reporting import create_alerts_and_notify
from run_lifecycle_state import record_target_lifecycle
from stable_confirmation import finalize_stable_change_run, observe_stable_change_state
from workspace_v7 import _previous_run, change_intelligence
from dashboard_core import _latest_successful_runs


class BaselineIntegrityTests(unittest.TestCase):
    TARGET = "example.test"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("Offline baseline repair attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.paths = AppPaths.from_root(Path(temporary.name))
        self.paths.ensure()
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = TargetPolicy.from_dict({"name": self.TARGET, "roots": [self.TARGET]})
        self.sequence = 0

    def start(self, run, *, baseline=False):
        self.sequence += 1
        timestamp = f"2026-01-01T00:{self.sequence:02}:00Z"
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,'running',?,1)",
                        (run, APP_VERSION, timestamp))
        directory = self.paths.output / self.TARGET / "runs" / run
        (directory / "current").mkdir(parents=True)
        self.db.create_run_target(run, self.policy, directory, baseline)
        return directory

    def complete(self, run, *, partial=False):
        for stage in ("subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "report"):
            metrics = {"collection_status": "completed"}
            if stage == "javascript":
                metrics = {"collection_status": "no_input", "files": 0, "downloaded": 0}
            if stage == "urls" and partial:
                metrics = {"collection_status": "partial", "origin_probe_failed": 1}
            self.db.stage_begin(run, self.TARGET, stage, 1)
            self.db.stage_finish(run, self.TARGET, stage, "partial" if partial and stage == "urls" else "success", metrics=metrics)
        record_target_lifecycle(self.db, run, self.TARGET, collection_status="partial" if partial else "success",
                                analysis_status="success", report_status="success", notification_status="not_run",
                                overall_status="partial" if partial else "success", baseline_reason="fixture")
        self.db.finish_run_target(run, self.TARGET, "partial" if partial else "success")
        self.db.finish_run(run, "partial" if partial else "success")
        self.db.execute("UPDATE runs SET finished_at=started_at WHERE id=?", (run,))

    def legacy(self, *, frozen_401=True, stored_gap=False):
        directory = self.start("OLD", baseline=True)
        self.db.upsert_asset(self.TARGET, "old.example.test", ["root"], "OLD")
        self.db.upsert_dns(self.TARGET, self.TARGET, "A", "192.0.2.1", "OLD")
        self.db.upsert_url(self.TARGET, "https://example.test/old", "url", "fixture", "OLD")
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 200}, "old", "OLD")
        self.db.replace_recon_derived_working_state("OLD", self.TARGET, "sources", {"old": {"hash": "a"}})
        self.complete("OLD")
        # Reproduce an already-committed pre-fix snapshot. New commits must not
        # be allowed to enter this state through finish_run_target.
        if frozen_401:
            self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 401}, "restricted", "OLD")
            with self.db.transaction():
                self.db._replace_successful_snapshot_no_tx(self.TARGET, "OLD")
        if stored_gap:
            self.db.stage_finish("OLD", self.TARGET, "urls", "success", metrics={"collection_status": "completed",
                "coverage_audit": {"origin_coverage_status": "partial", "origin_probe_failed": 1}})
        self.db.execute("DELETE FROM successful_recon_integrity WHERE target=?", (self.TARGET,))
        (directory / "report.json").write_text(json_dumps({"run_id": "OLD", "target": self.TARGET, "counts": {}, "changes": {"events": []}}))
        return directory

    def test_frozen_restriction_quarantines_without_erasing_history_or_snapshot(self):
        self.legacy()
        before = [tuple(row) for row in self.db.all("SELECT * FROM successful_recon_state ORDER BY table_name,row_hash")]
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertEqual(baseline_review(self.db, self.TARGET, "OLD")["state"], "quarantined")
        self.assertEqual(before, [tuple(row) for row in self.db.all("SELECT * FROM successful_recon_state ORDER BY table_name,row_hash")])
        self.assertEqual(self.db.stage_status("OLD", self.TARGET, "urls"), "success")
        self.assertEqual(self.db.one("SELECT baseline_eligible FROM target_run_lifecycle WHERE run_id='OLD'")[0], 1)
        self.start("NEXT")
        for table in ("assets", "dns_records", "urls", "fingerprints"):
            self.assertEqual(self.db.one(f"SELECT COUNT(*) FROM {table} WHERE target=?", (self.TARGET,))[0], 0)
        self.assertEqual(self.db.one("SELECT baseline FROM run_targets WHERE run_id='NEXT'")[0], 1)

    def test_stored_origin_gap_excludes_otherwise_healthy_snapshot(self):
        self.legacy(frozen_401=False, stored_gap=True)
        self.assertFalse(self.db.target_has_history(self.TARGET))

    def test_unknown_and_no_input_metrics_do_not_revoke_a_healthy_baseline(self):
        self.legacy(frozen_401=False)
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))

    def test_explicit_repair_audits_retained_proof_and_is_idempotent(self):
        directory = self.legacy(frozen_401=False)
        proof = directory / "current" / "origin-probe.jsonl"
        proof.write_text(json_dumps({"url": "https://example.test", "status_code": 401, "transport_status": "ok"}) + "\n")
        first = repair_baselines(self.paths, self.db, run_id="OLD")
        review = baseline_review(self.db, self.TARGET, "OLD")
        second = repair_baselines(self.paths, self.db, run_id="OLD")
        self.assertTrue(first["baseline_changed"])
        self.assertFalse(second["baseline_changed"])
        self.assertEqual(review, baseline_review(self.db, self.TARGET, "OLD"))
        self.assertEqual(first["network_requests"], 0)
        self.assertFalse(first["historical_outcomes_changed"])
        result = json.loads((directory / "report.json").read_text())["diagnostics_finalization"]
        self.assertTrue(result["baseline_quarantined"])
        self.assertFalse(result["baseline_review_required"])
        self.assertIn("Incomplete baseline excluded", (directory / "report.html").read_text())

    def test_retained_timeout_proof_is_audited_before_automatic_restore(self):
        directory = self.legacy(frozen_401=False)
        (directory / "current" / "origin-probe.jsonl").write_text(json_dumps({
            "url": "https://example.test:8443", "status_code": 0, "transport_status": "error", "error": "timeout"}) + "\n")
        review_committed_baseline(self.db, self.TARGET, paths=self.paths)
        self.start("NEXT")
        self.assertIsNone(self.db.one("SELECT 1 FROM assets"))

    def test_complete_replacement_establishes_a_new_identity_without_change_alerts(self):
        self.legacy()
        self.assertFalse(self.db.target_has_history(self.TARGET))
        directory = self.start("NEW")
        self.db.upsert_asset(self.TARGET, "new.example.test", ["root"], "NEW")
        events = directory / "events.jsonl"
        events.write_text(json_dumps({"category": "subdomain", "item": "new.example.test"}) + "\n")
        baseline = bool(self.db.one("SELECT baseline FROM run_targets WHERE run_id='NEW'")[0])
        result = create_alerts_and_notify(SimpleNamespace(events_path=events, policy=self.policy,
            config=SimpleNamespace(bool=lambda name, default: default)), baseline=baseline)
        self.assertEqual(result["new_alerts"], 0)
        self.complete("NEW")
        registry = self.db.one("SELECT * FROM target_baselines WHERE target=?", (self.TARGET,))
        self.assertEqual(registry["established_run_id"], "NEW")
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], "NEW")
        self.assertEqual(baseline_review(self.db, self.TARGET, "OLD")["state"], "quarantined")

    def test_partial_replacement_never_restores_the_quarantined_baseline(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.start("PARTIAL")
        self.db.upsert_asset(self.TARGET, "partial.example.test", ["root"], "PARTIAL")
        self.complete("PARTIAL", partial=True)
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], "OLD")
        self.start("AFTER")
        self.assertIsNone(self.db.one("SELECT 1 FROM assets"))

    def test_old_repair_cannot_revoke_a_new_healthy_snapshot(self):
        self.legacy(frozen_401=False, stored_gap=True)
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        self.complete("NEW")
        before = dict(self.db.one("SELECT * FROM target_baselines"))
        repair_baselines(self.paths, self.db, run_id="OLD")
        self.assertEqual(before, dict(self.db.one("SELECT * FROM target_baselines")))
        self.assertTrue(self.db.target_has_history(self.TARGET))

    def test_repair_refuses_a_target_that_is_currently_scanning(self):
        self.legacy(frozen_401=False)
        self.start("RUNNING")
        before = dict(self.db.one("SELECT * FROM target_baselines"))
        with self.assertRaisesRegex(ReconError, "target is running"):
            repair_baselines(self.paths, self.db, run_id="OLD")
        self.assertEqual(before, dict(self.db.one("SELECT * FROM target_baselines")))
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))

    def test_healthy_resume_of_same_run_replaces_frozen_restriction(self):
        directory = self.legacy()
        self.db.target_has_history(self.TARGET)
        self.db.create_run_target("OLD", self.policy, directory, False)
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 200}, "healthy", "OLD")
        self.complete("OLD")
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertEqual(baseline_review(self.db, self.TARGET, "OLD")["state"], "recovered")

    def test_resume_preserves_its_own_progress_and_drops_inherited_comparison_rows(self):
        self.legacy()
        directory = self.paths.output / self.TARGET / "runs" / "INFLIGHT"
        directory.mkdir()
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES('INFLIGHT',?,'partial','2026-01-01T01:00:00Z',1)", (APP_VERSION,))
        BaseDatabase.create_run_target(self.db, "INFLIGHT", self.policy, directory, False)
        self.db.upsert_asset(self.TARGET, "progress.example.test", ["root"], "INFLIGHT")
        self.db.create_run_target("INFLIGHT", self.policy, directory, False)
        self.assertIsNotNone(self.db.one("SELECT 1 FROM assets WHERE host='progress.example.test'"))
        self.assertIsNone(self.db.one("SELECT 1 FROM assets WHERE host='old.example.test'"))
        self.assertEqual(self.db.one("SELECT baseline FROM run_targets WHERE run_id='INFLIGHT'")[0], 1)

    def test_quarantined_derived_receipt_stays_excluded_after_core_replacement(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        self.complete("NEW")
        result = self.db.replace_recon_derived_working_state("LATER", self.TARGET, "sources", {"new": {"hash": "b"}})
        self.assertFalse(result["baseline_exists"])
        self.assertEqual(result["removed"], [])
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM successful_recon_derived_state")[0], 1)

    def test_stable_confirmation_does_not_count_an_excluded_run(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        kwargs = dict(target=self.TARGET, subject_key="dns:example.test:A", category="dns_change", state_version="v1", confirmations=2, immediately_confirmed=False)
        observe_stable_change_state(self.db, run_id="OLD", **kwargs)
        finalize_stable_change_run(self.db, "OLD", self.TARGET, "success")
        result = observe_stable_change_state(self.db, run_id="NEXT", **kwargs)
        self.assertEqual(result["occurrences"], 1)
        self.assertEqual(result["confirmation_state"], "observed")

    def test_history_views_do_not_reintroduce_the_excluded_run(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        self.complete("NEW")
        self.assertEqual(_previous_run(self.db, self.TARGET, "NEW"), "")
        self.assertEqual(_latest_successful_runs(self.db, self.TARGET)[0]["previous_run"], "")
        old = change_intelligence(self.db, target=self.TARGET, run_id="OLD", persist=False)
        self.assertEqual(old["comparison_status"], "baseline_quarantined")
        self.assertEqual(old["changes"], [])

    def test_quarantine_update_is_atomic(self):
        self.legacy()
        original = self.db.execute
        def fail_registry(sql, args=()):
            if sql.startswith("UPDATE target_baselines SET state='quarantined'"):
                raise RuntimeError("controlled write failure")
            return original(sql, args)
        with patch.object(self.db, "execute", side_effect=fail_registry):
            with self.assertRaisesRegex(RuntimeError, "controlled write"):
                review_committed_baseline(self.db, self.TARGET)
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))
        self.assertEqual(self.db.one("SELECT state FROM target_baselines")[0], "established")

    def test_outer_transaction_rollback_also_rolls_back_quarantine(self):
        self.legacy()
        with self.assertRaisesRegex(RuntimeError, "outer failure"):
            with self.db.transaction():
                review_committed_baseline(self.db, self.TARGET)
                raise RuntimeError("outer failure")
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))
        self.assertEqual(self.db.one("SELECT state FROM target_baselines")[0], "established")

    def test_resuming_a_healthy_committed_run_does_not_revoke_its_frozen_snapshot(self):
        directory = self.legacy(frozen_401=False)
        self.db.create_run_target("OLD", self.policy, directory, True)
        self.db.stage_finish("OLD", self.TARGET, "urls", "partial", metrics={"collection_status": "partial"})
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))

    def test_repair_requires_a_finished_source_run(self):
        self.start("ACTIVE")
        with self.assertRaisesRegex(ReconError, "running scan"):
            repair_baselines(self.paths, self.db, run_id="ACTIVE")

    def test_another_targets_baseline_is_preserved(self):
        self.legacy()
        self.db.execute("INSERT INTO target_baselines SELECT 'other.test',state,established_run_id,established_at,last_refreshed_run_id,last_refreshed_at,reason,migrated,updated_at FROM target_baselines WHERE target=?", (self.TARGET,))
        before = dict(self.db.one("SELECT * FROM target_baselines WHERE target='other.test'"))
        repair_baselines(self.paths, self.db, run_id="OLD", target=self.TARGET)
        self.assertEqual(before, dict(self.db.one("SELECT * FROM target_baselines WHERE target='other.test'")))

    def test_new_incomplete_http_snapshot_cannot_enter_the_registry(self):
        self.start("RESTRICTED", baseline=True)
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 403}, "denied", "RESTRICTED")
        self.complete("RESTRICTED")
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertIsNone(self.db.one("SELECT 1 FROM successful_recon_commits"))

    def test_failed_resume_keeps_the_previously_healthy_frozen_receipt(self):
        directory = self.legacy(frozen_401=False)
        self.db.create_run_target("OLD", self.policy, directory, True)
        self.complete("OLD", partial=True)
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))

    def test_same_id_recovery_cannot_rehabilitate_stale_derived_receipts(self):
        directory = self.legacy()
        self.db.target_has_history(self.TARGET)
        self.db.create_run_target("OLD", self.policy, directory, True)
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 200}, "healthy", "OLD")
        self.complete("OLD")
        result = self.db.replace_recon_derived_working_state("NEXT", self.TARGET, "sources", {"new": {"hash": "b"}})
        self.assertFalse(result["baseline_exists"])
        self.assertEqual(result["removed"], [])

    def test_js_comparisons_ignore_availability_and_hashes_from_excluded_runs(self):
        self.legacy()
        url = "https://example.test/app.js"
        self.db.record_js_availability("OLD", self.TARGET, url, "live", status_code=200)
        self.db.upsert_js(self.TARGET, url, "old-raw", "old-semantic", "unused", 1, "OLD")
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        availability = self.db.record_js_availability("NEW", self.TARGET, url, "not_found", status_code=404)
        self.assertIsNone(availability["previous"])
        is_new, raw_changed, semantic_changed = self.db.upsert_js(self.TARGET, url, "new-raw", "new-semantic", "unused", 1, "NEW")
        self.assertTrue(is_new)
        self.assertFalse(raw_changed)
        self.assertFalse(semantic_changed)

    def test_rebaseline_does_not_compare_with_an_older_unreconstructable_snapshot(self):
        self.start("EARLIER", baseline=True)
        self.complete("EARLIER")
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        self.complete("NEW")
        self.assertEqual(_previous_run(self.db, self.TARGET, "NEW"), "")
        self.assertEqual(_latest_successful_runs(self.db, self.TARGET)[0]["previous_run"], "")

    def test_quarantine_survives_database_reopen_and_migration(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.db.close()
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertTrue(self.db.successful_snapshot_status(self.TARGET)["exists"])
        self.assertFalse(self.db.successful_snapshot_status(self.TARGET)["usable"])

    def test_failed_replacement_commit_keeps_the_old_evidence_quarantined(self):
        self.legacy()
        self.db.target_has_history(self.TARGET)
        self.start("NEW")
        self.db.upsert_asset(self.TARGET, "new.example.test", ["root"], "NEW")
        with patch.object(self.db, "_promote_derived_working_state_no_tx", side_effect=RuntimeError("controlled promotion failure")):
            with self.assertRaisesRegex(RuntimeError, "controlled promotion"):
                self.complete("NEW")
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], "OLD")
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertIsNotNone(self.db.one("SELECT 1 FROM successful_recon_state WHERE committed_run_id='OLD'"))

    def test_automatic_quarantine_invalidates_dependent_change_snapshots(self):
        self.legacy()
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES('NEXT',?,'success','2026-01-01T00:02:00Z',1)", (APP_VERSION,))
        self.db.execute("INSERT INTO change_intelligence_snapshots VALUES('OLD',?,'','{}','2026-01-01T00:00:00Z')", (self.TARGET,))
        self.db.execute("INSERT INTO change_intelligence_snapshots VALUES('NEXT',?,'OLD','{}','2026-01-01T00:01:00Z')", (self.TARGET,))
        self.db.target_has_history(self.TARGET)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM change_intelligence_snapshots")[0], 0)

    def test_same_id_recovery_does_not_rehabilitate_unobserved_js_rows(self):
        directory = self.legacy()
        url = "https://example.test/app.js"
        self.db.record_js_availability("OLD", self.TARGET, url, "live", status_code=200)
        self.db.upsert_js(self.TARGET, url, "old", "old", "unused", 1, "OLD")
        self.db.target_has_history(self.TARGET)
        self.db.create_run_target("OLD", self.policy, directory, True)
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 200}, "healthy", "OLD")
        self.complete("OLD")
        self.start("NEXT")
        result = self.db.record_js_availability("NEXT", self.TARGET, url, "not_found", status_code=404)
        self.assertIsNone(result["previous"])
        self.assertEqual(self.db.upsert_js(self.TARGET, url, "new", "new", "unused", 1, "NEXT"), (True, False, False))

    def test_fresh_js_observations_in_a_healthy_same_id_resume_remain_comparable(self):
        directory = self.legacy()
        url = "https://example.test/app.js"
        self.db.record_js_availability("OLD", self.TARGET, url, "live", status_code=200)
        self.db.upsert_js(self.TARGET, url, "old", "old", "unused", 1, "OLD")
        self.db.target_has_history(self.TARGET)
        self.db.create_run_target("OLD", self.policy, directory, True)
        self.db.record_js_availability("OLD", self.TARGET, url, "live", status_code=200)
        self.db.upsert_js(self.TARGET, url, "healthy", "healthy", "unused", 1, "OLD")
        review_committed_baseline(self.db, self.TARGET)
        self.db.upsert_fingerprint(self.TARGET, "https://example.test", {"status_code": 200}, "healthy", "OLD")
        self.complete("OLD")
        self.start("NEXT")
        result = self.db.record_js_availability("NEXT", self.TARGET, url, "live", status_code=200)
        self.assertEqual(result["previous"]["run_id"], "OLD")
        self.assertEqual(self.db.upsert_js(self.TARGET, url, "next", "next", "unused", 1, "NEXT"), (False, True, True))

    def test_cli_uses_the_same_lock_as_a_live_scan(self):
        self.legacy(frozen_401=False)
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
        logger = SimpleNamespace(warn=lambda *args, **kwargs: None)
        output = io.StringIO()
        with runtime.RunLock(self.paths.lock, logger), patch.object(runtime, "ROOT_DIR", self.paths.root), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ReconError, "Another Recon Monitor run is active"):
                runtime.main(["platform", "baseline-repair", "--run", "OLD"])
            self.assertTrue(self.paths.lock.exists())
        self.assertIsNone(baseline_review(self.db, self.TARGET, "OLD"))


if __name__ == "__main__":
    unittest.main()

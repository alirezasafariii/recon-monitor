from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy, ReconError
from execution import BudgetManager
from katana_completion import CONTRACT
from product_platform import run_completeness, run_completeness_snapshot
from reporting import generate_report
from scan_coverage import origin_probe_coverage, stage_coverage
from scan_finalization import finalize_run_diagnostics
from stages import StageContext, _origin_probe_one, stage_urls, stage_fingerprint, stage_javascript


class ScanVisibilityTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline regression attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = AppPaths.from_root(Path(tmp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "modules": {"ports": True, "nuclei": False, "screenshots": False},
            "fingerprint": {"collect_tls": False},
            "analysis": {"asset_graph": False},
        })
        self.paths.policy.write_text(json.dumps({"schema": 1, "targets": [self.policy.raw]}))
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.phase = "restricted"
        self.crawls = []

    def context(self):
        run = self.db.create_run(self.policy.name, 1, "test")
        root = self.paths.output / self.policy.name / "runs" / run
        root.mkdir(parents=True)
        self.db.create_run_target(run, self.policy, root, True)
        return StageContext(self.paths, self.config, self.policy, self.db, self.logger,
                            SimpleNamespace(run=self.tool), MagicMock(), run, root, False,
                            BudgetManager.create(self.db, run, self.policy.name, self.policy))

    def probe_rows(self):
        rows = []
        for url in ("http://example.test", "https://example.test", "http://example.test:8080", "https://example.test:8443"):
            failed = self.phase == "restricted" and ":8" in url
            status = 0 if failed else 401 if self.phase == "restricted" and url == "https://example.test" else 200
            rows.append({"url": url, "status_code": status, "live": bool(status),
                         "transport_status": "error" if failed else "ok", "error": "timed out" if failed else ""})
        return rows

    def probes(self, _ctx, _urls):
        rows = [row for row in self.probe_rows() if row["url"] in _urls]
        return [r["url"] for r in rows if r["live"]], rows

    def tool(self, args, **kwargs):
        output = Path(kwargs["output_path"])
        if args[0] == "katana":
            origins = Path(args[args.index("-list") + 1]).read_text().splitlines()
            frontier = Path(args[args.index("-recon-checkpoint-dir") + 1])
            (frontier / "retained-proof").write_text("prior artifact")
            self.crawls.append((list(origins), frontier))
            output.write_text("".join(origin + "/\n" for origin in origins))
            rows = []
            for origin in origins:
                fail = self.phase == "recovering" and origin == "https://example.test"
                rows.append(dict(contract=CONTRACT, origin=origin,
                                 stop_reason="request_errors" if fail else "queue_exhausted",
                                 attempted_requests=1, failed_requests=int(fail),
                                 limited_requests=0, pending_items=0, active_items=0))
            Path(args[args.index("-recon-completion-log") + 1]).write_text("\n".join(json.dumps(r) for r in rows))
        elif args[0] == "httpx":
            origins = Path(args[args.index("-l") + 1]).read_text().splitlines()
            output.write_text("\n".join(json.dumps({"input": origin, "url": origin,
                "status_code": 401 if self.phase == "restricted" else 200,
                "title": "Login" if self.phase == "restricted" else "Static page",
                "content_type": "text/html"}) for origin in origins))
        else:
            raise AssertionError("unexpected tool: " + str(args))
        return SimpleNamespace(returncode=0, timed_out=False, operator_next=False, duration=.1,
                               lines=len(output.read_text().splitlines()))

    @contextlib.contextmanager
    def tools(self):
        with patch("stages.tool_path", side_effect=lambda name: name if name in {"katana", "httpx"} else None), \
             patch("stages._probe_live_origins", side_effect=self.probes), \
             patch("stages._katana_completion_supported", return_value=True), \
             patch("stages._katana_checkpoint_supported", return_value=True):
            yield

    def test_failed_and_restricted_origins_survive_successful_crawl(self):
        ctx = self.context()
        (ctx.current / "port-web-origins.txt").write_text("http://example.test:8080\nhttps://example.test:8443\n")
        with self.tools():
            metrics = stage_urls(ctx)
        self.assertEqual(metrics["origin_probe_failed"], 2)
        self.assertEqual(metrics["origin_access_restricted"], 1)
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertIn("origin_probe_failed", metrics["collection_reasons"])
        self.assertIn("http_access_restricted", metrics["collection_reasons"])
        self.assertEqual(metrics["katana_origins_completed"], 2)
        self.assertEqual(metrics["katana_pending_origins"], 2)
        self.assertEqual(len((ctx.current / "origin-probe-pending.txt").read_text().splitlines()), 3)
        self.assertIn("https://example.test/", (ctx.current / "urls.txt").read_text())

    def test_access_recovery_restarts_empty_frontier_but_retains_new_frontier_on_retry(self):
        ctx = self.context()
        with self.tools():
            first = stage_urls(ctx)
            old_path = next(path for origins, path in self.crawls if origins == ["https://example.test"])
            self.phase = "recovering"
            second = stage_urls(ctx)
            new_path = self.crawls[-1][1]
            self.phase = "healthy"
            third = stage_urls(ctx)
        self.assertEqual(first["collection_status"], "partial")
        self.assertEqual(second["collection_status"], "partial")
        self.assertEqual(third["collection_status"], "completed")
        self.assertNotEqual(old_path, new_path)
        self.assertEqual(self.crawls[-1][1], new_path)
        self.assertTrue((old_path / "retained-proof").is_file())
        self.assertEqual(third["origin_access_restricted"], 0)

    def test_head_auth_rejection_is_confirmed_with_bounded_get(self):
        ctx = self.context()
        calls = []
        def transport(item, _policy, **kwargs):
            calls.append(item)
            status = 401 if item["method"] == "HEAD" else 200
            return kwargs["observation"](item["method"], item["url"], status, {}, b""), "ok"
        with patch("stages.perform_pinned_request", side_effect=transport):
            result = _origin_probe_one(ctx, "https://example.test")
        self.assertEqual([r["method"] for r in calls], ["HEAD", "GET"])
        self.assertEqual(calls[1]["headers"]["Range"], "bytes=0-0")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(origin_probe_coverage([result])["origin_access_restricted"], 0)
        self.assertEqual(ctx.budget.snapshot()["http_requests"]["used"], 2)

    def test_fingerprint_restriction_cannot_hide_behind_successful_head(self):
        ctx = self.context()
        (ctx.current / "base-urls.txt").write_text("https://example.test\nhttp://example.test\n")
        with self.tools():
            result = stage_fingerprint(ctx)
        self.assertEqual(result["http_access_restricted"], 2)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["probed"], 2)

    def test_no_input_and_running_are_not_complete_or_failed_coverage(self):
        row = {"status": "success", "metrics_json": {"collection_status": "no_input", "files": 0, "downloaded": 0}}
        self.assertEqual(stage_coverage("javascript", row)["score"], 0)
        row["status"] = "running"
        self.assertEqual(stage_coverage("report", row)["status"], "running")
        self.assertEqual(stage_coverage("endpoint_validation", {"status": "success", "metrics_json": {"checked": 0}})["status"], "no_input")

    def test_verified_reuse_and_not_found_count_as_completed_js_observations(self):
        for extra in ({"reused_work_items": 1}, {"not_found": 1}):
            row = {"status": "success", "metrics_json": {"collection_status": "completed", "files": 1,
                                                          "downloaded": 0, "errors": 0, **extra}}
            self.assertEqual(stage_coverage("javascript", row)["status"], "complete")

    def test_missing_stage_on_second_target_does_not_count_as_complete(self):
        ctx = self.context()
        other = TargetPolicy.from_dict({"name": "other.test", "roots": ["other.test"]})
        self.db.create_run_target(ctx.run_id, other, self.paths.output / other.name, True)
        for stage, _ in runtime.STAGES:
            self.db.stage_begin(ctx.run_id, self.policy.name, stage, 1)
            self.db.stage_finish(ctx.run_id, self.policy.name, stage, "success", metrics={"records": 1})
        result = run_completeness(self.db, ctx.run_id)
        self.assertLess(result["execution_score"], 100)
        self.assertEqual(result["dimensions"]["dns"]["targets"]["other.test"]["status"], "not_observed")

    def seed_report(self):
        ctx = self.context()
        for stage, _ in runtime.STAGES:
            self.db.stage_begin(ctx.run_id, self.policy.name, stage, 1)
            if stage != "report":
                metrics = {"collection_status": "completed"}
                if stage == "javascript":
                    metrics.update(collection_status="no_input", files=0, downloaded=0)
                if stage == "endpoint_validation":
                    metrics.update(checked=0, candidates=0)
                self.db.stage_finish(ctx.run_id, self.policy.name, stage, "success", metrics=metrics)
        provisional = run_completeness_snapshot(self.db, ctx.run_id, refresh=True)
        summary = {"bug_candidates": {"product_platform": {"run_completeness": provisional, "suite_v6": {}},
                   "workspace_v7": {"targets": {self.policy.name: {"coverage": {"blind_spots": ["No successful run available"]}}}}}}
        self.db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        ("AN-final", ctx.run_id, self.policy.name, "test", "test", "automatic", "success", "2026-01-01", "2026-01-01", json.dumps(summary)))
        generate_report(ctx, True, {"new_alerts": 0, "notified": False})
        self.db.stage_finish(ctx.run_id, self.policy.name, "report", "success", metrics={"analysis": {"analysis_id": "AN-final", **summary}})
        from run_lifecycle_state import record_target_lifecycle
        record_target_lifecycle(self.db, ctx.run_id, self.policy.name,
                                collection_status="success", analysis_status="success", report_status="success",
                                notification_status="success", overall_status="success", baseline_reason="collection_complete")
        self.db.finish_run_target(ctx.run_id, self.policy.name, "success")
        self.db.finish_run(ctx.run_id, "success")
        return ctx, provisional

    def test_finalization_corrects_db_files_analysis_and_existing_cache_without_recursion(self):
        ctx, before = self.seed_report()
        self.assertEqual(before["dimensions"]["report"]["status"], "running")
        self.assertNotIn("Run finalization/report stage is incomplete.", before["warnings"])
        snapshot_before = self.db.successful_snapshot_status(self.policy.name)
        first = finalize_run_diagnostics(self.paths, self.db, ctx.run_id)
        result = run_completeness_snapshot(self.db, ctx.run_id)
        self.assertEqual(result["dimensions"]["report"]["status"], "complete")
        self.assertEqual(result["execution_score"], 100)
        self.assertEqual(result["dimensions"]["javascript"]["status"], "no_input")
        self.assertLess(result["score"], 100)
        summary = json.loads(self.db.one("SELECT summary_json FROM analysis_runs WHERE id='AN-final'")[0])
        self.assertEqual(summary["bug_candidates"]["product_platform"]["run_completeness"]["dimensions"], result["dimensions"])
        self.assertNotIn("No successful run available", summary["bug_candidates"]["workspace_v7"]["targets"][self.policy.name]["coverage"]["blind_spots"])
        for name in ("report.json", "run-manifest.json"):
            saved = json.loads((ctx.run_dir / name).read_text())
            self.assertEqual(saved["stages"]["report"]["status"], "success")
            self.assertNotIn("analysis", saved["stages"]["report"]["metrics"])
        self.assertIn("Coverage: no_input", (ctx.run_dir / "report.html").read_text())
        size = (ctx.run_dir / "report.json").stat().st_size
        second = finalize_run_diagnostics(self.paths, self.db, ctx.run_id)
        self.assertLess(abs((ctx.run_dir / "report.json").stat().st_size - size), 200)
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name), snapshot_before)
        self.assertEqual(first["network_requests"], 0)
        self.assertEqual(second["network_requests"], 0)

    def test_finalization_refuses_running_scan(self):
        ctx = self.context()
        with self.assertRaisesRegex(ReconError, "running"):
            finalize_run_diagnostics(self.paths, self.db, ctx.run_id)

    def test_historical_probe_audit_preserves_outcomes_and_baseline_but_exposes_restriction(self):
        ctx, _ = self.seed_report()
        self.db.stage_finish(ctx.run_id, self.policy.name, "urls", "success", metrics={
            "collection_status": "completed", "urls": 2, "katana_status": "completed", "truncated": False})
        (ctx.current / "origin-probe.jsonl").write_text("\n".join(json.dumps(row) for row in self.probe_rows()))
        snapshot = self.db.successful_snapshot_status(self.policy.name)
        finalize_run_diagnostics(self.paths, self.db, ctx.run_id)
        row = self.db.one("SELECT status,metrics_json FROM stage_runs WHERE run_id=? AND stage='urls'", (ctx.run_id,))
        self.assertEqual(row["status"], "success")
        self.assertEqual(json.loads(row["metrics_json"])["collection_status"], "completed")
        visibility = run_completeness(self.db, ctx.run_id)["dimensions"]["urls"]
        self.assertEqual(visibility["status"], "access_restricted")
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name), snapshot)
        report = json.loads((ctx.run_dir / "report.json").read_text())
        self.assertEqual(report["collection_quality"]["dimensions"]["urls"]["origin_probe_failed"], 2)
        self.assertIn("http_access_restricted", report["collection_quality"]["dimensions"]["urls"]["reason"])
        self.assertTrue(report["diagnostics_finalization"]["baseline_review_required"])

    def test_zero_response_fingerprint_stays_partial_and_accounts_attempted_inputs(self):
        ctx = self.context()
        (ctx.current / "base-urls.txt").write_text("https://example.test\nhttp://example.test\n")
        def empty(_args, **kwargs):
            Path(kwargs["output_path"]).write_text("")
            return SimpleNamespace(returncode=0, lines=0)
        ctx.runner.run = empty
        with self.tools():
            result = stage_fingerprint(ctx)
        self.assertEqual(result["probed"], 2)
        self.assertEqual(result["live"], 0)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(len(result["http_probe_unobserved_inputs"]), 2)

    def exercise_pipeline(self, resume_id=None):
        orchestrator = runtime.Orchestrator(self.paths, self.config, self.logger, self.db, progress=False, allow_active=False)
        def offline(ctx):
            self.db.upsert_asset(self.policy.name, self.policy.name, ["fixture"], ctx.run_id)
            (ctx.current / "subdomains.txt").write_text(self.policy.name + "\n")
            (ctx.current / "resolved-hosts.txt").write_text(self.policy.name + "\n")
            (ctx.current / "port-web-origins.txt").write_text("http://example.test:8080\nhttps://example.test:8443\n")
            return {"collection_status": "completed", "successful_rrtypes": ["A", "AAAA", "CNAME", "NS"]}
        stages = {name: offline for name in runtime.STAGE_FUNCTIONS}
        stages.update(urls=stage_urls, javascript=stage_javascript, fingerprint=stage_fingerprint)
        with self.tools(), patch.dict(runtime.STAGE_FUNCTIONS, stages), \
             patch.object(orchestrator, "_record_versions"), patch.object(orchestrator, "install_signal_handlers"), \
             patch.object(orchestrator.runner, "run", side_effect=self.tool), contextlib.redirect_stdout(io.StringIO()):
            code = orchestrator.run(PolicySet({}, [self.policy], self.paths.policy), resume_id=resume_id)
        return code, orchestrator.current_run_id

    def test_actual_pipeline_restricted_scan_never_establishes_baseline_and_resume_recovers(self):
        code, run = self.exercise_pipeline()
        self.assertEqual(code, 2)
        lifecycle = self.db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run,))
        self.assertEqual(lifecycle["collection_status"], "partial")
        self.assertEqual(lifecycle["report_status"], "success")
        self.assertFalse(lifecycle["baseline_eligible"])
        self.assertFalse(self.db.successful_snapshot_status(self.policy.name)["exists"])
        self.phase = "healthy"
        code, _ = self.exercise_pipeline(resume_id=run)
        self.assertEqual(code, 0)
        self.assertTrue(self.db.successful_snapshot_status(self.policy.name)["exists"])
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name)["run_id"], run)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM bug_candidates")[0], 0)

    def test_restricted_followup_preserves_existing_baseline(self):
        self.phase = "healthy"
        code, healthy_run = self.exercise_pipeline()
        self.assertEqual(code, 0)
        self.phase = "restricted"
        code, failed_run = self.exercise_pipeline()
        self.assertEqual(code, 2)
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name)["run_id"], healthy_run)
        self.assertEqual(self.db.one("SELECT baseline_state FROM target_run_lifecycle WHERE run_id=?", (failed_run,))[0], "retained")

    def test_failed_final_projection_is_visible_without_invalidating_complete_collection(self):
        self.phase = "healthy"
        with patch("scan_finalization.finalize_run_diagnostics", side_effect=OSError("controlled disk failure")):
            code, run = self.exercise_pipeline()
        self.assertEqual(code, 2)
        state = self.db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run,))
        self.assertEqual(state["collection_status"], "success")
        self.assertEqual(state["report_status"], "failed")
        self.assertEqual(self.db.stage_status(run, self.policy.name, "report"), "failed")
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name)["run_id"], run)

    def test_explicit_resume_rechecks_legacy_success_with_retained_probe_failures(self):
        code, run = self.exercise_pipeline()
        self.assertEqual(code, 2)
        # Simulate the old release's incorrect successful URL-stage receipt.
        row = self.db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND stage='urls'", (run,))
        metrics = json.loads(row[0])
        for key in list(metrics):
            if key.startswith("origin_probe_") or key.startswith("origin_access_") or key.startswith("origin_coverage_"):
                metrics.pop(key)
        metrics.update(collection_status="completed", collection_reasons=[])
        self.db.stage_finish(run, self.policy.name, "urls", "success", metrics=metrics)
        run_dir = self.paths.output / self.policy.name / "runs" / run
        (run_dir / "current" / "url-collection.json").write_text(json.dumps({"run_id": run, "metrics": metrics}))
        self.phase = "healthy"
        self.crawls.clear()
        code, _ = self.exercise_pipeline(resume_id=run)
        self.assertEqual(code, 0)
        self.assertTrue(self.crawls)
        saved = json.loads(self.db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND stage='urls'", (run,))[0])
        self.assertTrue(saved["resumed_origin_probe_gap"])
        self.assertEqual(self.db.stage_status(run, self.policy.name, "javascript"), "success")


if __name__ == "__main__":
    unittest.main()

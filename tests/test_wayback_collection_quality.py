from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core as runtime
import test_collection_quality as quality_fixture
import test_katana_execution_quality as katana_fixture
from collection_quality import snapshot_collection_quality
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy
from reporting import _stage_metrics
from stages import stage_urls


class WaybackCollectionQualityTests(unittest.TestCase):
    TARGET = "example.test"
    ARCHIVE = "https://example.test/archive.js"
    CRAWL = "https://example.test/crawl.js"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.tool_calls = []

    def _tool(self, wayback):
        def run(args, **kwargs):
            self.tool_calls.append((args, kwargs))
            if args[0] == "waybackurls":
                code, timed_out, output, operator_next = wayback() if callable(wayback) else wayback
            else:
                code, timed_out, output, operator_next = 0, False, self.CRAWL + "\n", False
            if output is not None:
                Path(kwargs["output_path"]).write_text(output, encoding="utf-8")
            return SimpleNamespace(
                returncode=code, timed_out=timed_out, operator_next=operator_next,
                duration=2.5 if args[0] == "waybackurls" else 0.1,
                lines=len((output or "").splitlines()),
            )
        return run

    def _context(self, root, wayback):
        ctx = katana_fixture.KatanaExecutionQualityTests()._context(root, SimpleNamespace(run=self._tool(wayback)))
        ctx.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET],
            "exclude": [r"(^|\.)blocked\.example\.test$"],
            "analysis": {"asset_graph": False},
            "limits": {"timeout_seconds": 1800, "request_rate": 3},
        })
        return ctx

    def _collect(self, ctx, *, available=True):
        with patch("stages.tool_path", side_effect=lambda tool: tool == "katana" or (tool == "waybackurls" and available)), patch(
            "stages._probe_live_origins", return_value=(["https://example.test"], []),
        ):
            return stage_urls(ctx)

    def test_timeout_remains_partial_despite_successful_katana_and_keeps_scoped_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self.ARCHIVE + "\nhttps://blocked.example.test/private.js\nhttps://outside.test/app.js\n"
            ctx = self._context(Path(tmp), (124, True, output, False))
            (ctx.current / "resolved-hosts.txt").write_text("example.test\napi.example.test\n")
            metrics = self._collect(ctx)
            self.assertEqual(metrics["katana_status"], "completed")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["collection_reasons"], ["wayback_timeout"])
            self.assertEqual(metrics["wayback_status"], "timeout")
            outcome = metrics["wayback_tool_outcomes"][0]
            self.assertEqual(outcome["input_hosts"], 2)
            self.assertEqual(outcome["exit_code"], 124)
            self.assertTrue(outcome["timed_out"])
            self.assertEqual(outcome["duration_seconds"], 2.5)
            self.assertEqual(outcome["lines"], 3)
            self.assertEqual(outcome["stop_reason"], "timeout")
            self.assertEqual((ctx.current / "wayback-urls.txt").read_text(), output)
            self.assertEqual((ctx.current / outcome["output_file"]).read_text(), output)
            self.assertEqual(set((ctx.current / "urls.txt").read_text().splitlines()), {"https://example.test/", self.ARCHIVE, self.CRAWL})
            wayback_call = self.tool_calls[0][1]
            self.assertEqual(wayback_call["input_text"], "api.example.test\nexample.test\n")
            self.assertEqual(wayback_call["timeout"], 1800)
            persisted = json.loads((ctx.current / "url-collection.json").read_text())["metrics"]
            self.assertEqual(persisted, metrics)

    def test_all_nonzero_exits_including_one_remain_partial(self):
        for code in (1, 2, 124):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                ctx = self._context(Path(tmp), (code, False, self.ARCHIVE + "\n", False))
                metrics = self._collect(ctx)
                self.assertEqual(metrics["collection_status"], "partial")
                self.assertEqual(metrics["wayback_status"], "nonzero_exit")
                self.assertEqual(metrics["wayback_tool_outcomes"][0]["exit_code"], code)

    def test_timeout_flag_cannot_be_hidden_by_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            metrics = self._collect(self._context(Path(tmp), (0, True, "", False)))
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["wayback_status"], "timeout")

    def test_missing_output_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            metrics = self._collect(self._context(Path(tmp), (0, False, None, False)))
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["wayback_status"], "output_missing")

    def test_successful_empty_archive_does_not_invent_partial_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            metrics = self._collect(self._context(Path(tmp), (0, False, "", False)))
            self.assertEqual(metrics["collection_status"], "completed")
            self.assertEqual(metrics["wayback_status"], "completed")
            self.assertEqual(metrics["collection_reasons"], [])
            self.assertEqual(metrics["wayback_tool_outcomes"][0]["lines"], 0)

    def test_never_attempted_optional_archive_has_no_fabricated_tool_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            metrics = self._collect(self._context(Path(tmp), (0, False, "", False)), available=False)
            self.assertEqual(metrics["collection_status"], "completed")
            self.assertEqual(metrics["wayback_status"], "not_available")
            self.assertEqual(metrics["wayback_tool_outcomes"], [])
            self.assertEqual([args[0] for args, _kwargs in self.tool_calls], ["katana"])

    def test_operator_next_during_archive_is_recorded_and_does_not_launch_katana(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), (125, False, self.ARCHIVE + "\n", True))
            metrics = self._collect(ctx)
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["wayback_status"], "operator_next")
            self.assertEqual(metrics["katana_status"], "operator_next")
            self.assertEqual([args[0] for args, _kwargs in self.tool_calls], ["waybackurls"])
            self.assertIn(self.ARCHIVE, (ctx.current / "urls.txt").read_text().splitlines())

    def test_quality_identifies_archive_gap_without_claiming_katana_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            for stage_status in ("partial", "success"):
                with self.subTest(stage_status=stage_status):
                    ctx = quality_fixture.make_ctx(Path(tmp), {"urls": {"status": stage_status, "metrics": {
                        "urls": 2, "truncated": False, "katana_status": "completed",
                        "wayback_status": "timeout",
                    }}})
                    urls = snapshot_collection_quality(ctx, persist=False)["dimensions"]["urls"]
                    self.assertEqual(urls["status"], "partial")
                    self.assertEqual(urls["wayback_status"], "timeout")
                    self.assertEqual(urls["not_collected"], ["incomplete_wayback_archive"])
                    self.assertIn("waybackurls: timeout", urls["reason"])

    def test_missing_archive_on_resume_does_not_erase_a_known_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), (124, True, self.ARCHIVE + "\n", False))
            first = self._collect(ctx)
            second = self._collect(ctx, available=False)
            self.assertEqual(second["collection_status"], "partial")
            self.assertFalse(second["wayback_available"])
            self.assertEqual(second["wayback_tool_outcomes"], first["wayback_tool_outcomes"])
            self.assertIn(self.ARCHIVE, (ctx.current / "urls.txt").read_text().splitlines())
            self.assertIn(self.CRAWL, (ctx.current / "urls.txt").read_text().splitlines())

    def test_past_archive_next_does_not_cancel_the_new_resume_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), (125, False, self.ARCHIVE + "\n", True))
            self._collect(ctx)
            metrics = self._collect(ctx, available=False)
            self.assertEqual(metrics["wayback_status"], "operator_next")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["katana_status"], "completed")
            self.assertEqual([args[0] for args, _kwargs in self.tool_calls], ["waybackurls", "katana"])

    def _run_lifecycle(self, stack, phase, *, with_baseline=False):
        tmp = stack.enter_context(tempfile.TemporaryDirectory())
        paths = AppPaths.from_root(Path(tmp))
        paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
        db = runtime.Database(paths.db)
        stack.callback(db.close)
        policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET], "analysis": {"asset_graph": False},
            "limits": {"timeout_seconds": 1800, "request_rate": 3},
        })
        seed_run = None
        if with_baseline:
            seed_run = db.create_run(None, 1, "offline-seed")
            db.create_run_target(seed_run, policy, paths.output / "seed", True)
            db.upsert_url(self.TARGET, "https://example.test/previous.js", "javascript", "offline", seed_run)
            db.finish_run_target(seed_run, self.TARGET, "success")
            db.finish_run(seed_run, "success")
        orchestrator = runtime.Orchestrator(paths, Config(paths), Logger(paths), db, progress=False, allow_active=False)
        stack.enter_context(patch.object(orchestrator, "_record_versions"))
        stack.enter_context(patch.object(orchestrator, "install_signal_handlers"))
        stack.enter_context(patch("stages.tool_path", side_effect=lambda tool: tool in {"waybackurls", "katana"}))
        stack.enter_context(patch("stages._probe_live_origins", return_value=(["https://example.test"], [])))
        downstream = []
        reports = []

        def wayback():
            if phase[0] == "timeout":
                return 124, True, self.ARCHIVE + "\n", False
            return 0, False, "https://example.test/resumed.js\n", False

        def offline_stage(ctx):
            stage = ctx.db.one("SELECT current_stage FROM run_targets WHERE run_id=? AND target=?", (ctx.run_id, ctx.policy.name))[0]
            downstream.append((phase[0], stage))
            return {"collection_status": "completed"}

        def offline_report(ctx, _baseline):
            reports.append(_stage_metrics(ctx))
            return {"analysis": {"analysis_id": "offline"}, "finding_notifications": {"status": "success"}}

        stages = {name: offline_stage for name in runtime.STAGE_FUNCTIONS}
        stages["urls"] = stage_urls
        stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
        stack.enter_context(patch("recon_monitor_core.stage_report", side_effect=offline_report))
        stack.enter_context(patch.object(orchestrator.runner, "run", side_effect=self._tool(wayback)))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return paths, db, policy, orchestrator, seed_run, downstream, reports

    def test_archive_timeout_is_partial_through_report_run_and_baseline_persistence(self):
        for with_baseline in (False, True):
            with self.subTest(with_baseline=with_baseline), contextlib.ExitStack() as stack:
                _paths, db, policy, orchestrator, seed_run, downstream, reports = self._run_lifecycle(stack, ["timeout"], with_baseline=with_baseline)
                self.assertEqual(orchestrator.run(PolicySet({}, [policy], orchestrator.paths.policy)), 2)
                run_id = orchestrator.current_run_id
                self.assertIn(("timeout", "javascript"), downstream)
                self.assertEqual(db.stage_status(run_id, self.TARGET, "urls"), "partial")
                self.assertEqual(db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "partial")
                self.assertEqual(db.one("SELECT status FROM run_targets WHERE run_id=?", (run_id,))[0], "partial")
                lifecycle = db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run_id,))
                self.assertFalse(lifecycle["baseline_eligible"])
                self.assertEqual(lifecycle["collection_status"], "partial")
                report = reports[0]["urls"]
                self.assertEqual(report["status"], "partial")
                self.assertEqual(report["metrics"]["katana_status"], "completed")
                self.assertEqual(report["metrics"]["wayback_status"], "timeout")
                snapshot = db.successful_snapshot_status(self.TARGET)
                self.assertEqual(snapshot["exists"], with_baseline)
                if seed_run:
                    self.assertEqual(snapshot["run_id"], seed_run)

    def test_resume_retries_archive_and_keeps_previous_archive_and_completed_crawl(self):
        phase = ["timeout"]
        with contextlib.ExitStack() as stack:
            _paths, db, policy, orchestrator, _seed_run, downstream, reports = self._run_lifecycle(stack, phase)
            policies = PolicySet({}, [policy], orchestrator.paths.policy)
            self.assertEqual(orchestrator.run(policies), 2)
            run_id = orchestrator.current_run_id
            run_dir = Path(db.one("SELECT run_dir FROM run_targets WHERE run_id=?", (run_id,))[0])
            first = reports[0]["urls"]["metrics"]
            first_output = run_dir / "current" / first["wayback_tool_outcomes"][0]["output_file"]
            phase[0] = "completed"
            self.assertEqual(orchestrator.run(policies, resume_id=run_id), 0)
            self.assertEqual([args[0] for args, _kwargs in self.tool_calls], ["waybackurls", "katana", "waybackurls"])
            current = reports[1]["urls"]["metrics"]
            self.assertEqual(current["collection_status"], "completed")
            self.assertEqual(current["wayback_status"], "completed")
            self.assertEqual([row["stop_reason"] for row in current["wayback_tool_outcomes"]], ["timeout", "completed"])
            self.assertEqual(first_output.read_text(), self.ARCHIVE + "\n")
            selected = set((run_dir / "current" / "urls.txt").read_text().splitlines())
            self.assertTrue({self.ARCHIVE, self.CRAWL, "https://example.test/resumed.js"} <= selected)
            self.assertIn(("completed", "javascript"), downstream)
            self.assertIn(("completed", "fingerprint"), downstream)
            self.assertEqual(db.stage_status(run_id, self.TARGET, "urls"), "success")
            self.assertEqual(db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "success")
            self.assertTrue(db.successful_snapshot_status(self.TARGET)["exists"])


if __name__ == "__main__":
    unittest.main()

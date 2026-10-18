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
import stages
from core import AppPaths, Config, Logger, PolicySet, Progress, TargetPolicy, json_dumps
from collector_status import normalize_collection_metrics
from reporting import _stage_metrics
from run_lifecycle_state import derive_collection_status
from stages import StageContext
from storage import cas_transaction


class MissingCollectorToolsTests(unittest.TestCase):
    TARGET = "example.test"
    FUNCTIONS = {
        "subdomains": stages.stage_subdomains,
        "fingerprint": stages.stage_fingerprint,
        "ports": stages.stage_ports,
        "nuclei": stages.stage_nuclei,
    }

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\n'
            'AUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n'
        )
        self.db = runtime.Database(self.paths.db)
        self.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET],
            "modules": {"ports": True, "nuclei": True, "endpoint_validation": True},
            "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING", "nuclei_template_ids": ["offline"]},
            "fingerprint": {"collect_tls": False},
            "analysis": {"asset_graph": False}, "limits": {"retries": 0},
        })
        self.calls, self.tool_calls, self.reports = [], [], []

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def ctx(self):
        run = self.db.create_run(self.TARGET, 1, "offline")
        run_dir = self.paths.output / run
        self.db.create_run_target(run, self.policy, run_dir, not self.db.target_has_history(self.TARGET))
        return StageContext(self.paths, Config(self.paths), self.policy, self.db, Logger(self.paths, verbose=False),
                            SimpleNamespace(run=self.tool), Progress(False), run, run_dir, True)

    def inputs(self, ctx):
        (ctx.current / "base-urls.txt").write_text("https://example.test/\n")
        (ctx.current / "resolved-hosts.txt").write_text("example.test\n")
        (ctx.changes / "new-live-http.txt").write_text("https://example.test/\n")

    def tool(self, args, **kwargs):
        self.tool_calls.append(args[0])
        tool = args[0]
        rows = {
            "subfinder": {"host": "resumed.example.test", "sources": ["offline"]},
            "httpx": {"url": "https://example.test/", "status_code": 200, "title": "fixture"},
            "naabu": {"host": self.TARGET, "ip": "93.184.216.34", "port": 443},
            "nuclei": {"template-id": "offline", "matched-at": "https://example.test/", "info": {"name": "fixture", "severity": "info"}},
        }
        output = "resumed.example.test\n" if tool == "assetfinder" else json.dumps(rows[tool]) + "\n"
        path = kwargs.get("output_path") or args[args.index("-o") + 1]
        Path(path).write_text(output)
        return SimpleNamespace(returncode=0, timed_out=False, operator_next=False, lines=1, duration=0.1)

    def offline_stage(self, ctx):
        name = self.db.one("SELECT current_stage FROM run_targets WHERE run_id=? AND target=?", (ctx.run_id, ctx.policy.name))[0]
        self.calls.append(name)
        self.inputs(ctx)
        return {"collection_status": "completed"}

    def report(self, ctx, baseline):
        self.calls.append("report")
        self.reports.append((_stage_metrics(ctx), baseline))
        return {"analysis": {"analysis_id": "offline"}, "finding_notifications": {"status": "success"}}

    def execute(self, stage, available=(), resume_id=None, *, custom=None):
        runner = runtime.Orchestrator(self.paths, Config(self.paths), Logger(self.paths, verbose=False),
                                      self.db, progress=False, allow_active=True)
        functions = {name: self.offline_stage for name in runtime.STAGE_FUNCTIONS}
        functions[stage] = custom or self.FUNCTIONS[stage]
        with patch.dict(runtime.STAGE_FUNCTIONS, functions), \
                patch("stages.tool_path", side_effect=lambda tool: tool if tool in available else None), \
                patch.object(runner, "_record_versions"), patch.object(runner, "install_signal_handlers"), \
                patch.object(runner, "_update_latest_pointers"), patch.object(runner.runner, "run", side_effect=self.tool), \
                patch("recon_monitor_core.stage_report", side_effect=self.report), contextlib.redirect_stdout(io.StringIO()):
            code = runner.run(PolicySet({}, [self.policy], self.paths.policy), resume_id=resume_id)
        return code, runner.current_run_id

    def test_no_subdomain_tools_preserves_roots_as_partial(self):
        ctx = self.ctx()
        with patch("stages.tool_path", return_value=None):
            result = stages.stage_subdomains(ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(set(result["missing_tools"]), {"subfinder", "assetfinder"})
        self.assertEqual(result["collection_reasons"], ["subdomain_tools_missing"])
        self.assertEqual((ctx.current / "subdomains.txt").read_text(), "example.test\n")
        self.assertEqual(self.tool_calls, [])

    def test_one_available_discovery_source_can_complete(self):
        for tool in ("subfinder", "assetfinder"):
            with self.subTest(tool=tool):
                ctx = self.ctx()
                with patch("stages.tool_path", side_effect=lambda value: value if value == tool else None):
                    result = stages.stage_subdomains(ctx)
                self.assertEqual(result["collection_status"], "completed")
                self.assertEqual(len(result["missing_tools"]), 1)
                self.assertIn("resumed.example.test", (ctx.current / "subdomains.txt").read_text())
                self.db.finish_run_target(ctx.run_id, self.TARGET, "success")

    def test_missing_required_tools_are_partial_when_work_exists(self):
        ctx = self.ctx()
        self.inputs(ctx)
        for stage, tool in (("fingerprint", "httpx"), ("ports", "naabu"), ("nuclei", "nuclei")):
            with self.subTest(stage=stage), patch("stages.tool_path", return_value=None):
                result = self.FUNCTIONS[stage](ctx)
                self.assertEqual(result["collection_status"], "partial")
                self.assertEqual(result["stop_reason"], "tool_missing")
                self.assertEqual(result["missing_tools"], [tool])

    def test_empty_inputs_are_not_missing_tools(self):
        ctx = self.ctx()
        (ctx.current / "base-urls.txt").write_text("")
        (ctx.current / "resolved-hosts.txt").write_text("")
        # A resumed upstream collector can leave no work after an earlier attempt.
        (ctx.changes / "new-live-http.txt").write_text("https://example.test/stale\n")
        (ctx.changes / "changed-fingerprints.txt").write_text("https://example.test/stale\n")
        (ctx.current / "port-web-origins.txt").write_text("https://example.test:8443\n")
        with patch("stages.tool_path") as tool:
            for stage in ("fingerprint", "ports", "nuclei"):
                self.assertEqual(self.FUNCTIONS[stage](ctx)["collection_status"], "no_input")
            tool.assert_not_called()
        self.assertEqual((ctx.current / "port-web-origins.txt").read_text(), "")
        self.assertEqual((ctx.changes / "new-live-http.txt").read_text(), "")
        self.assertEqual((ctx.changes / "changed-fingerprints.txt").read_text(), "")

    def test_absent_input_artifacts_are_partial(self):
        ctx = self.ctx()
        for stage in ("fingerprint", "ports"):
            with self.subTest(stage=stage), patch("stages.tool_path") as tool:
                self.assertEqual(self.FUNCTIONS[stage](ctx)["stop_reason"], "input_missing")
                tool.assert_not_called()

    def test_active_authorization_and_allowlist_skips_remain_intentional(self):
        ctx = self.ctx()
        self.inputs(ctx)
        ctx.allow_active = False
        with patch("stages.tool_path") as tool:
            for stage in ("ports", "nuclei"):
                self.assertEqual(self.FUNCTIONS[stage](ctx)["collection_status"], "skipped")
            ctx.allow_active = True
            self.policy.active["nuclei_template_ids"] = []
            self.assertEqual(stages.stage_nuclei(ctx)["collection_status"], "skipped")
            tool.assert_not_called()

    def test_disabled_module_never_runs_or_blocks_baseline(self):
        self.policy.modules["fingerprint"] = False
        code, run = self.execute("fingerprint", custom=MagicMock(side_effect=AssertionError("disabled collector ran")))
        self.assertEqual(code, 0)
        metrics = self.reports[-1][0]["fingerprint"]["metrics"]
        self.assertEqual(metrics["collection_status"], "disabled")
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], run)

    def test_missing_httpx_keeps_report_and_downstream_but_cannot_establish_baseline(self):
        code, run = self.execute("fingerprint")
        self.assertEqual(code, 2)
        self.assertIn("nuclei", self.calls)
        self.assertIn("report", self.calls)
        self.assertEqual(self.db.stage_status(run, self.TARGET, "fingerprint"), "partial")
        self.assertEqual(self.reports[-1][0]["fingerprint"]["status"], "partial")
        lifecycle = self.db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run,))
        self.assertEqual(lifecycle["collection_status"], "partial")
        self.assertFalse(lifecycle["baseline_eligible"])
        self.assertFalse(self.db.target_has_history(self.TARGET))

    def test_missing_tool_cannot_replace_a_prior_baseline(self):
        self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
        previous = self.db.successful_snapshot_status(self.TARGET)["run_id"]
        self.assertEqual(self.execute("fingerprint")[0], 2)
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], previous)

    def test_installing_httpx_then_resuming_reruns_only_affected_dependents(self):
        code, run = self.execute("fingerprint")
        self.assertEqual(code, 2)
        self.calls.clear()
        self.assertEqual(self.execute("fingerprint", ("httpx",), run)[0], 0)
        self.assertEqual(self.tool_calls, ["httpx"])
        self.assertNotIn("urls", self.calls)
        self.assertNotIn("javascript", self.calls)
        self.assertIn("nuclei", self.calls)
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], run)

    def test_installing_discovery_tool_then_resuming_refreshes_all_downstream(self):
        code, run = self.execute("subdomains")
        self.assertEqual(code, 2)
        self.calls.clear()
        self.assertEqual(self.execute("subdomains", ("subfinder",), run)[0], 0)
        for stage in ("dns", "ports", "urls", "javascript", "endpoint_validation", "fingerprint", "nuclei", "report"):
            self.assertIn(stage, self.calls)
        self.assertIsNotNone(self.db.one("SELECT 1 FROM assets WHERE host='resumed.example.test'"))

    def test_missing_active_tool_is_partial_and_recoverable_on_resume(self):
        for stage, tool in (("ports", "naabu"), ("nuclei", "nuclei")):
            with self.subTest(stage=stage):
                code, run = self.execute(stage)
                self.assertEqual(code, 2)
                self.assertEqual(self.db.stage_status(run, self.TARGET, stage), "partial")
                self.assertEqual(self.execute(stage, (tool,), run)[0], 0)
                self.assertEqual(self.db.stage_status(run, self.TARGET, stage), "success")

    def test_explicit_unavailable_result_is_partial_without_aborting_downstream(self):
        code, run = self.execute("fingerprint", custom=lambda ctx: {"collection_status": "unavailable"})
        self.assertEqual(code, 2)
        self.assertEqual(self.db.stage_status(run, self.TARGET, "fingerprint"), "partial")
        self.assertIn("nuclei", self.calls)

    def legacy_run(self, stage, metrics):
        ctx = self.ctx()
        self.inputs(ctx)
        for name, _ in runtime.STAGES:
            self.db.stage_begin(ctx.run_id, self.TARGET, name, 1)
            self.db.stage_finish(ctx.run_id, self.TARGET, name, "success", metrics=metrics if name == stage else {})
        return ctx

    def test_legacy_false_success_is_not_resume_skipped_or_hidden_from_lifecycle(self):
        cases = (("fingerprint", {"skipped": "httpx missing"}, "httpx"),
                 ("subdomains", {"collection_status": "completed", "subdomain_tool_outcomes": []}, "subfinder"),
                 ("ports", {"skipped": "naabu missing"}, "naabu"),
                 ("nuclei", {"skipped": "nuclei missing"}, "nuclei"))
        for stage, metrics, tool in cases:
            with self.subTest(stage=stage):
                ctx = self.legacy_run(stage, metrics)
                self.assertEqual(derive_collection_status(self.db, ctx.run_id, self.TARGET, [stage])[0], "partial")
                self.calls.clear()
                code, run = self.execute(stage, (tool,), ctx.run_id)
                self.assertEqual(code, 0)
                self.assertIn(tool, self.tool_calls)
                if stage != "nuclei":
                    self.assertIn("nuclei", self.calls)
                self.assertEqual(self.db.stage_status(run, self.TARGET, stage), "success")

    def test_resume_of_truly_successful_stage_still_skips_completed_work(self):
        code, run = self.execute("fingerprint", ("httpx",))
        self.assertEqual(code, 0)
        self.calls.clear()
        self.assertEqual(self.execute("fingerprint", (), run)[0], 0)
        self.assertEqual(self.tool_calls, ["httpx"])
        self.assertEqual(self.calls, ["report"])

    def test_old_false_success_baseline_is_invalidated_without_deleting_evidence(self):
        for stage, metrics in (("fingerprint", {"skipped": "httpx missing"}),
                               ("subdomains", {"collection_status": "completed", "subdomain_tool_outcomes": []})):
            with self.subTest(stage=stage):
                # Seed a trusted commit, then reproduce metadata written by the old runtime.
                self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
                run = self.db.successful_snapshot_status(self.TARGET)["run_id"]
                self.db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND stage=?", (json_dumps(metrics), run, stage))
                history_before = self.db.one("SELECT COUNT(*) FROM run_targets")[0]
                self.db.close()
                self.db = runtime.Database(self.paths.db)
                self.assertFalse(self.db.target_has_history(self.TARGET))
                self.assertFalse(self.db.successful_snapshot_status(self.TARGET)["exists"])
                self.assertEqual(self.db.stage_status(run, self.TARGET, stage), "partial")
                self.assertEqual(self.db.one("SELECT COUNT(*) FROM run_targets")[0], history_before)
                self.assertIsNotNone(self.db.one("SELECT 1 FROM fingerprints WHERE target=?", (self.TARGET,)))
                self.db.close()
                self.db = runtime.Database(self.paths.db)
                self.assertFalse(self.db.target_has_history(self.TARGET))
                self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
                self.assertTrue(self.reports[-1][1], "replacement must establish a silent baseline")

    def test_legacy_bootstrap_rejects_explicit_missing_tool_success(self):
        self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
        run = self.db.successful_snapshot_status(self.TARGET)["run_id"]
        self.db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND stage='fingerprint'",
                        (json_dumps({"skipped": "httpx missing"}), run))
        self.db.execute("DELETE FROM successful_recon_commits")
        self.db.execute("DELETE FROM target_baselines")
        self.db.execute("DELETE FROM schema_meta WHERE key='successful_snapshot_bootstrap_v1'")
        self.db.close()
        self.db = runtime.Database(self.paths.db)
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertFalse(self.db.successful_snapshot_status(self.TARGET)["exists"])

    def test_unknown_legacy_metrics_are_not_guessed_missing(self):
        self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
        previous = self.db.successful_snapshot_status(self.TARGET)["run_id"]
        self.db.execute("UPDATE stage_runs SET metrics_json='{}' WHERE run_id=?", (previous,))
        self.db.close()
        self.db = runtime.Database(self.paths.db)
        self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], previous)

    def test_baseline_repair_rechecks_commit_and_metrics_after_acquiring_lock(self):
        for scenario in ("collector_completed", "newer_commit"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
                original = self.db.successful_snapshot_status(self.TARGET)["run_id"]
                current = original
                if scenario == "newer_commit":
                    self.assertEqual(self.execute("fingerprint", ("httpx",))[0], 0)
                    current = self.db.successful_snapshot_status(self.TARGET)["run_id"]
                    self.db.execute("UPDATE successful_recon_commits SET run_id=? WHERE target=?", (original, self.TARGET))
                self.db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND stage='fingerprint'",
                                (json_dumps({"skipped": "httpx missing"}), original))

                @contextlib.contextmanager
                def interleaved_transaction(db):
                    if scenario == "collector_completed":
                        db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND stage='fingerprint'",
                                   (json_dumps({"collection_status": "completed"}), original))
                    else:
                        db.execute("UPDATE successful_recon_commits SET run_id=? WHERE target=?", (current, self.TARGET))
                    with cas_transaction(db):
                        yield

                with patch("successful_snapshot.cas_transaction", side_effect=interleaved_transaction):
                    self.db._repair_unavailable_collector_baselines()
                self.assertEqual(self.db.successful_snapshot_status(self.TARGET)["run_id"], current)
                self.assertTrue(self.db.target_has_history(self.TARGET))

    def test_optional_missing_source_does_not_turn_completed_collection_partial(self):
        metrics = {"collection_status": "completed", "subdomain_tool_outcomes": [{"tool": "subfinder"}],
                   "missing_tools": ["assetfinder"]}
        self.assertEqual(normalize_collection_metrics("subdomains", metrics), metrics)


if __name__ == "__main__":
    unittest.main()

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

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy
from reporting import _stage_metrics
from stages import StageContext, stage_subdomains


class SubdomainCollectionQualityTests(unittest.TestCase):
    TARGET = "example.test"
    TOOLS = ("subfinder", "assetfinder")

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET],
            "exclude": [r"(^|\.)blocked\.example\.test$"],
            "analysis": {"asset_graph": False},
            "limits": {"timeout_seconds": 1800},
        })
        self.tool_calls = []

    def _output(self, tool, host):
        return json.dumps({"host": host, "sources": ["offline-source"]}) + "\n" if tool == "subfinder" else host + "\n"

    def _tool(self, outcomes=None):
        outcomes = outcomes or {}

        def run(args, **kwargs):
            self.tool_calls.append((args, kwargs))
            tool = args[0]
            root = args[args.index("-d") + 1] if tool == "subfinder" else args[-1]
            code, timed_out, output = outcomes.get(
                (tool, root), (0, False, self._output(tool, tool + "." + root)),
            )
            if output is not None:
                Path(kwargs["output_path"]).write_text(output, encoding="utf-8")
            return SimpleNamespace(
                returncode=code, timed_out=timed_out, operator_next=False,
                duration=0.25, lines=len((output or "").splitlines()),
            )

        return run

    def _context(self, runner):
        return StageContext(
            paths=self.paths, config=Config(self.paths), policy=self.policy,
            db=self.db, runner=SimpleNamespace(run=runner), run_id="offline-run",
            logger=MagicMock(), progress=MagicMock(), run_dir=Path(self.temp.name),
            allow_active=False,
        )

    def _collect(self, outcomes=None, available=TOOLS):
        ctx = self._context(self._tool(outcomes))
        with patch("stages.tool_path", side_effect=lambda tool: tool if tool in available else None):
            metrics = stage_subdomains(ctx)
        return ctx, metrics

    def test_each_timeout_preserves_scoped_partial_output_and_reports_tool_details(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                output = self._output(tool, "partial.example.test")
                output += self._output(tool, "blocked.example.test")
                output += self._output(tool, "outside.test")
                if tool == "subfinder":
                    output += '{"host":"truncated.example.test"'
                ctx, metrics = self._collect({(tool, self.TARGET): (124, True, output)}, available=(tool,))
                self.assertEqual(metrics["collection_status"], "partial")
                self.assertEqual(metrics["collection_reasons"], [tool + "_timeout"])
                self.assertEqual(set((ctx.current / "subdomains.txt").read_text().splitlines()), {self.TARGET, "partial.example.test"})
                self.assertIsNotNone(self.db.one("SELECT host FROM assets WHERE host='partial.example.test'"))
                outcome = metrics["subdomain_tool_outcomes"][0]
                self.assertEqual(outcome["tool"], tool)
                self.assertEqual(outcome["root"], self.TARGET)
                self.assertEqual(outcome["stop_reason"], "timeout")
                self.assertEqual(outcome["exit_code"], 124)
                self.assertTrue(outcome["timed_out"])
                self.assertEqual(outcome["input_hosts"], 1)
                self.assertEqual(outcome["duration_seconds"], 0.25)
                self.assertEqual(outcome["lines"], len(output.splitlines()))
                self.assertEqual(Path(self.tool_calls[-1][1]["output_path"]).read_text(), output)
                self.assertEqual(self.tool_calls[-1][1]["timeout"], 1800)

    def test_successful_sources_and_later_roots_do_not_hide_one_failed_source(self):
        self.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET, "other.test"],
            "analysis": {"asset_graph": False}, "limits": {"timeout_seconds": 1800},
        })
        ctx, metrics = self._collect({
            ("subfinder", self.TARGET): (124, True, self._output("subfinder", "partial.example.test")),
        })
        self.assertEqual(metrics["collection_status"], "partial")
        outcomes = metrics["subdomain_tool_outcomes"]
        self.assertEqual([(row["tool"], row["root"]) for row in outcomes], [
            ("subfinder", self.TARGET), ("assetfinder", self.TARGET),
            ("subfinder", "other.test"), ("assetfinder", "other.test"),
        ])
        self.assertEqual([row["stop_reason"] for row in outcomes], ["timeout", "completed", "completed", "completed"])
        self.assertEqual(set((ctx.current / "subdomains.txt").read_text().splitlines()), {
            self.TARGET, "other.test", "partial.example.test", "assetfinder.example.test",
            "subfinder.other.test", "assetfinder.other.test",
        })

    def test_timeout_flag_cannot_be_hidden_by_zero_returncode(self):
        _ctx, metrics = self._collect({("subfinder", self.TARGET): (0, True, "")})
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(metrics["collection_reasons"], ["subfinder_timeout"])

    def test_nonzero_exits_including_one_are_partial(self):
        for tool in self.TOOLS:
            for code in (1, 2, 124):
                with self.subTest(tool=tool, code=code):
                    _ctx, metrics = self._collect({(tool, self.TARGET): (code, False, "")}, available=(tool,))
                    self.assertEqual(metrics["collection_status"], "partial")
                    self.assertEqual(metrics["collection_reasons"], [tool + "_nonzero_exit"])
                    self.assertEqual(metrics["subdomain_tool_outcomes"][0]["exit_code"], code)

    def test_missing_output_cannot_be_reported_completed(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                _ctx, metrics = self._collect({(tool, self.TARGET): (0, False, None)}, available=(tool,))
                self.assertEqual(metrics["collection_status"], "partial")
                self.assertEqual(metrics["collection_reasons"], [tool + "_output_missing"])

    def test_successful_empty_output_is_completed_and_keeps_roots(self):
        ctx, metrics = self._collect({(tool, self.TARGET): (0, False, "") for tool in self.TOOLS})
        self.assertEqual(metrics["collection_status"], "completed")
        self.assertEqual(metrics["collection_reasons"], [])
        self.assertEqual(metrics["discovered"], 1)
        self.assertEqual((ctx.current / "subdomains.txt").read_text(), self.TARGET + "\n")
        self.assertEqual([row["stop_reason"] for row in metrics["subdomain_tool_outcomes"]], ["completed", "completed"])

    def _orchestrator(self, stack, phase):
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
        orchestrator = runtime.Orchestrator(self.paths, Config(self.paths), Logger(self.paths), self.db, progress=False, allow_active=False)
        stack.enter_context(patch.object(orchestrator, "_record_versions"))
        stack.enter_context(patch.object(orchestrator, "install_signal_handlers"))
        stack.enter_context(patch("stages.tool_path", side_effect=lambda tool: tool if tool in self.TOOLS else None))
        downstream = []
        reports = []

        def fake_tool(args, **kwargs):
            output = self._output("subfinder", "partial.example.test")
            if phase[0] == "completed":
                output += self._output("subfinder", "resumed.example.test")
            return self._tool({("subfinder", self.TARGET): (124 if phase[0] == "timeout" else 0, phase[0] == "timeout", output)})(args, **kwargs)

        def offline_stage(ctx):
            stage = ctx.db.one("SELECT current_stage FROM run_targets WHERE run_id=? AND target=?", (ctx.run_id, ctx.policy.name))[0]
            downstream.append((phase[0], stage))
            return {"collection_status": "completed"}

        def offline_report(ctx, _baseline):
            reports.append(_stage_metrics(ctx))
            return {"analysis": {"analysis_id": "offline"}, "finding_notifications": {"status": "success"}}

        stages = {name: offline_stage for name in runtime.STAGE_FUNCTIONS}
        stages["subdomains"] = stage_subdomains
        stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
        stack.enter_context(patch("recon_monitor_core.stage_report", side_effect=offline_report))
        stack.enter_context(patch.object(orchestrator.runner, "run", side_effect=fake_tool))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return orchestrator, downstream, reports

    def test_timeout_is_partial_in_run_report_and_does_not_create_or_replace_baseline(self):
        for with_baseline in (False, True):
            with self.subTest(with_baseline=with_baseline), contextlib.ExitStack() as stack:
                seed_run = None
                if with_baseline:
                    seed_run = self.db.create_run(None, 1, "offline-seed")
                    self.db.create_run_target(seed_run, self.policy, self.paths.output / "seed", True)
                    self.db.upsert_asset(self.TARGET, "previous.example.test", ["offline"], seed_run)
                    self.db.finish_run_target(seed_run, self.TARGET, "success")
                    self.db.finish_run(seed_run, "success")
                orchestrator, downstream, reports = self._orchestrator(stack, ["timeout"])
                code = orchestrator.run(PolicySet({}, [self.policy], self.paths.policy))
                run_id = orchestrator.current_run_id
                self.assertEqual(code, 2)
                self.assertIn(("timeout", "dns"), downstream)
                self.assertIn(("timeout", "javascript"), downstream)
                self.assertEqual(self.db.stage_status(run_id, self.TARGET, "subdomains"), "partial")
                self.assertEqual(self.db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "partial")
                self.assertEqual(self.db.one("SELECT status FROM run_targets WHERE run_id=?", (run_id,))[0], "partial")
                lifecycle = self.db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run_id,))
                self.assertEqual(lifecycle["collection_status"], "partial")
                self.assertFalse(lifecycle["baseline_eligible"])
                persisted = json.loads(self.db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND stage='subdomains'", (run_id,))[0])
                self.assertEqual(reports[0]["subdomains"]["status"], "partial")
                self.assertEqual(reports[0]["subdomains"]["metrics"], persisted)
                self.assertEqual(persisted["subdomain_tool_outcomes"][0]["stop_reason"], "timeout")
                snapshot = self.db.successful_snapshot_status(self.TARGET)
                self.assertEqual(snapshot["exists"], with_baseline)
                if seed_run:
                    self.assertEqual(snapshot["run_id"], seed_run)

    def test_resume_reruns_timed_out_collection_and_its_downstream_stages(self):
        phase = ["timeout"]
        with contextlib.ExitStack() as stack:
            orchestrator, downstream, reports = self._orchestrator(stack, phase)
            policies = PolicySet({}, [self.policy], self.paths.policy)
            self.assertEqual(orchestrator.run(policies), 2)
            run_id = orchestrator.current_run_id
            phase[0] = "completed"
            self.assertEqual(orchestrator.run(policies, resume_id=run_id), 0)
            self.assertEqual(len(self.tool_calls), 4)
            for stage in ("dns", "urls", "javascript", "fingerprint"):
                self.assertIn(("completed", stage), downstream)
            self.assertEqual(self.db.stage_status(run_id, self.TARGET, "subdomains"), "success")
            self.assertEqual(self.db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "success")
            self.assertEqual(reports[0]["subdomains"]["metrics"]["collection_status"], "partial")
            self.assertEqual(reports[1]["subdomains"]["metrics"]["collection_status"], "completed")
            snapshot = self.db.successful_snapshot_status(self.TARGET)
            self.assertTrue(snapshot["exists"])
            self.assertEqual(snapshot["run_id"], run_id)
            self.assertIsNotNone(self.db.one("SELECT host FROM assets WHERE host='resumed.example.test'"))

    def test_resume_of_completed_collection_keeps_successful_collectors_skipped(self):
        phase = ["completed"]
        with contextlib.ExitStack() as stack:
            orchestrator, downstream, reports = self._orchestrator(stack, phase)
            policies = PolicySet({}, [self.policy], self.paths.policy)
            self.assertEqual(orchestrator.run(policies), 0)
            run_id = orchestrator.current_run_id
            phase[0] = "unchanged"
            self.assertEqual(orchestrator.run(policies, resume_id=run_id), 0)
            self.assertEqual(len(self.tool_calls), 2)
            self.assertFalse(any(state == "unchanged" for state, _stage in downstream))
            self.assertEqual(len(reports), 2)

    def test_partial_target_resume_does_not_rerun_other_targets_successful_collectors(self):
        other = TargetPolicy.from_dict({
            "name": "other.test", "roots": ["other.test"],
            "analysis": {"asset_graph": False}, "limits": {"timeout_seconds": 1800},
        })
        phase = ["timeout"]
        with contextlib.ExitStack() as stack:
            orchestrator, _downstream, _reports = self._orchestrator(stack, phase)
            policies = PolicySet({}, [self.policy, other], self.paths.policy)
            self.assertEqual(orchestrator.run(policies), 2)
            run_id = orchestrator.current_run_id
            phase[0] = "completed"
            original = orchestrator._run_stage
            with patch.object(orchestrator, "_run_stage", wraps=original) as stages:
                self.assertEqual(orchestrator.run(policies, resume_id=run_id), 0)
            for call in stages.call_args_list:
                ctx, stage = call.args[:2]
                if stage != "report":
                    self.assertEqual(call.args[-1], ctx.policy.name == other.name)
            self.assertEqual(len(self.tool_calls), 6)
            for target in (self.TARGET, other.name):
                self.assertEqual(self.db.one("SELECT status FROM run_targets WHERE run_id=? AND target=?", (run_id, target))[0], "success")


if __name__ == "__main__":
    unittest.main()

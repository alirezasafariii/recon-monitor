from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, StageError, TargetPolicy
from execution import BudgetExceeded
from katana_reliability import persist_shared_throttle_state
from stages import stage_fingerprint, stage_javascript, stage_nuclei, stage_ports


class CollectionStageContinuationTests(unittest.TestCase):
    """Exercise real orchestration, stage persistence, JS receipts and Analysis."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = AppPaths.from_root(Path(tmp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n'
        )
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "limits": {"retries": 0},
            "modules": {"ports": False, "nuclei": False, "endpoint_validation": False},
            "analysis": {"asset_graph": False},
            "fingerprint": {"collect_tls": False},
        })
        self.paths.policy.write_text(json.dumps({"schema": 1, "targets": [self.policy.raw]}))
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.phase = "failed"
        self.calls = []
        self.downloads = []
        self.recovered = False
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("unexpected external I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def offline_stage(self, name):
        def collect(ctx):
            self.calls.append(name)
            if name == "subdomains":
                ctx.db.upsert_asset(ctx.policy.name, ctx.policy.name, ["root"], ctx.run_id)
                (ctx.current / "subdomains.txt").write_text(ctx.policy.name + "\n")
                if self.phase == "runtime_exhausted":
                    ctx.budget.started_monotonic -= 120
            if name == "dns":
                (ctx.current / "resolved-hosts.txt").write_text(ctx.policy.name + "\n")
            return {"collection_status": "completed"}
        return collect

    def urls(self, ctx):
        self.calls.append("urls")
        if self.phase == "interrupted":
            raise KeyboardInterrupt
        if self.phase == "failed_without_input":
            raise StageError("URL collector failed before output", retryable=False)
        urls = ["https://example.test/app.js"]
        if self.recovered:
            urls.append("https://example.test/second.js")
        (ctx.current / "urls.txt").write_text("\n".join(urls) + "\n")
        (ctx.current / "base-urls.txt").write_text("https://example.test\n")
        for url in urls:
            ctx.db.upsert_url(ctx.policy.name, url, "javascript", "fixture", ctx.run_id)
        metrics = {
            "collection_status": "completed" if self.phase == "healthy" else "partial",
            "collection_reasons": [] if self.phase == "healthy" else ["collector_failed"],
        }
        (ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": ctx.run_id, "target": ctx.policy.name, "metrics": metrics,
        }))
        if self.phase == "budget_exhausted":
            raise BudgetExceeded("http_requests", 11, 10)
        if self.phase == "cooldown":
            persist_shared_throttle_state(ctx.db, {
                "example.test": {"retry_not_before": 10**12},
            }, ctx.run_id)
        if self.phase not in {"healthy", "partial"}:
            raise StageError("URL collector failed after preserving output", retryable=False)
        return metrics

    def download(self, _ctx, url, _limit):
        self.downloads.append(url)
        return {"url": url, "final_url": url, "status_code": 200,
                "transport_status": "ok", "content_type": "application/javascript",
                "data": b'const endpoint = "/api/catalog"; console.log(endpoint);'}

    def exercise(self, resume_id=None, *, real_transport=False, real_active=False):
        orchestrator = runtime.Orchestrator(
            self.paths, self.config, self.logger, self.db, progress=False, allow_active=False,
        )
        functions = {name: self.offline_stage(name) for name in runtime.STAGE_FUNCTIONS}
        functions.update(urls=self.urls, javascript=stage_javascript)
        if real_transport:
            functions["fingerprint"] = stage_fingerprint
        if real_active:
            functions.update(ports=stage_ports, nuclei=stage_nuclei)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, functions))
            for method in ("_record_versions", "install_signal_handlers"):
                stack.enter_context(patch.object(orchestrator, method))
            if not real_transport:
                stack.enter_context(patch("stages._download_url", side_effect=self.download))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = orchestrator.run(
                PolicySet({}, [self.policy], self.paths.policy), resume_id=resume_id,
            )
        return code, orchestrator.current_run_id

    def metrics(self, run_id, stage):
        row = self.db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND stage=?", (run_id, stage))
        return json.loads(row["metrics_json"])

    def assert_analyzed_without_baseline(self, run_id, collection_status):
        row = self.db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run_id,))
        self.assertEqual(row["collection_status"], collection_status)
        self.assertEqual(row["analysis_status"], "success")
        self.assertEqual(row["report_status"], "success")
        self.assertFalse(row["baseline_eligible"])
        self.assertFalse(self.db.target_has_history(self.policy.name))

    def test_failed_url_collector_keeps_real_javascript_and_analysis_running(self):
        code, run_id = self.exercise()
        self.assertEqual(code, 2)
        self.assertEqual(self.downloads, ["https://example.test/app.js"])
        self.assertEqual(self.metrics(run_id, "javascript")["downloaded"], 1)
        self.assertIn("fingerprint", self.calls)
        self.assertEqual(self.db.stage_status(run_id, self.policy.name, "urls"), "failed")
        self.assertEqual(self.db.one(
            "SELECT error FROM stage_runs WHERE run_id=? AND stage='urls'", (run_id,),
        )[0], "URL collector failed after preserving output")
        self.assertEqual(self.db.work_status(run_id, self.policy.name, "javascript-items", self.downloads[0]), "completed")
        self.assert_analyzed_without_baseline(run_id, "failed")

    def test_partial_url_collection_also_processes_its_available_javascript(self):
        self.phase = "partial"
        code, run_id = self.exercise()
        self.assertEqual(code, 2)
        self.assertEqual(len(self.downloads), 1)
        self.assertIn("fingerprint", self.calls)
        self.assert_analyzed_without_baseline(run_id, "partial")

    def test_resume_reuses_finished_js_and_refreshes_downstream_for_new_inputs(self):
        _code, run_id = self.exercise()
        self.assertEqual(self.downloads, ["https://example.test/app.js"])
        self.phase = "healthy"
        self.recovered = True
        self.calls.clear()
        code, resumed_id = self.exercise(run_id)
        self.assertEqual(code, 0)
        self.assertEqual(resumed_id, run_id)
        self.assertEqual(self.downloads, ["https://example.test/app.js", "https://example.test/second.js"])
        self.assertNotIn("subdomains", self.calls)
        self.assertNotIn("dns", self.calls)
        self.assertIn("fingerprint", self.calls)
        self.assertTrue(self.db.successful_snapshot_status(self.policy.name)["usable"])
        self.assertEqual(self.metrics(run_id, "javascript")["reused_work_items"], 1)

    def test_failed_followup_keeps_trusted_snapshot_while_preserving_new_js(self):
        self.phase = "healthy"
        _code, first = self.exercise()
        snapshot = self.db.successful_snapshot_status(self.policy.name)
        self.phase = "failed"
        self.recovered = True
        code, second = self.exercise()
        self.assertEqual(code, 2)
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.successful_snapshot_status(self.policy.name), snapshot)
        self.assertEqual(self.metrics(second, "javascript")["downloaded"], 2)
        self.assertEqual(self.db.one("SELECT baseline_state FROM target_run_lifecycle WHERE run_id=?", (second,))[0], "retained")

    def test_missing_url_output_does_not_invent_javascript_input(self):
        self.phase = "failed_without_input"
        code, run_id = self.exercise(real_transport=True)
        self.assertEqual(code, 2)
        self.assertEqual(self.metrics(run_id, "javascript")["downloaded"], 0)
        self.assertIn("url_input_missing", self.metrics(run_id, "javascript")["collection_reasons"])
        self.assertEqual(self.metrics(run_id, "fingerprint")["probed"], 0)
        self.assert_analyzed_without_baseline(run_id, "failed")

    def test_budget_stop_is_not_retried_and_still_prevents_later_collectors(self):
        self.phase = "budget_exhausted"
        self.policy.limits.retries = 3
        with patch("recon_monitor_core.time.sleep") as sleep:
            code, run_id = self.exercise()
        self.assertEqual(code, 2)
        sleep.assert_not_called()
        metrics = self.metrics(run_id, "urls")
        self.assertEqual(metrics["stop_reason"], "budget_exhausted")
        self.assertEqual(metrics["budget_metric"], "http_requests")
        self.assertEqual(metrics["attempt"], 1)
        self.assertEqual(self.downloads, [])
        self.assertNotIn("fingerprint", self.calls)
        self.assert_analyzed_without_baseline(run_id, "failed")

    def test_expired_runtime_prevents_next_external_stage_but_allows_analysis(self):
        self.phase = "runtime_exhausted"
        self.policy.limits.max_runtime_minutes = 1
        code, run_id = self.exercise()
        self.assertEqual(code, 2)
        self.assertEqual(self.calls, ["subdomains"])
        self.assertEqual(self.metrics(run_id, "dns")["budget_metric"], "runtime_seconds")
        self.assert_analyzed_without_baseline(run_id, "failed")

    def test_interrupt_stops_without_launching_remaining_stages(self):
        self.phase = "interrupted"
        code, run_id = self.exercise()
        self.assertEqual(code, 130)
        self.assertEqual(self.db.stage_status(run_id, self.policy.name, "urls"), "interrupted")
        self.assertIsNone(self.db.stage_status(run_id, self.policy.name, "report"))
        self.assertNotIn("fingerprint", self.calls)
        self.assertEqual(self.downloads, [])

    def test_failure_continuation_obeys_shared_http_cooldown(self):
        self.phase = "cooldown"
        with patch("stages.perform_pinned_download", side_effect=AssertionError("cooling host was requested")):
            code, run_id = self.exercise(real_transport=True)
        self.assertEqual(code, 2)
        self.assertEqual(self.metrics(run_id, "javascript")["downloaded"], 0)
        self.assertEqual(self.metrics(run_id, "fingerprint")["collection_reasons"], ["http_rate_limit_cooldown"])
        self.assert_analyzed_without_baseline(run_id, "failed")

    def test_failure_continuation_keeps_active_authorization_gates(self):
        self.policy.modules.update(ports=True, nuclei=True)
        code, run_id = self.exercise(real_active=True)
        self.assertEqual(code, 2)
        for name in ("ports", "nuclei"):
            self.assertEqual(self.metrics(run_id, name)["skipped"], "active authorization gate not satisfied")
        self.assertEqual(len(self.downloads), 1)


if __name__ == "__main__":
    unittest.main()

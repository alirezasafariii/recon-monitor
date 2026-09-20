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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy
from reporting import _stage_metrics
from stages import stage_urls


class KatanaRunLifecycleTests(unittest.TestCase):
    def test_timeout_survives_real_stage_target_run_and_report_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
                stack.enter_context(patch(name, side_effect=AssertionError("offline test attempted I/O")))
            paths = AppPaths.from_root(Path(tmp))
            paths.ensure()
            paths.config.write_text(
                'I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n',
                encoding="utf-8",
            )
            config = Config(paths)
            db = runtime.Database(paths.db)
            stack.callback(db.close)
            policy = TargetPolicy.from_dict({
                "name": "example.test", "roots": ["example.test"],
                "limits": {"timeout_seconds": 1800, "request_rate": 3},
            })
            orchestrator = runtime.Orchestrator(
                paths, config, Logger(paths), db, progress=False, allow_active=False,
            )
            stack.enter_context(patch.object(orchestrator, "_record_versions"))
            stack.enter_context(patch.object(orchestrator, "install_signal_handlers"))
            stack.enter_context(patch("stages.tool_path", side_effect=lambda name: name == "katana"))
            stack.enter_context(patch("stages._probe_live_origins", return_value=(["https://example.test"], [])))
            calls = []
            captured = {}

            def fake_tool(_args, **kwargs):
                Path(kwargs["output_path"]).write_text("https://example.test/app.js\n")
                return SimpleNamespace(returncode=124, timed_out=True, duration=120.1, lines=1)

            def offline_stage(ctx):
                calls.append(ctx.db.one(
                    "SELECT current_stage FROM run_targets WHERE run_id=? AND target=?",
                    (ctx.run_id, ctx.policy.name),
                )[0])
                return {"collection_status": "completed"}

            def offline_report(ctx, _baseline):
                captured.update(_stage_metrics(ctx))
                return {"analysis": {"analysis_id": "offline"}, "finding_notifications": {"status": "success"}}

            stages = {name: offline_stage for name in runtime.STAGE_FUNCTIONS}
            stages["urls"] = stage_urls
            stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
            stack.enter_context(patch("recon_monitor_core.stage_report", side_effect=offline_report))
            stack.enter_context(patch.object(orchestrator.runner, "run", side_effect=fake_tool))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = orchestrator.run(PolicySet({}, [policy], paths.policy))
            run_id = orchestrator.current_run_id

            self.assertEqual(code, 2)
            self.assertIn("javascript", calls)
            self.assertIn("fingerprint", calls)
            self.assertEqual(db.stage_status(run_id, policy.name, "urls"), "partial")
            self.assertEqual(db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "partial")
            self.assertEqual(db.one("SELECT status FROM run_targets WHERE run_id=?", (run_id,))[0], "partial")
            lifecycle = db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run_id,))
            self.assertEqual(lifecycle["collection_status"], "partial")
            self.assertFalse(lifecycle["baseline_eligible"])
            self.assertFalse(db.successful_snapshot_status(policy.name)["exists"])
            metrics = json.loads(db.one(
                "SELECT metrics_json FROM stage_runs WHERE run_id=? AND stage='urls'", (run_id,),
            )[0])
            self.assertEqual(metrics["katana_exit_code"], 124)
            self.assertEqual(metrics["katana_stop_reason"], "batch_timeout")
            self.assertEqual(captured["urls"]["status"], "partial")
            self.assertEqual(captured["urls"]["metrics"]["katana_batch_outcomes"], metrics["katana_batch_outcomes"])


if __name__ == "__main__":
    unittest.main()

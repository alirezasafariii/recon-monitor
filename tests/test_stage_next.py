from __future__ import annotations

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

from core import AppPaths, Config, Database, Logger, NextStageRequested, TargetPolicy
from dashboard import DashboardHandler
import recon_monitor_core as runtime
from stages import StageContext, _select_javascript_urls, stage_javascript, stage_urls


def policy():
    return TargetPolicy.from_dict({
        "name": "example.test",
        "roots": ["example.test"],
        "include": [r"(^|\.)example\.test$"],
        "limits": {"request_rate": 3, "max_runtime_minutes": 0, "max_http_requests": 0},
        "analysis": {"asset_graph": False},
    })


class StageNextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = AppPaths.from_root(Path(self.tmp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\n', encoding="utf-8")
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = policy()
        self.run_id = self.db.create_run("example.test", 1, "offline-config")
        self.run_dir = self.paths.output / self.policy.name / "runs" / self.run_id
        self.run_dir.mkdir(parents=True)
        self.db.create_run_target(self.run_id, self.policy, self.run_dir, True)

    def test_request_is_scoped_to_running_stage_and_cleared_on_new_attempt(self):
        self.db.stage_begin(self.run_id, self.policy.name, "urls", 1)
        self.assertFalse(self.db.request_stage_next(self.run_id, self.policy.name, "dns", 1, "analyst"))
        self.assertFalse(self.db.request_stage_next(self.run_id, "wrong.test", "urls", 1, "analyst"))
        self.assertFalse(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 2, "analyst"))
        self.assertFalse(self.db.request_stage_next(self.run_id, self.policy.name, "report", 1, "analyst"))
        self.assertTrue(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 1, "analyst"))
        self.assertTrue(self.db.stage_next_requested(self.run_id, self.policy.name, "urls", 1))
        self.db.stage_finish(self.run_id, self.policy.name, "urls", "partial")
        self.assertFalse(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 1, "analyst"))
        self.db.stage_begin(self.run_id, self.policy.name, "urls", 2)
        self.assertFalse(self.db.stage_next_requested(self.run_id, self.policy.name, "urls", 2))
        self.assertTrue(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 2, "analyst"))
        self.db.finish_run(self.run_id, "partial")
        self.assertFalse(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 2, "analyst"))

    def test_katana_next_preserves_output_and_resume_only_retries_pending(self):
        current = self.run_dir / "current"
        current.mkdir()
        (current / "resolved-hosts.txt").write_text("example.test\n", encoding="utf-8")
        db = MagicMock()
        db.upsert_url.return_value = False
        flag = {"next": False}
        origins = [f"https://{i}.example.test" for i in range(7)]
        first_pass = []

        def first_run(args, **kwargs):
            batch = Path(args[args.index("-list") + 1]).read_text(encoding="utf-8").splitlines()
            first_pass.append(batch)
            Path(kwargs["output_path"]).write_text(
                "".join(f"{origin}/app.js\n" for origin in batch),
                encoding="utf-8",
            )
            cancelled = len(first_pass) == 2
            if cancelled:
                flag["next"] = True
            return SimpleNamespace(
                returncode=125 if cancelled else 0,
                operator_next=cancelled,
                timed_out=False, lines=len(batch), duration=0.1,
            )

        ctx = SimpleNamespace(
            current=current, changes=self.run_dir / "changes",
            policy=self.policy, db=db, runner=SimpleNamespace(run=first_run),
            budget=None, run_id=self.run_id, logger=MagicMock(), progress=MagicMock(),
            next_requested=lambda: flag["next"],
        )
        ctx.changes.mkdir()
        with patch("stages.tool_path", side_effect=lambda name: name == "katana"), patch(
            "stages._probe_live_origins", return_value=(origins, []),
        ):
            first = stage_urls(ctx)
        self.assertEqual(first["katana_status"], "operator_next")
        self.assertEqual(first["collection_status"], "partial")
        self.assertEqual(first["katana_origins_completed"], 5)
        self.assertEqual(first["katana_pending_origins"], 2)
        self.assertEqual(len(first_pass), 2)
        prior = (current / "katana-urls.txt").read_text(encoding="utf-8")

        flag["next"] = False
        resumed = []

        def resume_run(args, **kwargs):
            batch = Path(args[args.index("-list") + 1]).read_text(encoding="utf-8").splitlines()
            resumed.extend(batch)
            Path(kwargs["output_path"]).write_text(
                "".join(f"{origin}/resumed.js\n" for origin in batch),
                encoding="utf-8",
            )
            return SimpleNamespace(returncode=0, operator_next=False, timed_out=False, lines=len(batch), duration=0.1)

        ctx.runner = SimpleNamespace(run=resume_run)
        with patch("stages.tool_path", side_effect=lambda name: name == "katana"), patch(
            "stages._probe_live_origins", return_value=(origins, []),
        ):
            second = stage_urls(ctx)
        self.assertEqual(resumed, origins[5:])
        self.assertEqual(second["katana_origins_completed"], 7)
        self.assertEqual(second["katana_pending_origins"], 0)
        self.assertEqual(second["collection_status"], "completed")
        self.assertEqual(len(second["katana_batch_outcomes"]), 3)
        combined = (current / "katana-urls.txt").read_text(encoding="utf-8")
        self.assertIn(prior, combined)
        self.assertIn("https://6.example.test/resumed.js", combined)

    def test_resume_keeps_pending_origins_when_they_are_temporarily_offline(self):
        current = self.run_dir / "current"
        current.mkdir()
        (current / "resolved-hosts.txt").write_text("example.test\n", encoding="utf-8")
        old = [f"https://{i}.example.test" for i in range(4)]
        (current / "url-collection.json").write_text(json.dumps({
            "run_id": self.run_id,
            "metrics": {"collection_status": "partial"},
        }), encoding="utf-8")
        (current / "katana-pending-origins.txt").write_text(
            "\n".join(old[2:]) + "\n", encoding="utf-8",
        )
        (current / "katana-completed-origins.txt").write_text(
            "\n".join(old[:2]) + "\n", encoding="utf-8",
        )
        (current / "katana-urls.txt").write_text(
            old[0] + "/found.js\n", encoding="utf-8",
        )
        ctx = SimpleNamespace(
            current=current, changes=self.run_dir / "changes", policy=self.policy,
            db=MagicMock(), runner=SimpleNamespace(run=MagicMock()),
            budget=None, run_id=self.run_id, logger=MagicMock(), progress=MagicMock(),
        )
        ctx.changes.mkdir()
        with patch("stages.tool_path", side_effect=lambda name: name == "katana"), patch(
            "stages._probe_live_origins", return_value=(old[:2], []),
        ):
            metrics = stage_urls(ctx)
        self.assertEqual(metrics["katana_status"], "no_live_pending")
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(metrics["katana_pending_origins"], 2)
        self.assertEqual(
            (current / "katana-pending-origins.txt").read_text().splitlines(),
            old[2:],
        )
        self.assertIn(old[0] + "/found.js", (current / "katana-urls.txt").read_text())
        ctx.runner.run.assert_not_called()

    def test_javascript_host_balanced_selection_is_deterministic_and_lossless(self):
        candidates = [
            "https://a.example.test/z.js",
            "https://a.example.test/y.js",
            "https://a.example.test/x.js",
            "https://b.example.test/a.js",
            "https://c.example.test/a.js",
        ]
        selected, unselected = _select_javascript_urls(candidates, 3)
        self.assertEqual(selected, [
            "https://a.example.test/x.js",
            "https://b.example.test/a.js",
            "https://c.example.test/a.js",
        ])
        self.assertEqual(unselected, [
            "https://a.example.test/y.js",
            "https://a.example.test/z.js",
        ])
        self.assertEqual(
            _select_javascript_urls(list(reversed(candidates)) + candidates, 3),
            (selected, unselected),
        )
        self.assertEqual(
            _select_javascript_urls(candidates, 10),
            ([
                "https://a.example.test/x.js",
                "https://b.example.test/a.js",
                "https://c.example.test/a.js",
                "https://a.example.test/y.js",
                "https://a.example.test/z.js",
            ], []),
        )
        self.assertEqual(_select_javascript_urls(candidates, 0), ([], sorted(candidates)))

    def test_javascript_stage_persists_unselected_urls_without_extra_requests(self):
        self.policy.limits.max_js_files = 2
        current = self.run_dir / "current"
        current.mkdir()
        candidates = [
            "https://a.example.test/1.js",
            "https://a.example.test/2.js",
            "https://a.example.test/3.js",
            "https://b.example.test/1.js",
        ]
        (current / "urls.txt").write_text(
            "\n".join(candidates) + "\n", encoding="utf-8",
        )
        ctx = StageContext(
            self.paths, Config(self.paths), self.policy, self.db,
            Logger(self.paths), MagicMock(), MagicMock(), self.run_id,
            self.run_dir, False,
        )
        with patch("stages._download_url", side_effect=lambda _ctx, url, _max_bytes: {
            "url": url, "status_code": 404, "not_found": True,
        }) as download:
            metrics = stage_javascript(ctx)

        self.assertEqual(download.call_count, 2)
        self.assertEqual(metrics["selected_input_count"], 2)
        self.assertEqual(metrics["javascript_dropped_by_file_limit"], 2)
        self.assertEqual(metrics["javascript_selected_hosts"], 2)
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(
            (current / "javascript-urls.txt").read_text().splitlines(),
            ["https://a.example.test/1.js", "https://b.example.test/1.js"],
        )
        self.assertEqual(
            (current / "javascript-unselected-urls.txt").read_text().splitlines(),
            ["https://a.example.test/2.js", "https://a.example.test/3.js"],
        )

    def test_cooperative_collectors_avoid_new_network_requests_after_next(self):
        from stages import _download_url, _safe_validate_endpoint
        ctx = SimpleNamespace(policy=self.policy, next_requested=lambda: True)
        with patch("stages.perform_pinned_download", side_effect=AssertionError("new download after Next")), patch(
            "stages.perform_pinned_request", side_effect=AssertionError("new request after Next"),
        ):
            self.assertTrue(_download_url(ctx, "https://example.test/x.js", 4096)["operator_next"])
            self.assertEqual(
                _safe_validate_endpoint(ctx, "https://example.test/api")["skipped"],
                "operator_next",
            )

    def test_real_subprocess_next_drains_stdout_without_a_wall_clock_deadline(self):
        from core import CommandRunner
        runner = CommandRunner(Logger(self.paths))
        runner.next_raise = False
        ticks = {"count": 0}

        def requested():
            ticks["count"] += 1
            return ticks["count"] >= 2

        runner.next_check = requested
        output = self.run_dir / "current" / "sleeping-tool.txt"
        result = runner.run(
            [sys.executable, "-u", "-c", "import time; print('ready', flush=True); time.sleep(30)"],
            timeout=None, output_path=output,
        )
        self.assertTrue(result.operator_next)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 125)
        self.assertIn("ready", output.read_text(encoding="utf-8"))

    def test_non_katana_next_is_partial_not_failed_and_next_stage_runs(self):
        orchestrator = runtime.Orchestrator(
            self.paths, Config(self.paths), Logger(self.paths), self.db,
            progress=False, allow_active=False,
        )
        self.db.stage_begin(self.run_id, self.policy.name, "subdomains", 1)
        ctx = StageContext(
            self.paths, Config(self.paths), self.policy, self.db, Logger(self.paths),
            orchestrator.runner, orchestrator.progress, self.run_id, self.run_dir, False,
        )
        def interrupted_stage(context):
            (context.current / "subfinder-raw.txt").write_text("observed.example.test\n", encoding="utf-8")
            self.assertTrue(self.db.request_stage_next(
                self.run_id, self.policy.name, "subdomains", 1, "analyst",
            ))
            raise NextStageRequested("operator_next")

        with patch.dict(runtime.STAGE_FUNCTIONS, {
            "subdomains": interrupted_stage,
            "dns": lambda _context: {"collection_status": "completed"},
        }):
            result, metrics = orchestrator._run_stage(
                ctx, "subdomains", "Subdomains", 1, 2, 1, 1, True, False,
            )
            self.assertEqual(result, "success")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertTrue(metrics["pending_stage_resume"])
            self.assertEqual(self.db.stage_status(self.run_id, self.policy.name, "subdomains"), "partial")
            self.assertTrue((ctx.current / "subfinder-raw.txt").exists())
            result2, metrics2 = orchestrator._run_stage(
                ctx, "dns", "DNS", 2, 2, 1, 1, True, False,
            )
        self.assertEqual(result2, "success")
        self.assertEqual(metrics2["collection_status"], "completed")
        self.assertEqual(self.db.stage_status(self.run_id, self.policy.name, "dns"), "success")

    def test_run_review_shows_next_only_for_current_running_stage(self):
        self.db.stage_begin(self.run_id, self.policy.name, "urls", 1)
        handler = object.__new__(DashboardHandler)
        handler.query = lambda: {"id": [self.run_id]}
        handler.db = lambda: Database(self.paths.db)
        rendered = {}
        handler.send_html = lambda title, body, status=200: rendered.update(title=title, body=body, status=status)
        handler.run_review()
        self.assertIn("action='/run/next-stage'", rendered["body"])
        self.assertIn("name='attempt' value='1'", rendered["body"])
        self.assertIn("name='target' value='example.test'", rendered["body"])
        self.assertNotIn("name='stage' value='report'", rendered["body"])
        self.assertTrue(self.db.request_stage_next(self.run_id, self.policy.name, "urls", 1, "analyst"))
        handler.run_review()
        self.assertIn("Next requested", rendered["body"])
        self.assertNotIn("action='/run/next-stage'", rendered["body"])
        self.db.stage_finish(self.run_id, self.policy.name, "urls", "partial")
        handler.run_review()
        self.assertNotIn("action='/run/next-stage'", rendered["body"])


if __name__ == "__main__":
    unittest.main()

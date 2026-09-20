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

from core import TargetPolicy
from execution import BudgetExceeded
from stages import _katana_crawl_plan, stage_javascript, stage_urls


class KatanaExecutionQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        # These regressions must never start a tool, resolve DNS, or connect.
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def _context(self, root: Path, runner) -> SimpleNamespace:
        current = root / "current"
        changes = root / "changes"
        current.mkdir(parents=True, exist_ok=True)
        changes.mkdir(parents=True, exist_ok=True)
        (current / "resolved-hosts.txt").write_text("example.test\n", encoding="utf-8")
        policy = TargetPolicy.from_dict({
            "name": "example.test",
            "roots": ["example.test"],
            "include": [r"(^|\.)example\.test$"],
            "analysis": {"asset_graph": False},
            "limits": {"timeout_seconds": 1800, "request_rate": 3},
        })
        db = MagicMock()
        db.upsert_url.return_value = False
        return SimpleNamespace(
            current=current, changes=changes, policy=policy,
            db=db, runner=runner, budget=None,
            run_id="offline-test", logger=MagicMock(),
            progress=MagicMock(),
        )

    def test_timeout_preserves_crawl_output_and_marks_stage_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(_args, **kwargs):
                Path(kwargs["output_path"]).write_text(
                    "https://example.test/app.js\n", encoding="utf-8",
                )
                return SimpleNamespace(
                    returncode=124, timed_out=True, duration=120.1, lines=1,
                )

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins",
                return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)

            self.assertEqual(metrics["katana_status"], "timeout")
            self.assertTrue(metrics["katana_timed_out"])
            self.assertEqual(metrics["katana_exit_code"], 124)
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["katana_batches_attempted"], 1)
            self.assertEqual(metrics["katana_input_origins"], 1)
            self.assertEqual(metrics["katana_observed"], 1)
            self.assertEqual(metrics["katana_duration_seconds"], 120.1)
            self.assertEqual(metrics["katana_stop_reason"], "batch_timeout")
            outcome = metrics["katana_batch_outcomes"][0]
            self.assertEqual(outcome["origin_urls"], ["https://example.test"])
            self.assertEqual(outcome["stop_reason"], "timeout")
            self.assertTrue(outcome["started_at"])
            self.assertTrue(outcome["finished_at"])
            self.assertEqual(outcome["exit_code"], 124)
            self.assertEqual(outcome["lines"], 1)
            self.assertEqual(json.loads((ctx.current / "katana-batches.jsonl").read_text()), outcome)
            self.assertIn("https://example.test/app.js", (
                ctx.current / "katana-urls.txt"
            ).read_text(encoding="utf-8"))
            self.assertIn("https://example.test/app.js", (
                ctx.current / "urls.txt"
            ).read_text(encoding="utf-8"))

    def test_katana_is_batched_and_scoped_to_each_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            batches = []

            def fake_run(args, **kwargs):
                sources = Path(args[args.index("-list") + 1]).read_text(
                    encoding="utf-8",
                ).splitlines()
                batches.append((sources, args[args.index("-cs") + 1]))
                Path(kwargs["output_path"]).write_text("", encoding="utf-8")
                return SimpleNamespace(
                    returncode=0, timed_out=False, duration=0.01, lines=0,
                )

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            live = [f"https://{i}.example.test" for i in range(6)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ):
                metrics = stage_urls(ctx)

            self.assertEqual([len(x[0]) for x in batches], [5, 1])
            self.assertEqual(metrics["katana_batches_completed"], 2)
            self.assertEqual(metrics["katana_origins_attempted"], 6)
            self.assertEqual(metrics["katana_status"], "completed")
            self.assertEqual(metrics["katana_exit_code"], 0)
            self.assertEqual(metrics["katana_stop_reason"], "completed")
            self.assertNotIn("5.example.test", batches[0][1])
            self.assertIn("5\\.example\\.test", batches[1][1])

    def test_timed_out_batch_does_not_hide_later_origins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            seen = []

            def fake_run(args, **kwargs):
                origins = Path(args[args.index("-list") + 1]).read_text(
                    encoding="utf-8",
                ).splitlines()
                seen.append(origins)
                Path(kwargs["output_path"]).write_text(
                    "https://0.example.test/app.js\n" if len(seen) == 1 else
                    "https://5.example.test/next.js\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(
                    returncode=124 if len(seen) == 1 else 0,
                    timed_out=len(seen) == 1,
                    duration=120.1 if len(seen) == 1 else 0.01,
                    lines=1,
                )

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            live = [f"https://{i}.example.test" for i in range(6)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ):
                metrics = stage_urls(ctx)

            self.assertEqual([len(origins) for origins in seen], [5, 1])
            self.assertEqual(metrics["katana_origins_attempted"], 6)
            self.assertEqual(metrics["katana_origins_completed"], 1)
            self.assertEqual(metrics["katana_pending_origins"], 5)
            self.assertEqual(metrics["katana_batches_incomplete"], 1)
            self.assertEqual(metrics["katana_status"], "timeout")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(
                (ctx.current / "katana-pending-origins.txt").read_text(
                    encoding="utf-8",
                ).splitlines(), live[:5],
            )
            combined = (ctx.current / "katana-urls.txt").read_text(
                encoding="utf-8",
            )
            self.assertIn("https://0.example.test/app.js", combined)
            self.assertIn("https://5.example.test/next.js", combined)

    def test_nonzero_exit_preserves_evidence_and_marks_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(_args, **kwargs):
                Path(kwargs["output_path"]).write_text("https://example.test/app.js\n")
                return SimpleNamespace(returncode=1, timed_out=False, duration=0.5, lines=1)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_exit_code"], 1)
            self.assertEqual(metrics["katana_status"], "nonzero_exit")
            self.assertEqual(metrics["katana_stop_reason"], "nonzero_exit")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["katana_pending_origins"], 1)
            self.assertIn("https://example.test/app.js", (ctx.current / "urls.txt").read_text())

    def test_missing_katana_is_incomplete_and_keeps_origins_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), SimpleNamespace())
            with patch("stages.tool_path", return_value=None), patch(
                "stages._probe_live_origins", return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_status"], "tool_missing")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertIsNone(metrics["katana_exit_code"])
            self.assertEqual(metrics["katana_pending_origins"], 1)
            self.assertEqual(metrics["katana_batch_outcomes"], [])
            self.assertEqual((ctx.current / "katana-pending-origins.txt").read_text(), "https://example.test\n")

    def test_batches_reserve_only_their_bounded_share(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            seen = []

            def fake_run(args, **kwargs):
                origins = Path(args[args.index("-list") + 1]).read_text().splitlines()
                crawl_seconds = int(args[args.index("-ct") + 1][:-1])
                self.assertLessEqual(crawl_seconds * len(origins), kwargs["timeout"])
                self.assertLessEqual(kwargs["timeout"], 120)
                seen.append(origins)
                if len(seen) == 2:
                    previous = [json.loads(line) for line in (ctx.current / "katana-batches.jsonl").read_text().splitlines()]
                    self.assertEqual(previous[0]["origin_urls"], seen[0])
                Path(kwargs["output_path"]).write_text("")
                return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=0)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            ctx.budget = MagicMock()
            ctx.budget.snapshot.return_value = {"http_requests": {"used": 0, "limit": 10000}}
            live = [f"https://{i}.example.test" for i in range(6)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ):
                metrics = stage_urls(ctx)
            reserved = sum(call.args[1] for call in ctx.budget.consume.call_args_list)
            self.assertEqual(reserved, metrics["katana_reserved_requests"])
            self.assertEqual(reserved, sum(row["reserved_requests"] for row in metrics["katana_batch_outcomes"]))
            self.assertLess(reserved, metrics["katana_request_envelope"])
            self.assertEqual(ctx.policy.limits.timeout_seconds, 1800)

    def test_global_deadline_is_distinct_from_process_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clock = [0.0]

            def fake_run(_args, **kwargs):
                Path(kwargs["output_path"]).write_text("")
                clock[0] = 1801.0
                return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=0)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            live = [f"https://{i}.example.test" for i in range(6)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ), patch("stages.time.monotonic", side_effect=lambda: clock[0]):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_batches_attempted"], 1)
            self.assertEqual(metrics["katana_pending_origins"], 1)
            self.assertEqual(metrics["katana_status"], "partial")
            self.assertEqual(metrics["katana_stop_reason"], "global_deadline")
            self.assertFalse(metrics["katana_timed_out"])
            self.assertEqual(metrics["katana_exit_code"], 0)

    def test_one_request_budget_still_launches_one_bounded_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(_args, **kwargs):
                self.assertGreater(kwargs["timeout"], 0)
                self.assertLessEqual(kwargs["timeout"], 1)
                Path(kwargs["output_path"]).write_text("")
                return SimpleNamespace(returncode=124, timed_out=True, duration=1.1, lines=0)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            ctx.budget = MagicMock()
            ctx.budget.snapshot.return_value = {"http_requests": {"used": 99, "limit": 100}}
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_batches_attempted"], 1)
            self.assertEqual(metrics["katana_reserved_requests"], 1)
            ctx.budget.consume.assert_called_once_with("http_requests", 1)

    def test_budget_exhaustion_after_success_keeps_only_unfinished_origins_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(_args, **kwargs):
                Path(kwargs["output_path"]).write_text("https://0.example.test/app.js\n")
                return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=1)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            ctx.budget = MagicMock()
            ctx.budget.snapshot.return_value = {"http_requests": {"used": 0, "limit": 10000}}
            ctx.budget.consume.side_effect = [None, BudgetExceeded("http_requests", 10000, 10000)]
            live = [f"https://{i}.example.test" for i in range(6)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_batches_attempted"], 1)
            self.assertEqual(metrics["katana_origins_completed"], 5)
            self.assertEqual(metrics["katana_pending_origins"], 1)
            self.assertEqual(metrics["katana_status"], "budget_exhausted")
            self.assertEqual(metrics["katana_stop_reason"], "request_budget")
            self.assertEqual((ctx.current / "katana-pending-origins.txt").read_text().splitlines(), live[5:])

    def test_exhausted_budget_does_not_reuse_stale_tool_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), SimpleNamespace())
            ctx.budget = MagicMock()
            ctx.budget.snapshot.return_value = {"http_requests": {"used": 100, "limit": 100}}
            (ctx.current / "katana-urls.txt").write_text("https://example.test/stale.js\n")
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_batches_attempted"], 0)
            self.assertEqual(metrics["katana_status"], "budget_exhausted")
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertEqual(metrics["katana_pending_origins"], 1)
            self.assertNotIn("stale.js", (ctx.current / "urls.txt").read_text())
            ctx.budget.consume.assert_not_called()

    def test_many_batches_stay_within_the_shared_request_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(_args, **kwargs):
                Path(kwargs["output_path"]).write_text("")
                return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=0)

            ctx = self._context(Path(tmp), SimpleNamespace(run=fake_run))
            ctx.budget = MagicMock()
            ctx.budget.snapshot.return_value = {"http_requests": {"used": 5000, "limit": 10000}}
            live = [f"https://{i}.example.test" for i in range(100)]
            with patch("stages.tool_path", side_effect=lambda tool: tool == "katana"), patch(
                "stages._probe_live_origins", return_value=(live, []),
            ):
                metrics = stage_urls(ctx)
            self.assertEqual(metrics["katana_origins_completed"], 100)
            self.assertEqual(metrics["katana_batches_completed"], 20)
            self.assertLessEqual(metrics["katana_reserved_requests"], 5000)
            self.assertEqual(metrics["katana_reserved_requests"], sum(
                call.args[1] for call in ctx.budget.consume.call_args_list
            ))
            self.assertTrue(all(row["rate_limit"] <= 3 for row in metrics["katana_batch_outcomes"]))

    def test_crawl_plan_uses_configured_envelope_not_fixed_30_seconds(self) -> None:
        plan = _katana_crawl_plan(
            [f"https://{i}.example.test" for i in range(100)],
            remaining_requests=5000,
            request_rate=3,
            timeout_seconds=1800,
            http_threads=8,
            max_urls=10000,
        )
        self.assertEqual(len(plan["origins"]), 100)
        self.assertEqual(plan["reservation"], 5000)
        self.assertGreater(plan["crawl_seconds"], 1)
        self.assertLessEqual(plan["wall_seconds"] * plan["rate_limit"], plan["reservation"])
        self.assertLessEqual(
            plan["crawl_seconds"] * plan["rate_limit"] * len(plan["origins"]),
            plan["reservation"],
        )

    def test_crawl_plan_keeps_unaffordable_origins_outside_batch(self) -> None:
        plan = _katana_crawl_plan(
            [f"https://{i}.example.test" for i in range(8)],
            remaining_requests=3,
            request_rate=3,
            timeout_seconds=1800,
            http_threads=8,
            max_urls=10000,
        )
        self.assertEqual(len(plan["origins"]), 3)
        self.assertEqual(plan["reservation"], 3)
        self.assertEqual(plan["wall_seconds"], 3)

    def test_no_js_input_is_recorded_as_no_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._context(Path(tmp), SimpleNamespace())
            (ctx.current / "urls.txt").write_text(
                "https://example.test/\n", encoding="utf-8",
            )
            with patch(
                "stages._prepare_javascript_derived_differentials",
                return_value=([], {"prepared_sets": 0, "initialized_sets": 0}),
            ):
                metrics = stage_javascript(ctx)
            self.assertEqual(metrics["collection_status"], "no_input")
            self.assertEqual(metrics["input_url_count"], 0)
            self.assertEqual(metrics["downloaded"], 0)


if __name__ == "__main__":
    unittest.main()

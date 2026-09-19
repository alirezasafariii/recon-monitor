from __future__ import annotations

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
from stages import stage_javascript, stage_urls


class KatanaExecutionQualityTests(unittest.TestCase):
    def _context(self, root: Path, runner) -> SimpleNamespace:
        current = root / "current"
        changes = root / "changes"
        current.mkdir(parents=True, exist_ok=True)
        changes.mkdir(parents=True, exist_ok=True)
        (current / "resolved-hosts.txt").write_text("example.test\n", encoding="utf-8")
        policy = TargetPolicy.from_dict({
            "name": "example.test",
            "roots": ["example.test"],
            "include": [r"(^|\\.)example\\.test$"],
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
            self.assertNotIn("5.example.test", batches[0][1])
            self.assertIn("5\\.example\\.test", batches[1][1])

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

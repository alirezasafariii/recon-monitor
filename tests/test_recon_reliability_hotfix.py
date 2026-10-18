from __future__ import annotations

"""Offline regression tests for the scan-completeness reliability hotfix.

No live scan or external binary is launched by this suite.
"""

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

from core import Database, TargetPolicy
from execution import BudgetExceeded
from stages import _katana_crawl_plan, stage_dns, stage_urls


class ReconReliabilityHotfixTests(unittest.TestCase):
    def test_rejected_budget_is_not_written_to_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "test.db")
            try:
                db.budget_init("run", "example.test", {"http_requests": 3})
                self.assertEqual(db.budget_consume("run", "example.test", "http_requests", 2), (2, 3, True))
                self.assertEqual(db.budget_consume("run", "example.test", "http_requests", 2), (4, 3, False))
                self.assertEqual(db.budget_consume("run", "example.test", "http_requests", 1), (3, 3, True))
                self.assertEqual(
                    db.one("SELECT used FROM run_budgets WHERE run_id='run' AND target='example.test' AND metric='http_requests'")["used"], 3
                )
                self.assertEqual(db.budget_consume("run", "example.test", "http_requests", 1), (4, 3, False))
                self.assertEqual(
                    db.one("SELECT used FROM run_budgets WHERE run_id='run' AND target='example.test' AND metric='http_requests'")["used"], 3
                )
                db.budget_init("run", "example.test", {"new_assets": 0})
                self.assertEqual(db.budget_consume("run", "example.test", "new_assets", 500), (500, 0, True))
            finally:
                db.close()

    def test_large_checkpointed_frontier_gets_time_without_more_requests(self):
        plan = _katana_crawl_plan(
            [f"https://{i}.example.test" for i in range(99)],
            remaining_requests=5400,
            request_rate=3,
            timeout_seconds=1800,
            http_threads=5,
            max_urls=10000,
        )
        self.assertEqual(len(plan["origins"]), 99)
        self.assertEqual(plan["reservation"], 5400)
        self.assertGreaterEqual(plan["crawl_seconds"], 30)
        self.assertLessEqual(plan["rate_limit"], 3)
        self.assertLessEqual(plan["crawl_seconds"] * plan["rate_limit"] * len(plan["origins"]), 5400)
        self.assertLessEqual(plan["wall_seconds"] * plan["rate_limit"], 5400)

    def _ctx(self, root, *, max_urls=10):
        current, changes = root / "current", root / "changes"
        current.mkdir()
        changes.mkdir()
        policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "include": [r"(^|\.)example\.test$"],
            "analysis": {"asset_graph": False},
            "limits": {"max_urls": max_urls, "timeout_seconds": 1800},
        })
        db = MagicMock()
        db.all.return_value = []
        db.upsert_url.return_value = False
        return SimpleNamespace(
            current=current, changes=changes, policy=policy, run_id="offline",
            db=db, runner=MagicMock(), budget=None,
            progress=MagicMock(), logger=MagicMock(),
        )

    def test_url_cap_is_partial_and_preserves_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(Path(tmp), max_urls=100)
            (ctx.current / "resolved-hosts.txt").write_text("example.test\n")
            def run_wayback(args, **kwargs):
                self.assertEqual(args[0], "waybackurls")
                kwargs["output_path"].write_text(
                    "".join(f"https://example.test/path/{i}\n" for i in range(105))
                )
                return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=105)
            ctx.runner.run.side_effect = run_wayback
            with patch("stages.tool_path", side_effect=lambda x: x == "waybackurls"), patch(
                "stages._probe_live_origins", return_value=(["https://example.test"], []),
            ):
                metrics = stage_urls(ctx)
            self.assertTrue(metrics["truncated"])
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertIn("url_selection_truncated", metrics["collection_reasons"])
            self.assertEqual(len((ctx.current / "urls.txt").read_text().splitlines()), 100)

    def test_dns_budget_admits_subset_instead_of_failing_entire_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(Path(tmp))
            (ctx.current / "subdomains.txt").write_text(
                "one.example.test\ntwo.example.test\n"
            )
            ctx.budget = MagicMock()
            ctx.budget.consume.side_effect = [
                BudgetExceeded("dns_queries", 8, 4),
                (4, 4),
            ]
            ctx.budget.snapshot.return_value = {
                "dns_queries": {"used": 0, "limit": 4},
            }
            with patch("stages.tool_path", return_value=False), patch(
                "stages.query_host_records_fallback",
                return_value={"A": [], "AAAA": []},
            ):
                metrics = stage_dns(ctx)
            self.assertEqual(metrics["dns_budget_admitted_hosts"], 1)
            self.assertEqual(metrics["dns_budget_pending_hosts"], 1)
            self.assertEqual(metrics["collection_status"], "partial")
            self.assertIn("dns_budget_uncovered_hosts", metrics["collection_reasons"])
            self.assertEqual(len((ctx.current / "dns-budget-pending-hosts.txt").read_text().splitlines()), 1)
            self.assertEqual(ctx.budget.consume.call_count, 2)


if __name__ == "__main__":
    unittest.main()

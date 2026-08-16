from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from family_analyzers.base import FamilyAnalyzerContext
import family_analyzers.router as family_router


class _BudgetDb:
    def __init__(self):
        self.audit_events: list[tuple[str, dict]] = []

    def all(self, _sql, _params=()):
        return []

    def audit(self, action, **fields):
        self.audit_events.append((str(action), dict(fields)))


class RawRoutingHardeningV961Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-HARDEN',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-HARDEN','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-HARDEN")),
        )
        return temp, paths, db, now

    def test_scary_raw_names_create_hypotheses_but_not_potential_findings(self):
        temp, paths, db, now = self.project()
        try:
            hard_negatives = [
                ("https://example.test/admin", "administration"),
                ("https://example.test/debug", "development"),
                ("https://example.test/backup.sql", "export"),
                ("https://example.test/oauth/callback?code=opaque", "authentication"),
                ("https://example.test/search?query=hello", "search"),
                ("https://example.test/reports/export.csv", "export"),
                ("https://example.test/token/jwt", "authentication"),
                ("https://example.test/graphql", "api"),
                ("https://example.test/upload", "upload"),
                ("https://example.test/proxy", "api"),
                ("https://example.test/xml", "api"),
                ("https://example.test/api/v1/internal", "api"),
                ("https://example.test/storage/s3/report", "storage"),
                ("https://example.test/redirect?return=/home", "navigation"),
                ("https://example.test/template/preview", "content"),
                ("https://example.test/settings/profile", "account"),
            ]
            for index, (endpoint, category) in enumerate(hard_negatives):
                db.execute(
                    "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "example.test",
                        endpoint,
                        "absolute_url",
                        category,
                        82,
                        json_dumps([{"category": category, "confidence": 82}]),
                        json_dumps(["Route name only; no unsafe behavior observed"]),
                        json_dumps([f"hard-negative-{index}"]),
                        now,
                        now,
                        "RUN-HARDEN",
                    ),
                )

            result = run_analysis(paths, db, "RUN-HARDEN", "example.test")
            routing = result["bug_candidates"]["raw_surface_routing"]
            budget = routing["analyzer_budget"]

            self.assertEqual(result["alerts"], 0)
            self.assertEqual(result["analysis_inputs"], "raw_only")
            self.assertGreater(routing["hypotheses"], 0)
            self.assertEqual(routing["promoted"], 0)
            self.assertGreater(budget["attempted"], 0)
            self.assertGreater(budget["executed"], 0)
            self.assertEqual(budget["skipped"], 0)
            self.assertFalse(budget["exhausted"])
            self.assertGreaterEqual(budget["limit"], 100_000)
            self.assertEqual(
                db.one(
                    "SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=?",
                    (result["analysis_id"],),
                )["count"],
                0,
            )
            self.assertEqual(
                db.one(
                    "SELECT COUNT(*) count FROM analysis_hypotheses "
                    "WHERE analysis_id=? AND source_ref LIKE 'raw-%' AND state='promoted'",
                    (result["analysis_id"],),
                )["count"],
                0,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_raw_analyzer_budget_is_bounded_audited_and_raw_only(self):
        original_limit = family_router.RAW_ANALYZER_INVOCATION_LIMIT
        analysis_id = "analysis-raw-budget-regression"
        db = _BudgetDb()
        try:
            family_router.clear_raw_analysis_budget(analysis_id)
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = 5
            analyzer = family_router.analyzer_for_family("security_headers")
            self.assertIsNotNone(analyzer)

            normal = FamilyAnalyzerContext(
                db=db,
                analysis_id=analysis_id,
                target="example.test",
                endpoint="https://example.test/normal",
                method="GET",
                details={},
            )
            for _ in range(3):
                analyzer.analyze(normal)
            untouched = family_router.raw_analysis_budget_snapshot(analysis_id)
            self.assertEqual(untouched["attempted"], 0)
            self.assertEqual(untouched["executed"], 0)

            raw = FamilyAnalyzerContext(
                db=db,
                analysis_id=analysis_id,
                target="example.test",
                endpoint="https://example.test/raw",
                method="GET",
                details={"raw_surface_observation": True},
            )
            for _ in range(8):
                analyzer.analyze(raw)

            snapshot = family_router.raw_analysis_budget_snapshot(analysis_id)
            self.assertEqual(snapshot["attempted"], 8)
            self.assertEqual(snapshot["executed"], 5)
            self.assertEqual(snapshot["skipped"], 3)
            self.assertTrue(snapshot["exhausted"])
            self.assertEqual(snapshot["families"].get("security_headers"), 5)
            exhausted = [
                fields
                for action, fields in db.audit_events
                if action == "raw_family_budget_exhausted"
            ]
            self.assertEqual(len(exhausted), 1)
            self.assertEqual(exhausted[0]["entity_value"], analysis_id)
        finally:
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = original_limit
            family_router.clear_raw_analysis_budget(analysis_id)

    def test_budget_exhaustion_is_visible_in_analysis_summary(self):
        original_limit = family_router.RAW_ANALYZER_INVOCATION_LIMIT
        temp, paths, db, now = self.project()
        analysis_id = ""
        try:
            db.execute(
                "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "https://example.test/api/profile?id=demo",
                    "absolute_url",
                    "api",
                    80,
                    json_dumps([{"category": "api", "confidence": 80}]),
                    json_dumps(["Budget visibility regression surface"]),
                    json_dumps(["budget-summary-test"]),
                    now,
                    now,
                    "RUN-HARDEN",
                ),
            )
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = 5
            result = run_analysis(paths, db, "RUN-HARDEN", "example.test")
            analysis_id = str(result["analysis_id"])
            budget = result["bug_candidates"]["raw_surface_routing"]["analyzer_budget"]

            self.assertEqual(budget["limit"], 5)
            self.assertEqual(budget["executed"], 5)
            self.assertGreater(budget["attempted"], budget["executed"])
            self.assertGreater(budget["skipped"], 0)
            self.assertTrue(budget["exhausted"])
        finally:
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = original_limit
            if analysis_id:
                family_router.clear_raw_analysis_budget(analysis_id)
            db.close()
            temp.cleanup()

    def test_router_status_exposes_scale_guard_without_generic_fallback(self):
        status = family_router.router_status()
        budget = status["raw_analyzer_budget"]
        self.assertEqual(status["pending_count"], 0)
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertTrue(budget["raw_context_only"])
        self.assertGreaterEqual(budget["invocation_limit_per_analysis"], 100_000)


if __name__ == "__main__":
    unittest.main()

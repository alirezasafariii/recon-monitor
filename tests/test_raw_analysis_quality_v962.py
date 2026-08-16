from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import analysis_quality, run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
import family_analyzers.router as family_router
from raw_analysis_quality import RAW_ANALYSIS_QUALITY_VERSION


class RawAnalysisQualityV962Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-QUALITY',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-QUALITY','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-QUALITY")),
        )
        return temp, paths, db, now

    def test_raw_only_quality_tracks_hidden_and_promoted_paths(self):
        temp, paths, db, now = self.project()
        try:
            db.execute(
                "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "https://example.test/admin",
                    "absolute_url",
                    "administration",
                    84,
                    json_dumps([{"category": "administration", "confidence": 84}]),
                    json_dumps(["Route name only; no unsafe behavior observed"]),
                    json_dumps(["quality-hard-negative"]),
                    now,
                    now,
                    "RUN-QUALITY",
                ),
            )
            db.execute(
                "INSERT INTO findings(target,dedup_key,template_id,name,severity,matched_at,details_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "quality-missing-security-header",
                    "missing-security-header",
                    "Required browser security header missing",
                    "medium",
                    "https://example.test/",
                    json_dumps(
                        {
                            "browser_security_header_surface": True,
                            "required_security_header_missing_or_invalid_observed": True,
                            "status_code": 200,
                        }
                    ),
                    now,
                    now,
                    "RUN-QUALITY",
                ),
            )

            result = run_analysis(paths, db, "RUN-QUALITY", "example.test")
            quality = result["quality"]
            raw = quality["raw_analysis"]
            routing_budget = result["bug_candidates"]["raw_surface_routing"]["analyzer_budget"]

            self.assertEqual(result["alerts"], 0)
            self.assertEqual(result["analysis_inputs"], "raw_only")
            self.assertEqual(quality["alerts"], 0)
            self.assertEqual(quality["raw_analysis_quality_version"], RAW_ANALYSIS_QUALITY_VERSION)
            self.assertEqual(raw["version"], RAW_ANALYSIS_QUALITY_VERSION)
            self.assertEqual(raw["status"], "observed")
            self.assertGreater(raw["hypotheses"], 0)
            self.assertGreater(raw["raw_observation_roots"], 0)
            self.assertGreaterEqual(raw["admitted"], 1)
            self.assertGreaterEqual(raw["promoted"], 1)
            self.assertGreater(raw["context_only_hypotheses"], 0)
            self.assertEqual(raw["context_only_promoted"], 0)
            self.assertTrue(raw["guardrails"]["context_only_never_promoted"])
            self.assertIn("security_headers", raw["families"])
            self.assertGreaterEqual(raw["families"]["security_headers"]["promoted"], 1)
            self.assertEqual(raw["budget"]["attempted"], routing_budget["attempted"])
            self.assertEqual(raw["budget"]["executed"], routing_budget["executed"])
            self.assertEqual(raw["budget"]["skipped"], routing_budget["skipped"])
            self.assertFalse(raw["budget"]["exhausted"])
            self.assertEqual(raw["budget"]["execution_coverage"], 1.0)
            self.assertEqual(raw["routing"]["active_requests"], 0)
            self.assertTrue(raw["diagnostic_only"])
            self.assertEqual(raw["accuracy_claim"], "none")

            snapshot = db.one(
                "SELECT metrics_json FROM analysis_quality_snapshots "
                "WHERE analysis_id=? ORDER BY id DESC LIMIT 1",
                (result["analysis_id"],),
            )
            persisted = json.loads(snapshot["metrics_json"])
            self.assertEqual(
                persisted["raw_analysis"]["hypotheses"],
                raw["hypotheses"],
            )
            self.assertEqual(
                persisted["raw_analysis"]["context_only_promoted"],
                0,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_budget_exhaustion_survives_quality_rehydration(self):
        temp, paths, db, now = self.project()
        original_limit = family_router.RAW_ANALYZER_INVOCATION_LIMIT
        try:
            for index in range(3):
                endpoint = f"https://example.test/admin/{index}"
                db.execute(
                    "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "example.test",
                        endpoint,
                        "absolute_url",
                        "administration",
                        80,
                        json_dumps([{"category": "administration", "confidence": 80}]),
                        json_dumps(["Budget quality regression"]),
                        json_dumps([f"budget-{index}"]),
                        now,
                        now,
                        "RUN-QUALITY",
                    ),
                )

            family_router.RAW_ANALYZER_INVOCATION_LIMIT = 2
            result = run_analysis(paths, db, "RUN-QUALITY", "example.test")
            raw = result["quality"]["raw_analysis"]

            self.assertEqual(raw["status"], "budget_exhausted")
            self.assertTrue(raw["budget"]["exhausted"])
            self.assertEqual(raw["budget"]["executed"], 2)
            self.assertGreater(raw["budget"]["skipped"], 0)
            self.assertLess(raw["budget"]["execution_coverage"], 1.0)
            original_budget = dict(raw["budget"])

            # Prove the public quality reader rehydrates budget telemetry from
            # the persisted Analysis summary, not the router's process cache.
            family_router.clear_raw_analysis_budget(result["analysis_id"])
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = original_limit
            reread = analysis_quality(db, "example.test")["raw_analysis"]

            self.assertEqual(reread["status"], "budget_exhausted")
            self.assertEqual(reread["budget"]["attempted"], original_budget["attempted"])
            self.assertEqual(reread["budget"]["executed"], 2)
            self.assertEqual(reread["budget"]["skipped"], original_budget["skipped"])
            self.assertTrue(reread["budget"]["exhausted"])
        finally:
            family_router.RAW_ANALYZER_INVOCATION_LIMIT = original_limit
            family_router.clear_raw_analysis_budget()
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

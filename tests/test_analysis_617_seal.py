from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from raw_family_collectors import AUTHORIZATION_FAMILIES, AUTHORIZATION_OBSERVATIONS


class Analysis617SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_617(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.17.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.17.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.17.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.17")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.17")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.17")

    def test_run_analysis_routes_both_authorization_families_to_hypothesis_and_candidate(self) -> None:
        families = set(AUTHORIZATION_FAMILIES)
        self.assertEqual(families, {"broken_function_authorization", "mass_assignment"})

        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td))
            paths.ensure()
            db = Database(paths.db)
            try:
                now = utc_now()
                run_id = "run-617-seal"
                target = "fixture.invalid"
                db.execute(
                    "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
                    (run_id, "6.17.0", "success", now, now, target),
                )
                alerts = [
                    (
                        "Lower privilege admin execution",
                        "/api/admin/users/disable",
                        {
                            "method": "POST",
                            "body_fields": ["user_id"],
                            "status_code": 200,
                            "context_observations": [
                                {
                                    "context": "viewer",
                                    "role": "viewer",
                                    "expected_access": False,
                                    "status_code": 200,
                                }
                            ],
                        },
                    ),
                    (
                        "Privileged profile property accepted",
                        "/api/profile",
                        {
                            "method": "PATCH",
                            "body_fields": ["display_name", "role"],
                            "status_code": 200,
                            "privileged_property_accepted": True,
                        },
                    ),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(
                        target,
                        f"617:{title}",
                        "new_endpoint",
                        "HIGH",
                        90,
                        title,
                        endpoint,
                        details,
                        run_id,
                    )

                result = run_analysis(paths, db, run_id, target)
                hypothesis_rows = db.all(
                    "SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                routed = {}
                for row in hypothesis_rows:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in families and "raw-collector-authorization-v1" in rules:
                        routed[family] = row

                self.assertEqual(set(routed), families, hypothesis_rows)
                for family, expected in AUTHORIZATION_OBSERVATIONS.items():
                    row = routed[family]
                    self.assertEqual(str(row["bug_variant"]), expected.variant)
                    self.assertEqual(str(row["state"]), "promoted")

                candidate_rows = db.all(
                    "SELECT bug_family,bug_variant,rule_ids_json FROM bug_candidates WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                candidates = {}
                for row in candidate_rows:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in families and "raw-collector-authorization-v1" in rules:
                        candidates[family] = row

                self.assertEqual(set(candidates), families, candidate_rows)
                for family, expected in AUTHORIZATION_OBSERVATIONS.items():
                    self.assertEqual(str(candidates[family]["bug_variant"]), expected.variant)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

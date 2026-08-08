from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import Database, utc_now
from hypothesis_admission import record_hypothesis
from product_platform import learn_target_profile
from security_reasoning import reasoning_regression_gate
from workspace_v7 import _current_case_ids, _latest_run, recon_coverage


class AbstentionConsistencyV844Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        self.target = "x.test"
        self.run_id = "run-partial"
        self.baseline_id = "analysis-baseline"
        self.current_id = "analysis-current"
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)",
            (self.run_id, "8.5.0", "partial", "2026-08-08T17:00:00Z", "2026-08-08T17:10:00Z", 2),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,?,?)",
            (self.run_id, self.target, "p", "success", "report", "2026-08-08T17:00:00Z", "2026-08-08T17:09:00Z", self.tmp.name, 0),
        )
        for stage in ("subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "report"):
            self.db.execute(
                "INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,finished_at,metrics_json) VALUES(?,?,?,?,1,?,?,?)",
                (self.run_id, self.target, stage, "success", now, now, "{}"),
            )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.baseline_id, self.run_id, self.target, "old", "old", "analysis", "success", "2026-08-08T17:20:00Z", "2026-08-08T17:21:00Z", "{}"),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.current_id, self.run_id, self.target, "new", "new", "analysis", "success", "2026-08-08T17:30:00Z", "2026-08-08T17:31:00Z", "{}"),
        )
        self._candidate("base-file", "fp-file", "file_upload", coverage=22)
        self._candidate("base-path", "fp-path", "path_traversal", coverage=22)
        record_hypothesis(
            self.db, analysis_id=self.current_id, source_run_id=self.run_id, target=self.target, alert_id=None,
            asset=self.target, endpoint="https://x.test/", source_ref="replay", family="file_upload", variant="file_validation",
            support=[{"type": "file_surface", "source": "semantic", "text": "content_type"}], contradict=[], missing=[], rule_ids=["weak-file"], summary="retained file clue",
        )
        record_hypothesis(
            self.db, analysis_id=self.current_id, source_run_id=self.run_id, target=self.target, alert_id=None,
            asset=self.target, endpoint="https://x.test/", source_ref="replay", family="path_traversal", variant="path_construction",
            support=[{"type": "path_surface", "source": "semantic", "text": "path download"}], contradict=[], missing=[], rule_ids=["weak-path"], summary="retained path clue",
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def _candidate(self, candidate_id: str, fingerprint: str, family: str, coverage: int = 0) -> None:
        now = utc_now()
        self.db.execute(
            """INSERT INTO bug_candidates(
            candidate_id,candidate_fingerprint,analysis_id,source_run_id,target,bug_family,bug_variant,title,summary,
            likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,safe_next_action,rule_version,
            evidence_coverage,exploitability_confidence,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (candidate_id, fingerprint, self.baseline_id, self.run_id, self.target, family, "test", family, "baseline candidate",
             25, 30, 30, 25, "possible", "review", "old", coverage, 15, now, now),
        )

    def test_partial_global_run_with_successful_target_is_usable(self) -> None:
        self.assertEqual(_latest_run(self.db, self.target), self.run_id)
        coverage = recon_coverage(self.db, target=self.target, persist=False)
        self.assertEqual(coverage["run_id"], self.run_id)
        self.assertNotIn("No successful run available", coverage.get("blind_spots", []))

    def test_zero_candidate_abstention_passes_when_families_are_retained(self) -> None:
        gate = reasoning_regression_gate(self.db, self.current_id, self.baseline_id, persist=False)
        self.assertTrue(gate["passed"], gate)
        checks = {item["name"]: item for item in gate["checks"]}
        self.assertTrue(checks["evidence_coverage"]["passed"])
        self.assertEqual(checks["evidence_coverage"]["current"], "not_applicable")
        self.assertTrue(checks["abstention_signal_retention"]["passed"])
        self.assertEqual(gate["lost_unconfirmed_families"], [])
        self.assertTrue(gate["current"]["abstained_with_retained_hypotheses"])

    def test_recall_gate_fails_when_a_previous_family_disappears_entirely(self) -> None:
        self.db.execute("DELETE FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='path_traversal'", (self.current_id,))
        gate = reasoning_regression_gate(self.db, self.current_id, self.baseline_id, persist=False)
        checks = {item["name"]: item for item in gate["checks"]}
        self.assertFalse(checks["abstention_signal_retention"]["passed"])
        self.assertIn("path_traversal", gate["lost_unconfirmed_families"])

    def test_target_learning_separates_current_analysis_from_history(self) -> None:
        profile = learn_target_profile(self.db, self.target, self.current_id, persist=False)
        self.assertEqual(profile["baseline"]["candidate_count"], 0)
        self.assertEqual(profile["baseline"]["common_families"], [])
        self.assertEqual(profile["baseline"]["history"]["candidate_count"], 2)
        self.assertEqual(dict(profile["baseline"]["history"]["common_families"]), {"file_upload": 1, "path_traversal": 1})

    def test_current_case_selector_ignores_stale_historical_cases(self) -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CASE-OLD", "old", self.baseline_id, self.run_id, self.target, "old", "old", "file_upload", 90, "new", "", "unknown", 0, now, now),
        )
        self.db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CASE-CURRENT", "current", self.current_id, self.run_id, self.target, "current", "current", "file_upload", 50, "new", "", "unknown", 0, now, now),
        )
        self.assertEqual(_current_case_ids(self.db, [self.target]), ["CASE-CURRENT"])


if __name__ == "__main__":
    unittest.main()

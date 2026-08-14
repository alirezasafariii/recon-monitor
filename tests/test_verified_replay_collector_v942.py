from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, utc_now
from verified_replay_collector import (
    _evidence_snapshot_id,
    collect_verified_replay_drafts,
    finalize_verified_replay_draft,
)

GOOD_QUALITY = {
    "reliability": 0.95,
    "specificity": 0.90,
    "directness": 0.95,
    "freshness": 0.90,
    "independence": 0.90,
    "reproducibility": 0.85,
    "uncertainty": 0.10,
}


class VerifiedReplayCollectorV942Tests(unittest.TestCase):
    def project(self, *, decision: str = "confirmed_by_analyst", actor: str = "reviewer-1"):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-1',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES('AN-1','RUN-1','example.com','8.6','r','analysis','success',?,?, '{}')",
            (now, now),
        )
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json,investigation_value) "
            "VALUES('C-1','fp-1','AN-1','RUN-1',NULL,'example.com','example.com','/api/orders/{orderId}','fixture','broken_object_authorization','object_scope','Possible BOLA','Reviewed object authorization boundary.',86,84,88,88,'strong_candidate',?,?,?,?,?,'r',?,'reviewed by analyst',?,?,86,70,80,80,'[]',90)",
            (
                json.dumps([
                    {"type": "object_identifier", "source": "schema", "source_group": "schema", "weight": 10, "text": "orderId"},
                    {"type": "object_operation", "source": "endpoint", "source_group": "endpoint", "weight": 10, "text": "read order"},
                    {"type": "cross_identity_object_access", "source": "behavior", "source_group": "behavior", "weight": 25, "text": "authorized differential"},
                ]),
                "[]",
                "[]",
                "Review stored authorized differential",
                json.dumps(["test-rule"]),
                decision,
                now,
                now,
            ),
        )
        state = "confirmed" if decision == "confirmed_by_analyst" else "rejected"
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) "
            "VALUES('CASE-1','investigation-cluster:test','AN-1','RUN-1','example.com','Investigate BOLA','review','broken_object_authorization',90,?,'','in_scope',0,?,?)",
            (state, now, now),
        )
        db.execute(
            "INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) "
            "VALUES('CASE-1','candidate','C-1','cluster_candidate','{}',?)",
            (now,),
        )
        db.execute(
            "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
            (
                "CASE-1",
                "investigation_cluster_decision",
                actor,
                json.dumps({"decision": decision, "primary_family": "broken_object_authorization", "candidate_count": 1}),
                now,
            ),
        )
        return temp, db

    def test_confirmed_analyst_decision_becomes_positive_review_draft(self):
        temp, db = self.project(decision="confirmed_by_analyst")
        try:
            report = collect_verified_replay_drafts(db)
            self.assertEqual(report["draft_count"], 1)
            self.assertEqual(report["positive_drafts"], 1)
            draft = report["drafts"][0]
            self.assertTrue(draft["label"])
            self.assertEqual(draft["reviewer_id"], "reviewer-1")
            self.assertEqual(draft["family"], "broken_object_authorization")
            self.assertTrue(draft["evidence_snapshot_id"].startswith("sha256:"))
            self.assertEqual(len(draft["missing_for_contract"]), 7)
            self.assertGreaterEqual(draft["decision_readiness_score"], 0)
            self.assertLessEqual(draft["decision_readiness_score"], 100)
        finally:
            db.close()
            temp.cleanup()

    def test_rejected_analyst_decision_becomes_negative_review_draft(self):
        temp, db = self.project(decision="rejected")
        try:
            report = collect_verified_replay_drafts(db)
            self.assertEqual(report["draft_count"], 1)
            self.assertEqual(report["negative_drafts"], 1)
            self.assertFalse(report["drafts"][0]["label"])
        finally:
            db.close()
            temp.cleanup()

    def test_latest_decisive_event_wins(self):
        temp, db = self.project(decision="rejected")
        try:
            db.execute(
                "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
                (
                    "CASE-1",
                    "investigation_cluster_decision",
                    "reviewer-old",
                    json.dumps({"decision": "confirmed_by_analyst", "primary_family": "broken_object_authorization"}),
                    "2000-01-01T00:00:00Z",
                ),
            )
            report = collect_verified_replay_drafts(db)
            self.assertEqual(report["draft_count"], 1)
            self.assertFalse(report["drafts"][0]["label"])
            self.assertEqual(report["drafts"][0]["reviewer_id"], "reviewer-1")
        finally:
            db.close()
            temp.cleanup()

    def test_non_human_actor_is_not_collected(self):
        temp, db = self.project(actor="system")
        try:
            report = collect_verified_replay_drafts(db)
            self.assertEqual(report["draft_count"], 0)
        finally:
            db.close()
            temp.cleanup()

    def test_explicit_quality_review_finalizes_against_canonical_contract(self):
        temp, db = self.project(decision="confirmed_by_analyst")
        try:
            draft = collect_verified_replay_drafts(db)["drafts"][0]
            validation = finalize_verified_replay_draft(draft, GOOD_QUALITY)
            self.assertTrue(validation["valid"], validation["errors"])
            self.assertEqual(validation["record"]["family"], "broken_object_authorization")
            self.assertTrue(validation["record"]["human_verified"])
            self.assertEqual(validation["record"]["label_source"], "investigation_cluster_decision")
        finally:
            db.close()
            temp.cleanup()

    def test_snapshot_hash_does_not_depend_on_analyst_label(self):
        temp, db = self.project(decision="confirmed_by_analyst")
        try:
            row = dict(db.one("SELECT * FROM bug_candidates WHERE candidate_id='C-1'"))
            first = _evidence_snapshot_id(row)
            row["analyst_decision"] = "rejected"
            row["analyst_note"] = "changed label"
            second = _evidence_snapshot_id(row)
            self.assertEqual(first, second)
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

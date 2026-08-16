from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, ReconError, utc_now
from dashboard import NAV_SECTIONS, _workflow_panel
from investigation_workflow import (
    cluster_case_id,
    cluster_case_key,
    cluster_workflow_snapshot,
    ensure_cluster_case,
    record_cluster_decision,
)


SAMPLE_ITEM = {
    "cluster_id": "cluster-workflow-1",
    "target": "example.com",
    "queue_score": 86,
    "primary_bug": "BOLA / IDOR",
    "primary_family": "broken_object_authorization",
    "bug_proximity_score": 91,
    "target_evidence_confidence": 61,
    "hunt_priority": "HIGH",
    "cluster_strength": 84,
    "endpoints": ["/api/orders/{orderId}"],
    "hypothesis_ids": [],
    "families": [{"family": "broken_object_authorization", "score": 91}],
    "object_tokens": ["order", "user"],
    "auth_boundaries": ["authenticated:User A"],
    "why": ["shared object authorization surface"],
    "status": "investigation_queue_not_confirmed",
}


class InvestigationCaseWorkflowV866Tests(unittest.TestCase):
    def project(self, *, with_candidate: bool = True):
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
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES('example.com','/api/orders/{orderId}','path','object',90,'[]','[]','[]',?,?, 'RUN-1')",
            (now, now),
        )
        db.execute(
            "INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at) "
            "VALUES('AN-1','example.com','/api/orders/{orderId}','User A','authenticated',200,'shape-a','{}','fixture',90,?)",
            (now,),
        )
        db.execute(
            "INSERT INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) "
            "VALUES('AN-1','example.com','/api/orders/{orderId}','authenticated:User A',90,'[]',?)",
            (now,),
        )
        if with_candidate:
            db.execute(
                "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json,investigation_value) "
                "VALUES('C-1','fp-1','AN-1','RUN-1',NULL,'example.com','example.com','/api/orders/{orderId}','fixture','broken_object_authorization','object_scope','Possible BOLA','Object ownership should remain bound to the authorized identity.',78,72,88,84,'plausible','[{\"type\":\"object_identifier\",\"source\":\"schema\",\"text\":\"orderId observed\"}]','[]','[\"second identity\",\"ownership map\"]','Collect a second authorized context','[]','r','unreviewed','',?,?,78,40,45,80,'[\"second identity\"]',82)",
                (now, now),
            )
        return temp, db

    def test_cluster_case_identity_is_deterministic(self):
        self.assertEqual(cluster_case_key("abc"), "investigation-cluster:abc")
        self.assertEqual(cluster_case_id("example.com", "abc"), cluster_case_id("example.com", "abc"))
        self.assertTrue(cluster_case_id("example.com", "abc").startswith("CASE-"))

    def test_start_investigation_reuses_existing_case_engines(self):
        temp, db = self.project(with_candidate=True)
        try:
            result = ensure_cluster_case(
                db,
                analysis_id="AN-1",
                cluster_id=SAMPLE_ITEM["cluster_id"],
                target="example.com",
                actor="tester",
                item=SAMPLE_ITEM,
            )
            self.assertEqual(result["status"], "started")
            self.assertEqual(result["case"]["state"], "reviewing")
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(result["primary_candidate_count"], 1)
            self.assertIn("coverage", result["evidence"])
            self.assertTrue(result["autopilot"]["tasks"])
            self.assertEqual(result["validation"]["recommended_level"], "controlled")
            self.assertFalse(result["validation"]["executable_in_this_release"])
            self.assertTrue(result["safety"]["case_does_not_confirm_vulnerability"])
            member = db.one(
                "SELECT relation FROM security_case_members WHERE case_id=? AND member_type='candidate' AND member_id='C-1'",
                (result["case_id"],),
            )
            self.assertEqual(member["relation"], "cluster_candidate")
            self.assertGreater(
                db.one("SELECT COUNT(*) c FROM case_autopilot_tasks WHERE case_id=?", (result["case_id"],))["c"],
                0,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_needs_more_evidence_updates_case_and_promoted_candidate(self):
        temp, db = self.project(with_candidate=True)
        try:
            started = ensure_cluster_case(
                db,
                analysis_id="AN-1",
                cluster_id=SAMPLE_ITEM["cluster_id"],
                target="example.com",
                actor="tester",
                item=SAMPLE_ITEM,
            )
            result = record_cluster_decision(
                db,
                started["case_id"],
                "needs_more_evidence",
                note="Need second authorized identity",
                actor="tester",
            )
            self.assertEqual(result["case"]["state"], "needs_evidence")
            candidate = db.one("SELECT analyst_decision,analyst_note FROM bug_candidates WHERE candidate_id='C-1'")
            self.assertEqual(candidate["analyst_decision"], "needs_more_evidence")
            self.assertIn("second authorized identity", candidate["analyst_note"])
        finally:
            db.close()
            temp.cleanup()

    def test_proximity_only_cluster_cannot_be_confirmed(self):
        temp, db = self.project(with_candidate=False)
        try:
            started = ensure_cluster_case(
                db,
                analysis_id="AN-1",
                cluster_id=SAMPLE_ITEM["cluster_id"],
                target="example.com",
                actor="tester",
                item=SAMPLE_ITEM,
            )
            self.assertEqual(started["primary_candidate_count"], 0)
            with self.assertRaisesRegex(ReconError, "proximity-only cluster cannot be confirmed"):
                record_cluster_decision(
                    db,
                    started["case_id"],
                    "confirmed_by_analyst",
                    actor="tester",
                )
            self.assertEqual(db.one("SELECT state FROM security_cases WHERE case_id=?", (started["case_id"],))["state"], "reviewing")
        finally:
            db.close()
            temp.cleanup()

    def test_workflow_snapshot_is_read_only_when_not_started(self):
        temp, db = self.project(with_candidate=True)
        try:
            snapshot = cluster_workflow_snapshot(db, analysis_id="AN-1", item=SAMPLE_ITEM)
            self.assertEqual(snapshot["status"], "not_started")
            self.assertEqual(db.one("SELECT COUNT(*) c FROM security_cases")["c"], 0)
            self.assertTrue(snapshot["safety"]["safe_validation_remains_approval_gated"])
        finally:
            db.close()
            temp.cleanup()

    def test_workflow_ui_exposes_actions_without_new_workspace(self):
        not_started = {
            "status": "not_started",
            "case_id": cluster_case_id("example.com", SAMPLE_ITEM["cluster_id"]),
        }
        html = _workflow_panel("AN-1", SAMPLE_ITEM, not_started)
        self.assertIn("Start Investigation", html)
        self.assertIn("does not confirm", html)
        self.assertNotIn("Confirmed by analyst", html)

        started = {
            "status": "started",
            "case_id": "CASE-X",
            "case": {"case_id": "CASE-X", "state": "reviewing"},
            "evidence": {
                "coverage": 57,
                "missing_count": 3,
                "requirements": [{"key": "second_identity", "label": "Second authorized test identity", "why": "Required for comparison", "status": "missing"}],
            },
            "autopilot": {"autopilot_score": 44, "tasks": [{"rank": 1, "type": "evidence", "title": "Capture the same authorized workflow with a second permitted test identity.", "status": "open"}]},
            "validation": {"recommended_level": "controlled", "executable_in_this_release": False, "reasons": ["Explicit test identities are required."]},
            "primary_candidate_count": 1,
        }
        html = _workflow_panel("AN-1", SAMPLE_ITEM, started)
        for text in ["Evidence readiness", "Next Best Actions", "Safe Validation Eligibility", "Analyst Decision", "Confirmed by analyst", "historical prior", "Open full Security Case"]:
            self.assertIn(text, html)
        self.assertNotIn("Create controlled Validation Plan", html)

        self.assertEqual(
            [(section_id, label) for section_id, label, _icon, _hint, _links in NAV_SECTIONS],
            [("recon", "01 · Recon"), ("analysis", "02 · Analysis"), ("findings", "03 · Potential Findings"), ("alerts", "04 · Alerts")],
        )


if __name__ == "__main__":
    unittest.main()

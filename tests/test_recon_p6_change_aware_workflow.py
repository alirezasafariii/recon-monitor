from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import APP_VERSION, AppPaths, Database, utc_now
from dashboard import _workflow_panel
from investigation_workflow import (
    _change_guidance,
    cluster_workflow_snapshot,
    ensure_cluster_case,
)
from safe_validation import validation_eligibility
from workspace_v7 import case_autopilot, evidence_gap_for_case


CHANGE_ITEM = {
    "cluster_id": "cluster-p6",
    "target": "example.test",
    "queue_score": 72,
    "primary_bug": "BOLA / IDOR",
    "primary_family": "broken_object_authorization",
    "bug_proximity_score": 78,
    "target_evidence_confidence": 42,
    "hunt_priority": "MEDIUM",
    "cluster_strength": 70,
    "endpoints": ["/api/orders/{orderId}"],
    "hypothesis_ids": [],
    "families": [{"family": "broken_object_authorization", "score": 78}],
    "derived_change_score": 92,
    "derived_change_matched_signals": 1,
    "derived_change_signal_types": ["source_map_source_changed"],
    "derived_change_source_run_ids": ["RUN-P6"],
    "derived_change_matches": [
        {
            "signal_type": "source_map_source_changed",
            "state_type": "source_map_source",
            "change": "changed",
            "item": "src/admin/orders.ts",
            "item_key": "map:orders",
            "baseline_run_id": "RUN-PREV",
            "score": 92,
            "reasons": [
                "exact source reference changed",
                "embedded source semantic hash changed",
            ],
        }
    ],
    "change_linked": True,
    "derived_change_advisory_only": True,
    "why": ["recent derived Recon change affinity: 92/100 (non-evidentiary)"],
    "status": "investigation_queue_not_confirmed",
}


class ReconP6ChangeAwareWorkflowTests(unittest.TestCase):
    def project(self) -> tuple[tempfile.TemporaryDirectory, Database]:
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-P6',?,'success',?,?, 'example.test',1)",
            (APP_VERSION, now, now),
        )
        db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES('AN-P6','RUN-P6','example.test','fixture','fixture','analysis','success',?,?, '{}')",
            (now, now),
        )
        db.execute(
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES('example.test','/api/orders/{orderId}','path','object',90,'[]','[]','[]',?,?, 'RUN-P6')",
            (now, now),
        )
        db.execute(
            "INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at) "
            "VALUES('AN-P6','example.test','/api/orders/{orderId}','User A','authenticated',200,'shape-a','{}','fixture',90,?)",
            (now,),
        )
        db.execute(
            "INSERT INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) "
            "VALUES('AN-P6','example.test','/api/orders/{orderId}','authenticated:User A',90,'[]',?)",
            (now,),
        )
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json,investigation_value) "
            "VALUES('C-P6','fp-p6','AN-P6','RUN-P6',NULL,'example.test','example.test','/api/orders/{orderId}','fixture','broken_object_authorization','object_scope','Possible BOLA','Object ownership should remain bound to the authorized identity.',78,72,88,84,'plausible','[{\"type\":\"object_identifier\",\"source\":\"schema\",\"text\":\"orderId observed\"}]','[]','[\"second identity\",\"ownership map\"]','Collect a second authorized context','[]','r','unreviewed','',?,?,78,40,45,80,'[\"second identity\"]',82)",
            (now, now),
        )
        return temp, db

    def test_change_guidance_prioritizes_existing_missing_requirements_only(self) -> None:
        gap = {
            "requirements": [
                {"key": "endpoint", "label": "Endpoint", "why": "known route", "status": "present"},
                {"key": "ownership_map", "label": "Ownership map", "why": "bind object owner", "status": "missing"},
                {"key": "second_identity", "label": "Second identity", "why": "compare identities", "status": "missing"},
                {"key": "comparable_response", "label": "Comparable response", "why": "like-for-like", "status": "missing"},
            ]
        }
        guidance = _change_guidance(CHANGE_ITEM, gap)
        self.assertTrue(guidance["available"])
        self.assertEqual(guidance["score"], 92)
        self.assertEqual(
            guidance["prioritized_requirements"][0]["key"],
            "ownership_map",
        )
        self.assertTrue(guidance["tasks"])
        self.assertEqual(guidance["tasks"][0]["type"], "change_review")
        self.assertTrue(guidance["tasks"][0]["advisory_only"])
        self.assertFalse(guidance["safety"]["counts_as_evidence"])
        self.assertFalse(guidance["safety"]["changes_evidence_coverage"])
        self.assertFalse(guidance["safety"]["changes_validation_eligibility"])
        self.assertFalse(guidance["safety"]["network_requests"])

    def test_not_started_snapshot_is_read_only_but_exposes_change_preview(self) -> None:
        temp, db = self.project()
        try:
            snapshot = cluster_workflow_snapshot(
                db,
                analysis_id="AN-P6",
                item=CHANGE_ITEM,
            )
            self.assertEqual(snapshot["status"], "not_started")
            self.assertTrue(snapshot["change_guidance"]["available"])
            self.assertEqual(
                db.one("SELECT COUNT(*) c FROM security_cases")["c"],
                0,
            )
            self.assertTrue(
                snapshot["safety"]["change_context_cannot_trigger_validation"]
            )
        finally:
            db.close()
            temp.cleanup()

    def test_started_workflow_reorders_tasks_without_changing_evidence_or_validation(self) -> None:
        temp, db = self.project()
        try:
            result = ensure_cluster_case(
                db,
                analysis_id="AN-P6",
                cluster_id=CHANGE_ITEM["cluster_id"],
                target="example.test",
                actor="tester",
                item=CHANGE_ITEM,
            )
            case_id = result["case_id"]

            base_gap = evidence_gap_for_case(db, case_id, persist=False)
            base_autopilot = case_autopilot(
                db,
                case_id,
                actor="test-preview",
                persist=False,
            )
            base_validation = validation_eligibility(db, case_id)

            self.assertEqual(result["evidence"]["coverage"], base_gap["coverage"])
            self.assertEqual(
                result["evidence"]["missing_count"],
                base_gap["missing_count"],
            )
            self.assertEqual(
                result["autopilot"]["autopilot_score"],
                base_autopilot["autopilot_score"],
            )
            self.assertEqual(
                result["validation"]["recommended_level"],
                base_validation["recommended_level"],
            )
            self.assertEqual(
                result["validation"]["executable_in_this_release"],
                base_validation["executable_in_this_release"],
            )

            self.assertTrue(result["change_guidance"]["available"])
            self.assertTrue(result["autopilot"]["change_aware"])
            first_task = result["autopilot"]["tasks"][0]
            self.assertEqual(first_task["type"], "change_review")
            self.assertTrue(first_task["advisory_only"])
            self.assertIn("src/admin/orders.ts", first_task["title"])

            missing_status = {
                row["key"]: row["status"]
                for row in result["evidence"]["requirements"]
            }
            for row in result["evidence"]["change_prioritized_requirements"]:
                self.assertEqual(missing_status[row["key"]], "missing")

            persisted = db.one(
                "SELECT task_id,task_type,rank,details_json FROM case_autopilot_tasks "
                "WHERE case_id=? AND task_id LIKE 'task-change-%' ORDER BY rank LIMIT 1",
                (case_id,),
            )
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted["rank"], 1)
            self.assertEqual(persisted["task_type"], "change_review")
            details = json.loads(persisted["details_json"])
            self.assertTrue(details["advisory_only"])
            self.assertFalse(details["counts_as_evidence"])
            self.assertFalse(details["can_execute_validation"])

            normal = db.one(
                "SELECT MIN(rank) r FROM case_autopilot_tasks "
                "WHERE case_id=? AND task_id NOT LIKE 'task-change-%' AND status='open'",
                (case_id,),
            )
            self.assertGreater(int(normal["r"]), 1)
        finally:
            db.close()
            temp.cleanup()

    def test_workflow_ui_labels_change_guidance_without_claiming_evidence(self) -> None:
        workflow = {
            "status": "started",
            "case_id": "CASE-P6",
            "case": {"case_id": "CASE-P6", "state": "reviewing"},
            "evidence": {
                "coverage": 44,
                "missing_count": 3,
                "requirements": [
                    {
                        "key": "ownership_map",
                        "label": "Ownership map",
                        "why": "Required for comparison",
                        "status": "missing",
                    }
                ],
            },
            "autopilot": {
                "autopilot_score": 31,
                "tasks": [
                    {
                        "rank": 1,
                        "type": "change_review",
                        "title": "Review changed source module src/admin/orders.ts",
                        "status": "open",
                        "advisory_only": True,
                    },
                    {
                        "rank": 2,
                        "type": "evidence",
                        "title": "Document object ownership",
                        "status": "open",
                    },
                ],
            },
            "validation": {
                "recommended_level": "controlled",
                "executable_in_this_release": False,
                "reasons": ["Explicit test identities are required."],
            },
            "change_guidance": {
                "available": True,
                "score": 92,
                "prioritized_requirements": [
                    {
                        "key": "ownership_map",
                        "label": "Ownership map",
                        "status": "missing",
                    }
                ],
            },
            "primary_candidate_count": 1,
        }
        html = _workflow_panel("AN-P6", CHANGE_ITEM, workflow)
        for text in (
            "Change-aware task ordering",
            "change-guided",
            "Recent change",
            "Change-prioritized gaps",
            "remain missing until target evidence satisfies them",
            "no validation is triggered automatically",
        ):
            self.assertIn(text, html)


if __name__ == "__main__":
    unittest.main()

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

import api_server
import recon_monitor
from change_guidance_evaluation import case_change_guidance_metrics
from core import AppPaths, Database, utc_now
from dashboard import _workflow_panel
from investigation_workflow import (
    _persist_change_advisory_tasks,
    record_change_task_feedback,
)


GUIDANCE = {
    "available": True,
    "score": 92,
    "prioritized_requirements": [
        {
            "key": "ownership_map",
            "label": "Ownership map",
            "why": "bind the object to its expected owner",
            "status": "missing",
        }
    ],
    "tasks": [
        {
            "rank": 1,
            "type": "change_review",
            "title": "Review changed source module src/admin/orders.ts",
            "status": "open",
            "advisory_only": True,
            "signal_type": "source_map_source_changed",
            "item": "src/admin/orders.ts",
            "item_key": "map:orders",
            "reasons": ["exact source reference changed"],
        }
    ],
}


class ReconP8TaskLifecycleFeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(self.temp.name))
        paths.ensure()
        self.db = Database(paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO security_cases("
            "case_id,case_key,analysis_id,source_run_id,target,title,summary,"
            "primary_family,priority_score,state,assigned_to,scope_status,"
            "report_readiness,created_at,updated_at"
            ") VALUES("
            "'CASE-P8','investigation-cluster:p8','AN-P8','RUN-P8','example.test',"
            "'Investigation','fixture','broken_object_authorization',70,'reviewing','',"
            "'in_scope',0,?,?"
            ")",
            (now, now),
        )
        self.db.execute(
            "INSERT INTO security_case_events("
            "case_id,event_type,actor,details_json,created_at"
            ") VALUES('CASE-P8','investigation_cluster_started','tester','{}',?)",
            (now,),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _persist_task(self) -> str:
        _persist_change_advisory_tasks(
            self.db,
            "CASE-P8",
            GUIDANCE,
            actor="tester",
        )
        row = self.db.one(
            "SELECT task_id FROM case_autopilot_tasks "
            "WHERE case_id='CASE-P8' AND task_id LIKE 'task-change-%'"
        )
        self.assertIsNotNone(row)
        return str(row["task_id"])

    def test_feedback_records_explicit_terminal_lifecycle_without_creating_evidence(self) -> None:
        task_id = self._persist_task()
        before = {
            "evidence_records": self.db.one(
                "SELECT COUNT(*) c FROM evidence_records"
            )["c"],
            "gap_snapshots": self.db.one(
                "SELECT COUNT(*) c FROM evidence_gap_snapshots"
            )["c"],
            "validation_plans": self.db.one(
                "SELECT COUNT(*) c FROM validation_plans"
            )["c"],
            "validation_runs": self.db.one(
                "SELECT COUNT(*) c FROM validation_runs"
            )["c"],
        }

        result = record_change_task_feedback(
            self.db,
            "CASE-P8",
            task_id,
            status="completed",
            usefulness="useful",
            note="Pointed directly to the ownership branch.",
            actor="alice",
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["usefulness"], "useful")
        self.assertFalse(result["safety"]["counts_as_target_evidence"])
        self.assertFalse(result["safety"]["changes_admission"])
        self.assertFalse(result["safety"]["changes_validation_eligibility"])
        self.assertFalse(result["safety"]["auto_tuning"])
        self.assertFalse(result["safety"]["network_requests"])

        row = self.db.one(
            "SELECT status,details_json FROM case_autopilot_tasks WHERE task_id=?",
            (task_id,),
        )
        self.assertEqual(row["status"], "completed")
        details = json.loads(row["details_json"])
        self.assertEqual(
            details["analyst_feedback"]["usefulness"],
            "useful",
        )
        self.assertEqual(
            details["analyst_feedback"]["status"],
            "completed",
        )
        self.assertFalse(details["feedback_is_target_evidence"])
        self.assertFalse(details["feedback_can_auto_tune"])

        event = self.db.one(
            "SELECT details_json FROM security_case_events "
            "WHERE case_id='CASE-P8' "
            "AND event_type='investigation_change_task_feedback' "
            "ORDER BY id DESC LIMIT 1"
        )
        event_details = json.loads(event["details_json"])
        self.assertEqual(event_details["task_status"], "completed")
        self.assertEqual(event_details["usefulness"], "useful")
        self.assertFalse(event_details["counts_as_evidence"])
        self.assertFalse(event_details["can_auto_tune"])

        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM evidence_records")["c"],
            before["evidence_records"],
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM evidence_gap_snapshots")["c"],
            before["gap_snapshots"],
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM validation_plans")["c"],
            before["validation_plans"],
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM validation_runs")["c"],
            before["validation_runs"],
        )

    def test_refresh_persistence_preserves_terminal_feedback(self) -> None:
        task_id = self._persist_task()
        record_change_task_feedback(
            self.db,
            "CASE-P8",
            task_id,
            status="skipped",
            usefulness="noisy",
            note="Change was unrelated after manual source review.",
            actor="alice",
        )

        _persist_change_advisory_tasks(
            self.db,
            "CASE-P8",
            GUIDANCE,
            actor="refresh",
        )

        rows = self.db.all(
            "SELECT task_id,status,details_json FROM case_autopilot_tasks "
            "WHERE case_id='CASE-P8' AND task_id LIKE 'task-change-%'"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_id"], task_id)
        self.assertEqual(rows[0]["status"], "skipped")
        details = json.loads(rows[0]["details_json"])
        self.assertEqual(details["analyst_feedback"]["usefulness"], "noisy")
        self.assertEqual(
            details["analyst_feedback"]["note"],
            "Change was unrelated after manual source review.",
        )

    def test_terminal_status_cannot_be_rewritten_but_rating_can_be_updated(self) -> None:
        task_id = self._persist_task()
        record_change_task_feedback(
            self.db,
            "CASE-P8",
            task_id,
            status="completed",
            usefulness="neutral",
            actor="alice",
        )
        updated = record_change_task_feedback(
            self.db,
            "CASE-P8",
            task_id,
            status="completed",
            usefulness="useful",
            note="Useful after deeper review.",
            actor="alice",
        )
        self.assertEqual(updated["usefulness"], "useful")

        with self.assertRaisesRegex(Exception, "cannot transition"):
            record_change_task_feedback(
                self.db,
                "CASE-P8",
                task_id,
                status="skipped",
                usefulness="noisy",
                actor="alice",
            )

    def test_evaluator_counts_only_explicit_task_outcomes_and_feedback(self) -> None:
        task_id = self._persist_task()
        before = case_change_guidance_metrics(self.db, "CASE-P8")
        self.assertTrue(before["change_guided"])
        self.assertEqual(before["guided_task_count"], 1)
        self.assertEqual(before["guided_task_terminal_count"], 0)
        self.assertEqual(before["guided_task_feedback_count"], 0)

        record_change_task_feedback(
            self.db,
            "CASE-P8",
            task_id,
            status="completed",
            usefulness="useful",
            actor="alice",
        )
        after = case_change_guidance_metrics(self.db, "CASE-P8")
        self.assertEqual(after["guided_task_completed_count"], 1)
        self.assertEqual(after["guided_task_terminal_count"], 1)
        self.assertEqual(after["guided_task_feedback_count"], 1)
        self.assertEqual(after["guided_task_useful_count"], 1)
        self.assertEqual(after["guided_task_noisy_count"], 0)
        self.assertIsNotNone(after["median_time_to_guided_task_outcome_hours"])

    def test_workflow_ui_exposes_explicit_feedback_controls_and_terminal_state(self) -> None:
        base_workflow = {
            "status": "started",
            "case_id": "CASE-P8",
            "case": {"case_id": "CASE-P8", "state": "reviewing"},
            "evidence": {
                "coverage": 40,
                "missing_count": 1,
                "requirements": [],
            },
            "autopilot": {
                "autopilot_score": 30,
                "tasks": [
                    {
                        **GUIDANCE["tasks"][0],
                        "task_id": "task-change-test",
                        "feedback_usefulness": "",
                        "feedback_note": "",
                    }
                ],
            },
            "validation": {
                "recommended_level": "controlled",
                "executable_in_this_release": False,
                "reasons": [],
            },
            "change_guidance": {
                "available": True,
                "score": 92,
                "prioritized_requirements": [],
            },
            "primary_candidate_count": 0,
        }
        html = _workflow_panel(
            "AN-P8",
            {
                "cluster_id": "p8",
                "target": "example.test",
                "primary_family": "broken_object_authorization",
            },
            base_workflow,
        )
        self.assertIn("/investigation/task-feedback", html)
        self.assertIn("Record task outcome", html)
        self.assertIn("Useful", html)
        self.assertIn("Noisy", html)
        self.assertIn("Feedback is observational only", html)

        terminal = json.loads(json.dumps(base_workflow))
        terminal["autopilot"]["tasks"][0]["status"] = "completed"
        terminal["autopilot"]["tasks"][0]["feedback_usefulness"] = "useful"
        terminal_html = _workflow_panel(
            "AN-P8",
            {
                "cluster_id": "p8",
                "target": "example.test",
                "primary_family": "broken_object_authorization",
            },
            terminal,
        )
        self.assertIn("Outcome locked: completed", terminal_html)
        self.assertIn("Update usefulness", terminal_html)

    def test_api_and_cli_publish_feedback_safety_contract(self) -> None:
        for payload in (
            api_server.investigation_queue_payload(
                object(),
                analysis_id="",
                target="",
                limit=5,
            ),
            recon_monitor.investigation_queue_cli_payload(
                object(),
                analysis_id="",
                target="",
                limit=5,
            ),
        ):
            safety = payload["safety"]
            self.assertTrue(safety["change_task_feedback_is_observational_only"])
            self.assertTrue(safety["change_task_feedback_cannot_auto_tune"])
            self.assertTrue(safety["change_task_feedback_is_not_target_evidence"])


if __name__ == "__main__":
    unittest.main()

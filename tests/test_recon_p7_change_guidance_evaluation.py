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
from change_guidance_evaluation import (
    case_change_guidance_metrics,
    change_guidance_evaluation,
)
from core import AppPaths, Database
from dashboard import _change_guidance_evaluation_panel


class ReconP7ChangeGuidanceEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(self.temp.name))
        paths.ensure()
        self.db = Database(paths.db)
        self._seed_cohorts()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _insert_case(
        self,
        *,
        index: int,
        guided: bool,
        gain_hours: int,
        decision_hours: int,
        coverage_gain: int,
    ) -> None:
        case_id = f"CASE-{'G' if guided else 'C'}-{index}"
        key = f"investigation-cluster:{'guided' if guided else 'control'}-{index}"
        start = f"2026-09-{index + 1:02d}T00:00:00Z"
        first_snapshot = f"2026-09-{index + 1:02d}T00:05:00Z"
        gain_at = f"2026-09-{index + 1:02d}T{gain_hours:02d}:00:00Z"
        decision_at = f"2026-09-{index + 1:02d}T{decision_hours:02d}:00:00Z"
        self.db.execute(
            "INSERT INTO security_cases("
            "case_id,case_key,analysis_id,source_run_id,target,title,summary,"
            "primary_family,priority_score,state,assigned_to,scope_status,"
            "report_readiness,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,'reviewing','','in_scope',0,?,?)",
            (
                case_id,
                key,
                f"AN-{index}",
                f"RUN-{index}",
                "example.test",
                "Investigation",
                "fixture",
                "broken_object_authorization",
                70,
                start,
                decision_at,
            ),
        )
        self.db.execute(
            "INSERT INTO security_case_events("
            "case_id,event_type,actor,details_json,created_at"
            ") VALUES(?,?,?,?,?)",
            (
                case_id,
                "investigation_cluster_started",
                "tester",
                "{}",
                start,
            ),
        )
        if guided:
            self.db.execute(
                "INSERT INTO security_case_events("
                "case_id,event_type,actor,details_json,created_at"
                ") VALUES(?,?,?,?,?)",
                (
                    case_id,
                    "investigation_change_guidance_refreshed",
                    "tester",
                    json.dumps(
                        {
                            "advisory_score": 92,
                            "task_count": 1,
                            "status": "advisory_only_not_evidence",
                        }
                    ),
                    f"2026-09-{index + 1:02d}T00:10:00Z",
                ),
            )
            self.db.execute(
                "INSERT INTO case_autopilot_tasks("
                "task_id,case_id,task_type,title,rank,status,details_json,created_at,updated_at"
                ") VALUES(?,?,?,?,?,'open',?,?,?)",
                (
                    f"task-change-{index}",
                    case_id,
                    "change_review",
                    "Review changed source module",
                    1,
                    json.dumps(
                        {
                            "source": "derived_change_advisory",
                            "advisory_only": True,
                            "counts_as_evidence": False,
                        }
                    ),
                    f"2026-09-{index + 1:02d}T00:10:00Z",
                    f"2026-09-{index + 1:02d}T00:10:00Z",
                ),
            )
        else:
            self.db.execute(
                "INSERT INTO case_autopilot_tasks("
                "task_id,case_id,task_type,title,rank,status,details_json,created_at,updated_at"
                ") VALUES(?,?,?,?,?,'open',?,?,?)",
                (
                    f"task-base-{index}",
                    case_id,
                    "evidence",
                    "Collect existing missing evidence",
                    1,
                    json.dumps({"source": "case_autopilot"}),
                    f"2026-09-{index + 1:02d}T00:10:00Z",
                    f"2026-09-{index + 1:02d}T00:10:00Z",
                ),
            )

        self.db.execute(
            "INSERT INTO evidence_gap_snapshots("
            "case_id,coverage,requirements_json,next_actions_json,created_at"
            ") VALUES(?,?,?,?,?)",
            (case_id, 40, "[]", "[]", first_snapshot),
        )
        self.db.execute(
            "INSERT INTO evidence_gap_snapshots("
            "case_id,coverage,requirements_json,next_actions_json,created_at"
            ") VALUES(?,?,?,?,?)",
            (case_id, 40 + coverage_gain, "[]", "[]", gain_at),
        )
        self.db.execute(
            "INSERT INTO security_case_events("
            "case_id,event_type,actor,details_json,created_at"
            ") VALUES(?,?,?,?,?)",
            (
                case_id,
                "investigation_cluster_decision",
                "tester",
                json.dumps(
                    {
                        "decision": "needs_more_evidence",
                        "primary_family": "broken_object_authorization",
                        "candidate_count": 1,
                    }
                ),
                decision_at,
            ),
        )

    def _seed_cohorts(self) -> None:
        for index in range(5):
            self._insert_case(
                index=index,
                guided=True,
                gain_hours=2,
                decision_hours=3,
                coverage_gain=20,
            )
        for index in range(5, 10):
            self._insert_case(
                index=index,
                guided=False,
                gain_hours=8,
                decision_hours=12,
                coverage_gain=10,
            )

    def test_case_metrics_detect_guidance_and_evidence_gain_without_task_completion_inference(self) -> None:
        metrics = case_change_guidance_metrics(self.db, "CASE-G-0")
        self.assertTrue(metrics["available"])
        self.assertTrue(metrics["change_guided"])
        self.assertEqual(metrics["initial_coverage"], 40)
        self.assertEqual(metrics["latest_coverage"], 60)
        self.assertEqual(metrics["coverage_delta"], 20)
        self.assertTrue(metrics["evidence_gain"])
        self.assertEqual(metrics["time_to_first_evidence_gain_hours"], 2.0)
        self.assertEqual(metrics["time_to_decision_hours"], 3.0)
        self.assertEqual(metrics["decision"], "needs_more_evidence")
        self.assertEqual(metrics["guided_task_count"], 1)

    def test_evaluation_is_read_only_and_gates_directional_comparison_on_sample_size(self) -> None:
        before_events = self.db.one(
            "SELECT COUNT(*) c FROM security_case_events"
        )["c"]
        before_tasks = self.db.one(
            "SELECT COUNT(*) c FROM case_autopilot_tasks"
        )["c"]

        report = change_guidance_evaluation(
            self.db,
            target="example.test",
            limit=100,
        )

        self.assertEqual(report["case_count"], 10)
        self.assertTrue(report["comparison_ready"])
        self.assertEqual(report["guided"]["case_count"], 5)
        self.assertEqual(report["control"]["case_count"], 5)
        self.assertEqual(report["guided"]["evidence_gain_rate"], 1.0)
        self.assertEqual(report["control"]["evidence_gain_rate"], 1.0)
        self.assertEqual(report["guided"]["median_coverage_delta"], 20.0)
        self.assertEqual(report["control"]["median_coverage_delta"], 10.0)
        self.assertEqual(
            report["directional_deltas_guided_minus_control"]["median_coverage_delta"],
            10.0,
        )
        self.assertEqual(
            report["directional_deltas_guided_minus_control"][
                "median_time_to_first_evidence_gain_hours"
            ],
            -6.0,
        )
        self.assertEqual(
            report["directional_deltas_guided_minus_control"][
                "median_time_to_decision_hours"
            ],
            -9.0,
        )
        self.assertFalse(report["interpretation"]["causal"])
        self.assertFalse(report["interpretation"]["auto_tuning"])
        self.assertFalse(report["interpretation"]["winner_selection"])
        self.assertFalse(report["interpretation"]["task_completion_observed"])
        self.assertTrue(report["limitations"])

        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM security_case_events")["c"],
            before_events,
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM case_autopilot_tasks")["c"],
            before_tasks,
        )

        small = change_guidance_evaluation(
            self.db,
            target="example.test",
            limit=4,
        )
        self.assertFalse(small["comparison_ready"])
        self.assertEqual(small["directional_deltas_guided_minus_control"], {})

    def test_dashboard_panel_labels_metrics_as_observational_non_causal(self) -> None:
        report = change_guidance_evaluation(self.db, target="example.test")
        html = _change_guidance_evaluation_panel(report)
        for text in (
            "Change-guidance Evaluation",
            "Observational, not causal",
            "Change-guided",
            "Non-guided",
            "Directional delta",
            "never auto-tune",
            "no cohort is labeled a winner",
        ):
            self.assertIn(text, html)

    def test_api_and_cli_expose_same_evaluation_safety_contract(self) -> None:
        api_payload = api_server.investigation_queue_payload(
            self.db,
            analysis_id="",
            target="example.test",
            limit=5,
        )
        cli_payload = recon_monitor.investigation_queue_cli_payload(
            self.db,
            analysis_id="",
            target="example.test",
            limit=5,
        )
        for payload in (api_payload, cli_payload):
            evaluation = payload["change_guidance_evaluation"]
            self.assertEqual(evaluation["case_count"], 10)
            self.assertTrue(evaluation["comparison_ready"])
            self.assertFalse(evaluation["interpretation"]["causal"])
            self.assertIn("change_guidance_evaluation", payload["engines"])
            self.assertTrue(
                payload["safety"][
                    "change_guidance_evaluation_is_observational_only"
                ]
            )
            self.assertTrue(
                payload["safety"]["change_guidance_evaluation_is_non_causal"]
            )
            self.assertTrue(
                payload["safety"]["change_guidance_evaluation_cannot_auto_tune"]
            )


if __name__ == "__main__":
    unittest.main()

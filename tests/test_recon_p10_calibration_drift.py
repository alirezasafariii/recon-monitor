from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server
import recon_monitor
from change_guidance_drift import change_guidance_drift_report
from core import AppPaths, Database
from dashboard import _change_guidance_drift_panel


class ReconP10CalibrationDriftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(self.temp.name))
        paths.ensure()
        self.db = Database(paths.db)
        self._seed()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _case(self, case_id: str, *, target: str, family: str) -> None:
        created = "2026-07-01T00:00:00Z"
        self.db.execute(
            "INSERT INTO security_cases("
            "case_id,case_key,analysis_id,source_run_id,target,title,summary,"
            "primary_family,priority_score,state,assigned_to,scope_status,"
            "report_readiness,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,'reviewing','','in_scope',0,?,?)",
            (
                case_id,
                "investigation-cluster:" + case_id.lower(),
                "AN-P10",
                "RUN-P10",
                target,
                "Investigation",
                "fixture",
                family,
                70,
                created,
                created,
            ),
        )

    def _task(
        self,
        case_id: str,
        index: int,
        *,
        signal_type: str,
        usefulness: str,
        recorded_at: str,
        status: str = "completed",
    ) -> None:
        details = {
            "source": "derived_change_advisory",
            "advisory_only": True,
            "counts_as_evidence": False,
            "can_execute_validation": False,
            "signal_type": signal_type,
            "item": f"item-{index}",
            "item_key": f"{signal_type}:{case_id}:{index}",
            "analyst_feedback": {
                "status": status,
                "usefulness": usefulness,
                "note": "",
                "actor": "tester",
                "recorded_at": recorded_at,
            },
        }
        self.db.execute(
            "INSERT INTO case_autopilot_tasks("
            "task_id,case_id,task_type,title,rank,status,details_json,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                f"task-change-{case_id.lower()}-{index}",
                case_id,
                "change_review",
                f"Review {signal_type}",
                index + 1,
                status,
                json.dumps(details),
                recorded_at,
                recorded_at,
            ),
        )

    def _seed_signal(
        self,
        case_id: str,
        *,
        target: str,
        family: str,
        signal_type: str,
        previous: list[str],
        recent: list[str],
    ) -> None:
        self._case(case_id, target=target, family=family)
        previous_dates = [
            "2026-07-25T12:00:00Z",
            "2026-07-30T12:00:00Z",
            "2026-08-04T12:00:00Z",
            "2026-08-09T12:00:00Z",
            "2026-08-14T12:00:00Z",
        ]
        recent_dates = [
            "2026-08-24T12:00:00Z",
            "2026-08-29T12:00:00Z",
            "2026-09-03T12:00:00Z",
            "2026-09-10T12:00:00Z",
            "2026-09-18T12:00:00Z",
        ]
        for index, usefulness in enumerate(previous):
            self._task(
                case_id,
                index,
                signal_type=signal_type,
                usefulness=usefulness,
                recorded_at=previous_dates[index],
            )
        for offset, usefulness in enumerate(recent, start=10):
            self._task(
                case_id,
                offset,
                signal_type=signal_type,
                usefulness=usefulness,
                recorded_at=recent_dates[offset - 10],
                status="skipped" if usefulness == "noisy" else "completed",
            )

    def _seed(self) -> None:
        self._seed_signal(
            "CASE-NOISE",
            target="example.test",
            family="file_upload",
            signal_type="javascript_chunk_added",
            previous=["useful", "useful", "useful", "useful", "neutral"],
            recent=["useful", "neutral", "noisy", "noisy", "noisy"],
        )
        self._seed_signal(
            "CASE-DECLINE",
            target="example.test",
            family="broken_object_authorization",
            signal_type="source_map_source_changed",
            previous=["useful", "useful", "useful", "useful", "neutral"],
            recent=["useful", "useful", "neutral", "neutral", "neutral"],
        )
        self._seed_signal(
            "CASE-IMPROVE",
            target="example.test",
            family="graphql_authorization",
            signal_type="source_map_source_added",
            previous=["useful", "useful", "neutral", "neutral", "neutral"],
            recent=["useful", "useful", "useful", "useful", "neutral"],
        )
        self._seed_signal(
            "CASE-STABLE",
            target="example.test",
            family="authentication_session",
            signal_type="javascript_chunk_changed",
            previous=["useful", "useful", "useful", "neutral", "neutral"],
            recent=["useful", "useful", "useful", "neutral", "neutral"],
        )
        self._seed_signal(
            "CASE-SPARSE",
            target="example.test",
            family="open_redirect",
            signal_type="source_map_source_removed",
            previous=["useful", "neutral", "noisy", "useful"],
            recent=["useful", "useful", "neutral", "neutral", "noisy"],
        )
        self._seed_signal(
            "CASE-OTHER",
            target="other.test",
            family="file_upload",
            signal_type="javascript_chunk_removed",
            previous=["neutral", "neutral", "neutral", "neutral", "neutral"],
            recent=["noisy", "noisy", "noisy", "neutral", "neutral"],
        )

    def test_drift_classifies_longitudinal_signal_quality_with_sample_gate(self) -> None:
        report = change_guidance_drift_report(
            self.db,
            target="example.test",
            window_days=30,
        )
        by_signal = {row["signal_type"]: row for row in report["signals"]}

        self.assertEqual(
            by_signal["javascript_chunk_added"]["drift_status"],
            "noise_increase_watch",
        )
        self.assertEqual(
            by_signal["javascript_chunk_added"][
                "noisy_rate_delta_recent_minus_previous"
            ],
            0.6,
        )

        self.assertEqual(
            by_signal["source_map_source_changed"]["drift_status"],
            "utility_decline_watch",
        )
        self.assertEqual(
            by_signal["source_map_source_changed"][
                "useful_rate_delta_recent_minus_previous"
            ],
            -0.4,
        )

        self.assertEqual(
            by_signal["source_map_source_added"]["drift_status"],
            "utility_improvement_watch",
        )
        self.assertEqual(
            by_signal["source_map_source_added"][
                "useful_rate_delta_recent_minus_previous"
            ],
            0.4,
        )

        self.assertEqual(
            by_signal["javascript_chunk_changed"]["drift_status"],
            "stable",
        )
        self.assertEqual(
            by_signal["source_map_source_removed"]["drift_status"],
            "insufficient history",
        )
        self.assertFalse(
            by_signal["source_map_source_removed"]["history_sufficient"]
        )
        self.assertNotIn("javascript_chunk_removed", by_signal)

        self.assertEqual(report["activation"], "monitoring_only")
        self.assertEqual(report["window_days"], 30)
        self.assertEqual(report["anchor_at"], "2026-09-18T12:00:00Z")
        self.assertEqual(report["minimum_feedback_per_window"], 5)
        self.assertEqual(report["status_counts"]["noise_increase_watch"], 1)
        self.assertEqual(report["status_counts"]["utility_decline_watch"], 1)
        self.assertEqual(report["status_counts"]["utility_improvement_watch"], 1)
        self.assertEqual(report["status_counts"]["stable"], 1)
        self.assertEqual(report["status_counts"]["insufficient_history"], 1)

    def test_recent_target_and_family_slices_are_descriptive_only(self) -> None:
        report = change_guidance_drift_report(self.db, target="example.test")
        target_slices = report["recent_target_slices"]
        family_slices = report["recent_family_slices"]

        self.assertTrue(target_slices)
        self.assertTrue(family_slices)
        self.assertTrue(
            all(row["target"] == "example.test" for row in target_slices)
        )
        self.assertTrue(
            all(row["production_change_allowed"] is False for row in target_slices)
        )
        self.assertTrue(
            all(row["production_change_allowed"] is False for row in family_slices)
        )
        self.assertTrue(
            all(row["sample_sufficient"] for row in target_slices)
        )

    def test_report_is_read_only_and_monitoring_cannot_change_production(self) -> None:
        before_tasks = self.db.one(
            "SELECT COUNT(*) c FROM case_autopilot_tasks"
        )["c"]
        before_events = self.db.one(
            "SELECT COUNT(*) c FROM security_case_events"
        )["c"]

        report = change_guidance_drift_report(self.db, target="example.test")

        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM case_autopilot_tasks")["c"],
            before_tasks,
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM security_case_events")["c"],
            before_events,
        )
        self.assertFalse(report["interpretation"]["causal"])
        self.assertFalse(report["interpretation"]["production_activation"])
        self.assertFalse(report["interpretation"]["auto_tuning"])
        self.assertTrue(report["interpretation"]["trend_is_not_significance_test"])
        self.assertTrue(report["safety"]["monitoring_only"])
        self.assertFalse(report["safety"]["may_change_meta_ranker_weights"])
        self.assertFalse(report["safety"]["may_change_thresholds"])
        self.assertFalse(report["safety"]["may_change_queue_score"])
        self.assertFalse(report["safety"]["may_change_task_ordering"])
        self.assertFalse(report["safety"]["may_change_admission"])
        self.assertFalse(report["safety"]["may_change_validation"])
        self.assertFalse(report["safety"]["network_requests"])

    def test_dashboard_panel_labels_drift_as_monitoring_only(self) -> None:
        report = change_guidance_drift_report(self.db, target="example.test")
        html = _change_guidance_drift_panel(report)
        for text in (
            "Change-guidance Drift",
            "monitoring only",
            "Longitudinal monitoring",
            "no auto-tuning",
            "javascript_chunk_added",
            "source_map_source_changed",
            "noise increase watch",
            "utility decline watch",
            "insufficient_history",
        ):
            self.assertIn(text, html)

    def test_api_and_cli_expose_drift_and_safety_contract(self) -> None:
        with mock.patch("api_server.investigation_queue", return_value=[]):
            api_payload = api_server.investigation_queue_payload(
                self.db,
                analysis_id="AN-P10",
                target="example.test",
                limit=5,
            )
        with mock.patch("recon_monitor.investigation_queue", return_value=[]):
            cli_payload = recon_monitor.investigation_queue_cli_payload(
                self.db,
                analysis_id="AN-P10",
                target="example.test",
                limit=5,
            )

        for payload in (api_payload, cli_payload):
            drift = payload["change_guidance_drift"]
            self.assertEqual(drift["activation"], "monitoring_only")
            self.assertEqual(drift["anchor_at"], "2026-09-18T12:00:00Z")
            self.assertIn("change_guidance_drift", payload["engines"])
            self.assertTrue(
                payload["safety"]["change_guidance_drift_is_monitoring_only"]
            )
            self.assertTrue(
                payload["safety"]["change_guidance_drift_cannot_auto_tune"]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_drift_cannot_change_weights_thresholds_or_ordering"
                ]
            )


if __name__ == "__main__":
    unittest.main()

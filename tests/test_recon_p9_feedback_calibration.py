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
from change_guidance_calibration import change_guidance_calibration_report
from core import AppPaths, Database, utc_now
from dashboard import _change_guidance_calibration_panel


class ReconP9FeedbackCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(self.temp.name))
        paths.ensure()
        self.db = Database(paths.db)
        self._seed()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _case(self, case_id: str, target: str, family: str) -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO security_cases("
            "case_id,case_key,analysis_id,source_run_id,target,title,summary,"
            "primary_family,priority_score,state,assigned_to,scope_status,"
            "report_readiness,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,'reviewing','','in_scope',0,?,?)",
            (
                case_id,
                "investigation-cluster:" + case_id.lower(),
                "AN-P9",
                "RUN-P9",
                target,
                "Investigation",
                "fixture",
                family,
                70,
                now,
                now,
            ),
        )

    def _task(
        self,
        case_id: str,
        index: int,
        *,
        signal_type: str,
        usefulness: str,
        status: str = "completed",
    ) -> None:
        now = utc_now()
        details = {
            "source": "derived_change_advisory",
            "advisory_only": True,
            "counts_as_evidence": False,
            "can_execute_validation": False,
            "signal_type": signal_type,
            "item": f"item-{index}",
            "item_key": f"{signal_type}:{index}",
            "analyst_feedback": {
                "status": status,
                "usefulness": usefulness,
                "note": "",
                "actor": "tester",
                "recorded_at": now,
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
                now,
                now,
            ),
        )

    def _seed(self) -> None:
        self._case("CASE-UTILITY", "example.test", "broken_object_authorization")
        for index, usefulness in enumerate(["useful", "useful", "useful", "useful", "neutral"]):
            self._task(
                "CASE-UTILITY",
                index,
                signal_type="source_map_source_changed",
                usefulness=usefulness,
            )

        self._case("CASE-NOISE", "example.test", "file_upload")
        for index, usefulness in enumerate(["noisy", "noisy", "noisy", "neutral", "neutral"]):
            self._task(
                "CASE-NOISE",
                index,
                signal_type="javascript_chunk_added",
                usefulness=usefulness,
                status="skipped" if usefulness == "noisy" else "completed",
            )

        self._case("CASE-SMALL", "example.test", "graphql_authorization")
        for index, usefulness in enumerate(["useful", "noisy", "neutral", "useful"]):
            self._task(
                "CASE-SMALL",
                index,
                signal_type="source_map_source_added",
                usefulness=usefulness,
            )

        self._case("CASE-OTHER", "other.test", "broken_object_authorization")
        for index in range(5):
            self._task(
                "CASE-OTHER",
                index,
                signal_type="javascript_chunk_removed",
                usefulness="noisy",
            )

    def test_signal_calibration_is_sample_gated_and_shadow_only(self) -> None:
        report = change_guidance_calibration_report(
            self.db,
            target="example.test",
        )
        by_signal = {row["signal_type"]: row for row in report["signals"]}

        useful = by_signal["source_map_source_changed"]
        self.assertEqual(useful["feedback_count"], 5)
        self.assertEqual(useful["useful_rate"], 0.8)
        self.assertEqual(useful["noisy_rate"], 0.0)
        self.assertEqual(useful["shadow_status"], "utility_watch")
        self.assertFalse(useful["production_change_allowed"])
        self.assertEqual(len(useful["useful_rate_wilson_95"]), 2)

        noisy = by_signal["javascript_chunk_added"]
        self.assertEqual(noisy["feedback_count"], 5)
        self.assertEqual(noisy["noisy_rate"], 0.6)
        self.assertEqual(noisy["shadow_status"], "noise_watch")
        self.assertFalse(noisy["production_change_allowed"])

        small = by_signal["source_map_source_added"]
        self.assertEqual(small["feedback_count"], 4)
        self.assertEqual(small["shadow_status"], "insufficient_feedback")

        self.assertNotIn("javascript_chunk_removed", by_signal)
        self.assertEqual(report["activation"], "shadow_only")
        self.assertFalse(report["interpretation"]["production_activation"])
        self.assertFalse(report["interpretation"]["auto_tuning"])
        self.assertFalse(report["interpretation"]["threshold_learning"])
        self.assertFalse(report["interpretation"]["weight_learning"])
        self.assertTrue(report["interpretation"]["human_review_required"])
        self.assertTrue(report["safety"]["shadow_only"])
        self.assertFalse(report["safety"]["may_change_meta_ranker_weights"])
        self.assertFalse(report["safety"]["may_change_queue_score"])
        self.assertFalse(report["safety"]["may_change_task_ordering"])
        self.assertFalse(report["safety"]["network_requests"])

    def test_report_is_read_only_and_family_slices_do_not_activate_production(self) -> None:
        before_tasks = self.db.one(
            "SELECT COUNT(*) c FROM case_autopilot_tasks"
        )["c"]
        before_events = self.db.one(
            "SELECT COUNT(*) c FROM security_case_events"
        )["c"]

        report = change_guidance_calibration_report(self.db, target="example.test")

        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM case_autopilot_tasks")["c"],
            before_tasks,
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM security_case_events")["c"],
            before_events,
        )
        self.assertTrue(report["signal_family_slices"])
        for row in report["signal_family_slices"]:
            self.assertFalse(row["production_change_allowed"])
        self.assertEqual(
            report["status_counts"]["insufficient_feedback"],
            1,
        )
        self.assertEqual(report["status_counts"]["utility_watch"], 1)
        self.assertEqual(report["status_counts"]["noise_watch"], 1)

    def test_dashboard_panel_makes_shadow_boundary_explicit(self) -> None:
        report = change_guidance_calibration_report(self.db, target="example.test")
        html = _change_guidance_calibration_panel(report)
        for text in (
            "Change-guidance Calibration",
            "Shadow report",
            "Review signal quality",
            "do not tune production",
            "source_map_source_changed",
            "javascript_chunk_added",
            "utility watch",
            "noise watch",
            "no production activation path exists",
        ):
            self.assertIn(text, html)

    def test_api_and_cli_expose_calibration_and_safety_contract(self) -> None:
        with mock.patch("api_server.investigation_queue", return_value=[]):
            api_payload = api_server.investigation_queue_payload(
                self.db,
                analysis_id="AN-P9",
                target="example.test",
                limit=5,
            )
        with mock.patch("recon_monitor.investigation_queue", return_value=[]):
            cli_payload = recon_monitor.investigation_queue_cli_payload(
                self.db,
                analysis_id="AN-P9",
                target="example.test",
                limit=5,
            )

        for payload in (api_payload, cli_payload):
            calibration = payload["change_guidance_calibration"]
            self.assertEqual(calibration["activation"], "shadow_only")
            self.assertEqual(calibration["feedback_count"], 14)
            self.assertIn("change_guidance_calibration", payload["engines"])
            self.assertTrue(
                payload["safety"]["change_guidance_calibration_is_shadow_only"]
            )
            self.assertTrue(
                payload["safety"]["change_guidance_calibration_cannot_auto_tune"]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_calibration_cannot_change_weights_or_thresholds"
                ]
            )


if __name__ == "__main__":
    unittest.main()

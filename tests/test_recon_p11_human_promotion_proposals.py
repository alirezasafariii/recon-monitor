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
from change_guidance_review_packet import change_guidance_review_packets
from core import AppPaths, Database
from dashboard import _change_guidance_review_packet_panel


class ReconP11HumanPromotionProposalTests(unittest.TestCase):
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
                "AN-P11",
                "RUN-P11",
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
                "note": "fixture feedback",
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

    def _signal(
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
        self._signal(
            "CASE-PROMOTE",
            target="example.test",
            family="broken_object_authorization",
            signal_type="source_map_source_changed",
            previous=["useful", "useful", "useful", "useful", "neutral"],
            recent=["useful", "useful", "useful", "useful", "neutral"],
        )
        self._signal(
            "CASE-NOISE",
            target="example.test",
            family="file_upload",
            signal_type="javascript_chunk_added",
            previous=["useful", "neutral", "neutral", "neutral", "neutral"],
            recent=["noisy", "noisy", "noisy", "noisy", "neutral"],
        )
        self._signal(
            "CASE-DECLINE",
            target="example.test",
            family="graphql_authorization",
            signal_type="source_map_source_added",
            previous=["useful", "useful", "useful", "useful", "neutral"],
            recent=["useful", "useful", "neutral", "neutral", "neutral"],
        )

        self._case(
            "CASE-SPARSE",
            target="example.test",
            family="open_redirect",
        )
        sparse_dates = [
            "2026-08-01T12:00:00Z",
            "2026-08-10T12:00:00Z",
            "2026-09-01T12:00:00Z",
            "2026-09-18T12:00:00Z",
        ]
        for index, usefulness in enumerate(["useful", "neutral", "useful", "noisy"]):
            self._task(
                "CASE-SPARSE",
                index,
                signal_type="source_map_source_removed",
                usefulness=usefulness,
                recorded_at=sparse_dates[index],
            )

        self._signal(
            "CASE-OTHER",
            target="other.test",
            family="file_upload",
            signal_type="javascript_chunk_removed",
            previous=["neutral", "neutral", "neutral", "neutral", "neutral"],
            recent=["noisy", "noisy", "noisy", "noisy", "neutral"],
        )

    def test_packets_require_both_calibration_and_history_and_are_deterministic(self) -> None:
        first = change_guidance_review_packets(
            self.db,
            target="example.test",
        )
        second = change_guidance_review_packets(
            self.db,
            target="example.test",
        )
        self.assertEqual(first, second)
        by_signal = {row["signal_type"]: row for row in first["packets"]}

        promote = by_signal["source_map_source_changed"]
        self.assertEqual(promote["review_status"], "ready_for_manual_review")
        self.assertEqual(
            promote["proposal_direction"],
            "consider_manual_promotion_review",
        )
        self.assertTrue(promote["proposal_id"].startswith("CGRP-"))
        self.assertFalse(promote["production_change_allowed"])
        self.assertFalse(promote["automatic_activation"])
        self.assertTrue(promote["requires_separate_policy_change"])
        self.assertTrue(promote["requires_human_review"])

        noise = by_signal["javascript_chunk_added"]
        self.assertEqual(noise["review_status"], "ready_for_manual_review")
        self.assertEqual(
            noise["proposal_direction"],
            "consider_manual_noise_mitigation_review",
        )

        decline = by_signal["source_map_source_added"]
        self.assertEqual(decline["review_status"], "ready_for_manual_review")
        self.assertEqual(
            decline["proposal_direction"],
            "consider_manual_regression_review",
        )

        sparse = by_signal["source_map_source_removed"]
        self.assertEqual(sparse["review_status"], "collect_more_data")
        self.assertEqual(
            sparse["proposal_direction"],
            "retain_shadow_monitoring",
        )

        self.assertNotIn("javascript_chunk_removed", by_signal)
        self.assertEqual(first["activation"], "human_review_only")
        self.assertEqual(first["ready_for_manual_review_count"], 3)
        self.assertEqual(first["collect_more_data_count"], 1)

    def test_packets_contain_context_but_no_executable_policy_change(self) -> None:
        report = change_guidance_review_packets(
            self.db,
            target="example.test",
        )
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn('"proposed_weight"', encoded)
        self.assertNotIn('"new_weight"', encoded)
        self.assertNotIn('"proposed_threshold"', encoded)
        self.assertNotIn('"patch"', encoded)
        self.assertTrue(report["interpretation"]["proposal_is_not_policy_change"])
        self.assertTrue(
            report["interpretation"]["proposal_is_not_numeric_weight_or_threshold"]
        )
        self.assertTrue(report["interpretation"]["manual_review_is_required"])
        self.assertTrue(
            report["interpretation"]["separate_explicit_policy_change_is_required"]
        )
        self.assertFalse(report["interpretation"]["automatic_activation"])
        self.assertTrue(report["safety"]["human_review_only"])
        self.assertFalse(report["safety"]["may_change_meta_ranker_weights"])
        self.assertFalse(report["safety"]["may_change_thresholds"])
        self.assertFalse(report["safety"]["may_change_queue_score"])
        self.assertFalse(report["safety"]["may_change_task_ordering"])
        self.assertFalse(report["safety"]["may_change_admission"])
        self.assertFalse(report["safety"]["may_change_validation"])
        self.assertFalse(report["safety"]["network_requests"])

        for packet in report["packets"]:
            self.assertTrue(packet["review_checklist"])
            self.assertTrue(packet["prohibited_automatic_actions"])
            self.assertFalse(packet["production_change_allowed"])
            self.assertTrue(packet["recent_target_slices"])
            self.assertTrue(packet["recent_family_slices"])

    def test_report_is_read_only(self) -> None:
        before_tasks = self.db.one(
            "SELECT COUNT(*) c FROM case_autopilot_tasks"
        )["c"]
        before_events = self.db.one(
            "SELECT COUNT(*) c FROM security_case_events"
        )["c"]
        before_audit = self.db.one(
            "SELECT COUNT(*) c FROM audit_log"
        )["c"]

        change_guidance_review_packets(self.db, target="example.test")

        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM case_autopilot_tasks")["c"],
            before_tasks,
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM security_case_events")["c"],
            before_events,
        )
        self.assertEqual(
            self.db.one("SELECT COUNT(*) c FROM audit_log")["c"],
            before_audit,
        )

    def test_dashboard_panel_states_manual_non_executable_boundary(self) -> None:
        report = change_guidance_review_packets(
            self.db,
            target="example.test",
        )
        html = _change_guidance_review_packet_panel(report)
        for text in (
            "Change-guidance Review Packets",
            "human review only",
            "Proposal is not a policy change",
            "ready for manual review",
            "consider manual promotion review",
            "consider manual noise mitigation review",
            "separate explicit code/config proposal",
            "cannot modify ranking",
        ):
            self.assertIn(text, html)

    def test_api_and_cli_expose_review_packet_contract(self) -> None:
        with mock.patch("api_server.investigation_queue", return_value=[]):
            api_payload = api_server.investigation_queue_payload(
                self.db,
                analysis_id="AN-P11",
                target="example.test",
                limit=5,
            )
        with mock.patch("recon_monitor.investigation_queue", return_value=[]):
            cli_payload = recon_monitor.investigation_queue_cli_payload(
                self.db,
                analysis_id="AN-P11",
                target="example.test",
                limit=5,
            )

        for payload in (api_payload, cli_payload):
            packets = payload["change_guidance_review_packets"]
            self.assertEqual(packets["activation"], "human_review_only")
            self.assertEqual(packets["ready_for_manual_review_count"], 3)
            self.assertIn("change_guidance_review_packets", payload["engines"])
            self.assertTrue(
                payload["safety"][
                    "change_guidance_review_packets_are_human_review_only"
                ]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_review_packets_are_non_executable"
                ]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_review_packets_require_separate_policy_change"
                ]
            )


if __name__ == "__main__":
    unittest.main()

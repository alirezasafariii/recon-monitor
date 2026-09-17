from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server
import correlation_engine
import recon_monitor
from dashboard import (
    _investigation_cluster_detail_panel,
    _investigation_queue_panel,
    _queue_item_card,
)


def _admission(*, derived_score: int = 92) -> dict:
    matches = (
        [
            {
                "signal_type": "source_map_source_changed",
                "state_type": "source_map_source",
                "change": "changed",
                "item": "src/admin/orders.ts",
                "item_key": "map:orders",
                "baseline_run_id": "RUN-PREV",
                "score": derived_score,
                "reasons": [
                    "exact source reference changed",
                    "embedded source semantic hash changed",
                ],
            }
        ]
        if derived_score
        else []
    )
    return {
        "admitted": False,
        "derived_change_advisory": {
            "source_run_id": "RUN-P5",
            "score": derived_score or None,
            "matched_signal_count": len(matches),
            "matches": matches,
            "safety": {
                "advisory_only": True,
                "counts_as_target_evidence": False,
                "can_satisfy_admission": False,
            },
        },
        "knowledge_context": {
            "meta_ranker": {
                "primary": {
                    "family": "broken_object_authorization",
                    "label": "BOLA / IDOR",
                    "bug_proximity_score": 74,
                    "target_evidence_confidence": 26,
                    "hunt_priority": "MEDIUM",
                    "components": {
                        "target_evidence": 26,
                        "profile_compatibility": 70,
                        "correlation": 64,
                        "derived_change": derived_score or None,
                    },
                    "why": [
                        "supporting target signals: object_identifier",
                        (
                            f"recent derived Recon change affinity: {derived_score}/100 "
                            "(non-evidentiary)"
                        )
                        if derived_score
                        else "supporting target signals only",
                    ],
                },
                "rankings": [
                    {
                        "family": "broken_object_authorization",
                        "bug_proximity_score": 74,
                    }
                ],
            },
            "derived_change_context": {
                "source_run_id": "RUN-P5",
                "score": derived_score or None,
                "matched_signal_count": len(matches),
                "matches": matches,
            },
        },
    }


class QueueDB:
    def __init__(self, admission: dict) -> None:
        self.admission = admission

    def all(self, query, params=()):
        if "FROM analysis_hypotheses" in query:
            return [
                {
                    "hypothesis_id": "H-P5",
                    "target": "example.test",
                    "asset": "example.test",
                    "endpoint": "/api/admin/orders/{id}",
                    "source_ref": "https://example.test/static/app.js",
                    "alert_id": None,
                    "bug_family": "broken_object_authorization",
                    "state": "shadow_partial",
                    "summary": "changed admin order client surface",
                    "admission_json": json.dumps(self.admission),
                }
            ]
        return []


CORRELATION_CONTEXT = {
    "cluster_id": "cluster-p5",
    "cluster_strength": 70,
    "object_tokens": ["order", "user"],
    "auth_boundaries": ["session_required"],
}


SAMPLE_ITEM = {
    "cluster_id": "cluster-p5",
    "target": "example.test",
    "queue_score": 58,
    "primary_bug": "BOLA / IDOR",
    "primary_family": "broken_object_authorization",
    "bug_proximity_score": 74,
    "target_evidence_confidence": 26,
    "hunt_priority": "MEDIUM",
    "cluster_strength": 70,
    "derived_change_score": 92,
    "derived_change_matched_signals": 1,
    "derived_change_signal_types": ["source_map_source_changed"],
    "derived_change_source_run_ids": ["RUN-P5"],
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
    "endpoints": ["/api/admin/orders/{id}"],
    "hypothesis_ids": ["H-P5"],
    "families": [{"family": "broken_object_authorization", "score": 74}],
    "object_tokens": ["order", "user"],
    "auth_boundaries": ["session_required"],
    "why": [
        "supporting target signals: object_identifier",
        "recent derived Recon change affinity: 92/100 (non-evidentiary)",
    ],
    "status": "investigation_queue_not_confirmed",
}


class ReconP5ChangeLinkedInvestigationTests(unittest.TestCase):
    def _queue(self, derived_score: int) -> list[dict]:
        with mock.patch.object(
            correlation_engine,
            "build_correlation_context",
            return_value=dict(CORRELATION_CONTEXT),
        ):
            return correlation_engine.investigation_queue(
                QueueDB(_admission(derived_score=derived_score)),
                "AN-P5",
                target="example.test",
                limit=20,
            )

    def test_queue_surfaces_bounded_change_provenance(self) -> None:
        item = self._queue(92)[0]
        self.assertEqual(item["derived_change_score"], 92)
        self.assertTrue(item["change_linked"])
        self.assertTrue(item["derived_change_advisory_only"])
        self.assertEqual(item["derived_change_matched_signals"], 1)
        self.assertEqual(
            item["derived_change_signal_types"],
            ["source_map_source_changed"],
        )
        self.assertEqual(item["derived_change_source_run_ids"], ["RUN-P5"])
        self.assertEqual(
            item["derived_change_matches"][0]["item"],
            "src/admin/orders.ts",
        )
        self.assertEqual(
            item["derived_change_matches"][0]["reasons"],
            [
                "exact source reference changed",
                "embedded source semantic hash changed",
            ],
        )

    def test_queue_score_does_not_double_count_change_prior(self) -> None:
        linked = self._queue(92)[0]
        neutral = self._queue(0)[0]
        self.assertEqual(linked["bug_proximity_score"], neutral["bug_proximity_score"])
        self.assertEqual(
            linked["target_evidence_confidence"],
            neutral["target_evidence_confidence"],
        )
        self.assertEqual(linked["cluster_strength"], neutral["cluster_strength"])
        self.assertEqual(linked["hunt_priority"], neutral["hunt_priority"])
        self.assertEqual(linked["queue_score"], neutral["queue_score"])
        self.assertEqual(linked["queue_score"], 58)

    def test_dashboard_card_and_panel_show_advisory_change_context(self) -> None:
        card = _queue_item_card(dict(SAMPLE_ITEM))
        self.assertIn("change-linked", card)
        self.assertIn("Recent change", card)
        self.assertIn("source_map_source_changed", card)
        self.assertIn("src/admin/orders.ts", card)
        self.assertIn("not counted again in Queue score", card)
        self.assertIn("non-evidentiary", card)

        panel = _investigation_queue_panel("AN-P5", [dict(SAMPLE_ITEM)])
        self.assertIn("Change-linked", panel)
        self.assertIn("recent source-map/chunk affinity", panel)
        self.assertIn("not double-counted", panel)

    def test_drilldown_shows_change_affinity_as_non_evidentiary_component(self) -> None:
        detail = {
            "item": dict(SAMPLE_ITEM),
            "hypotheses": [],
            "candidates": [],
            "support": [],
            "contradict": [],
            "missing": [],
            "decisive": [],
            "primary_meta": {
                "why": SAMPLE_ITEM["why"],
                "components": {
                    "target_evidence": 26,
                    "profile_compatibility": 70,
                    "correlation": 64,
                    "derived_change": 92,
                },
            },
            "correlation": {"related_surfaces": [], "edges": []},
            "workflow": {"status": "unavailable"},
        }
        html = _investigation_cluster_detail_panel("AN-P5", detail)
        self.assertIn("Recent Recon change context", html)
        self.assertIn("Recent Recon change affinity", html)
        self.assertIn("source_map_source_changed", html)
        self.assertIn("Advisory only", html)
        self.assertIn("cannot satisfy Admission", html)
        self.assertIn("Queue score does not count it a second time", html)

    def test_api_and_cli_expose_change_advisory_safety_contract(self) -> None:
        with mock.patch(
            "api_server.investigation_queue",
            return_value=[dict(SAMPLE_ITEM)],
        ):
            api_payload = api_server.investigation_queue_payload(
                object(),
                analysis_id="AN-P5",
                target="example.test",
                limit=5,
            )
        with mock.patch(
            "recon_monitor.investigation_queue",
            return_value=[dict(SAMPLE_ITEM)],
        ):
            cli_payload = recon_monitor.investigation_queue_cli_payload(
                object(),
                analysis_id="AN-P5",
                target="example.test",
                limit=5,
            )

        for payload in (api_payload, cli_payload):
            self.assertIn("derived_change_advisory", payload["engines"])
            self.assertTrue(payload["safety"]["derived_change_is_advisory_only"])
            self.assertTrue(
                payload["safety"]["derived_change_cannot_satisfy_admission"]
            )
            self.assertTrue(
                payload["safety"][
                    "derived_change_is_not_double_counted_in_queue_score"
                ]
            )
            self.assertEqual(payload["items"][0]["derived_change_score"], 92)


if __name__ == "__main__":
    unittest.main()

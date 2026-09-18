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
from change_guidance_policy_proposal import (
    CHANGE_GUIDANCE_POLICY_PROPOSAL_SCHEMA_VERSION,
    create_policy_change_proposal,
    current_policy_snapshot,
    decide_policy_change_proposal,
    ensure_change_guidance_policy_proposal_schema,
    list_policy_change_proposals,
    submit_policy_change_proposal,
    supported_policy_surfaces,
)
from core import AppPaths, Database, ReconError
from dashboard import _change_guidance_policy_proposal_panel


READY_PACKET = {
    "proposal_id": "CGRP-fixture-ready",
    "signal_type": "source_map_source_changed",
    "review_status": "ready_for_manual_review",
    "proposal_direction": "consider_manual_promotion_review",
    "review_rationale": "Strong explicit utility with stable longitudinal monitoring.",
    "calibration": {
        "shadow_status": "utility_watch",
        "feedback_count": 12,
        "useful_rate": 0.75,
        "noisy_rate": 0.08,
    },
    "drift": {
        "drift_status": "stable",
        "history_sufficient": True,
        "anchor_at": "2026-09-18T12:00:00Z",
    },
    "recent_target_slices": [
        {
            "signal_type": "source_map_source_changed",
            "target": "example.test",
            "feedback_count": 8,
        }
    ],
    "recent_family_slices": [
        {
            "signal_type": "source_map_source_changed",
            "family": "broken_object_authorization",
            "feedback_count": 7,
        }
    ],
}

NOT_READY_PACKET = {
    **READY_PACKET,
    "proposal_id": "CGRP-fixture-not-ready",
    "signal_type": "javascript_chunk_added",
    "review_status": "collect_more_data",
    "proposal_direction": "retain_shadow_monitoring",
}

PACKET_REPORT = {
    "activation": "human_review_only",
    "packets": [READY_PACKET, NOT_READY_PACKET],
}


class ReconP12PolicyChangeProposalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(self.temp.name))
        paths.ensure()
        self.db = Database(paths.db)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _create(
        self,
        *,
        after: dict | None = None,
        rationale: str = "Review a lower advisory weight based on explicit analyst feedback.",
        rollback: str = "Restore the current derived-change weight and rerun the full regression suite.",
        tests: list[str] | None = None,
    ) -> dict:
        return create_policy_change_proposal(
            self.db,
            source_packet_id="CGRP-fixture-ready",
            target="example.test",
            policy_surface="meta_ranker.derived_change_weight",
            after=after or {"derived_change_weight": 0.06},
            rationale=rationale,
            rollback_plan=rollback,
            test_requirements=tests
            or [
                "Run unit and integration suites on Python 3.11 and 3.13",
                "Verify zero-evidence proximity cap remains unchanged",
                "Compare shadow calibration before and after the separate implementation",
            ],
            actor="alice",
            review_packet_report=PACKET_REPORT,
        )

    def test_additive_schema_and_supported_current_policy_snapshots(self) -> None:
        ensure_change_guidance_policy_proposal_schema(self.db)
        self.assertEqual(
            self.db.meta_get("change_guidance_policy_proposal_schema_version"),
            str(CHANGE_GUIDANCE_POLICY_PROPOSAL_SCHEMA_VERSION),
        )
        tables = {
            row[0]
            for row in self.db.all(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("change_guidance_policy_proposals", tables)

        surfaces = supported_policy_surfaces()
        self.assertEqual(
            surfaces,
            [
                "change_guidance.calibration_sample_gate",
                "change_guidance.drift_window_and_sample_gate",
                "meta_ranker.derived_change_weight",
            ],
        )
        current = current_policy_snapshot("meta_ranker.derived_change_weight")
        self.assertEqual(current["derived_change_weight"], 0.08)
        self.assertIn("meta_ranker_version", current)

    def test_creation_requires_ready_packet_and_persists_before_after_diff_rollback_tests(self) -> None:
        proposal = self._create()
        self.assertEqual(proposal["proposal_version"], 1)
        self.assertEqual(proposal["state"], "draft")
        self.assertEqual(proposal["source_packet_id"], "CGRP-fixture-ready")
        self.assertEqual(
            proposal["policy_surface"],
            "meta_ranker.derived_change_weight",
        )
        self.assertEqual(proposal["before"]["derived_change_weight"], 0.08)
        self.assertEqual(proposal["after"]["derived_change_weight"], 0.06)
        self.assertEqual(
            proposal["diff"],
            [
                {
                    "field": "derived_change_weight",
                    "before": 0.08,
                    "after": 0.06,
                }
            ],
        )
        self.assertIn("Restore the current", proposal["rollback_plan"])
        self.assertGreaterEqual(len(proposal["test_requirements"]), 2)
        self.assertFalse(proposal["production_applied"])
        self.assertFalse(proposal["apply_available"])
        self.assertFalse(proposal["safety"]["production_change_applied"])
        self.assertFalse(proposal["safety"]["apply_endpoint_exists"])
        self.assertTrue(
            proposal["safety"]["requires_separate_code_or_config_change"]
        )

        audit = self.db.one(
            "SELECT action,details_json FROM audit_log "
            "WHERE entity_value=? ORDER BY id DESC LIMIT 1",
            (proposal["proposal_version_id"],),
        )
        self.assertEqual(audit["action"], "change_guidance_policy_proposal_created")
        details = json.loads(audit["details_json"])
        self.assertFalse(details["production_change_applied"])

        with self.assertRaisesRegex(ReconError, "not ready"):
            create_policy_change_proposal(
                self.db,
                source_packet_id="CGRP-fixture-not-ready",
                target="example.test",
                policy_surface="meta_ranker.derived_change_weight",
                after={"derived_change_weight": 0.05},
                rationale="Would otherwise be a proposal.",
                rollback_plan="Restore current weight.",
                test_requirements=["Run tests"],
                review_packet_report=PACKET_REPORT,
            )

    def test_idempotency_amendment_versioning_and_terminal_acceptance(self) -> None:
        first = self._create()
        same = self._create()
        self.assertEqual(
            same["proposal_version_id"],
            first["proposal_version_id"],
        )

        second = self._create(
            after={"derived_change_weight": 0.05},
            rationale="Amended candidate after additional human review.",
        )
        self.assertEqual(second["proposal_version"], 2)
        self.assertNotEqual(
            second["proposal_version_id"],
            first["proposal_version_id"],
        )
        previous = self.db.one(
            "SELECT state FROM change_guidance_policy_proposals "
            "WHERE proposal_version_id=?",
            (first["proposal_version_id"],),
        )
        self.assertEqual(previous["state"], "superseded")

        submitted = submit_policy_change_proposal(
            self.db,
            second["proposal_version_id"],
            actor="reviewer",
        )
        self.assertEqual(submitted["state"], "under_review")

        accepted = decide_policy_change_proposal(
            self.db,
            second["proposal_version_id"],
            decision="accept",
            note="Accepted only for a separate implementation PR with the listed tests.",
            actor="reviewer",
        )
        self.assertEqual(
            accepted["state"],
            "accepted_for_separate_implementation",
        )
        self.assertFalse(accepted["production_applied"])
        self.assertFalse(accepted["apply_available"])

        with self.assertRaisesRegex(ReconError, "cannot be amended"):
            self._create(
                after={"derived_change_weight": 0.04},
                rationale="Attempt to mutate an already accepted proposal.",
            )

        events = self.db.all(
            "SELECT action FROM audit_log WHERE entity_value=? ORDER BY id",
            (second["proposal_version_id"],),
        )
        self.assertEqual(
            [row["action"] for row in events],
            [
                "change_guidance_policy_proposal_created",
                "change_guidance_policy_proposal_submitted",
                "change_guidance_policy_proposal_decided",
            ],
        )

    def test_state_machine_rejects_invalid_transitions_and_invalid_candidate_shapes(self) -> None:
        draft = self._create()
        with self.assertRaisesRegex(ReconError, "under-review"):
            decide_policy_change_proposal(
                self.db,
                draft["proposal_version_id"],
                decision="accept",
                note="Too early",
            )

        submitted = submit_policy_change_proposal(
            self.db,
            draft["proposal_version_id"],
        )
        rejected = decide_policy_change_proposal(
            self.db,
            submitted["proposal_version_id"],
            decision="reject",
            note="Insufficient confidence to justify a separate implementation.",
        )
        self.assertEqual(rejected["state"], "rejected")

        with self.assertRaisesRegex(ReconError, "Only draft"):
            submit_policy_change_proposal(
                self.db,
                rejected["proposal_version_id"],
            )

        with self.assertRaisesRegex(ReconError, "must contain only"):
            create_policy_change_proposal(
                self.db,
                source_packet_id="CGRP-fixture-ready",
                target="example.test",
                policy_surface="meta_ranker.derived_change_weight",
                after={"derived_change_weight": 0.06, "other": 1},
                rationale="Invalid shape fixture.",
                rollback_plan="Rollback fixture.",
                test_requirements=["test"],
                review_packet_report=PACKET_REPORT,
            )
        with self.assertRaisesRegex(ReconError, "between 0.0 and 0.5"):
            create_policy_change_proposal(
                self.db,
                source_packet_id="CGRP-fixture-ready",
                target="example.test",
                policy_surface="meta_ranker.derived_change_weight",
                after={"derived_change_weight": 0.9},
                rationale="Invalid range fixture.",
                rollback_plan="Rollback fixture.",
                test_requirements=["test"],
                review_packet_report=PACKET_REPORT,
            )

    def test_dashboard_panel_exposes_draft_review_decision_but_no_apply_action(self) -> None:
        draft = self._create()
        html = _change_guidance_policy_proposal_panel(
            PACKET_REPORT,
            [draft],
            target="example.test",
        )
        for text in (
            "Explicit Policy-change Proposals",
            "Accepted does not mean applied",
            "/investigation/policy-proposal/create",
            "/investigation/policy-proposal/submit",
            "Draft versioned proposal",
            "Current supported policy snapshots",
            "separate code/config change",
        ):
            self.assertIn(text, html)
        self.assertNotIn("/investigation/policy-proposal/apply", html)

        submitted = submit_policy_change_proposal(
            self.db,
            draft["proposal_version_id"],
        )
        html = _change_guidance_policy_proposal_panel(
            PACKET_REPORT,
            [submitted],
            target="example.test",
        )
        self.assertIn("/investigation/policy-proposal/decision", html)
        self.assertIn("Accept for separate implementation", html)
        self.assertNotIn("/investigation/policy-proposal/apply", html)

    def test_api_and_cli_expose_proposal_ledger_safety_contract(self) -> None:
        proposal = self._create()
        with mock.patch("api_server.investigation_queue", return_value=[]):
            api_payload = api_server.investigation_queue_payload(
                self.db,
                analysis_id="AN-P12",
                target="example.test",
                limit=5,
            )
        with mock.patch("recon_monitor.investigation_queue", return_value=[]):
            cli_payload = recon_monitor.investigation_queue_cli_payload(
                self.db,
                analysis_id="AN-P12",
                target="example.test",
                limit=5,
            )

        for payload in (api_payload, cli_payload):
            proposals = payload["change_guidance_policy_proposals"]
            self.assertEqual(len(proposals), 1)
            self.assertEqual(
                proposals[0]["proposal_version_id"],
                proposal["proposal_version_id"],
            )
            self.assertFalse(proposals[0]["apply_available"])
            self.assertIn("change_guidance_policy_proposals", payload["engines"])
            self.assertTrue(
                payload["safety"][
                    "change_guidance_policy_proposals_are_versioned_and_audited"
                ]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_policy_proposals_have_no_apply_endpoint"
                ]
            )
            self.assertTrue(
                payload["safety"][
                    "change_guidance_policy_proposals_cannot_change_production"
                ]
            )


if __name__ == "__main__":
    unittest.main()

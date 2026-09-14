from __future__ import annotations

import pathlib
import sys
import unittest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from core import ReconError
from reviewed_evidence_admission import (
    REVIEWED_EVIDENCE_ADMISSION_VERSION,
    ReviewedAdmissionConfig,
    _eligibility,
    _validated_identifier,
)


class ReviewedEvidenceAdmissionFrameworkTests(unittest.TestCase):
    def _config(self) -> ReviewedAdmissionConfig:
        return ReviewedAdmissionConfig(
            version="1.0.0",
            family="example_family",
            id_name="review_id",
            id_prefix="REV-",
            review_table="example_review_runs",
            review_id_column="review_id",
            bridge_table="example_bridge_runs",
            bridge_id_column="review_id",
            evidence_type="reviewed_direct_observation",
            source_kind="analyst_verified_review",
            direct_signals=frozenset({"direct_observation"}),
            structural_groups=(frozenset({"surface"}), frozenset({"context"})),
            blocking_types=frozenset({"control_observed"}),
            support_source="analyst_verified_review",
            support_group_prefix="reviewed",
            support_text="Reviewed direct observation.",
            support_weights={"direct_observation": 40},
            rule_id="reviewed-admission-v1",
            source_ref_prefix="reviewed",
            default_variant="reviewed_direct",
            default_summary="Potential reviewed observation.",
            candidate_summary="Potential Finding supported by reviewed evidence.",
            confidence=85,
            relation_template="reviewed:{signal}",
            audit_event="reviewed_admission_applied",
        )

    def test_framework_version_is_explicit(self) -> None:
        self.assertEqual(REVIEWED_EVIDENCE_ADMISSION_VERSION, "1.0.0")

    def test_eligibility_requires_reviewed_direct_evidence_and_structure(self) -> None:
        config = self._config()
        review = {"signal_type": "direct_observation", "polarity": "support"}
        evidence = {
            "evidence_type": "reviewed_direct_observation",
            "polarity": "support",
            "source_kind": "analyst_verified_review",
            "directness": "direct",
        }
        hypothesis = {
            "bug_family": "example_family",
            "supporting_evidence_json": [
                {"type": "surface", "source_group": "one"},
                {"type": "context", "source_group": "two"},
            ],
            "contradicting_evidence_json": [],
        }
        eligible, reason, signal = _eligibility(config, review, evidence, hypothesis)
        self.assertTrue(eligible)
        self.assertEqual(reason, "eligible")
        self.assertEqual(signal, "direct_observation")

    def test_blocking_control_fails_closed(self) -> None:
        config = self._config()
        review = {"signal_type": "direct_observation", "polarity": "support"}
        evidence = {
            "evidence_type": "reviewed_direct_observation",
            "polarity": "support",
            "source_kind": "analyst_verified_review",
            "directness": "direct",
        }
        hypothesis = {
            "bug_family": "example_family",
            "supporting_evidence_json": [{"type": "surface"}, {"type": "context"}],
            "contradicting_evidence_json": [{"type": "control_observed"}],
        }
        eligible, reason, _ = _eligibility(config, review, evidence, hypothesis)
        self.assertFalse(eligible)
        self.assertEqual(reason, "blocking_contradiction_present")

    def test_missing_structural_group_fails_closed(self) -> None:
        config = self._config()
        review = {"signal_type": "direct_observation", "polarity": "support"}
        evidence = {
            "evidence_type": "reviewed_direct_observation",
            "polarity": "support",
            "source_kind": "analyst_verified_review",
            "directness": "direct",
        }
        hypothesis = {
            "bug_family": "example_family",
            "supporting_evidence_json": [{"type": "surface"}],
            "contradicting_evidence_json": [],
        }
        eligible, reason, _ = _eligibility(config, review, evidence, hypothesis)
        self.assertFalse(eligible)
        self.assertEqual(reason, "missing_structural_context_group_2")

    def test_wrong_provenance_is_rejected(self) -> None:
        config = self._config()
        review = {"signal_type": "direct_observation", "polarity": "support"}
        evidence = {
            "evidence_type": "reviewed_direct_observation",
            "polarity": "support",
            "source_kind": "untrusted_source",
            "directness": "direct",
        }
        hypothesis = {
            "bug_family": "example_family",
            "supporting_evidence_json": [{"type": "surface"}, {"type": "context"}],
            "contradicting_evidence_json": [],
        }
        eligible, reason, _ = _eligibility(config, review, evidence, hypothesis)
        self.assertFalse(eligible)
        self.assertEqual(reason, "review_source_kind_mismatch")

    def test_dynamic_sql_identifiers_are_strictly_validated(self) -> None:
        self.assertEqual(_validated_identifier("review_runs_1"), "review_runs_1")
        for value in ("review-runs", "review runs", "x;drop_table", "1review"):
            with self.assertRaises(ReconError):
                _validated_identifier(value)

    def test_framework_source_has_no_network_client(self) -> None:
        source = (APP_DIR / "reviewed_evidence_admission.py").read_text(encoding="utf-8").lower()
        for token in ("urllib.request", "requests.", "urlopen(", "socket.", "http.client"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()

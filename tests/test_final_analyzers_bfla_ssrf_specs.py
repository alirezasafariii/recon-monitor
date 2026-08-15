from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.bfla import BFLA_FALSE_POSITIVE_CHECKS, BFLA_METHOD, BFLA_SPEC, BFLA_TAXONOMY
from family_analyzers.ssrf import SSRF_FALSE_POSITIVE_CHECKS, SSRF_METHOD, SSRF_SPEC, SSRF_TAXONOMY
from family_specs.knowledge_projection import (
    family_knowledge_projection,
    taxonomy_projection,
    validate_knowledge_projection,
)
from family_specs.registry import MIGRATED_FAMILIES, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersBflaSsrfSpecTests(unittest.TestCase):
    def test_registry_covers_three_reference_families_without_drift(self) -> None:
        self.assertEqual(
            MIGRATED_FAMILIES,
            ("broken_object_authorization", "broken_function_authorization", "ssrf"),
        )
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)

    def test_bfla_compatibility_and_knowledge_are_spec_projections(self) -> None:
        self.assertEqual(BFLA_TAXONOMY, BFLA_SPEC.taxonomy())
        self.assertEqual(BFLA_METHOD, tuple(step.as_dict() for step in BFLA_SPEC.standard.methodology))
        self.assertEqual(BFLA_FALSE_POSITIVE_CHECKS, BFLA_SPEC.standard.false_positive_checks)
        self.assertEqual(taxonomy_for_family(BFLA_SPEC.family), taxonomy_projection(BFLA_SPEC))
        self.assertEqual(BUILTIN_KNOWLEDGE[BFLA_SPEC.family], family_knowledge_projection(BFLA_SPEC))
        self.assertEqual(validate_knowledge_projection(BFLA_SPEC), [])
        ids = {str(doc.get("id") or "") for doc in BUILTIN_KNOWLEDGE[BFLA_SPEC.family]}
        self.assertIn("capec-122", ids)
        self.assertTrue({item.id for item in BFLA_SPEC.standard.writeups} <= ids)
        self.assertTrue(all(doc.get("counts_as_target_evidence") is False for doc in BUILTIN_KNOWLEDGE[BFLA_SPEC.family]))
        self.assertTrue(all("type" not in doc for doc in BUILTIN_KNOWLEDGE[BFLA_SPEC.family]))

    def test_ssrf_compatibility_and_knowledge_are_spec_projections(self) -> None:
        self.assertEqual(SSRF_TAXONOMY, SSRF_SPEC.taxonomy())
        self.assertEqual(SSRF_METHOD, tuple(step.as_dict() for step in SSRF_SPEC.standard.methodology))
        self.assertEqual(SSRF_FALSE_POSITIVE_CHECKS, SSRF_SPEC.standard.false_positive_checks)
        self.assertEqual(taxonomy_for_family(SSRF_SPEC.family), taxonomy_projection(SSRF_SPEC))
        self.assertEqual(BUILTIN_KNOWLEDGE[SSRF_SPEC.family], family_knowledge_projection(SSRF_SPEC))
        self.assertEqual(validate_knowledge_projection(SSRF_SPEC), [])
        ids = {str(doc.get("id") or "") for doc in BUILTIN_KNOWLEDGE[SSRF_SPEC.family]}
        self.assertIn("capec-664", ids)
        self.assertIn("ghsl-wekan-2026-045", ids)
        self.assertTrue(all(doc.get("counts_as_target_evidence") is False for doc in BUILTIN_KNOWLEDGE[SSRF_SPEC.family]))
        self.assertTrue(all("type" not in doc for doc in BUILTIN_KNOWLEDGE[SSRF_SPEC.family]))

    def test_bfla_surface_only_stays_hidden(self) -> None:
        result = assess_admission(
            "broken_function_authorization",
            [
                {"type": "privileged_function", "source_group": "function-surface"},
                {"type": "state_change", "source_group": "function-operation"},
            ],
        )
        self.assertFalse(result["admitted"])
        missing = [set(group) for group in result["required_missing"]]
        self.assertTrue(any("unauthorized_function_success" in group for group in missing))

    def test_bfla_target_boundary_evidence_can_promote(self) -> None:
        result = assess_admission(
            "broken_function_authorization",
            [
                {"type": "privileged_function", "source_group": "function-surface"},
                {"type": "state_change", "source_group": "function-operation"},
                {"type": "unauthorized_function_success", "source_group": "controlled-role-boundary"},
            ],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")

    def test_ssrf_structural_surface_stays_hidden(self) -> None:
        result = assess_admission(
            "ssrf",
            [
                {"type": "remote_destination", "source_group": "endpoint-contract"},
                {"type": "server_feature", "source_group": "semantic-feature"},
            ],
        )
        self.assertFalse(result["admitted"])
        missing = [set(group) for group in result["required_missing"]]
        self.assertTrue(any("server_fetch_observed" in group for group in missing))

    def test_ssrf_stored_server_fetch_can_promote_but_not_confirm(self) -> None:
        result = assess_admission(
            "ssrf",
            [
                {"type": "remote_destination", "source_group": "endpoint-contract"},
                {"type": "server_feature", "source_group": "semantic-feature"},
                {"type": "server_fetch_observed", "source_group": "controlled-runtime"},
            ],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")
        self.assertEqual(
            result["confirmation_required"],
            [["destination_policy_bypass_observed", "restricted_destination_accepted"]],
        )

    def test_ssrf_destination_control_blocks_plain_server_fetch(self) -> None:
        result = assess_admission(
            "ssrf",
            [
                {"type": "remote_destination", "source_group": "endpoint-contract"},
                {"type": "server_feature", "source_group": "semantic-feature"},
                {"type": "server_fetch_observed", "source_group": "controlled-runtime"},
            ],
            [{"type": "destination_validation_observed", "source_group": "controlled-runtime"}],
        )
        self.assertFalse(result["admitted"])
        self.assertEqual(result["state"], "shadow_contradicted")
        self.assertIn("destination_validation_observed", result["blocking_contradictions"])

    def test_ssrf_real_boundary_failure_can_override_control_evidence(self) -> None:
        result = assess_admission(
            "ssrf",
            [
                {"type": "remote_destination", "source_group": "endpoint-contract"},
                {"type": "server_feature", "source_group": "semantic-feature"},
                {"type": "server_fetch_observed", "source_group": "controlled-runtime"},
                {"type": "destination_policy_bypass_observed", "source_group": "controlled-runtime"},
            ],
            [{"type": "destination_validation_observed", "source_group": "controlled-runtime"}],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")


if __name__ == "__main__":
    unittest.main()

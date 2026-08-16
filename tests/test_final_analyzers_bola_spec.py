from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.bola import BOLA_FALSE_POSITIVE_CHECKS, BOLA_METHOD, BOLA_SPEC
from family_reasoning import FAMILY_REASONING
from family_specs.knowledge_projection import (
    family_knowledge_projection,
    taxonomy_projection,
    validate_knowledge_projection,
    writeup_knowledge_projection,
)
from family_specs.registry import registry_status, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import (
    BUILTIN_KNOWLEDGE,
    SPEC_KNOWLEDGE_ERRORS,
    knowledge_for_family,
    taxonomy_for_family,
)


class FinalAnalyzersBolaSpecTests(unittest.TestCase):
    family = "broken_object_authorization"

    def test_registry_is_drift_free(self) -> None:
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertEqual(registry_status()["coverage_mode"], "incremental_reference_implementation")

    def test_detection_spec_projects_live_reasoning_contract(self) -> None:
        live = FAMILY_REASONING[self.family]
        self.assertEqual(BOLA_SPEC.promotion_required, tuple(frozenset(group) for group in live["promotion_required"]))
        self.assertEqual(BOLA_SPEC.confirmation_required, tuple(frozenset(group) for group in live["confirmation_required"]))
        self.assertEqual(BOLA_SPEC.blocking_contradictions, live["blocking_contradictions"])
        self.assertEqual(BOLA_SPEC.override_signals, live["override_signals"])
        self.assertEqual(BOLA_SPEC.min_independent_sources, live["min_independent_sources"])

    def test_standards_and_writeups_are_non_evidentiary(self) -> None:
        self.assertTrue(BOLA_SPEC.standard.owasp)
        self.assertTrue(BOLA_SPEC.standard.wstg)
        self.assertTrue(BOLA_SPEC.standard.cwe)
        self.assertTrue(BOLA_SPEC.standard.writeups)
        self.assertTrue(all(not item.counts_as_target_evidence for item in BOLA_SPEC.standard.writeups))

    def test_analyzer_compatibility_exports_come_from_spec(self) -> None:
        self.assertEqual(BOLA_METHOD, tuple(step.as_dict() for step in BOLA_SPEC.standard.methodology))
        self.assertEqual(BOLA_FALSE_POSITIVE_CHECKS, BOLA_SPEC.standard.false_positive_checks)

    def test_knowledge_projection_is_drift_free(self) -> None:
        self.assertEqual(validate_knowledge_projection(BOLA_SPEC), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)

    def test_knowledge_taxonomy_and_documents_come_from_spec(self) -> None:
        self.assertEqual(taxonomy_for_family(self.family), taxonomy_projection(BOLA_SPEC))
        self.assertEqual(BUILTIN_KNOWLEDGE[self.family], family_knowledge_projection(BOLA_SPEC))
        ids = {str(item["id"]) for item in BUILTIN_KNOWLEDGE[self.family]}
        self.assertIn("owasp-api1-2023", ids)
        self.assertTrue({item.id for item in BOLA_SPEC.standard.writeups} <= ids)

    def test_knowledge_writeups_are_exact_non_evidentiary_subset(self) -> None:
        projected = BUILTIN_KNOWLEDGE[self.family]
        writeup_ids = {str(item["id"]) for item in writeup_knowledge_projection(BOLA_SPEC)}
        actual_writeup_ids = {
            str(item["id"])
            for item in projected
            if str(item.get("relation") or "") != "standard"
        }
        self.assertEqual(actual_writeup_ids, writeup_ids)
        self.assertTrue(all(item.get("counts_as_target_evidence") is False for item in projected))
        self.assertTrue(all("type" not in item for item in projected))

        public_docs = knowledge_for_family(self.family)
        public_ids = {str(item.get("id") or "") for item in public_docs}
        self.assertIn("owasp-api1-2023", public_ids)
        self.assertTrue(writeup_ids <= public_ids)
        self.assertTrue(all("type" not in item for item in public_docs))

    def test_surface_only_bola_stays_hidden(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "object_identifier", "source_group": "endpoint-contract"},
                {"type": "object_operation", "source_group": "semantic-operation"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertIn(result["state"], {"shadow_partial", "shadow_signal"})
        self.assertTrue(result["required_missing"])

    def test_target_boundary_evidence_can_satisfy_admission(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "object_identifier", "source_group": "endpoint-contract"},
                {"type": "object_operation", "source_group": "semantic-operation"},
                {"type": "cross_identity_object_access", "source_group": "controlled-observation"},
            ],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")
        self.assertGreaterEqual(result["independent_sources"], 2)


if __name__ == "__main__":
    unittest.main()

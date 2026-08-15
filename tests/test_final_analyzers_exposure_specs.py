from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.account_enumeration import (
    ACCOUNT_ENUMERATION_METHOD,
    ACCOUNT_ENUMERATION_SPEC,
    ACCOUNT_ENUMERATION_TAXONOMY,
)
from family_analyzers.information_disclosure import (
    INFORMATION_DISCLOSURE_METHOD,
    INFORMATION_DISCLOSURE_SPEC,
    INFORMATION_DISCLOSURE_TAXONOMY,
)
from family_analyzers.secret_exposure import (
    SECRET_EXPOSURE_METHOD,
    SECRET_EXPOSURE_SPEC,
    SECRET_EXPOSURE_TAXONOMY,
)
from family_analyzers.source_map_exposure import (
    SOURCE_MAP_EXPOSURE_METHOD,
    SOURCE_MAP_EXPOSURE_SPEC,
    SOURCE_MAP_EXPOSURE_TAXONOMY,
)
from family_specs.knowledge_projection import family_knowledge_projection, taxonomy_projection, validate_knowledge_projection
from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersExposureSpecTests(unittest.TestCase):
    families = ("account_enumeration", "information_disclosure", "source_map_exposure", "secret_exposure")

    def test_registry_and_knowledge_are_drift_free(self):
        self.assertEqual(len(MIGRATED_FAMILIES), 17)
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)
        for family in self.families:
            spec = get_detection_spec(family)
            self.assertEqual(validate_knowledge_projection(spec), [])
            self.assertEqual(taxonomy_for_family(family), taxonomy_projection(spec))
            self.assertEqual(BUILTIN_KNOWLEDGE[family], family_knowledge_projection(spec))
            self.assertTrue(all(doc.get("counts_as_target_evidence") is False for doc in BUILTIN_KNOWLEDGE[family]))
            self.assertTrue(all("type" not in doc for doc in BUILTIN_KNOWLEDGE[family]))

    def test_analyzer_compatibility_exports_come_from_specs(self):
        rows = (
            (ACCOUNT_ENUMERATION_SPEC, ACCOUNT_ENUMERATION_TAXONOMY, ACCOUNT_ENUMERATION_METHOD),
            (INFORMATION_DISCLOSURE_SPEC, INFORMATION_DISCLOSURE_TAXONOMY, INFORMATION_DISCLOSURE_METHOD),
            (SOURCE_MAP_EXPOSURE_SPEC, SOURCE_MAP_EXPOSURE_TAXONOMY, SOURCE_MAP_EXPOSURE_METHOD),
            (SECRET_EXPOSURE_SPEC, SECRET_EXPOSURE_TAXONOMY, SECRET_EXPOSURE_METHOD),
        )
        for spec, taxonomy, methodology in rows:
            self.assertEqual(taxonomy, spec.taxonomy())
            self.assertEqual(methodology, tuple(step.as_dict() for step in spec.standard.methodology))

    def test_account_enumeration_requires_controlled_discrepancy(self):
        surface = assess_admission("account_enumeration", [
            {"type": "identity_lookup", "source_group": "identity_input"},
            {"type": "client_operation", "source_group": "identity_operation"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("account_enumeration", [
            {"type": "identity_lookup", "source_group": "identity_input"},
            {"type": "client_operation", "source_group": "identity_operation"},
            {"type": "identity_response_differential", "source_group": "controlled_identity_response"},
        ])
        self.assertTrue(direct["admitted"])

    def test_information_disclosure_requires_visibility_boundary_failure(self):
        surface = assess_admission("information_disclosure", [
            {"type": "sensitive_marker", "source_group": "surface"},
            {"type": "stored_evidence", "source_group": "storage"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("information_disclosure", [
            {"type": "sensitive_marker", "source_group": "surface"},
            {"type": "sensitive_response_observed", "source_group": "visibility_boundary"},
        ])
        self.assertTrue(direct["admitted"])

    def test_source_map_reference_and_internal_paths_remain_hidden(self):
        surface = assess_admission("source_map_exposure", [
            {"type": "source_map", "source_group": "reference"},
            {"type": "internal_sources", "source_group": "structure"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("source_map_exposure", [
            {"type": "source_map", "source_group": "reference"},
            {"type": "internal_sources", "source_group": "structure"},
            {"type": "source_map_publicly_reachable", "source_group": "passive_fetch"},
        ])
        self.assertTrue(direct["admitted"])

    def test_sensitive_source_content_without_reachability_can_promote_but_not_override_not_public(self):
        elevated = assess_admission("source_map_exposure", [
            {"type": "source_map", "source_group": "reference"},
            {"type": "sensitive_source_content_observed", "source_group": "redacted_review"},
        ])
        self.assertTrue(elevated["admitted"])
        contradicted = assess_admission(
            "source_map_exposure",
            [
                {"type": "source_map", "source_group": "reference"},
                {"type": "sensitive_source_content_observed", "source_group": "redacted_review"},
            ],
            [{"type": "source_map_not_public", "source_group": "passive_fetch"}],
        )
        self.assertFalse(contradicted["admitted"])

    def test_secret_pattern_and_context_are_not_enough_for_potential(self):
        surface = assess_admission("secret_exposure", [
            {"type": "secret_pattern", "source_group": "secret_pattern"},
            {"type": "context", "source_group": "client_delivery"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("secret_exposure", [
            {"type": "secret_pattern", "source_group": "secret_pattern"},
            {"type": "context", "source_group": "client_delivery"},
            {"type": "credential_material_confirmed", "source_group": "offline_structure"},
        ])
        self.assertTrue(direct["admitted"])

    def test_external_knowledge_is_zero_target_evidence(self):
        for family in self.families:
            decision = assess_admission(family, [
                {"source": "OWASP", "ref": "standard", "source_group": "knowledge"},
                {"source": "WSTG", "ref": "test", "source_group": "knowledge"},
                {"source": "CWE", "ref": "weakness", "source_group": "knowledge"},
                {"source": "GHSL", "ref": "writeup", "source_group": "knowledge"},
            ])
            self.assertFalse(decision["admitted"])
            self.assertEqual(decision["independent_sources"], 0)

    def test_reference_compatibility_is_preserved(self):
        account_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["account_enumeration"]}
        info_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["information_disclosure"]}
        source_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["source_map_exposure"]}
        secret_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["secret_exposure"]}
        self.assertIn("owasp-wstg-idnt-04-response-pattern", account_ids)
        self.assertIn("ghsl-2024-008-openhab-information-disclosure", info_ids)
        self.assertIn("owasp-wstg-info-05-source-maps", source_ids)
        self.assertIn("ghsl-2026-037-wekan-token-leak", secret_ids)


if __name__ == "__main__":
    unittest.main()

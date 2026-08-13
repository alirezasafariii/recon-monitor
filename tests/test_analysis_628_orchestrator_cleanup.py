from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import analysis_engine
import bug_candidates
import security_reasoning
from family_evidence_extractors import FAMILY_EVIDENCE_EXTRACTOR_PROFILES
from family_orchestration import (
    BOLA_OWNED_FAMILIES,
    ORCHESTRATION_ENGINE_VERSION,
    ORCHESTRATION_RULE_VERSION,
    PRIMARY_FAMILY_OWNERSHIP,
    RAW_COLLECTOR_BINDINGS,
    RAW_OWNED_FAMILIES,
    STATIC_OWNED_FAMILIES,
    collect_raw_owned_observations,
    validate_family_ownership,
)
from family_reasoners import FAMILY_REASONER_PROFILES
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, STATIC_SUPPLEMENTAL_FAMILIES, STATIC_SUPPLEMENTAL_IMPACTS


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


class Analysis628OrchestratorCleanupTests(unittest.TestCase):
    def test_release_lineage_and_exact_orchestration_version(self) -> None:
        self.assertGreaterEqual(_version_tuple(analysis_engine.ENGINE_VERSION), (6, 28, 0))
        self.assertGreaterEqual(_version_tuple(bug_candidates.CANDIDATE_ENGINE_VERSION), (6, 28, 0))
        self.assertGreaterEqual(_version_tuple(security_reasoning.REASONING_ENGINE_VERSION), (6, 28, 0))
        for rule in (
            analysis_engine.RULE_VERSION,
            bug_candidates.CANDIDATE_RULE_VERSION,
            security_reasoning.REASONING_RULE_VERSION,
        ):
            self.assertTrue(rule.startswith("2026.08.13.6."), rule)
            self.assertGreaterEqual(int(rule.rsplit(".", 1)[-1]), 28)
        self.assertEqual(ORCHESTRATION_ENGINE_VERSION, "1.0.0")
        self.assertEqual(ORCHESTRATION_RULE_VERSION, "2026.08.13.6.28")

    def test_primary_ownership_is_exact_30_plus_1_plus_5_partition(self) -> None:
        self.assertEqual(validate_family_ownership(), [])
        self.assertEqual(len(RAW_OWNED_FAMILIES), 30)
        self.assertEqual(len(set(RAW_OWNED_FAMILIES)), 30)
        self.assertEqual(BOLA_OWNED_FAMILIES, ("broken_object_authorization",))
        self.assertEqual(len(STATIC_OWNED_FAMILIES), 5)
        self.assertEqual(set(STATIC_OWNED_FAMILIES), set(STATIC_SPECIALIZED_FAMILIES))
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(len(families), 36)
        self.assertEqual(set(PRIMARY_FAMILY_OWNERSHIP), families)
        self.assertEqual(set(bug_candidates.BUG_FAMILIES), families)
        self.assertEqual(set(FAMILY_REASONER_PROFILES), families)
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), families)
        self.assertEqual(set(RAW_OWNED_FAMILIES) | set(BOLA_OWNED_FAMILIES) | set(STATIC_OWNED_FAMILIES), families)
        self.assertFalse(set(RAW_OWNED_FAMILIES) & set(BOLA_OWNED_FAMILIES))
        self.assertFalse(set(RAW_OWNED_FAMILIES) & set(STATIC_OWNED_FAMILIES))
        self.assertFalse(set(BOLA_OWNED_FAMILIES) & set(STATIC_OWNED_FAMILIES))

    def test_raw_binding_registry_has_no_family_overlap_and_collects_all_30_generically(self) -> None:
        seen: set[str] = set()
        for binding in RAW_COLLECTOR_BINDINGS:
            self.assertTrue(binding.name)
            self.assertTrue(binding.families)
            self.assertFalse(seen & set(binding.families), binding.name)
            seen.update(binding.families)
        self.assertEqual(seen, set(RAW_OWNED_FAMILIES))
        execution_map = {family: {"support": [{"type": "surface", "source": "fixture"}], "contradict": []} for family in RAW_OWNED_FAMILIES}
        observations = collect_raw_owned_observations(execution_map)
        self.assertEqual(len(observations), 30)
        self.assertEqual({item.family for item in observations}, set(RAW_OWNED_FAMILIES))

    def test_static_supplements_are_not_primary_owners(self) -> None:
        self.assertEqual(set(STATIC_SUPPLEMENTAL_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        self.assertTrue(set(STATIC_SUPPLEMENTAL_FAMILIES) <= set(RAW_OWNED_FAMILIES))
        self.assertFalse(set(STATIC_SUPPLEMENTAL_FAMILIES) & set(STATIC_OWNED_FAMILIES))
        for family in STATIC_SUPPLEMENTAL_FAMILIES:
            self.assertEqual(PRIMARY_FAMILY_OWNERSHIP[family], "raw")
            self.assertEqual(STATIC_SUPPLEMENTAL_IMPACTS[family], int(bug_candidates.BUG_FAMILIES[family]["impact"]))

    def test_bug_candidate_orchestrator_has_no_per_family_raw_or_static_branching(self) -> None:
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("analyze_bola_signal(", source)
        self.assertIn("collect_static_candidate_observations(db, analysis_id, target)", source)
        self.assertNotIn("detector-execution-fallback", source)
        self.assertNotIn("emitted_execution_families", source)
        for marker in (
            "collect_injection_observations(execution_map)",
            "collect_authorization_observations(execution_map)",
            "collect_file_remote_resource_observations(execution_map)",
            "collect_client_side_observations(execution_map)",
            "collect_api_configuration_observations(execution_map)",
            "collect_business_logic_observations(execution_map)",
            "collect_authentication_observations(execution_map)",
            "collect_exposure_headers_observations(execution_map)",
            "collect_owasp_top10_2025_observations(execution_map)",
            'if source == "postMessage"',
            'elif sink in {"innerHTML", "eval"}',
            'elif sink == "navigation"',
        ):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()

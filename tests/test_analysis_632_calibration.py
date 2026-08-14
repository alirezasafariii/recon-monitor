from __future__ import annotations

import unittest

from analysis_632_evidence import reconstruct_asserted_evidence
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission
from researcher_logic import researcher_logic_for_family, validate_researcher_logic
from security_family_ranker import production_family_rankings


def _complete_single_observation(family: str):
    policy = FAMILY_ADMISSION_POLICIES[family]
    support = []
    required = list(policy["required"])
    for index, group in enumerate(required):
        signal = sorted(group)[0]
        support.append({
            "type": signal,
            "source": "stored_assertion",
            "source_group": "one-stored-observation",
            "family_scope": family,
            "direct": index == len(required) - 1,
            "analysis_632_reconstruction": index == len(required) - 1,
        })
    return support


class Analysis632CalibrationTests(unittest.TestCase):
    def test_single_direct_complete_observation_can_satisfy_source_gate(self):
        family = "account_enumeration"
        result = assess_admission(family, _complete_single_observation(family), [])
        self.assertTrue(result["admitted"])
        self.assertEqual(result["independent_sources"], 1)
        self.assertFalse(result["source_ok_by_count"])
        self.assertTrue(result["direct_decisive_observation"])
        self.assertTrue(result["single_direct_observation_override"])

    def test_single_surface_or_identity_observation_cannot_admit(self):
        family = "account_enumeration"
        required = list(FAMILY_ADMISSION_POLICIES[family]["required"])
        support = [{
            "type": sorted(required[0])[0],
            "source": "stored_assertion",
            "source_group": "one-stored-observation",
            "family_scope": family,
            "direct": True,
        }]
        result = assess_admission(family, support, [])
        self.assertFalse(result["admitted"])
        self.assertFalse(result["single_direct_observation_override"])
        self.assertTrue(result["required_missing"])

    def test_blocking_control_still_blocks_complete_direct_observation(self):
        family = "account_enumeration"
        blocker = sorted(FAMILY_ADMISSION_POLICIES[family]["blocking_contradictions"])[0]
        result = assess_admission(
            family,
            _complete_single_observation(family),
            [{
                "type": blocker,
                "source": "stored_assertion",
                "source_group": "one-stored-observation",
                "family_scope": family,
                "direct": True,
            }],
        )
        self.assertFalse(result["admitted"])
        self.assertIn(blocker, result["blocking_contradictions"])

    def test_stored_fact_reconstruction_maps_direct_account_differential(self):
        reconstructed = reconstruct_asserted_evidence(
            target="stored authentication service",
            endpoint="authentication challenge",
            method="UNKNOWN",
            endpoint_schema={},
            details={
                "observation": "Known and unknown user identities produce a distinguishable account-existence response difference.",
                "observable_account_existence_differential": True,
            },
        )
        packet = reconstructed.get("account_enumeration") or {}
        types = {item["type"] for item in packet.get("support") or []}
        self.assertIn("account_existence_differential", types)
        condition = next(item for item in packet["support"] if item["type"] == "account_existence_differential")
        self.assertTrue(condition["direct"])
        self.assertEqual(condition["source_group"], "stored_observation")
        self.assertTrue(condition["execution_passive_only"])

    def test_secure_fixed_statement_is_not_reconstructed_as_cross_tenant_success(self):
        reconstructed = reconstruct_asserted_evidence(
            target="stored object service",
            endpoint="object access",
            method="GET",
            endpoint_schema={},
            details={"control_observation": "Patched version denied and blocked cross-tenant object access."},
        )
        packet = reconstructed.get("broken_object_authorization") or {}
        support_types = {item["type"] for item in packet.get("support") or []}
        self.assertNotIn("cross_tenant_object_access", support_types)

    def test_production_ranking_omits_zero_score_family_ties(self):
        self.assertEqual(production_family_rankings([], []), [])

    def test_researcher_logic_covers_all_families_without_provenance_keys(self):
        self.assertEqual(validate_researcher_logic(), [])
        self.assertEqual(len(DETECTOR_SPECS), 36)
        for family in DETECTOR_SPECS:
            logic = researcher_logic_for_family(family)
            self.assertEqual(logic["role"], "reasoning_guidance_only_not_target_evidence")
            self.assertTrue(logic["security_principle"])
            self.assertTrue(logic["decisive_condition_signals"])
            self.assertTrue(logic["writeup_logic"])
            self.assertNotIn("source", logic)
            self.assertNotIn("url", logic)
            self.assertNotIn("ref", logic)
            self.assertTrue("never count" in logic["evidence_policy"] or "never counts" in logic["evidence_policy"])


if __name__ == "__main__":
    unittest.main()

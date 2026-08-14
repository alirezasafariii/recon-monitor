from __future__ import annotations

from analysis_ranking import rank_families
from analysis_632_evidence import reconstruct_asserted_evidence
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission
from researcher_logic import researcher_logic_for_family, validate_researcher_logic


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


def test_single_direct_complete_observation_can_satisfy_source_gate():
    family = "account_enumeration"
    result = assess_admission(family, _complete_single_observation(family), [])
    assert result["admitted"] is True
    assert result["independent_sources"] == 1
    assert result["source_ok_by_count"] is False
    assert result["direct_decisive_observation"] is True
    assert result["single_direct_observation_override"] is True


def test_single_surface_or_identity_observation_cannot_admit():
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
    assert result["admitted"] is False
    assert result["single_direct_observation_override"] is False
    assert result["required_missing"]


def test_blocking_control_still_blocks_complete_direct_observation():
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
    assert result["admitted"] is False
    assert blocker in result["blocking_contradictions"]


def test_stored_fact_reconstruction_maps_direct_account_differential():
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
    assert "account_existence_differential" in types
    condition = next(item for item in packet["support"] if item["type"] == "account_existence_differential")
    assert condition["direct"] is True
    assert condition["source_group"] == "stored_observation"


def test_secure_fixed_statement_is_not_reconstructed_as_cross_tenant_success():
    reconstructed = reconstruct_asserted_evidence(
        target="stored object service",
        endpoint="object access",
        method="GET",
        endpoint_schema={},
        details={"control_observation": "Patched version denied and blocked cross-tenant object access."},
    )
    packet = reconstructed.get("broken_object_authorization") or {}
    support_types = {item["type"] for item in packet.get("support") or []}
    assert "cross_tenant_object_access" not in support_types


def test_zero_score_family_ties_are_not_returned_as_rankings():
    assert rank_families([], []) == []


def test_researcher_logic_covers_all_families_without_provenance_keys():
    assert validate_researcher_logic() == []
    assert len(DETECTOR_SPECS) == 36
    for family in DETECTOR_SPECS:
        logic = researcher_logic_for_family(family)
        assert logic["role"] == "reasoning_guidance_only_not_target_evidence"
        assert logic["security_principle"]
        assert logic["decisive_condition_signals"]
        assert logic["writeup_logic"]
        assert "source" not in logic
        assert "url" not in logic
        assert "ref" not in logic
        assert "never count" in logic["evidence_policy"] or "never counts" in logic["evidence_policy"]

from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

BUSINESS_LOGIC_COLLECTOR_VERSION = "1.0.0"
BUSINESS_LOGIC_COLLECTOR_RULE_VERSION = "2026.08.12.6.21"
BUSINESS_LOGIC_FAMILIES = (
    "business_logic",
    "race_condition",
)

BUSINESS_LOGIC_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "business_logic": RawFamilyObservation(
        family="business_logic",
        variant="workflow_invariant",
        base=12,
        missing=(
            "Intended workflow and state/value invariants",
            "Server-side calculation or transition enforcement",
            "Target evidence of an accepted impossible/forbidden business state",
        ),
        rules=(
            "raw-collector-business-logic-v1",
            "candidate-business-workflow",
            "admission-business-invariant",
        ),
        summary=(
            "Stored business-workflow artifacts expose a state-changing operation; promotion requires "
            "target evidence that the intended workflow, value, calculation, or transition invariant was violated."
        ),
        impact=72,
    ),
    "race_condition": RawFamilyObservation(
        family="race_condition",
        variant="duplicate_operation",
        base=10,
        missing=(
            "Idempotency key or transaction guard",
            "Atomic state-transition behavior",
            "Evidence that concurrency created a duplicate or otherwise impossible state",
        ),
        rules=(
            "raw-collector-business-logic-v1",
            "candidate-single-use-operation",
            "admission-atomicity-failure",
        ),
        summary=(
            "Stored artifacts expose a state-changing single-use or balance operation; promotion requires "
            "observed duplicate effect, atomicity failure, concurrency invariant violation, or double-spend behavior."
        ),
        impact=80,
    ),
}


def validate_business_logic_collectors() -> list[str]:
    errors: list[str] = []
    if set(BUSINESS_LOGIC_OBSERVATIONS) != set(BUSINESS_LOGIC_FAMILIES):
        errors.append("business-logic collector profile coverage drift")
    for family in BUSINESS_LOGIC_FAMILIES:
        observation = BUSINESS_LOGIC_OBSERVATIONS.get(family)
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not spec.wstg_ids:
            errors.append(f"business detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"business detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"business detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"business detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"business detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_business_logic_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_business_logic_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.21 business-logic collector registry: " + "; ".join(errors))
    return [
        BUSINESS_LOGIC_OBSERVATIONS[family]
        for family in BUSINESS_LOGIC_FAMILIES
        if BUSINESS_LOGIC_OBSERVATIONS[family].packet_present(execution_map)
    ]

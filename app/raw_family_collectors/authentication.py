from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

AUTHENTICATION_COLLECTOR_VERSION = "1.0.0"
AUTHENTICATION_COLLECTOR_RULE_VERSION = "2026.08.12.6.22"
AUTHENTICATION_FAMILIES = (
    "authentication_session",
    "account_enumeration",
)

AUTHENTICATION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "authentication_session": RawFamilyObservation(
        family="authentication_session",
        variant="auth_lifecycle",
        base=20,
        missing=(
            "Expected authentication/session lifecycle and trust boundary",
            "Token/session rotation, expiry, state, and validation controls",
            "Stored target evidence of an authentication boundary or lifecycle failure",
        ),
        rules=(
            "raw-collector-authentication-v1",
            "candidate-auth-surface",
            "admission-auth-lifecycle-failure",
        ),
        summary=(
            "Stored artifacts expose an authentication or session lifecycle surface; promotion requires "
            "target evidence of a boundary regression, session-validation failure, token lifecycle failure, missing state, or token exposure."
        ),
        impact=82,
    ),
    "account_enumeration": RawFamilyObservation(
        family="account_enumeration",
        variant="identity_response_difference",
        base=15,
        missing=(
            "Controlled present-versus-absent identity observations",
            "Repeatable response/body/length/timing comparison",
            "Evidence that the observable difference reveals account existence",
        ),
        rules=(
            "raw-collector-authentication-v1",
            "candidate-recovery-identity",
            "admission-identity-differential",
        ),
        summary=(
            "Stored artifacts expose an identity lookup surface; promotion requires a controlled, material "
            "existing-versus-nonexistent account response, error, body-length, or timing differential."
        ),
        impact=48,
    ),
}


def validate_authentication_collectors() -> list[str]:
    errors: list[str] = []
    if set(AUTHENTICATION_OBSERVATIONS) != set(AUTHENTICATION_FAMILIES):
        errors.append("authentication collector profile coverage drift")
    for family in AUTHENTICATION_FAMILIES:
        observation = AUTHENTICATION_OBSERVATIONS.get(family)
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
            errors.append(f"authentication detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"authentication detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"authentication detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"authentication detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"authentication detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_authentication_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_authentication_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.22 authentication collector registry: " + "; ".join(errors))
    return [
        AUTHENTICATION_OBSERVATIONS[family]
        for family in AUTHENTICATION_FAMILIES
        if AUTHENTICATION_OBSERVATIONS[family].packet_present(execution_map)
    ]

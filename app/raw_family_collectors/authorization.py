from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

AUTHORIZATION_COLLECTOR_VERSION = "1.0.0"
AUTHORIZATION_COLLECTOR_RULE_VERSION = "2026.08.12.6.17"
AUTHORIZATION_FAMILIES = (
    "broken_function_authorization",
    "mass_assignment",
)

AUTHORIZATION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "broken_function_authorization": RawFamilyObservation(
        family="broken_function_authorization",
        variant="role_boundary",
        base=22,
        missing=(
            "Expected role matrix",
            "Server-side permission enforcement",
            "Behavior for an authorized lower-privilege test role",
        ),
        rules=(
            "raw-collector-authorization-v1",
            "candidate-privileged-function",
            "candidate-role-boundary",
        ),
        summary=(
            "A privileged function may depend on role enforcement that is not visible in the "
            "collected evidence; promotion requires stored evidence of a function-level "
            "authorization failure."
        ),
    ),
    "mass_assignment": RawFamilyObservation(
        family="mass_assignment",
        variant="privileged_properties",
        base=24,
        missing=(
            "Server allow-list of writable fields",
            "Whether sensitive properties are ignored or rejected",
            "Expected property-level authorization",
        ),
        rules=(
            "raw-collector-authorization-v1",
            "candidate-write-schema",
            "candidate-privileged-property",
        ),
        summary=(
            "A client-visible write schema includes privilege-sensitive properties; promotion "
            "requires stored evidence that the server accepted or applied a property outside "
            "the caller's property policy."
        ),
    ),
}


def validate_authorization_collectors() -> list[str]:
    errors: list[str] = []
    if set(AUTHORIZATION_OBSERVATIONS) != set(AUTHORIZATION_FAMILIES):
        errors.append("authorization collector profile coverage drift")
    for family in AUTHORIZATION_FAMILIES:
        observation = AUTHORIZATION_OBSERVATIONS.get(family)
        if family not in DETECTOR_SPECS:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not DETECTOR_SPECS[family].condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_authorization_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_authorization_collectors()
    if errors:
        raise RuntimeError(
            "Invalid Analysis 6.17 authorization collector registry: " + "; ".join(errors)
        )
    return [
        AUTHORIZATION_OBSERVATIONS[family]
        for family in AUTHORIZATION_FAMILIES
        if AUTHORIZATION_OBSERVATIONS[family].packet_present(execution_map)
    ]

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import (
    API_CONFIGURATION_FAMILIES,
    AUTHENTICATION_FAMILIES,
    AUTHORIZATION_FAMILIES,
    BUSINESS_LOGIC_FAMILIES,
    CLIENT_SIDE_FAMILIES,
    EXPOSURE_HEADERS_FAMILIES,
    FILE_REMOTE_FAMILIES,
    INJECTION_FAMILIES,
    OWASP_TOP10_2025_FAMILIES,
    RawFamilyObservation,
    collect_api_configuration_observations,
    collect_authentication_observations,
    collect_authorization_observations,
    collect_business_logic_observations,
    collect_client_side_observations,
    collect_exposure_headers_observations,
    collect_file_remote_resource_observations,
    collect_injection_observations,
    collect_owasp_top10_2025_observations,
)
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES

ORCHESTRATION_ENGINE_VERSION = "1.0.0"
ORCHESTRATION_RULE_VERSION = "2026.08.13.6.28"


@dataclass(frozen=True)
class RawCollectorBinding:
    name: str
    families: tuple[str, ...]
    collector: Callable[[Mapping[str, Mapping[str, Any]]], list[RawFamilyObservation]]


RAW_COLLECTOR_BINDINGS: tuple[RawCollectorBinding, ...] = (
    RawCollectorBinding("injection", tuple(INJECTION_FAMILIES), collect_injection_observations),
    RawCollectorBinding("authorization", tuple(AUTHORIZATION_FAMILIES), collect_authorization_observations),
    RawCollectorBinding("file_remote_resource", tuple(FILE_REMOTE_FAMILIES), collect_file_remote_resource_observations),
    RawCollectorBinding("client_side", tuple(CLIENT_SIDE_FAMILIES), collect_client_side_observations),
    RawCollectorBinding("api_configuration", tuple(API_CONFIGURATION_FAMILIES), collect_api_configuration_observations),
    RawCollectorBinding("business_logic", tuple(BUSINESS_LOGIC_FAMILIES), collect_business_logic_observations),
    RawCollectorBinding("authentication", tuple(AUTHENTICATION_FAMILIES), collect_authentication_observations),
    RawCollectorBinding("exposure_headers", tuple(EXPOSURE_HEADERS_FAMILIES), collect_exposure_headers_observations),
    RawCollectorBinding("owasp_top10_2025", tuple(OWASP_TOP10_2025_FAMILIES), collect_owasp_top10_2025_observations),
)

RAW_OWNED_FAMILIES = tuple(sorted(family for binding in RAW_COLLECTOR_BINDINGS for family in binding.families))
BOLA_OWNED_FAMILIES = ("broken_object_authorization",)
STATIC_OWNED_FAMILIES = tuple(sorted(STATIC_SPECIALIZED_FAMILIES))

PRIMARY_FAMILY_OWNERSHIP: dict[str, str] = {
    **{family: "raw" for family in RAW_OWNED_FAMILIES},
    **{family: "bola" for family in BOLA_OWNED_FAMILIES},
    **{family: "static" for family in STATIC_OWNED_FAMILIES},
}


def validate_family_ownership() -> list[str]:
    errors: list[str] = []
    expected = set(FAMILY_ADMISSION_POLICIES)
    raw_seen: set[str] = set()
    duplicates: set[str] = set()
    for binding in RAW_COLLECTOR_BINDINGS:
        if not binding.name or not binding.families:
            errors.append(f"invalid raw collector binding: {binding.name!r}")
        for family in binding.families:
            if family in raw_seen:
                duplicates.add(family)
            raw_seen.add(family)
    if duplicates:
        errors.append(f"raw primary ownership overlap: {sorted(duplicates)}")
    if len(RAW_OWNED_FAMILIES) != 30 or len(set(RAW_OWNED_FAMILIES)) != 30:
        errors.append(f"raw ownership must be exactly 30 unique families, got {len(set(RAW_OWNED_FAMILIES))}")
    if set(BOLA_OWNED_FAMILIES) != {"broken_object_authorization"}:
        errors.append(f"BOLA ownership drift: {sorted(BOLA_OWNED_FAMILIES)}")
    if len(STATIC_OWNED_FAMILIES) != 5 or len(set(STATIC_OWNED_FAMILIES)) != 5:
        errors.append(f"static specialized ownership must be exactly 5 unique families, got {len(set(STATIC_OWNED_FAMILIES))}")
    raw = set(RAW_OWNED_FAMILIES)
    bola = set(BOLA_OWNED_FAMILIES)
    static = set(STATIC_OWNED_FAMILIES)
    if raw & bola or raw & static or bola & static:
        errors.append("primary ownership sets overlap")
    owned = raw | bola | static
    if owned != expected:
        errors.append(f"primary ownership drift: missing={sorted(expected-owned)} extra={sorted(owned-expected)}")
    if len(PRIMARY_FAMILY_OWNERSHIP) != 36:
        errors.append(f"primary ownership registry must contain 36 families, got {len(PRIMARY_FAMILY_OWNERSHIP)}")
    return errors


def collect_raw_owned_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_family_ownership()
    if errors:
        raise RuntimeError("Invalid Analysis 6.28 family ownership registry: " + "; ".join(errors))
    observations: list[RawFamilyObservation] = []
    for binding in RAW_COLLECTOR_BINDINGS:
        batch = binding.collector(execution_map)
        allowed = set(binding.families)
        for observation in batch:
            if observation.family not in allowed:
                raise RuntimeError(
                    f"Analysis 6.28 raw collector {binding.name} emitted unowned family {observation.family}"
                )
            observations.append(observation)
    return observations

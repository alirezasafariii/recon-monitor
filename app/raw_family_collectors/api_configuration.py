from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

API_CONFIGURATION_COLLECTOR_VERSION = "1.0.0"
API_CONFIGURATION_COLLECTOR_RULE_VERSION = "2026.08.12.6.20"
API_CONFIGURATION_FAMILIES = (
    "unrestricted_resource_consumption",
    "sensitive_business_flow_abuse",
    "security_misconfiguration",
    "improper_inventory_management",
    "unsafe_api_consumption",
)

API_CONFIGURATION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "unrestricted_resource_consumption": RawFamilyObservation(
        family="unrestricted_resource_consumption",
        variant="missing_resource_limit",
        base=16,
        missing=(
            "Maximum page/batch/payload size",
            "Per-client operation rate",
            "Execution timeout and provider spending limit",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-resource-surface",
            "admission-resource-limit-failure",
        ),
        summary=(
            "Stored API artifacts expose a resource-amplifying control or costly operation; "
            "promotion requires observed missing or ineffective size, rate, timeout, or cost limits."
        ),
    ),
    "sensitive_business_flow_abuse": RawFamilyObservation(
        family="sensitive_business_flow_abuse",
        variant="automation_abuse_boundary",
        base=15,
        missing=(
            "Per-user/business frequency limits",
            "Anti-automation controls",
            "Scarce-inventory or reservation abuse controls",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-sensitive-business-flow",
            "admission-business-flow-limit",
        ),
        summary=(
            "Stored API artifacts expose an abuse-sensitive business flow; promotion requires "
            "target evidence that automation, frequency, per-user, or inventory controls are absent or bypassable."
        ),
    ),
    "security_misconfiguration": RawFamilyObservation(
        family="security_misconfiguration",
        variant="deployment_hardening",
        base=17,
        missing=(
            "Expected hardening baseline",
            "Production transport/method policy",
            "Whether debug/default functionality is intentionally exposed",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-misconfiguration-surface",
            "admission-direct-misconfiguration",
        ),
        summary=(
            "Stored deployment/application-stack artifacts expose a configuration-sensitive surface; "
            "promotion requires directly observed insecure configuration behavior."
        ),
    ),
    "improper_inventory_management": RawFamilyObservation(
        family="improper_inventory_management",
        variant="legacy_or_nonproduction_exposure",
        base=14,
        missing=(
            "Current API inventory and retirement plan",
            "Control parity with current production API",
            "Whether non-production hosts use production data",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-api-inventory-surface",
            "admission-inventory-drift",
        ),
        summary=(
            "Stored API artifacts expose versioned, legacy, or non-production inventory; promotion requires "
            "observed active stale/undocumented exposure with security relevance."
        ),
    ),
    "unsafe_api_consumption": RawFamilyObservation(
        family="unsafe_api_consumption",
        variant="upstream_trust_boundary",
        base=17,
        missing=(
            "TLS and authentication to upstream service",
            "Redirect/timeout/response-size controls",
            "Validation and sanitization of third-party response data",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-upstream-integration",
            "admission-unsafe-api-consumption",
        ),
        summary=(
            "Stored API artifacts expose a third-party/upstream trust boundary; promotion requires "
            "observed unsafe transport, redirect, resource, authentication, or downstream-validation behavior."
        ),
    ),
}


def validate_api_configuration_collectors() -> list[str]:
    errors: list[str] = []
    if set(API_CONFIGURATION_OBSERVATIONS) != set(API_CONFIGURATION_FAMILIES):
        errors.append("API/configuration collector profile coverage drift")
    for family in API_CONFIGURATION_FAMILIES:
        observation = API_CONFIGURATION_OBSERVATIONS.get(family)
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
            errors.append(f"API/configuration detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"API/configuration detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"API/configuration detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"API/configuration detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"API/configuration write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_api_configuration_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_api_configuration_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.20 API/configuration collector registry: " + "; ".join(errors))
    return [
        API_CONFIGURATION_OBSERVATIONS[family]
        for family in API_CONFIGURATION_FAMILIES
        if API_CONFIGURATION_OBSERVATIONS[family].packet_present(execution_map)
    ]

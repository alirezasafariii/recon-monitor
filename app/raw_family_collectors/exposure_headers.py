from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

EXPOSURE_HEADERS_COLLECTOR_VERSION = "1.0.0"
EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION = "2026.08.12.6.23"
EXPOSURE_HEADERS_FAMILIES = (
    "information_disclosure",
    "cors_misconfiguration",
    "sensitive_caching",
)

EXPOSURE_HEADERS_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "information_disclosure": RawFamilyObservation(
        family="information_disclosure",
        variant="sensitive_metadata",
        base=18,
        missing=(
            "Exact sensitive/debug material exposed by the stored response",
            "Whether the response context is public, unauthorized, or otherwise unintended",
            "Minimum affected data scope and intended disclosure policy",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-sensitive-marker",
            "admission-sensitive-response-exposure",
        ),
        summary=(
            "Stored artifacts contain sensitive/debug disclosure evidence; promotion requires actual response exposure "
            "in a public, unauthorized, or otherwise unintended context."
        ),
        impact=66,
    ),
    "cors_misconfiguration": RawFamilyObservation(
        family="cors_misconfiguration",
        variant="origin_policy",
        base=18,
        missing=(
            "Exact origin allow-list/reflection policy",
            "Credential behavior or authenticated response context",
            "Whether sensitive response data is actually readable cross-origin",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-cors-header",
            "admission-cors-origin-exposure",
        ),
        summary=(
            "Stored CORS artifacts expose an unsafe-origin-policy hypothesis; promotion requires credentials, "
            "an authenticated context, or observed sensitive cross-origin response exposure."
        ),
        impact=64,
    ),
    "sensitive_caching": RawFamilyObservation(
        family="sensitive_caching",
        variant="cache_policy",
        base=20,
        missing=(
            "Whether the response contains sensitive or authenticated data",
            "Browser/shared cache policy including Cache-Control and Vary",
            "Observed cache isolation weakness such as missing no-store, missing auth Vary, or shared/CDN caching",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-cache-header",
            "admission-sensitive-cache-isolation",
        ),
        summary=(
            "Stored response/cache artifacts expose a cache-isolation hypothesis; promotion requires sensitive or "
            "authenticated content plus a concrete browser/shared-cache isolation weakness."
        ),
        impact=62,
    ),
}


def validate_exposure_headers_collectors() -> list[str]:
    errors: list[str] = []
    if set(EXPOSURE_HEADERS_OBSERVATIONS) != set(EXPOSURE_HEADERS_FAMILIES):
        errors.append("exposure/headers collector profile coverage drift")
    for family in EXPOSURE_HEADERS_FAMILIES:
        observation = EXPOSURE_HEADERS_OBSERVATIONS.get(family)
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
            errors.append(f"exposure detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"exposure detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"exposure detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"exposure detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"exposure detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_exposure_headers_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_exposure_headers_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.23 exposure/headers collector registry: " + "; ".join(errors))
    return [
        EXPOSURE_HEADERS_OBSERVATIONS[family]
        for family in EXPOSURE_HEADERS_FAMILIES
        if EXPOSURE_HEADERS_OBSERVATIONS[family].packet_present(execution_map)
    ]

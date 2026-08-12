from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

OWASP_TOP10_2025_COLLECTOR_VERSION = "1.0.0"
OWASP_TOP10_2025_COLLECTOR_RULE_VERSION = "2026.08.12.6.25"
OWASP_TOP10_2025_FAMILIES = (
    "software_supply_chain_failure",
    "cryptographic_failure",
    "software_data_integrity_failure",
    "security_logging_alerting_failure",
    "exceptional_condition_mishandling",
)

OWASP_TOP10_2025_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "software_supply_chain_failure": RawFamilyObservation(
        family="software_supply_chain_failure", variant="component_or_pipeline_trust", base=14, impact=88,
        missing=("Exact affected deployed component/build path", "Observed vulnerable, unmaintained, untrusted, or compromised supply-chain condition", "Whether the component/pipeline condition reaches the target runtime or privileged build"),
        rules=("raw-collector-owasp-top10-2025-v1", "candidate-supply-chain-surface", "admission-supply-chain-condition"),
        summary="Stored component/build artifacts expose a supply-chain hypothesis; promotion requires a concrete vulnerable, unmaintained, untrusted, or compromised component/pipeline condition.",
    ),
    "cryptographic_failure": RawFamilyObservation(
        family="cryptographic_failure", variant="cryptographic_control", base=16, impact=84,
        missing=("Exact security-sensitive cryptographic purpose", "Observed weak/downgraded/predictable/reused/plaintext behavior", "Effective TLS/algorithm/key-generation control"),
        rules=("raw-collector-owasp-top10-2025-v1", "candidate-crypto-surface", "admission-crypto-failure"),
        summary="Stored crypto/TLS artifacts expose a cryptographic-control hypothesis; promotion requires an observed weak, predictable, reused, downgraded, or plaintext security condition.",
    ),
    "software_data_integrity_failure": RawFamilyObservation(
        family="software_data_integrity_failure", variant="code_or_data_integrity", base=14, impact=90,
        missing=("Exact code/data trust boundary", "Observed missing signature/integrity verification or unsafe deserialization/trust", "Whether untrusted code/data reaches an executable or security-sensitive sink"),
        rules=("raw-collector-owasp-top10-2025-v1", "candidate-integrity-boundary", "admission-integrity-failure"),
        summary="Stored update/serialization/plugin artifacts expose an integrity-boundary hypothesis; promotion requires a concrete missing-verification or unsafe-trust condition.",
    ),
    "security_logging_alerting_failure": RawFamilyObservation(
        family="security_logging_alerting_failure", variant="security_event_visibility", base=10, impact=64,
        missing=("Exact auditable security event", "Stored logging/telemetry evidence for missing/unsafe logging or alerting", "Expected detection/retention/integrity policy"),
        rules=("raw-collector-owasp-top10-2025-v1", "candidate-security-logging", "admission-logging-alerting-failure"),
        summary="Stored logging/telemetry artifacts expose a security-observability hypothesis; absence is never inferred from HTTP behavior and promotion requires concrete logging/alerting evidence.",
    ),
    "exceptional_condition_mishandling": RawFamilyObservation(
        family="exceptional_condition_mishandling", variant="fail_closed_exception_handling", base=14, impact=82,
        missing=("Exact exceptional/abnormal condition", "Observed fail-open, crash, partial commit, state corruption, or control bypass", "Expected fail-closed/rollback/recovery behavior"),
        rules=("raw-collector-owasp-top10-2025-v1", "candidate-exception-surface", "admission-exception-outcome"),
        summary="Stored exception/error artifacts expose an exceptional-condition hypothesis; promotion requires an observed unsafe fail-open, crash, state, transaction, or control outcome.",
    ),
}


def validate_owasp_top10_2025_collectors() -> list[str]:
    errors: list[str] = []
    if set(OWASP_TOP10_2025_OBSERVATIONS) != set(OWASP_TOP10_2025_FAMILIES):
        errors.append("OWASP Top 10:2025 collector profile coverage drift")
    for family in OWASP_TOP10_2025_FAMILIES:
        observation = OWASP_TOP10_2025_OBSERVATIONS.get(family)
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None or observation.family != family:
            errors.append(f"missing/mismatched collector metadata: {family}")
            continue
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not spec.wstg_ids:
            errors.append(f"detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"detector lacks condition contract: {family}")
    return errors


def collect_owasp_top10_2025_observations(execution_map: Mapping[str, Mapping[str, Any]]) -> list[RawFamilyObservation]:
    errors = validate_owasp_top10_2025_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.25 OWASP Top 10:2025 collector registry: " + "; ".join(errors))
    return [
        OWASP_TOP10_2025_OBSERVATIONS[family]
        for family in OWASP_TOP10_2025_FAMILIES
        if OWASP_TOP10_2025_OBSERVATIONS[family].packet_present(execution_map)
    ]

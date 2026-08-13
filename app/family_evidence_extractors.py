from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES

FAMILY_EVIDENCE_EXTRACTOR_VERSION = "1.0.0"
FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.08.10.6.8"


# Extraction has an explicit copy of the identity gates so this module stays
# below the reasoning layer and cannot create an import cycle. Tests require
# exact equality with family_reasoners.FAMILY_IDENTITY_GATES.
FAMILY_EXTRACTION_IDENTITY_GATES: dict[str, tuple[int, ...]] = {
    "broken_object_authorization": (0, 1),
    "broken_function_authorization": (0, 1),
    "mass_assignment": (1,),
    "authentication_session": (0,),
    "account_enumeration": (0,),
    "dom_xss": (0,),
    "postmessage_trust": (0,),
    "open_redirect": (0, 1),
    "ssrf": (0,),
    "file_upload": (0, 1),
    "path_traversal": (0, 1),
    "information_disclosure": (0,),
    "graphql_authorization": (0, 1),
    "graphql_data_exposure": (0, 1),
    "websocket_authorization": (0, 1),
    "cors_misconfiguration": (0,),
    "sensitive_caching": (0, 1),
    "business_logic": (0,),
    "race_condition": (0, 1),
    "sql_injection": (1,),
    "nosql_injection": (1,),
    "command_injection": (1,),
    "server_side_template_injection": (1,),
    "ldap_injection": (1,),
    "unrestricted_resource_consumption": (0,),
    "sensitive_business_flow_abuse": (0,),
    "security_misconfiguration": (0,),
    "improper_inventory_management": (0,),
    "unsafe_api_consumption": (0,),
    "source_map_exposure": (0,),
    "secret_exposure": (0, 1),
    "software_supply_chain_failure": (0,),
    "cryptographic_failure": (0,),
    "software_data_integrity_failure": (0,),
    "security_logging_alerting_failure": (0,),
    "exceptional_condition_mishandling": (0,),
}


@dataclass(frozen=True)
class FamilyEvidenceExtractorProfile:
    """Defines where a vulnerability family is expected to obtain target evidence.

    The profile does not make a vulnerability claim. It owns the extraction
    namespace used before admission and reasoning so evidence from one family
    cannot silently satisfy another family merely because both use a signal
    name such as ``input_parameter`` or ``state_change``.
    """

    channels: tuple[str, ...]
    strategy: str


FAMILY_EVIDENCE_EXTRACTOR_PROFILES: dict[str, FamilyEvidenceExtractorProfile] = {
    "broken_object_authorization": FamilyEvidenceExtractorProfile(("endpoint_schema", "stored_context", "identity_graph", "graphql"), "object_identity_boundary"),
    "broken_function_authorization": FamilyEvidenceExtractorProfile(("endpoint_schema", "classification", "stored_context"), "role_function_boundary"),
    "mass_assignment": FamilyEvidenceExtractorProfile(("endpoint_schema", "request_contract", "stored_behavior"), "property_write_boundary"),
    "authentication_session": FamilyEvidenceExtractorProfile(("endpoint_schema", "http", "stored_behavior"), "authentication_lifecycle"),
    "account_enumeration": FamilyEvidenceExtractorProfile(("endpoint_schema", "response_shape", "timing", "stored_behavior"), "identity_differential"),
    "dom_xss": FamilyEvidenceExtractorProfile(("javascript", "js_dataflow", "runtime_behavior"), "browser_taint_to_executable_sink"),
    "postmessage_trust": FamilyEvidenceExtractorProfile(("javascript", "js_dataflow", "runtime_behavior"), "cross_window_message_trust"),
    "open_redirect": FamilyEvidenceExtractorProfile(("endpoint_schema", "javascript", "navigation", "stored_behavior"), "navigation_destination_boundary"),
    "ssrf": FamilyEvidenceExtractorProfile(("endpoint_schema", "server_fetch", "stored_behavior"), "server_outbound_request_boundary"),
    "file_upload": FamilyEvidenceExtractorProfile(("endpoint_schema", "request_contract", "stored_behavior"), "upload_storage_processing"),
    "path_traversal": FamilyEvidenceExtractorProfile(("endpoint_schema", "filesystem", "stored_behavior"), "path_confinement"),
    "information_disclosure": FamilyEvidenceExtractorProfile(("http", "response_shape", "stored_context"), "sensitive_response_exposure"),
    "graphql_authorization": FamilyEvidenceExtractorProfile(("graphql", "stored_context", "identity_graph"), "graphql_resolver_authorization"),
    "graphql_data_exposure": FamilyEvidenceExtractorProfile(("graphql", "response_shape", "stored_context"), "graphql_field_policy"),
    "websocket_authorization": FamilyEvidenceExtractorProfile(("websocket", "stored_context", "identity_graph"), "channel_identity_boundary"),
    "cors_misconfiguration": FamilyEvidenceExtractorProfile(("http_headers", "stored_context", "response_shape"), "cross_origin_credential_boundary"),
    "sensitive_caching": FamilyEvidenceExtractorProfile(("http_headers", "cache", "stored_context"), "shared_cache_isolation"),
    "business_logic": FamilyEvidenceExtractorProfile(("workflow", "stored_behavior", "response_shape"), "business_invariant"),
    "race_condition": FamilyEvidenceExtractorProfile(("workflow", "concurrency", "stored_behavior"), "atomicity_invariant"),
    "sql_injection": FamilyEvidenceExtractorProfile(("endpoint_schema", "database", "stored_behavior"), "sql_query_semantics"),
    "nosql_injection": FamilyEvidenceExtractorProfile(("endpoint_schema", "document_database", "stored_behavior"), "nosql_operator_semantics"),
    "command_injection": FamilyEvidenceExtractorProfile(("endpoint_schema", "process_execution", "stored_behavior"), "process_execution_semantics"),
    "server_side_template_injection": FamilyEvidenceExtractorProfile(("endpoint_schema", "template_engine", "stored_behavior"), "server_template_evaluation"),
    "ldap_injection": FamilyEvidenceExtractorProfile(("endpoint_schema", "directory_query", "stored_behavior"), "ldap_filter_semantics"),
    "unrestricted_resource_consumption": FamilyEvidenceExtractorProfile(("endpoint_schema", "resource_limits", "stored_behavior"), "resource_amplification_limit"),
    "sensitive_business_flow_abuse": FamilyEvidenceExtractorProfile(("workflow", "automation_controls", "stored_behavior"), "business_flow_frequency_limit"),
    "security_misconfiguration": FamilyEvidenceExtractorProfile(("http", "deployment", "configuration"), "insecure_configuration_observation"),
    "improper_inventory_management": FamilyEvidenceExtractorProfile(("endpoint_inventory", "deployment", "http"), "api_inventory_drift"),
    "unsafe_api_consumption": FamilyEvidenceExtractorProfile(("upstream_api", "server_fetch", "stored_behavior"), "upstream_trust_boundary"),
    "source_map_exposure": FamilyEvidenceExtractorProfile(("source_map", "http", "javascript"), "public_internal_source_map"),
    "secret_exposure": FamilyEvidenceExtractorProfile(("javascript", "secret_intelligence", "runtime_context"), "non_placeholder_client_secret"),
    "software_supply_chain_failure": FamilyEvidenceExtractorProfile(("component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "stored_behavior"), "supply_chain_provenance_and_component_lifecycle"),
    "cryptographic_failure": FamilyEvidenceExtractorProfile(("transport", "cryptography", "stored_source", "stored_behavior"), "cryptographic_control_failure"),
    "software_data_integrity_failure": FamilyEvidenceExtractorProfile(("integrity", "serialization", "update_artifact", "stored_source", "stored_behavior"), "software_data_integrity_boundary"),
    "security_logging_alerting_failure": FamilyEvidenceExtractorProfile(("logging", "audit", "telemetry", "configuration", "stored_behavior"), "security_event_logging_and_alerting"),
    "exceptional_condition_mishandling": FamilyEvidenceExtractorProfile(("error_handling", "response_shape", "workflow", "stored_behavior"), "exception_fail_closed_behavior"),
}


def _registry_errors() -> list[str]:
    policy_families = set(FAMILY_ADMISSION_POLICIES)
    extractor_families = set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES)
    errors: list[str] = []
    if policy_families != extractor_families:
        errors.append(
            "extractor coverage mismatch "
            f"missing={sorted(policy_families - extractor_families)} "
            f"extra={sorted(extractor_families - policy_families)}"
        )
    for family, profile in FAMILY_EVIDENCE_EXTRACTOR_PROFILES.items():
        if not profile.channels:
            errors.append(f"{family}: extractor channels must not be empty")
        if not profile.strategy.strip():
            errors.append(f"{family}: extractor strategy must not be empty")
        required = list(FAMILY_ADMISSION_POLICIES[family].get("required", []))
        if not required:
            errors.append(f"{family}: admission policy has no required evidence groups")
        gates = FAMILY_EXTRACTION_IDENTITY_GATES.get(family, ())
        if any(index < 0 or index >= len(required) for index in gates):
            errors.append(f"{family}: extractor cannot align invalid identity gates {gates}")
    return errors


_REGISTRY_ERRORS = _registry_errors()
if _REGISTRY_ERRORS:
    raise RuntimeError("Family evidence extractor registry is invalid: " + "; ".join(_REGISTRY_ERRORS))


def _scope_matches(item: Mapping[str, Any], family: str) -> bool:
    scope = str(item.get("family_scope") or "").strip()
    return not scope or scope == family


def filter_evidence_for_family(
    family: str,
    items: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return evidence that is unscoped legacy data or belongs to ``family``.

    Unscoped evidence remains accepted for historical benchmark/backward
    compatibility. New 6.8 extraction output is always scoped.
    """

    return [dict(item) for item in items if _scope_matches(item, family)]


def _policy_sets(family: str) -> tuple[list[set[str]], set[str], set[str]]:
    policy = FAMILY_ADMISSION_POLICIES[family]
    required = [set(str(value) for value in group) for group in policy.get("required", [])]
    overrides = {str(value) for value in policy.get("override_signals", set())}
    controls = {str(value) for value in policy.get("blocking_contradictions", set())}
    return required, overrides, controls


def evidence_role(family: str, signal: str, *, contradiction: bool = False) -> str:
    required, overrides, controls = _policy_sets(family)
    if contradiction:
        return "control" if signal in controls else "contextual_control"
    if signal in overrides:
        return "condition"
    # A signal may intentionally appear in both an identity group and the
    # decisive condition group. Decisive condition semantics must win.
    if required and signal in required[-1]:
        return "condition"
    for group in required[:-1]:
        if signal in group:
            return "identity"
    return "surface"


def _dedupe(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for raw in items:
        item = dict(raw)
        key = (
            str(item.get("family_scope") or ""),
            str(item.get("type") or ""),
            str(item.get("source_group") or ""),
            str(item.get("source") or ""),
            str(item.get("text") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(item)
    return rows


def scope_family_evidence(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
    *,
    channel: str = "candidate",
) -> dict[str, Any]:
    """Apply the authoritative 6.8 family evidence namespace.

    Cross-family pre-scoped evidence is quarantined instead of being silently
    re-labeled. Same-family and legacy-unscoped evidence is tagged with the
    extractor identity and signal role. Surface clues are deliberately
    preserved for hidden hypotheses, but only identity/condition/control
    signals can count toward the corresponding family policy.
    """

    if family not in FAMILY_EVIDENCE_EXTRACTOR_PROFILES:
        raise KeyError(f"unknown family evidence extractor: {family}")

    support_rows: list[dict[str, Any]] = []
    contradict_rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    def annotate(raw: Mapping[str, Any], contradiction: bool) -> dict[str, Any] | None:
        item = dict(raw)
        existing_scope = str(item.get("family_scope") or "").strip()
        if existing_scope and existing_scope != family:
            rejected.append(item)
            return None
        signal = str(item.get("type") or "").strip()
        role = evidence_role(family, signal, contradiction=contradiction)
        item["family_scope"] = family
        item["evidence_namespace"] = f"family:{family}"
        item["extractor_id"] = f"family-extractor:{family}"
        item["extractor_version"] = FAMILY_EVIDENCE_EXTRACTOR_VERSION
        item["extractor_rule_version"] = FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION
        item.setdefault("extractor_channel", channel)
        item["signal_role"] = role
        item["counts_for_family"] = role in {"identity", "condition", "control"}
        return item

    for raw in support:
        item = annotate(raw, False)
        if item is not None:
            support_rows.append(item)
    for raw in contradict or []:
        item = annotate(raw, True)
        if item is not None:
            contradict_rows.append(item)

    support_rows = _dedupe(support_rows)
    contradict_rows = _dedupe(contradict_rows)
    support_types = {str(item.get("type") or "") for item in support_rows}
    required, overrides, _ = _policy_sets(family)
    gate_indices = FAMILY_EXTRACTION_IDENTITY_GATES[family]
    gate_satisfied = all(bool(support_types & required[index]) for index in gate_indices)
    condition_signals = (required[-1] if required else set()) | overrides
    condition_hits = sorted(support_types & condition_signals)
    if condition_hits:
        extraction_state = "condition_observed"
    elif gate_satisfied:
        extraction_state = "family_identity"
    else:
        extraction_state = "surface_only"

    for item in support_rows:
        item["extraction_state"] = extraction_state
    for item in contradict_rows:
        item["extraction_state"] = extraction_state

    profile = FAMILY_EVIDENCE_EXTRACTOR_PROFILES[family]
    return {
        "family": family,
        "support": support_rows,
        "contradict": contradict_rows,
        "extraction_state": extraction_state,
        "identity_gate_satisfied": gate_satisfied,
        "condition_hits": condition_hits,
        "rejected_cross_family_evidence": rejected,
        "rejected_cross_family_count": len(rejected),
        "surface_count": sum(1 for item in support_rows if item.get("signal_role") == "surface"),
        "identity_count": sum(1 for item in support_rows if item.get("signal_role") == "identity"),
        "condition_count": sum(1 for item in support_rows if item.get("signal_role") == "condition"),
        "control_count": sum(1 for item in contradict_rows if item.get("signal_role") == "control"),
        "profile": {
            "channels": list(profile.channels),
            "strategy": profile.strategy,
        },
        "extractor_version": FAMILY_EVIDENCE_EXTRACTOR_VERSION,
        "extractor_rule_version": FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION,
    }

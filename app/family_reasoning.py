from __future__ import annotations

"""Canonical reasoning contracts for every vulnerability family.

This module is intentionally evidence-only and side-effect free.  It defines the
minimum evidence contract for promotion into Potential Findings, the evidence an
analyst should seek before confirmation, contradictions that should keep a signal
in the hidden hypothesis ledger, and the safest validation class.

The catalog does *not* create evidence.  Knowledge, correlation, historical priors
and LLM output are deliberately absent from these contracts.
"""

from typing import Any, Iterable, Mapping


FAMILY_REASONING_VERSION = "2.0.0"
FAMILY_REASONING_RULE_VERSION = "2026.08.12.2"

FAMILY_ORDER = (
    "broken_object_authorization",
    "broken_function_authorization",
    "mass_assignment",
    "authentication_session",
    "account_enumeration",
    "dom_xss",
    "postmessage_trust",
    "open_redirect",
    "ssrf",
    "file_upload",
    "path_traversal",
    "information_disclosure",
    "source_map_exposure",
    "secret_exposure",
    "graphql_authorization",
    "graphql_data_exposure",
    "business_logic",
    "race_condition",
    "websocket_authorization",
    "cors_misconfiguration",
    "sensitive_caching",
)


def _groups(*values: Iterable[str]) -> tuple[frozenset[str], ...]:
    return tuple(frozenset(str(item) for item in group) for group in values)


def _req(key: str, label: str, why: str) -> dict[str, str]:
    return {"key": key, "label": label, "why": why}


DEFAULT_CASE_REQUIREMENTS = (
    _req("endpoint", "Affected endpoint or asset", "A concrete affected surface is needed."),
    _req("evidence", "Direct supporting evidence", "At least one direct observation should support the candidate."),
    _req("expected_behavior", "Expected behavior", "The security expectation should be explicit."),
)

AUTH_CASE_REQUIREMENTS = (
    _req("authenticated_context", "Authenticated test identity", "The behavior must be tied to an authorized authenticated context."),
    _req("auth_boundary", "Authentication boundary", "The expected authenticated/anonymous boundary must be known."),
    _req("comparable_response", "Comparable response observation", "A like-for-like before/after or cross-context observation is needed."),
)

OBJECT_CASE_REQUIREMENTS = (
    _req("authenticated_context", "Authenticated test identity", "The endpoint must be observed in an authorized authenticated context."),
    _req("second_identity", "Second authorized test identity", "Ownership boundaries cannot be compared with a single identity."),
    _req("ownership_map", "Object ownership relationship", "The tested object must be tied to a known authorized identity or tenant."),
    _req("comparable_response", "Comparable response observation", "A status/shape/field comparison is required before concluding an authorization difference."),
)

ROLE_CASE_REQUIREMENTS = (
    _req("authenticated_context", "Authenticated test identity", "The function must be observed in an authorized authenticated context."),
    _req("second_identity", "Second authorized role context", "Role authorization requires a lower/higher privilege comparison context."),
    _req("role_map", "Role relationship", "The intended role boundary must be documented."),
    _req("comparable_response", "Comparable response observation", "A like-for-like role comparison is needed."),
)

GRAPHQL_CASE_REQUIREMENTS = (
    _req("authenticated_context", "Authenticated test identity", "GraphQL authorization or data exposure needs an authenticated observation."),
    _req("operation_context", "Operation or field context", "The relevant operation/field/object relationship must be known."),
    _req("comparable_response", "Comparable response observation", "A field/shape/role comparison is needed."),
)

WEBSOCKET_CASE_REQUIREMENTS = (
    _req("authenticated_context", "Authenticated test identity", "The WebSocket/session identity context must be known."),
    _req("channel_context", "Channel/topic relationship", "Expected authorization requires a channel/topic/resource mapping."),
    _req("comparable_response", "Comparable observation", "A like-for-like authorized channel comparison is needed."),
)


# ``promotion_required`` is the minimum evidence needed to expose a signal as a
# Potential Finding. It is deliberately weaker than ``confirmation_required``.
# Potential Finding != confirmed vulnerability.
FAMILY_REASONING: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {
        "label": "BOLA / IDOR",
        "category": "access_control",
        "promotion_required": _groups(
            {"object_identifier", "graphql_identifier"},
            {"object_operation", "graphql_operation"},
            {
                "cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch",
                "parent_child_scope_mismatch", "authorization_response_differential",
                "object_access_without_secondary_guard", "identity_object_relation_conflict",
                "unauthorized_object_response",
            },
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({
            "ownership_enforcement_observed", "cross_context_denied", "scope_binding_observed", "secondary_guard_enforced",
        }),
        "override_signals": frozenset({
            "cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch",
            "parent_child_scope_mismatch", "authorization_response_differential",
            "object_access_without_secondary_guard", "identity_object_relation_conflict", "unauthorized_object_response",
        }),
        "confirmation_required": _groups(
            {"cross_identity_object_access", "cross_tenant_object_access", "unauthorized_object_response", "authorization_response_differential"},
        ),
        "case_requirements": OBJECT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Map the expected identity/tenant-to-object ownership boundary.",
            "Compare the same object operation using explicitly authorized test identities and test-owned objects.",
            "Capture a minimal status/shape/field differential without exposing unrelated user data.",
        ),
        "validation_level": "controlled",
    },
    "broken_function_authorization": {
        "label": "Broken Function Level Authorization",
        "category": "access_control",
        "promotion_required": _groups(
            {"privileged_function", "privileged_classification"},
            {"state_change", "role_property"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"role_enforcement_observed", "lower_privilege_denied", "permission_check_enforced"}),
        "override_signals": frozenset({"unauthorized_function_success", "role_authorization_differential"}),
        "confirmation_required": _groups({"unauthorized_function_success", "role_authorization_differential"}),
        "case_requirements": ROLE_CASE_REQUIREMENTS,
        "next_evidence": (
            "Document the intended role-to-function permission matrix.",
            "Compare the same function with explicitly authorized lower- and higher-privilege test roles.",
            "Capture whether the lower-privilege context is denied or unexpectedly succeeds.",
        ),
        "validation_level": "controlled",
    },
    "mass_assignment": {
        "label": "Mass Assignment / Property Authorization",
        "category": "access_control",
        "promotion_required": _groups(
            {"privileged_property", "privileged_fields"},
            {"write_method", "body_schema", "object_update"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"protected_property_rejected", "server_allowlist_observed", "sensitive_property_ignored"}),
        "override_signals": frozenset({"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"}),
        "confirmation_required": _groups({"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"}),
        "case_requirements": ROLE_CASE_REQUIREMENTS,
        "next_evidence": (
            "Document which request properties are intended to be writable for the current role.",
            "Compare a harmless protected property against the server allow-list using a test-owned object.",
            "Observe whether the property is rejected, ignored, or persisted without attempting real privilege escalation.",
        ),
        "validation_level": "controlled",
    },
    "authentication_session": {
        "label": "Authentication or Session Weakness",
        "category": "authentication",
        "promotion_required": _groups(
            {"authentication_surface"},
            {"client_operation", "state_change", "auth_boundary"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"session_rotation_observed", "recovery_verification_enforced", "expired_session_rejected"}),
        "override_signals": frozenset({"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"}),
        "confirmation_required": _groups({"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"}),
        "case_requirements": AUTH_CASE_REQUIREMENTS,
        "next_evidence": (
            "Model the intended login, recovery, refresh, logout and expiration state machine.",
            "Compare only authorized before/after authentication states.",
            "Record token/session rotation and rejection behavior without credential guessing.",
        ),
        "validation_level": "passive_live",
    },
    "account_enumeration": {
        "label": "Account Enumeration",
        "category": "authentication",
        "promotion_required": _groups(
            {"identity_lookup"},
            {"authentication_surface", "client_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"uniform_identity_response", "uniform_identity_timing"}),
        "override_signals": frozenset({"identity_response_differential", "identity_timing_differential"}),
        "confirmation_required": _groups({"identity_response_differential", "identity_timing_differential"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Compare response shape/status/timing using only test identities you control.",
            "Check whether existing and non-existing test identities receive materially different metadata.",
            "Record rate-limit behavior without probing real user identifiers.",
        ),
        "validation_level": "passive_live",
    },
    "dom_xss": {
        "label": "DOM-based XSS",
        "category": "client_injection",
        "promotion_required": _groups(
            {"dataflow_source", "source_sink"},
            {"dataflow_sink", "source_sink"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"sanitization_observed", "runtime_unreachable"}),
        "override_signals": frozenset({"runtime_dom_sink_reached", "unsanitized_dom_flow"}),
        "confirmation_required": _groups({"runtime_dom_sink_reached", "unsanitized_dom_flow"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Establish runtime reachability from the user-influenced source to the DOM/executable sink.",
            "Inspect transformations, encoding and sanitization before the sink.",
            "Use only a harmless non-executing marker during explicitly authorized validation.",
        ),
        "validation_level": "manual_only",
    },
    "postmessage_trust": {
        "label": "Unsafe postMessage Trust",
        "category": "client_injection",
        "promotion_required": _groups(
            {"dataflow_source", "postmessage_source"},
            {"dataflow_sink", "message_handler", "sensitive_sink"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"origin_check_observed", "trusted_origin_only"}),
        "override_signals": frozenset({"untrusted_message_accepted", "origin_validation_absent"}),
        "confirmation_required": _groups({"untrusted_message_accepted", "origin_validation_absent"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Map message handlers, expected origins and accepted message schema.",
            "Confirm whether origin/source checks protect the sensitive sink.",
            "Do not send harmful message payloads during investigation.",
        ),
        "validation_level": "manual_only",
    },
    "open_redirect": {
        "label": "Open Redirect / Navigation Injection",
        "category": "redirect",
        "promotion_required": _groups(
            {"redirect_parameter", "dataflow_source", "source_sink"},
            {"navigation_context", "dataflow_sink", "source_sink"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"destination_allowlist_observed", "same_origin_navigation_enforced"}),
        "override_signals": frozenset({"external_destination_accepted", "navigation_validation_absent"}),
        "confirmation_required": _groups({"external_destination_accepted", "navigation_validation_absent"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Trace the user-influenced destination to the final navigation sink.",
            "Check allow-list or same-origin enforcement.",
            "Use only a harmless controlled destination when active validation is explicitly authorized.",
        ),
        "validation_level": "passive_live",
    },
    "ssrf": {
        "label": "Server-side Request Forgery Candidate",
        "category": "server_request",
        "promotion_required": _groups(
            {"remote_destination", "url_parameter"},
            {"server_feature", "server_fetch_semantic", "server_request_function"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"browser_side_fetch_observed", "destination_validation_observed", "server_fetch_not_observed"}),
        "override_signals": frozenset({"server_fetch_observed", "controlled_callback_observed"}),
        "confirmation_required": _groups({"server_fetch_observed", "controlled_callback_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Determine whether the server, not the browser, performs the outbound request.",
            "Document destination scheme/host validation and egress restrictions.",
            "Never target internal, metadata or unrelated third-party systems without explicit authorization.",
        ),
        "validation_level": "manual_only",
    },
    "file_upload": {
        "label": "Unsafe File Upload or Import",
        "category": "file_handling",
        "promotion_required": _groups(
            {"file_input"},
            {"upload_operation", "import_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"file_type_enforcement_observed", "safe_storage_observed"}),
        "override_signals": frozenset({"unsafe_file_accepted", "executable_upload_observed", "content_type_bypass_observed"}),
        "confirmation_required": _groups({"unsafe_file_accepted", "executable_upload_observed", "content_type_bypass_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Document accepted type, size, filename and storage controls.",
            "Determine whether uploaded content is served or executed in a security-sensitive context.",
            "Use only an inert benign test file when explicitly authorized.",
        ),
        "validation_level": "manual_only",
    },
    "path_traversal": {
        "label": "Path Traversal Candidate",
        "category": "file_handling",
        "promotion_required": _groups(
            {"path_parameter", "filename_field", "storage_path"},
            {"file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"canonicalization_enforced", "base_directory_enforced"}),
        "override_signals": frozenset({"path_escape_observed", "canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed"}),
        "confirmation_required": _groups({"canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Map path construction, canonicalization and base-directory enforcement.",
            "Determine whether user-controlled path data reaches a file-system operation and can resolve outside the intended root.",
            "Use only explicitly test-owned, non-sensitive sentinel resources; do not request sensitive filesystem paths.",
        ),
        "validation_level": "manual_only",
    },
    "information_disclosure": {
        "label": "Sensitive Information Disclosure",
        "category": "data_exposure",
        "promotion_required": _groups(
            {"sensitive_marker"},
            {"stored_evidence"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"intended_public_metadata", "redaction_enforced"}),
        "override_signals": frozenset({"sensitive_response_observed", "private_field_publicly_observed"}),
        "confirmation_required": _groups({"sensitive_response_observed", "private_field_publicly_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Determine whether the exposed field or metadata is intended to be public.",
            "Capture the minimum response shape needed to establish exposure.",
            "Redact personal data and credentials from stored evidence.",
        ),
        "validation_level": "passive_live",
    },
    "source_map_exposure": {
        "label": "Source-map Exposure",
        "category": "data_exposure",
        "promotion_required": _groups(
            {"source_map"},
            {"internal_sources"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"source_map_not_public", "sources_content_empty"}),
        "override_signals": frozenset({"source_map_publicly_reachable", "sensitive_source_content_observed"}),
        "confirmation_required": _groups({"source_map_publicly_reachable"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Confirm whether the referenced source-map URL is publicly reachable.",
            "Review only enough source metadata to establish impact.",
            "Do not treat internal-looking paths alone as secret disclosure.",
        ),
        "validation_level": "passive_live",
    },
    "secret_exposure": {
        "label": "Credential or Token Exposure",
        "category": "data_exposure",
        "promotion_required": _groups(
            {"secret_pattern"},
            {"context"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"placeholder"}),
        "override_signals": frozenset({"live_secret_context", "credential_material_confirmed"}),
        "confirmation_required": _groups({"live_secret_context", "credential_material_confirmed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Keep the value redacted and determine whether context indicates a placeholder or real credential material.",
            "Establish intended exposure and potential privilege without online credential validation.",
            "Document rotation/revocation status only from authorized evidence sources.",
        ),
        "validation_level": "passive_live",
    },
    "graphql_authorization": {
        "label": "GraphQL Authorization Weakness",
        "category": "graphql",
        "promotion_required": _groups(
            {"graphql_identifier"},
            {"graphql_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"resolver_authorization_observed", "cross_context_denied"}),
        "override_signals": frozenset({"graphql_unauthorized_object_response", "graphql_authorization_differential"}),
        "confirmation_required": _groups({"graphql_unauthorized_object_response", "graphql_authorization_differential"}),
        "case_requirements": GRAPHQL_CASE_REQUIREMENTS,
        "next_evidence": (
            "Map resolver-level ownership/role expectations for the operation.",
            "Compare the same operation using explicitly authorized test objects or roles.",
            "Capture only minimal field/shape differences needed to establish the boundary.",
        ),
        "validation_level": "controlled",
    },
    "graphql_data_exposure": {
        "label": "GraphQL Excessive Data Exposure",
        "category": "graphql",
        "promotion_required": _groups(
            {"sensitive_fields"},
            {"client_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"field_authorization_observed", "sensitive_fields_not_returned"}),
        "override_signals": frozenset({"sensitive_graphql_response_observed", "field_authorization_differential"}),
        "confirmation_required": _groups({"sensitive_graphql_response_observed", "field_authorization_differential"}),
        "case_requirements": GRAPHQL_CASE_REQUIREMENTS,
        "next_evidence": (
            "Determine whether sensitive fields are actually returned to the current role.",
            "Document the intended minimum response shape and field-level authorization.",
            "Capture field names/types rather than unnecessary sensitive values.",
        ),
        "validation_level": "passive_live",
    },
    "business_logic": {
        "label": "Business Logic Weakness",
        "category": "business_logic",
        "promotion_required": _groups(
            {"workflow_markers"},
            {"stateful_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"workflow_invariant_enforced", "invalid_transition_rejected"}),
        "override_signals": frozenset({"workflow_invariant_violation", "invalid_transition_accepted", "server_value_override_observed"}),
        "confirmation_required": _groups({"workflow_invariant_violation", "invalid_transition_accepted", "server_value_override_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Model the intended workflow states, transitions and business invariants.",
            "Identify which values must be server-controlled and which transitions must be ordered or single-use.",
            "Use only reversible actions and authorized test data when comparing transitions.",
        ),
        "validation_level": "manual_only",
    },
    "race_condition": {
        "label": "Race Condition / Duplicate Operation",
        "category": "business_logic",
        "promotion_required": _groups(
            {"workflow_markers"},
            {"stateful_operation"},
            {"single_use_semantics"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"idempotency_enforced", "atomic_transition_observed"}),
        "override_signals": frozenset({"duplicate_operation_observed", "non_atomic_transition_observed"}),
        "confirmation_required": _groups({"duplicate_operation_observed", "non_atomic_transition_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Document whether the operation is single-use, balance-changing or intended to be idempotent.",
            "Inspect idempotency/transaction controls from stored evidence before any concurrency test.",
            "Do not run concurrent requests unless explicit authorization permits it.",
        ),
        "validation_level": "manual_only",
    },
    "websocket_authorization": {
        "label": "WebSocket Authorization Weakness",
        "category": "realtime",
        "promotion_required": _groups(
            {"dataflow_source", "websocket_channel", "channel_identifier"},
            {"dataflow_sink", "websocket_operation", "subscription_operation"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"channel_authorization_observed", "unauthorized_subscription_denied"}),
        "override_signals": frozenset({"unauthorized_subscription_observed", "channel_authorization_differential"}),
        "confirmation_required": _groups({"unauthorized_subscription_observed", "channel_authorization_differential"}),
        "case_requirements": WEBSOCKET_CASE_REQUIREMENTS,
        "next_evidence": (
            "Map channel/topic identifiers to identities, tenants or resources.",
            "Compare only channels belonging to explicitly authorized test identities.",
            "Do not subscribe to unrelated user or tenant channels.",
        ),
        "validation_level": "controlled",
    },
    "cors_misconfiguration": {
        "label": "CORS Misconfiguration",
        "category": "headers",
        "promotion_required": _groups(
            {"cors_header"},
            {"sensitive_context"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"trusted_origin_only", "credentials_disabled", "cross_origin_read_blocked"}),
        "override_signals": frozenset({"untrusted_origin_allowed", "credentialed_cross_origin_read"}),
        "confirmation_required": _groups({"untrusted_origin_allowed", "credentialed_cross_origin_read"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Record the exact Access-Control-Allow-Origin and credential behavior.",
            "Determine whether a security-sensitive response is readable from an unintended controlled origin.",
            "Do not infer exploitability from wildcard/reflection headers alone.",
        ),
        "validation_level": "passive_live",
    },
    "sensitive_caching": {
        "label": "Sensitive Response Caching",
        "category": "headers",
        "promotion_required": _groups(
            {"cache_header"},
            {"sensitive_context"},
        ),
        "min_independent_sources": 2,
        "blocking_contradictions": frozenset({"private_cache_control_observed", "user_specific_vary_observed", "shared_cache_bypass_observed"}),
        "override_signals": frozenset({"shared_cache_sensitive_response", "cross_user_cache_observed"}),
        "confirmation_required": _groups({"shared_cache_sensitive_response", "cross_user_cache_observed"}),
        "case_requirements": DEFAULT_CASE_REQUIREMENTS,
        "next_evidence": (
            "Document authentication context, Cache-Control and Vary/cache-key behavior.",
            "Determine whether the response is user-specific and can enter a shared cache.",
            "Avoid storing sensitive response bodies during cache analysis.",
        ),
        "validation_level": "passive_live",
    },
}


def family_policy(family: str) -> dict[str, Any] | None:
    policy = FAMILY_REASONING.get(str(family or "").strip())
    return dict(policy) if policy else None


def admission_policy_map() -> dict[str, dict[str, Any]]:
    """Return the shape consumed by the admission engine.

    The legacy key ``required`` is intentionally retained at this boundary so
    existing admission code can migrate without changing persisted schema.
    """
    result: dict[str, dict[str, Any]] = {}
    for family, policy in FAMILY_REASONING.items():
        result[family] = {
            "required": [set(group) for group in policy["promotion_required"]],
            "min_independent_sources": int(policy.get("min_independent_sources", 1)),
            "label": policy["label"],
            "blocking_contradictions": set(policy.get("blocking_contradictions", ())),
            "override_signals": set(policy.get("override_signals", ())),
            "confirmation_required": [set(group) for group in policy.get("confirmation_required", ())],
            "validation_level": policy.get("validation_level", "offline"),
        }
    return result


def candidate_evidence_schema_map() -> dict[str, dict[str, Any]]:
    """Return the exact evidence groups Candidate Engine should use.

    This prevents detector/schema spelling drift such as ``privileged_property``
    vs ``privileged_fields`` and ``dataflow_source``/``dataflow_sink`` vs the old
    synthetic ``source_sink`` token.
    """
    return {
        family: {
            "required_any": tuple(tuple(sorted(group)) for group in policy["promotion_required"]),
            "label": policy["label"],
        }
        for family, policy in FAMILY_REASONING.items()
    }


def case_requirement_map() -> dict[str, list[dict[str, str]]]:
    return {
        family: [dict(item) for item in policy.get("case_requirements", DEFAULT_CASE_REQUIREMENTS)]
        for family, policy in FAMILY_REASONING.items()
    }


def validation_level_for_family(family: str) -> str:
    policy = FAMILY_REASONING.get(str(family or ""))
    return str(policy.get("validation_level") or "offline") if policy else "offline"


def confirmation_gaps(family: str, evidence_types: Iterable[str]) -> list[list[str]]:
    policy = FAMILY_REASONING.get(str(family or ""))
    if not policy:
        return [["family reasoning policy"]]
    types = {str(value) for value in evidence_types}
    missing: list[list[str]] = []
    for group in policy.get("confirmation_required", ()):
        if not (set(group) & types):
            missing.append(sorted(group))
    return missing


def catalog_audit(expected_families: Iterable[str] | None = None) -> dict[str, Any]:
    expected = set(str(value) for value in (expected_families or FAMILY_ORDER))
    actual = set(FAMILY_REASONING)
    invalid: list[str] = []
    for family, policy in FAMILY_REASONING.items():
        if not policy.get("promotion_required") or not policy.get("confirmation_required"):
            invalid.append(family)
        if policy.get("validation_level") not in {"offline", "passive_live", "controlled", "manual_only"}:
            invalid.append(family)
        if int(policy.get("min_independent_sources", 0)) < 1:
            invalid.append(family)
    return {
        "version": FAMILY_REASONING_VERSION,
        "rule_version": FAMILY_REASONING_RULE_VERSION,
        "expected_count": len(expected),
        "actual_count": len(actual),
        "missing": sorted(expected - actual),
        "unexpected": sorted(actual - expected),
        "invalid": sorted(set(invalid)),
        "complete": expected == actual and not invalid,
    }

from __future__ import annotations

import json
import math
import re
import uuid
from difflib import SequenceMatcher
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, parse_int, sha256_text, utc_now
from analysis_audit import build_evidence_dossier, capture_evidence_snapshot, record_analysis_version, record_excluded_signal

REASONING_ENGINE_VERSION = "5.1.1"
REASONING_RULE_VERSION = "2026.08.8.1"

SOURCE_TRUST = {
    "behavioral_diff": 94,
    "http": 90,
    "response_shape": 88,
    "endpoint_contract": 84,
    "graphql": 82,
    "identity_graph": 80,
    "javascript": 76,
    "semantic": 72,
    "source_map": 68,
    "historical_url": 48,
    "keyword": 24,
    "rule": 35,
    "unknown": 30,
}

# Each group means: at least one signal from the group should exist.
FAMILY_SCHEMAS: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {
        "label": "BOLA / IDOR",
        "required": [
            {"object_identifier", "graphql_identifier", "parameter_relation"},
            {"object_operation", "graphql_operation"},
        ],
        "support": {"sensitive_object", "business_context", "identity_relation", "client_controlled", "response_data", "cross_context"},
        "contradict": {"ownership_binding", "current_user_only", "identifier_ignored", "non_reachable"},
        "unknowns": ["Expected ownership or tenant boundary", "Server-side identity-to-object binding", "Behavior with another explicitly authorized test object"],
        "variants": {"tenant": "cross_tenant_object_boundary", "account": "cross_account_object_boundary", "invoice": "invoice_object_boundary", "order": "order_object_boundary"},
    },
    "broken_function_authorization": {
        "label": "Broken Function Level Authorization",
        "required": [{"privileged_function", "privileged_classification", "sensitive_operation"}, {"role_property", "state_change", "role_hint"}],
        "support": {"admin_route", "authorization_change", "feature_activation", "cross_context", "identity_relation"},
        "contradict": {"confirmed_role_enforcement", "non_reachable", "public_intended"},
        "unknowns": ["Expected role boundary", "Server-side function authorization", "Reachability by a lower-privileged authorized identity"],
        "variants": {"export": "privileged_export_boundary", "approve": "approval_role_boundary", "admin": "administrative_function_boundary"},
    },
    "mass_assignment": {
        "label": "Mass Assignment / Property Authorization",
        "required": [{"write_method", "state_change"}, {"privileged_fields", "body_schema", "input_fields"}],
        "support": {"endpoint_contract", "role_property", "identity_property", "client_controlled"},
        "contradict": {"field_allowlist", "privileged_fields_removed", "read_only_contract"},
        "unknowns": ["Server-side accepted-field allowlist", "Whether privileged fields are writable", "Object property authorization behavior"],
        "variants": {"role": "role_property_assignment", "tenant": "tenant_property_assignment", "status": "state_property_assignment"},
    },
    "authentication_session": {
        "label": "Authentication or Session Weakness",
        "required": [{"authentication_semantic", "auth_boundary", "oauth_parameter", "token_storage"}],
        "support": {"boundary_regression", "protected_to_public", "session_change", "token_exposure", "missing_state"},
        "contradict": {"authentication_required", "stable_boundary", "pkce_present", "state_present"},
        "unknowns": ["Intended authentication state", "Server-side session or token validation", "Behavior across authorized authentication contexts"],
        "variants": {"oauth": "oauth_flow_weakness", "session": "session_boundary_weakness", "token": "token_handling_weakness"},
    },
    "dom_xss": {
        "label": "DOM-based XSS",
        "rank_gate": {"source_sink", "dangerous_sink"},
        "required": [{"source_sink"}, {"reachable_route", "javascript_runtime", "semantic_unit"}],
        "support": {"dangerous_sink", "user_controlled_source", "no_sanitizer", "html_context"},
        "contradict": {"recognized_sanitizer", "text_only_sink", "constant_value", "non_reachable"},
        "unknowns": ["Runtime reachability of the source-to-sink flow", "Encoding or sanitization applied before the sink", "Exact browser execution context"],
        "variants": {"postmessage": "postmessage_to_dom_sink", "location": "url_source_to_dom_sink", "storage": "storage_source_to_dom_sink"},
    },
    "open_redirect": {
        "label": "Open Redirect / Navigation Injection",
        "rank_gate": {"redirect_parameter", "navigation_sink"},
        "required": [{"redirect_parameter", "source_sink", "navigation_sink"}],
        "support": {"external_url", "oauth_callback", "user_controlled_source", "client_navigation"},
        "contradict": {"same_origin_only", "relative_path_only", "host_allowlist", "constant_value"},
        "unknowns": ["Destination validation policy", "Same-origin or allowlist enforcement", "Whether the navigation target is user-controlled at runtime"],
        "variants": {"oauth": "oauth_callback_redirect", "next": "next_parameter_redirect", "return": "return_url_redirect"},
    },
    "ssrf": {
        "label": "Server-side Request Forgery Candidate",
        "rank_gate": {"server_fetch_semantic", "server_request_function", "webhook_operation"},
        "required": [{"url_parameter", "remote_resource"}, {"server_fetch_semantic", "server_request_function", "webhook_operation"}],
        "support": {"preview_operation", "remote_import", "pdf_from_url", "backend_fetch"},
        "contradict": {"browser_side_only", "relative_path_only", "host_allowlist", "predefined_destination"},
        "unknowns": ["Whether the server performs the request", "Destination allowlist and network restrictions", "Redirect and DNS resolution behavior"],
        "variants": {"webhook": "webhook_destination_fetch", "import": "remote_import_fetch", "preview": "url_preview_fetch"},
    },
    "information_disclosure": {
        "label": "Sensitive Information Disclosure",
        "required": [{"sensitive_fields", "secret_pattern", "source_map", "debug_information", "sensitive_expansion"}],
        "support": {"public_observation", "response_data", "internal_sources", "error_to_data", "protected_to_data"},
        "contradict": {"redacted_only", "placeholder", "authentication_required", "intended_public"},
        "unknowns": ["Intended visibility of the data", "Actual response exposure for the current role", "Whether values are real, placeholders, or redacted"],
        "variants": {"source": "source_code_disclosure", "secret": "credential_material_exposure", "debug": "debug_information_exposure"},
    },
    "graphql_authorization": {
        "label": "GraphQL Authorization Weakness",
        "rank_gate": {"graphql_operation"},
        "required": [{"graphql_operation"}, {"graphql_identifier", "sensitive_fields"}],
        "support": {"nested_sensitive_fields", "batch_operation", "identity_relation", "cross_context"},
        "contradict": {"resolver_authorization", "schema_only", "non_reachable"},
        "unknowns": ["Resolver-level authorization", "Field-level authorization", "Expected object ownership or role boundary"],
        "variants": {"mutation": "graphql_mutation_authorization", "field": "graphql_field_authorization", "object": "graphql_object_authorization"},
    },
    "business_logic": {
        "label": "Business Logic Weakness",
        "required": [{"business_operation", "state_change", "workflow_transition"}],
        "support": {"financial_context", "single_use_operation", "approval_operation", "amount_field", "feature_activation"},
        "contradict": {"idempotency_control", "state_machine_enforced", "read_only_contract"},
        "unknowns": ["Intended workflow and invariants", "Server-side state transition enforcement", "Idempotency or uniqueness controls"],
        "variants": {"refund": "refund_state_machine", "redeem": "single_use_redemption", "approve": "approval_workflow", "transfer": "amount_consistency"},
    },
    "race_condition": {
        "label": "Race Condition / Duplicate Operation",
        "required": [{"state_change"}, {"single_use_operation", "balance_operation", "duplicate_operation"}],
        "support": {"idempotency_unknown", "financial_context", "redeem_operation", "refund_operation"},
        "contradict": {"idempotency_control", "transaction_lock", "read_only_contract"},
        "unknowns": ["Idempotency or uniqueness enforcement", "Transaction isolation behavior", "Whether concurrent execution is explicitly authorized for validation"],
        "variants": {"redeem": "duplicate_redemption", "refund": "duplicate_refund", "transfer": "concurrent_balance_update"},
    },
    "websocket_authorization": {
        "label": "WebSocket Authorization Weakness",
        "rank_gate": {"websocket_channel", "websocket_url", "subscribe_operation"},
        "required": [{"websocket_channel", "websocket_url"}, {"object_identifier", "identity_relation", "subscribe_operation"}],
        "support": {"tenant_channel", "room_identifier", "user_channel", "missing_auth_message"},
        "contradict": {"channel_authorization", "authenticated_handshake", "non_reachable"},
        "unknowns": ["Channel subscription authorization", "Handshake identity binding", "Expected room, user, or tenant boundary"],
        "variants": {"tenant": "cross_tenant_subscription", "room": "room_subscription_boundary", "user": "user_channel_boundary"},
    },
    "sensitive_caching": {
        "label": "Sensitive Response Caching",
        "required": [{"cache_header", "public_cache"}, {"sensitive_fields", "authenticated_context", "response_data"}],
        "support": {"cache_regression", "missing_vary", "cdn_cache", "sensitive_expansion"},
        "contradict": {"no_store", "private_cache", "vary_authorization"},
        "unknowns": ["Effective shared-cache behavior", "Authentication context included in the cache key", "Whether sensitive responses are cacheable in production"],
        "variants": {"cdn": "cdn_sensitive_response_cache", "auth": "authenticated_response_cache"},
    },
    "account_enumeration": {
        "label": "Account Enumeration",
        "required": [{"authentication_semantic", "account_identifier"}, {"response_difference", "timing_difference", "error_schema"}],
        "support": {"anonymous_context", "distinct_error", "identity_field"},
        "contradict": {"uniform_response", "rate_limited", "generic_error"},
        "unknowns": ["Whether responses differ for controlled test identities", "Timing variance under repeated benign observations", "Intended account discovery behavior"],
        "variants": {"login": "login_identifier_enumeration", "reset": "password_reset_enumeration"},
    },
    "postmessage_trust": {
        "label": "Unsafe postMessage Trust",
        "rank_gate": {"postmessage_handler"},
        "required": [{"postmessage_handler"}, {"message_source", "message_sink", "semantic_unit"}],
        "support": {"missing_origin_check", "wildcard_origin", "dangerous_sink"},
        "contradict": {"strict_origin_check", "source_window_check", "schema_validation"},
        "unknowns": ["Origin and source-window validation", "Accepted message schema", "Reachability of security-sensitive message actions"],
        "variants": {"origin": "missing_message_origin_validation", "dom": "postmessage_to_dom_sink"},
    },
    "file_upload": {
        "label": "Unsafe File Upload or Import",
        "required": [{"file_input", "upload_operation", "import_operation"}, {"state_change", "write_method", "endpoint_contract"}],
        "support": {"filename_field", "content_type_field", "remote_import", "storage_path"},
        "contradict": {"strict_type_allowlist", "inert_storage", "read_only_contract"},
        "unknowns": ["Accepted file types and content validation", "Storage and serving behavior", "Filename and path normalization"],
        "variants": {"import": "unsafe_remote_import", "upload": "unsafe_direct_upload"},
    },
    "path_traversal": {
        "label": "Path Traversal Candidate",
        "required": [{"path_parameter", "filename_field", "storage_path"}, {"file_operation", "download_operation", "import_operation"}],
        "support": {"client_controlled", "path_join", "archive_operation"},
        "contradict": {"canonicalization", "fixed_directory", "opaque_file_id"},
        "unknowns": ["Server-side path canonicalization", "Base-directory enforcement", "Whether client input reaches a filesystem operation"],
        "variants": {"download": "file_download_path_boundary", "archive": "archive_entry_path_boundary"},
    },
    "source_map_exposure": {
        "label": "Source-map Exposure",
        "rank_gate": {"source_map"},
        "required": [{"source_map"}, {"internal_sources", "source_contents"}],
        "support": {"public_observation", "production_javascript", "debug_information"},
        "contradict": {"non_reachable", "empty_map", "intended_public"},
        "unknowns": ["Direct public reachability of the source map", "Sensitivity of included source contents", "Whether secrets or internal-only logic are present"],
        "variants": {"internal": "internal_source_path_exposure", "content": "source_content_exposure"},
    },
    "secret_exposure": {
        "label": "Credential or Token Exposure",
        "rank_gate": {"secret_pattern"},
        "required": [{"secret_pattern"}, {"javascript_runtime", "production_javascript", "client_operation"}],
        "support": {"token_exposure", "credential_context", "high_entropy_value"},
        "contradict": {"placeholder", "example_value", "redacted_only"},
        "unknowns": ["Whether the value is live or a placeholder", "Privilege and intended exposure", "Rotation or revocation status"],
        "variants": {"token": "client_token_exposure", "key": "client_api_key_exposure"},
    },
    "graphql_data_exposure": {
        "label": "GraphQL Excessive Data Exposure",
        "rank_gate": {"graphql_operation"},
        "required": [{"graphql_operation"}, {"sensitive_fields", "nested_sensitive_fields"}],
        "support": {"response_data", "field_expansion", "cross_context"},
        "contradict": {"schema_only", "field_authorization", "minimal_projection"},
        "unknowns": ["Fields actually returned to the current role", "Field-level authorization", "Intended minimum response projection"],
        "variants": {"field": "graphql_sensitive_field_exposure", "nested": "graphql_nested_data_exposure"},
    },
    "cors_misconfiguration": {
        "label": "CORS Misconfiguration",
        "rank_gate": {"cors_header", "wildcard_origin", "reflected_origin"},
        "required": [{"cors_header", "wildcard_origin", "reflected_origin"}],
        "support": {"credentials_allowed", "sensitive_fields", "authenticated_context"},
        "contradict": {"strict_origin_allowlist", "credentials_disabled", "public_intended"},
        "unknowns": ["Credentialed cross-origin behavior", "Effective origin validation", "Sensitivity of responses available cross-origin"],
        "variants": {"wildcard": "wildcard_origin_policy", "reflect": "reflected_origin_policy"},
    },
}

EXPERIMENTAL_SHADOW_RULES = {
    "shadow-cross-context-boundary": "Rank authorization candidates higher when the same endpoint has distinct stored identity contexts and a sensitive shape difference.",
    "shadow-feature-causal-chain": "Connect feature activation, endpoint appearance, authentication changes, and response expansion into one probable introduction chain.",
    "shadow-business-invariant": "Infer state-machine and idempotency candidates from sensitive business operations and contract changes.",
}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _norm_type(value: Any) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value or "unknown").strip().lower()).strip("_") or "unknown"


def _source_kind(item: Mapping[str, Any]) -> str:
    source = _norm_type(item.get("source") or item.get("source_group") or item.get("type"))
    if source in {"boundary_diff", "response_diff", "behavioral", "authentication_boundary_diff"}:
        return "behavioral_diff"
    if source in {"http", "reachability", "public_observation", "anonymous_boundary"}:
        return "http"
    if source in {"shape", "response_shape", "sensitive_fields"}:
        return "response_shape"
    if source in {"contract", "endpoint_schema", "endpoint_contract"}:
        return "endpoint_contract"
    if source in {"js", "javascript", "dataflow"}:
        return "javascript"
    if source in {"graphql"}:
        return "graphql"
    if source in {"identity", "identity_graph", "parameter_relationship"}:
        return "identity_graph"
    if source in {"semantic", "context", "classification"}:
        return "semantic"
    if source in {"source_map", "source_paths"}:
        return "source_map"
    return source if source in SOURCE_TRUST else "unknown"


def _signal_type(item: Mapping[str, Any]) -> str:
    return _norm_type(item.get("type") or item.get("kind") or "unknown")


def _root_fingerprint(candidate: Mapping[str, Any], item: Mapping[str, Any], polarity: str) -> str:
    source = _source_kind(item)
    source_group = _norm_type(item.get("source_group") or item.get("source") or item.get("type"))
    artifact = str(item.get("artifact") or item.get("source_ref") or candidate.get("source_ref") or candidate.get("endpoint") or "")
    text = str(item.get("text") or item.get("summary") or "")
    normalized_text = re.sub(r"\b\d{2,}\b", "{n}", text.lower())
    return sha256_text("|".join([str(candidate.get("target") or ""), source, source_group, artifact, normalized_text, polarity]))


def _trust(item: Mapping[str, Any]) -> int:
    source = _source_kind(item)
    direct = bool(item.get("direct") or source in {"behavioral_diff", "http", "response_shape"})
    trust = SOURCE_TRUST.get(source, SOURCE_TRUST["unknown"])
    if direct:
        trust += 4
    if _signal_type(item) in {"semantic_marker", "keyword", "business_context"}:
        trust = min(trust, 45)
    return _clamp(trust, 10, 98)


def _endpoint_key(endpoint: str) -> str:
    value = endpoint.lower().strip()
    value = re.sub(r"\b\d{2,}\b", "{n}", value)
    value = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", value, flags=re.I)
    return value


def _candidate_context(db: Database, candidate: Mapping[str, Any]) -> dict[str, Any]:
    analysis_id = str(candidate["analysis_id"])
    target = str(candidate["target"])
    endpoint = str(candidate.get("endpoint") or "")
    context: dict[str, Any] = {}
    context["contract"] = dict(db.one("SELECT * FROM endpoint_contracts WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, target, endpoint)) or {})
    context["boundary"] = dict(db.one("SELECT * FROM authentication_boundaries WHERE analysis_id=? AND target=? AND endpoint=?", (analysis_id, target, endpoint)) or {})
    context["boundary_diff"] = dict(db.one("SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, target, endpoint)) or {})
    context["shape"] = dict(db.one("SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, target, endpoint)) or {})
    context["shape_diff"] = dict(db.one("SELECT * FROM response_shape_diffs WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, target, endpoint)) or {})
    context["observations"] = [dict(row) for row in db.all("SELECT * FROM behavioral_observations WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY context", (analysis_id, target, endpoint))]
    context["protocols"] = [dict(row) for row in db.all("SELECT * FROM protocol_findings WHERE analysis_id=? AND target=? AND (entity=? OR entity LIKE ?) ORDER BY confidence DESC", (analysis_id, target, endpoint, f"%{endpoint}%"))]
    context["relations"] = [dict(row) for row in db.all("SELECT * FROM identity_relations WHERE analysis_id=? AND target=? AND (source_value=? OR destination_value=? OR source_value LIKE ? OR destination_value LIKE ?) ORDER BY confidence DESC LIMIT 100", (analysis_id, target, endpoint, endpoint, f"%{endpoint}%", f"%{endpoint}%"))]
    context["flags"] = [dict(row) for row in db.all("SELECT * FROM feature_flags WHERE analysis_id=? AND target=? ORDER BY confidence DESC LIMIT 100", (analysis_id, target))]
    context["deployments"] = [dict(row) for row in db.all("SELECT * FROM deployment_signatures WHERE analysis_id=? AND target=? ORDER BY confidence DESC LIMIT 20", (analysis_id, target))]
    return context


def _synthetic_evidence(candidate: Mapping[str, Any], context: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    endpoint = str(candidate.get("endpoint") or "")
    family = str(candidate.get("bug_family") or "")
    contract = context.get("contract") or {}
    boundary = context.get("boundary") or {}
    boundary_diff = context.get("boundary_diff") or {}
    shape = context.get("shape") or {}
    shape_diff = context.get("shape_diff") or {}
    observations = context.get("observations") or []
    protocols = context.get("protocols") or []
    relations = context.get("relations") or []

    if contract:
        support.append({"type": "endpoint_contract", "source": "endpoint_contract", "source_group": "contract", "weight": 8, "text": "A structured endpoint contract was extracted", "artifact": endpoint, "direct": True})
        method = str(contract.get("method") or "").upper()
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            support.append({"type": "write_method", "source": "endpoint_contract", "source_group": "contract_method", "weight": 8, "text": f"The endpoint uses state-changing method {method}", "artifact": endpoint, "direct": True})
            support.append({"type": "state_change", "source": "endpoint_contract", "source_group": "contract_method", "weight": 8, "text": "The contract represents a state-changing operation", "artifact": endpoint})
        inputs = _loads(contract.get("input_fields_json"), {})
        if inputs:
            support.append({"type": "input_fields", "source": "endpoint_contract", "source_group": "contract_inputs", "weight": 7, "text": "Client-visible input fields were extracted from the endpoint contract", "artifact": endpoint})
        boundary_name = str(contract.get("auth_boundary") or "unknown")
        if boundary_name not in {"", "unknown", "public"}:
            support.append({"type": "auth_boundary", "source": "endpoint_contract", "source_group": "authentication", "weight": 6, "text": f"Contract indicates authentication boundary: {boundary_name}", "artifact": endpoint})

    current_boundary = str(boundary.get("boundary") or "")
    if current_boundary:
        if current_boundary == "public":
            support.append({"type": "public_observation", "source": "http", "source_group": "authentication", "weight": 10, "text": "Stored evidence classifies the endpoint as public", "artifact": endpoint, "direct": True})
        elif current_boundary in {"authentication_required", "session_required", "bearer_required", "api_key_required"}:
            contradict.append({"type": "authentication_required", "source": "http", "source_group": "authentication", "weight": -4, "text": f"Stored evidence shows an authentication boundary ({current_boundary}); object and role authorization remain unknown", "artifact": endpoint, "direct": True})

    transition = str(boundary_diff.get("transition") or "")
    if transition and transition != "stable":
        support.append({"type": "boundary_regression", "source": "behavioral_diff", "source_group": "boundary_diff", "weight": 22, "text": f"Authentication boundary changed: {transition}", "artifact": endpoint, "direct": True})
        if "public" in transition or str(boundary_diff.get("current_boundary")) == "public":
            support.append({"type": "protected_to_public", "source": "behavioral_diff", "source_group": "boundary_diff", "weight": 20, "text": "A previously protected boundary appears public in the stored comparison", "artifact": endpoint, "direct": True})

    sensitive_keys = _loads(shape.get("sensitive_keys_json"), [])
    if sensitive_keys:
        support.append({"type": "sensitive_fields", "source": "response_shape", "source_group": "response_shape", "weight": min(18, 7 + len(sensitive_keys)), "text": f"Response shape contains sensitive field classes: {', '.join(map(str, sensitive_keys[:8]))}", "artifact": endpoint, "direct": True})
        support.append({"type": "response_data", "source": "response_shape", "source_group": "response_shape", "weight": 8, "text": "A structured data response was observed", "artifact": endpoint, "direct": True})
    shape_transition = str(shape_diff.get("transition") or "")
    if shape_transition and shape_transition != "stable":
        support.append({"type": "response_shape_change", "source": "behavioral_diff", "source_group": "response_diff", "weight": 13, "text": f"Stored response structure changed: {shape_transition}", "artifact": endpoint, "direct": True})
        if shape_transition in {"error_to_data", "protected_to_data"}:
            support.append({"type": shape_transition, "source": "behavioral_diff", "source_group": "response_diff", "weight": 22, "text": f"Security-relevant response transition observed: {shape_transition}", "artifact": endpoint, "direct": True})
        sensitive_added = _loads(shape_diff.get("sensitive_added_json"), [])
        if sensitive_added:
            support.append({"type": "sensitive_expansion", "source": "behavioral_diff", "source_group": "response_diff", "weight": min(22, 12 + len(sensitive_added)), "text": f"Sensitive response fields were added: {', '.join(map(str, sensitive_added[:8]))}", "artifact": endpoint, "direct": True})

    if len({str(row.get("context")) for row in observations}) >= 2:
        support.append({"type": "cross_context", "source": "behavioral_diff", "source_group": "stored_contexts", "weight": 14, "text": "The endpoint has observations from multiple stored identity contexts", "artifact": endpoint, "direct": True})
    for relation in relations[:6]:
        support.append({"type": "identity_relation", "source": "identity_graph", "source_group": "identity_graph", "weight": 8, "text": f"Identity graph relation: {relation.get('source_value')} {relation.get('relation')} {relation.get('destination_value')}", "artifact": endpoint})
        support.append({"type": "parameter_relation", "source": "identity_graph", "source_group": "identity_graph", "weight": 7, "text": "An object or identity relationship was inferred", "artifact": endpoint})
    for finding in protocols[:5]:
        kind = _norm_type(finding.get("kind"))
        protocol = _norm_type(finding.get("protocol"))
        support.append({"type": kind, "source": protocol if protocol in SOURCE_TRUST else "semantic", "source_group": f"protocol_{protocol}", "weight": max(5, min(15, parse_int(finding.get("confidence"), 50) // 8)), "text": str(finding.get("summary") or kind), "artifact": str(finding.get("entity") or endpoint)})
        if protocol == "graphql": support.append({"type": "graphql_operation", "source": "graphql", "source_group": "protocol_graphql", "weight": 9, "text": "GraphQL protocol intelligence is associated with this candidate", "artifact": endpoint})
        if protocol == "websocket": support.append({"type": "websocket_channel", "source": "semantic", "source_group": "protocol_websocket", "weight": 9, "text": "WebSocket channel intelligence is associated with this candidate", "artifact": endpoint})

    lower = " ".join([endpoint, str(candidate.get("bug_variant") or ""), str(candidate.get("summary") or "")]).lower()
    operations = {
        "refund": "refund_operation", "redeem": "redeem_operation", "transfer": "balance_operation", "withdraw": "balance_operation",
        "approve": "approval_operation", "export": "sensitive_operation", "delete": "sensitive_operation", "invite": "business_operation",
        "coupon": "single_use_operation", "payment": "financial_context", "invoice": "financial_context",
    }
    for token, signal in operations.items():
        if token in lower:
            support.append({"type": signal, "source": "semantic", "source_group": "business_semantics", "weight": 7, "text": f"Business operation marker observed: {token}", "artifact": endpoint})
            support.append({"type": "business_operation", "source": "semantic", "source_group": "business_semantics", "weight": 5, "text": "A security-relevant business operation was inferred", "artifact": endpoint})
    if family == "race_condition" and not any(_signal_type(x) == "idempotency_control" for x in support + contradict):
        support.append({"type": "idempotency_unknown", "source": "semantic", "source_group": "business_semantics", "weight": 4, "text": "No idempotency indicator was observed in the stored contract", "artifact": endpoint})
    return support, contradict


def _materialize_evidence(db: Database, candidate: Mapping[str, Any], support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    candidate_id = str(candidate["candidate_id"])
    analysis_id = str(candidate["analysis_id"])
    db.execute("DELETE FROM candidate_evidence_links WHERE candidate_id=?", (candidate_id,))
    db.execute("DELETE FROM candidate_evidence_snapshots WHERE candidate_id=?", (candidate_id,))
    db.execute("DELETE FROM candidate_evidence_exclusions WHERE candidate_id=?", (candidate_id,))
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    excluded: list[tuple[str, str, dict[str, Any], str, str]] = []
    raw_count = 0
    for polarity, values in (("support", support), ("contradict", contradict)):
        for raw in values:
            raw_count += 1
            item = dict(raw)
            item["type"] = _signal_type(item)
            item["source_kind"] = _source_kind(item)
            item["source_group"] = _norm_type(item.get("source_group") or item.get("source") or item.get("type"))
            item["trust_score"] = _trust(item)
            item["root_fingerprint"] = _root_fingerprint(candidate, item, polarity)
            key = (polarity, item["root_fingerprint"])
            current = selected.get(key)
            score = abs(parse_int(item.get("weight"), 0)) * 2 + item["trust_score"]
            item["_selection_score"] = score
            if current is None:
                selected[key] = item
            elif score > current["_selection_score"]:
                excluded.append((polarity, item["root_fingerprint"], dict(current), "correlated_duplicate", "Suppressed because a stronger signal from the same underlying evidence root was selected."))
                selected[key] = item
            else:
                excluded.append((polarity, item["root_fingerprint"], dict(item), "correlated_duplicate", "Suppressed because an equal or stronger signal from the same underlying evidence root was already selected."))
    out_support: list[dict[str, Any]] = []
    out_contradict: list[dict[str, Any]] = []
    for (polarity, root), item in selected.items():
        item.pop("_selection_score", None)
        evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:evidence:{analysis_id}:{root}"))
        source_artifact = str(item.get("artifact") or candidate.get("source_ref") or candidate.get("endpoint") or "")
        directness = "direct" if item.get("direct") or item["source_kind"] in {"behavioral_diff", "http", "response_shape"} else "inferred"
        db.execute(
            """INSERT OR REPLACE INTO evidence_records(
            evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,
            parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,
            summary,raw_reference,integrity_hash,first_seen,last_seen,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id, analysis_id, candidate["source_run_id"], candidate["target"], item["type"], polarity,
                item["source_kind"], str(item.get("source_tool") or item["source_kind"]), source_artifact,
                str(item.get("parser_name") or "security_reasoning"), str(item.get("parser_version") or REASONING_RULE_VERSION),
                item["source_group"], root, item["trust_score"], _clamp(item["trust_score"] + parse_int(item.get("weight"), 0) * 0.3, 10, 98), directness,
                str(item.get("text") or item.get("summary") or item["type"]), str(item.get("raw_reference") or source_artifact),
                sha256_text(json_dumps({"candidate": candidate_id, "item": item, "polarity": polarity})), candidate.get("created_at") or utc_now(), utc_now(), utc_now(),
            ),
        )
        db.execute("INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES(?,?,?,?,?,?)", (candidate_id, evidence_id, polarity, parse_int(item.get("weight"), 0), "supports" if polarity == "support" else "contradicts", utc_now()))
        capture_evidence_snapshot(db, candidate, evidence_id, item)
        item["evidence_id"] = evidence_id
        (out_support if polarity == "support" else out_contradict).append(item)
    for polarity, root, item, reason_code, reason in excluded:
        record_excluded_signal(db, candidate, item, polarity, root, reason_code, reason)
    metadata = {
        "raw_signals": raw_count,
        "independent_evidence": len(selected),
        "suppressed_correlated_signals": len(excluded),
        "support_roots": len(out_support),
        "contradict_roots": len(out_contradict),
    }
    return out_support, out_contradict, metadata


def _types(items: Iterable[Mapping[str, Any]]) -> set[str]:
    return {_signal_type(item) for item in items}


def _dedupe_unknowns(values: Iterable[str]) -> list[str]:
    selected: list[str] = []
    normalized: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        norm = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
        if any(norm == prior or SequenceMatcher(None, norm, prior).ratio() >= 0.78 for prior in normalized):
            continue
        selected.append(value)
        normalized.append(norm)
    return selected


def _schema_assessment(family: str, support: list[dict[str, Any]], contradict: list[dict[str, Any]], existing_missing: list[str]) -> dict[str, Any]:
    schema = FAMILY_SCHEMAS.get(family, {"required": [], "support": set(), "contradict": set(), "unknowns": []})
    support_types = _types(support)
    contradict_types = _types(contradict)
    required_groups = schema.get("required", [])
    satisfied = []
    missing_required = []
    for group in required_groups:
        matches = sorted(group & support_types)
        if matches:
            satisfied.append(matches)
        else:
            missing_required.append(sorted(group))
    supporting_matches = sorted(set(schema.get("support", set())) & support_types)
    contradicting_matches = sorted(set(schema.get("contradict", set())) & contradict_types)
    if not required_groups:
        precondition_state = "not_modeled"
    elif not missing_required:
        precondition_state = "complete"
    elif len(missing_required) < len(required_groups):
        precondition_state = "partial"
    else:
        precondition_state = "insufficient"
    required_coverage = 100 if not required_groups else round(100 * len(satisfied) / len(required_groups))
    supporting_total = max(1, min(4, len(schema.get("support", set()))))
    supporting_coverage = min(100, round(100 * len(supporting_matches) / supporting_total))
    contradiction_coverage = min(100, 20 * (len(contradict) + len(contradicting_matches)))
    overall = _clamp(required_coverage * .55 + supporting_coverage * .25 + contradiction_coverage * .20)
    unknowns = _dedupe_unknowns([*existing_missing, *schema.get("unknowns", [])])
    return {
        "precondition_state": precondition_state,
        "required_satisfied": satisfied,
        "required_missing": missing_required,
        "supporting_matches": supporting_matches,
        "contradicting_matches": contradicting_matches,
        "required_coverage": required_coverage,
        "supporting_coverage": supporting_coverage,
        "contradiction_coverage": contradiction_coverage,
        "overall_coverage": overall,
        "unknowns": unknowns,
    }


def _family_score(family: str, primary_family: str, support_types: set[str], contradict_types: set[str], text: str) -> tuple[int, dict[str, Any]]:
    schema = FAMILY_SCHEMAS.get(family)
    if not schema:
        return 0, {"matched_required": [], "matched_support": [], "matched_contradict": []}
    rank_gate = set(schema.get("rank_gate", set()))
    if family != primary_family and rank_gate and not (rank_gate & support_types):
        return 0, {"matched_required": [], "missing_required_groups": len(schema.get("required", [])), "matched_support": [], "matched_contradict": [], "rank_gate_missing": sorted(rank_gate)}
    matched_required: list[str] = []
    missing_groups = 0
    for group in schema["required"]:
        matches = sorted(group & support_types)
        if matches:
            matched_required.extend(matches[:2])
        else:
            missing_groups += 1
    matched_support = sorted(schema.get("support", set()) & support_types)
    matched_contradict = sorted(schema.get("contradict", set()) & contradict_types)
    score = 12 + (18 if family == primary_family else 0) + len(matched_required) * 13 + len(matched_support) * 5 - missing_groups * 16 - len(matched_contradict) * 10
    for token, variant in schema.get("variants", {}).items():
        if token in text:
            score += 5
    return _clamp(score, 0, 96), {"matched_required": matched_required, "missing_required_groups": missing_groups, "matched_support": matched_support, "matched_contradict": matched_contradict}


def _calibration_for_family(db: Database, family: str, target: str) -> dict[str, Any]:
    reviewed = [dict(row) for row in db.all("SELECT likelihood_score,analyst_decision FROM bug_candidates WHERE bug_family=? AND target=? AND analyst_decision<>'unreviewed'", (family, target))]
    gold = [dict(row) for row in db.all("SELECT label,expected_family FROM candidate_gold_labels WHERE target=? AND expected_family=?", (target, family))]
    positives = sum(1 for row in reviewed if row["analyst_decision"] in {"confirmed_by_analyst", "needs_more_evidence"})
    negatives = sum(1 for row in reviewed if row["analyst_decision"] in {"rejected", "duplicate", "out_of_scope"})
    positives += sum(1 for row in gold if row["label"] in {"confirmed", "useful", "useful_candidate", "correct_family", "useful_weak_signal"})
    negatives += sum(1 for row in gold if row["label"] in {"false_positive", "wrong_family", "expected_behavior", "parser_error"})
    sample = positives + negatives
    # Beta(2,2) prior avoids extreme values with tiny samples.
    observed = (positives + 2) / (sample + 4)
    confidence = min(1.0, sample / 20.0)
    avg_pred = sum(parse_int(row.get("likelihood_score"), 50) for row in reviewed) / max(1, len(reviewed)) / 100
    gap = observed - avg_pred if reviewed else 0.0
    adjustment = round(gap * 100 * confidence)
    return {"family": family, "target": target, "samples": sample, "positive": positives, "negative": negatives, "observed_useful_rate": round(observed, 3), "average_predicted": round(avg_pred, 3), "gap": round(gap, 3), "confidence": round(confidence, 3), "adjustment": adjustment, "status": "insufficient_data" if sample < 5 else "overconfident" if gap < -0.15 else "underconfident" if gap > 0.15 else "reasonable"}


def _reachability(candidate: Mapping[str, Any], support: list[dict[str, Any]], contradict: list[dict[str, Any]], context: Mapping[str, Any]) -> tuple[str, int]:
    st = _types(support); ct = _types(contradict)
    if "non_reachable" in ct:
        return "not_reachable", 20
    if context.get("observations") or {"public_observation", "response_data", "protected_to_data", "error_to_data"} & st:
        return "observed", 92
    if {"reachable_route", "endpoint_contract", "graphql_operation", "websocket_channel"} & st:
        return "reachable_or_referenced", 70
    if str(candidate.get("source_ref") or "").startswith(("source-map:", "secret:", "dataflow:")):
        return "static_only", 42
    return "unknown", 35


def _causal_chain(candidate: Mapping[str, Any], context: Mapping[str, Any], support: list[dict[str, Any]]) -> dict[str, Any]:
    chain: list[dict[str, Any]] = []
    deployments = context.get("deployments") or []
    flags = context.get("flags") or []
    st = _types(support)
    if deployments:
        dep = deployments[0]
        chain.append({"step": "deployment", "value": dep.get("signature"), "confidence": parse_int(dep.get("confidence"), 50)})
    if flags:
        active = next((row for row in flags if str(row.get("observed_value")).lower() in {"true", "1", "enabled", "on"}), flags[0])
        chain.append({"step": "feature_flag", "value": active.get("flag_name"), "confidence": parse_int(active.get("confidence"), 50)})
    if candidate.get("endpoint"):
        chain.append({"step": "endpoint", "value": candidate.get("endpoint"), "confidence": 82})
    if "boundary_regression" in st:
        chain.append({"step": "authentication_boundary_change", "value": (context.get("boundary_diff") or {}).get("transition"), "confidence": parse_int((context.get("boundary_diff") or {}).get("confidence"), 70)})
    if {"sensitive_expansion", "error_to_data", "protected_to_data"} & st:
        chain.append({"step": "response_security_change", "value": (context.get("shape_diff") or {}).get("transition"), "confidence": parse_int((context.get("shape_diff") or {}).get("confidence"), 70)})
    if len(chain) < 2:
        return {"available": False, "steps": chain, "confidence": 0}
    confidence = _clamp(sum(parse_int(step.get("confidence"), 50) for step in chain) / len(chain) - max(0, 4 - len(chain)) * 5)
    return {"available": True, "steps": chain, "confidence": confidence, "inference": "Probable introduction chain based on same-analysis temporal and semantic evidence; not proof of causation."}


def _falsification(schema: Mapping[str, Any], contradict: list[dict[str, Any]], assessment: Mapping[str, Any]) -> dict[str, Any]:
    actual = [str(item.get("text") or item.get("type")) for item in contradict]
    would_reject = []
    for signal in sorted(schema.get("contradict", set())):
        would_reject.append(signal.replace("_", " "))
    if not would_reject:
        would_reject = ["A direct observation demonstrating the expected security boundary", "Evidence that the inferred input is ignored or unreachable"]
    would_strengthen = list(assessment.get("unknowns") or [])[:8]
    return {
        "why_it_may_be_wrong": actual or ["No direct contradictory observation is stored; server-side security enforcement remains unknown."],
        "would_strengthen": would_strengthen,
        "would_weaken": ["A lower-trust or static-only origin for the decisive evidence", "Evidence that the relevant route or operation is not reachable"],
        "would_reject": would_reject[:8],
    }


def _shadow_rules(db: Database, candidate: Mapping[str, Any], context: Mapping[str, Any], support: list[dict[str, Any]], assessment: Mapping[str, Any]) -> int:
    st = _types(support)
    results: list[tuple[str, bool, int, dict[str, Any]]] = []
    observations = context.get("observations") or []
    results.append(("shadow-cross-context-boundary", len({str(x.get('context')) for x in observations}) >= 2 and bool({"sensitive_fields", "sensitive_expansion", "response_data"} & st), 76, {"contexts": sorted({str(x.get('context')) for x in observations}), "signals": sorted(st & {"sensitive_fields", "sensitive_expansion", "response_data"})}))
    causal = _causal_chain(candidate, context, support)
    results.append(("shadow-feature-causal-chain", bool(causal.get("available") and len(causal.get("steps", [])) >= 3), parse_int(causal.get("confidence"), 0), causal))
    business = bool({"business_operation", "single_use_operation", "approval_operation", "balance_operation"} & st and assessment.get("precondition_state") in {"partial", "complete"})
    results.append(("shadow-business-invariant", business, 68 if business else 30, {"signals": sorted(st & {"business_operation", "single_use_operation", "approval_operation", "balance_operation"}), "precondition_state": assessment.get("precondition_state")}))
    count = 0
    for rule_id, matched, confidence, evidence in results:
        db.execute("INSERT OR REPLACE INTO shadow_rule_results(analysis_id,candidate_id,rule_id,rule_version,matched,confidence,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?)", (candidate["analysis_id"], candidate["candidate_id"], rule_id, REASONING_RULE_VERSION, 1 if matched else 0, confidence, json_dumps(evidence), utc_now()))
        if matched: count += 1
    return count


def apply_security_reasoning(db: Database, analysis_id: str) -> dict[str, Any]:
    db.execute("DELETE FROM candidate_evidence_exclusions WHERE analysis_id=?", (analysis_id,))
    db.execute("DELETE FROM candidate_evidence_snapshots WHERE candidate_id IN (SELECT candidate_id FROM bug_candidates WHERE analysis_id=?)", (analysis_id,))
    db.execute("DELETE FROM evidence_records WHERE analysis_id=?", (analysis_id,))
    db.execute("DELETE FROM family_rankings WHERE analysis_id=?", (analysis_id,))
    db.execute("DELETE FROM candidate_reasoning_traces WHERE analysis_id=?", (analysis_id,))
    db.execute("DELETE FROM shadow_rule_results WHERE analysis_id=?", (analysis_id,))
    rows = [dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=?", (analysis_id,))]
    updated = 0; strong = 0; insufficient = 0; shadow_matches = 0
    for candidate in rows:
        support = [dict(x) for x in _loads(candidate.get("supporting_evidence_json"), []) if isinstance(x, Mapping)]
        contradict = [dict(x) for x in _loads(candidate.get("contradicting_evidence_json"), []) if isinstance(x, Mapping)]
        missing = [str(x) for x in _loads(candidate.get("missing_evidence_json"), [])]
        context = _candidate_context(db, candidate)
        synthetic_support, synthetic_contradict = _synthetic_evidence(candidate, context)
        support.extend(synthetic_support); contradict.extend(synthetic_contradict)
        support, contradict, evidence_meta = _materialize_evidence(db, candidate, support, contradict)
        family = str(candidate["bug_family"])
        schema = FAMILY_SCHEMAS.get(family, {"label": family, "required": [], "support": set(), "contradict": set(), "unknowns": [], "variants": {}})
        assessment = _schema_assessment(family, support, contradict, missing)
        support_types = _types(support); contradict_types = _types(contradict)
        text = " ".join([str(candidate.get("endpoint") or ""), str(candidate.get("summary") or ""), str(candidate.get("bug_variant") or "")]).lower()
        rankings: list[dict[str, Any]] = []
        for ranked_family in FAMILY_SCHEMAS:
            score, reason = _family_score(ranked_family, family, support_types, contradict_types, text)
            if score > 0:
                rankings.append({"family": ranked_family, "label": FAMILY_SCHEMAS[ranked_family]["label"], "score": score, "reason": reason})
        rankings.sort(key=lambda x: x["score"], reverse=True)
        top3 = rankings[:3]
        for rank, value in enumerate(top3, 1):
            db.execute("INSERT OR REPLACE INTO family_rankings(analysis_id,candidate_id,rank,bug_family,score,reason_json,created_at) VALUES(?,?,?,?,?,?,?)", (analysis_id, candidate["candidate_id"], rank, value["family"], value["score"], json_dumps(value["reason"]), utc_now()))
        calibration = _calibration_for_family(db, family, str(candidate["target"]))
        raw_likelihood = parse_int(candidate.get("likelihood_score"), 0)
        cache_payload = {
            "candidate_fingerprint": str(candidate.get("candidate_fingerprint") or ""),
            "family": family,
            "endpoint": str(candidate.get("endpoint") or candidate.get("source_ref") or ""),
            "analyst_decision": str(candidate.get("analyst_decision") or "unreviewed"),
            "roots": sorted((str(item.get("root_fingerprint") or ""), str(item.get("polarity") or "support"), parse_int(item.get("trust_score"), 0), parse_int(item.get("observation_quality"), 0)) for item in support + contradict),
            "assessment": assessment,
            "calibration": calibration,
        }
        evidence_fingerprint = sha256_text(json_dumps(cache_payload))
        cached_row = db.one("SELECT result_json FROM incremental_reasoning_cache WHERE candidate_fingerprint=? AND evidence_fingerprint=? AND rule_version=?", (str(candidate.get("candidate_fingerprint") or ""), evidence_fingerprint, REASONING_RULE_VERSION))
        if cached_row:
            cached = _loads(cached_row["result_json"], {})
            cached_scores = cached.get("scores", {}) if isinstance(cached, Mapping) else {}
            candidate_state = str(cached.get("candidate_state") or "possible")
            calibrated = parse_int(cached_scores.get("calibrated_likelihood"), raw_likelihood)
            evidence_strength = parse_int(cached_scores.get("evidence_strength"), parse_int(candidate.get("evidence_strength"), 0))
            exploitability = parse_int(cached_scores.get("exploitability_confidence"), 0)
            impact = parse_int(cached_scores.get("impact_potential"), parse_int(candidate.get("impact_potential"), 0))
            observation_quality = parse_int(cached_scores.get("observation_quality"), parse_int(candidate.get("observation_quality"), 50))
            investigation = parse_int(cached_scores.get("investigation_value"), parse_int(candidate.get("investigation_value"), 0))
            reachability = str(cached.get("reachability_state") or "unknown")
            unknowns = cached.get("unknowns", []) if isinstance(cached.get("unknowns", []), list) else []
            reasoning = cached.get("reasoning", {}) if isinstance(cached.get("reasoning", {}), Mapping) else {}
            reasoning = {**reasoning, "evidence_lineage": evidence_meta, "cache": {"reused": True, "evidence_fingerprint": evidence_fingerprint}, "engine_version": REASONING_ENGINE_VERSION, "rule_version": REASONING_RULE_VERSION}
            if candidate_state == "strong_candidate": strong += 1
            if candidate_state == "insufficient_evidence": insufficient += 1
            shadow_matches += _shadow_rules(db, candidate, context, support, assessment)
            db.execute(
                """UPDATE bug_candidates SET likelihood_score=?,calibrated_likelihood=?,evidence_strength=?,exploitability_confidence=?,
                evidence_coverage=?,observation_quality=?,investigation_value=?,priority_score=?,candidate_state=?,precondition_state=?,
                reachability_state=?,supporting_evidence_json=?,contradicting_evidence_json=?,missing_evidence_json=?,unknowns_json=?,
                alternative_families_json=?,reasoning_trace_json=?,quality_explanation_json=?,rule_version=?,updated_at=? WHERE candidate_id=?""",
                (calibrated, calibrated, evidence_strength, exploitability, assessment["overall_coverage"], observation_quality, investigation, investigation, candidate_state, assessment["precondition_state"], reachability, json_dumps(support), json_dumps(contradict), json_dumps(assessment["unknowns"]), json_dumps(unknowns), json_dumps(top3[1:]), json_dumps(reasoning), json_dumps(reasoning), REASONING_RULE_VERSION, utc_now(), candidate["candidate_id"]),
            )
            db.execute("INSERT OR REPLACE INTO candidate_reasoning_traces(candidate_id,analysis_id,trace_json,engine_version,rule_version,created_at) VALUES(?,?,?,?,?,?)", (candidate["candidate_id"], analysis_id, json_dumps(reasoning), REASONING_ENGINE_VERSION, REASONING_RULE_VERSION, utc_now()))
            record_analysis_version(db, str(candidate["candidate_id"]), reasoning, REASONING_ENGINE_VERSION, REASONING_RULE_VERSION)
            updated += 1
            continue
        ranked_primary = top3[0]["score"] if top3 else raw_likelihood
        precondition_adjust = 8 if assessment["precondition_state"] == "complete" else -8 if assessment["precondition_state"] == "partial" else -22 if assessment["precondition_state"] == "insufficient" else 0
        calibrated = _clamp(raw_likelihood * .55 + ranked_primary * .30 + assessment["overall_coverage"] * .15 + calibration["adjustment"] + precondition_adjust, 0, 96)
        maturity_limiter = ""
        if family == "broken_object_authorization":
            decisive_types = support_types & {"identity_relation", "cross_context", "response_data", "sensitive_response_shape", "structural_response_diff", "authentication_boundary_regression"}
            if not decisive_types:
                protected = bool(contradict_types & {"authentication_required", "protected_boundary", "anonymous_boundary"})
                cap = 44 if protected else 54
                if calibrated > cap:
                    calibrated = cap
                    maturity_limiter = "BOLA capped until direct identity/object, cross-context, or response evidence exists"
        reachability, reach_conf = _reachability(candidate, support, contradict, context)
        direct_groups = len({str(x.get("root_fingerprint")) for x in support if x.get("direct") or x.get("source_kind") in {"behavioral_diff", "http", "response_shape"}})
        exploitability = _clamp(12 + direct_groups * 12 + reach_conf * .22 + assessment["required_coverage"] * .18 + assessment["supporting_coverage"] * .08 - len(assessment["required_missing"]) * 12 - len(contradict) * 5, 5, 85)
        if candidate.get("analyst_decision") == "confirmed_by_analyst": exploitability = max(exploitability, 86)
        elif reachability in {"static_only", "unknown"}: exploitability = min(exploitability, 45)
        if maturity_limiter:
            exploitability = min(exploitability, 40)
        trust_avg = sum(parse_int(x.get("trust_score"), 30) for x in support) / max(1, len(support))
        evidence_strength = _clamp(parse_int(candidate.get("evidence_strength"), 0) * .45 + trust_avg * .30 + assessment["overall_coverage"] * .25 - len(contradict) * 2, 5, 96)
        impact = parse_int(candidate.get("impact_potential"), 0)
        observation_quality = _clamp(parse_int(candidate.get("observation_quality"), 50) * .55 + trust_avg * .45, 10, 98)
        investigation = _clamp(calibrated * .27 + evidence_strength * .22 + exploitability * .16 + impact * .20 + observation_quality * .10 + assessment["overall_coverage"] * .05, 0, 100)
        if assessment["precondition_state"] == "insufficient":
            candidate_state = "insufficient_evidence"; insufficient += 1
        elif calibrated >= 76 and evidence_strength >= 68 and assessment["overall_coverage"] >= 55 and len({x.get('root_fingerprint') for x in support}) >= 2:
            candidate_state = "strong_candidate"; strong += 1
        elif calibrated >= 56 and evidence_strength >= 45:
            candidate_state = "plausible"
        elif calibrated >= 34:
            candidate_state = "possible"
        else:
            candidate_state = "weak_signal"
        if candidate.get("analyst_decision") == "confirmed_by_analyst": candidate_state = "confirmed_by_analyst"
        elif candidate.get("analyst_decision") == "rejected": candidate_state = "rejected"
        causal = _causal_chain(candidate, context, support)
        falsification = _falsification(schema, contradict, assessment)
        unknowns = [{"fact": value, "state": "unknown", "security_meaning": "Absence of evidence is not evidence of a secure control."} for value in assessment["unknowns"]]
        reasoning = {
            "engine_version": REASONING_ENGINE_VERSION,
            "rule_version": REASONING_RULE_VERSION,
            "primary_family": family,
            "top_families": top3,
            "preconditions": assessment,
            "falsification": falsification,
            "unknown_model": unknowns,
            "reachability": {"state": reachability, "confidence": reach_conf},
            "calibration": calibration,
            "causal_chain": causal,
            "evidence_lineage": evidence_meta,
            "maturity_limiter": maturity_limiter,
            "scores": {
                "raw_likelihood": raw_likelihood,
                "calibrated_likelihood": calibrated,
                "evidence_strength": evidence_strength,
                "exploitability_confidence": exploitability,
                "impact_potential": impact,
                "observation_quality": observation_quality,
                "evidence_coverage": assessment["overall_coverage"],
                "investigation_value": investigation,
            },
            "safety": "This is an evidence-based review candidate, not a confirmed vulnerability. No active validation was performed by the reasoning engine.",
        }
        shadow_matches += _shadow_rules(db, candidate, context, support, assessment)
        db.execute(
            """UPDATE bug_candidates SET likelihood_score=?,calibrated_likelihood=?,evidence_strength=?,exploitability_confidence=?,
            evidence_coverage=?,observation_quality=?,investigation_value=?,priority_score=?,candidate_state=?,precondition_state=?,
            reachability_state=?,supporting_evidence_json=?,contradicting_evidence_json=?,missing_evidence_json=?,unknowns_json=?,
            alternative_families_json=?,reasoning_trace_json=?,quality_explanation_json=?,rule_version=?,updated_at=? WHERE candidate_id=?""",
            (calibrated, calibrated, evidence_strength, exploitability, assessment["overall_coverage"], observation_quality, investigation, investigation, candidate_state, assessment["precondition_state"], reachability, json_dumps(support), json_dumps(contradict), json_dumps(assessment["unknowns"]), json_dumps(unknowns), json_dumps(top3[1:]), json_dumps(reasoning), json_dumps(reasoning), REASONING_RULE_VERSION, utc_now(), candidate["candidate_id"]),
        )
        db.execute("INSERT OR REPLACE INTO candidate_reasoning_traces(candidate_id,analysis_id,trace_json,engine_version,rule_version,created_at) VALUES(?,?,?,?,?,?)", (candidate["candidate_id"], analysis_id, json_dumps(reasoning), REASONING_ENGINE_VERSION, REASONING_RULE_VERSION, utc_now()))
        record_analysis_version(db, str(candidate["candidate_id"]), reasoning, REASONING_ENGINE_VERSION, REASONING_RULE_VERSION)
        db.execute("INSERT OR REPLACE INTO incremental_reasoning_cache(candidate_fingerprint,evidence_fingerprint,rule_version,result_json,updated_at) VALUES(?,?,?,?,?)", (str(candidate.get("candidate_fingerprint") or ""), evidence_fingerprint, REASONING_RULE_VERSION, json_dumps({"candidate_state": candidate_state, "reachability_state": reachability, "unknowns": unknowns, "scores": reasoning["scores"], "reasoning": reasoning}), utc_now()))
        updated += 1
    evaluation = evaluate_reasoning(db, analysis_id, persist=True)
    return {"updated": updated, "strong_candidates": strong, "insufficient_evidence": insufficient, "evidence_records": int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"]), "shadow_rule_matches": shadow_matches, "evaluation": evaluation, "engine_version": REASONING_ENGINE_VERSION, "rule_version": REASONING_RULE_VERSION}


def evidence_trace(db: Database, candidate_id: str) -> dict[str, Any]:
    dossier = build_evidence_dossier(db, candidate_id)
    shadow = [dict(row) for row in db.all("SELECT * FROM shadow_rule_results WHERE candidate_id=? ORDER BY matched DESC,confidence DESC", (candidate_id,))]
    return {
        "candidate": dossier["candidate"],
        "evidence": [*dossier["supporting"], *dossier["contradicting"]],
        "family_rankings": dossier["family_rankings"],
        "reasoning": dossier["reasoning"],
        "shadow_rules": shadow,
        "audit": dossier,
    }


def family_calibration_report(db: Database, target: str | None = None) -> dict[str, Any]:
    families = sorted({str(row[0]) for row in db.all("SELECT DISTINCT bug_family FROM bug_candidates" + (" WHERE target=?" if target else ""), (target,) if target else ())})
    targets = [target] if target else sorted({str(row[0]) for row in db.all("SELECT DISTINCT target FROM bug_candidates")})
    rows = []
    for current_target in targets:
        for family in families:
            value = _calibration_for_family(db, family, current_target)
            if value["samples"] or target:
                rows.append(value)
                db.execute("INSERT OR REPLACE INTO family_calibration(target,bug_family,sample_count,positive_count,negative_count,average_predicted,observed_rate,calibration_gap,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (current_target, family, value["samples"], value["positive"], value["negative"], value["average_predicted"], value["observed_useful_rate"], value["gap"], value["status"], utc_now()))
    return {"target": target or "*", "families": rows}


def shadow_rule_report(db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    if not analysis_id:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
        analysis_id = str(row["id"]) if row else ""
    if not analysis_id:
        return {"analysis_id": "", "rules": []}
    rows = db.all("SELECT rule_id,COUNT(*) total,SUM(matched) matched,ROUND(AVG(confidence),1) avg_confidence FROM shadow_rule_results WHERE analysis_id=? GROUP BY rule_id ORDER BY matched DESC", (analysis_id,))
    return {"analysis_id": analysis_id, "rules": [{**dict(row), "description": EXPERIMENTAL_SHADOW_RULES.get(str(row["rule_id"]), "")} for row in rows]}


def evaluate_reasoning(db: Database, analysis_id: str, persist: bool = False) -> dict[str, Any]:
    candidates = [dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=?", (analysis_id,))]
    labels = [dict(row) for row in db.all("SELECT * FROM candidate_gold_labels WHERE source_run_id IN (SELECT source_run_id FROM analysis_runs WHERE id=?)", (analysis_id,))]
    label_by_fp: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for label in labels: label_by_fp[str(label["candidate_fingerprint"])].append(label)
    evaluated = 0; top1 = 0; top3 = 0; positive = 0; brier_values: list[float] = []
    for candidate in candidates:
        related = label_by_fp.get(str(candidate["candidate_fingerprint"]), [])
        if not related:
            continue
        expected = str(related[-1].get("expected_family") or candidate["bug_family"])
        label = str(related[-1].get("label") or "")
        rankings = [dict(row) for row in db.all("SELECT * FROM family_rankings WHERE candidate_id=? ORDER BY rank", (candidate["candidate_id"],))]
        families = [str(row["bug_family"]) for row in rankings]
        evaluated += 1
        top1 += 1 if families and families[0] == expected else 0
        top3 += 1 if expected in families[:3] else 0
        outcome = 1.0 if label in {"confirmed", "useful", "useful_candidate", "correct_family", "useful_weak_signal"} else 0.0
        positive += int(outcome)
        probability = parse_int(candidate.get("calibrated_likelihood"), parse_int(candidate.get("likelihood_score"), 0)) / 100
        brier_values.append((probability - outcome) ** 2)
    strong = [row for row in candidates if row.get("candidate_state") in {"strong_candidate", "confirmed_by_analyst"}]
    reviewed_strong = [row for row in strong if row.get("analyst_decision") != "unreviewed"]
    useful_strong = sum(1 for row in reviewed_strong if row.get("analyst_decision") in {"confirmed_by_analyst", "needs_more_evidence"})
    metrics = {
        "analysis_id": analysis_id,
        "candidates": len(candidates),
        "gold_evaluated": evaluated,
        "gold_positive": positive,
        "top1_family_accuracy": round(top1 / max(1, evaluated), 3),
        "top3_family_accuracy": round(top3 / max(1, evaluated), 3),
        "brier_score": round(sum(brier_values) / max(1, len(brier_values)), 4),
        "strong_candidates": len(strong),
        "reviewed_strong": len(reviewed_strong),
        "strong_precision_proxy": round(useful_strong / max(1, len(reviewed_strong)), 3),
        "average_evidence_coverage": round(sum(parse_int(row.get("evidence_coverage"), 0) for row in candidates) / max(1, len(candidates)), 2),
        "average_exploitability_confidence": round(sum(parse_int(row.get("exploitability_confidence"), 0) for row in candidates) / max(1, len(candidates)), 2),
        "candidate_rate_per_1000_evidence": round(len(candidates) * 1000 / max(1, int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"])), 2),
    }
    if persist:
        db.execute("INSERT INTO reasoning_evaluations(analysis_id,metrics_json,created_at) VALUES(?,?,?)", (analysis_id, json_dumps(metrics), utc_now()))
    return metrics


def reasoning_regression_gate(db: Database, analysis_id: str, baseline_analysis_id: str | None = None, persist: bool = True) -> dict[str, Any]:
    current_run = db.one("SELECT source_run_id,target,started_at FROM analysis_runs WHERE id=?", (analysis_id,))
    if not current_run:
        raise ValueError(f"Analysis not found: {analysis_id}")
    if not baseline_analysis_id:
        baseline = db.one(
            "SELECT id FROM analysis_runs WHERE id<>? AND status='success' AND target=? AND started_at<? ORDER BY started_at DESC LIMIT 1",
            (analysis_id, current_run["target"], current_run["started_at"]),
        )
        baseline_analysis_id = str(baseline["id"]) if baseline else ""
    current = evaluate_reasoning(db, analysis_id)
    if not baseline_analysis_id:
        result = {"analysis_id": analysis_id, "baseline_analysis_id": "", "passed": True, "status": "insufficient_history", "checks": [], "current": current}
        if persist:
            db.execute("INSERT INTO reasoning_regression_gates(analysis_id,baseline_analysis_id,passed,checks_json,created_at) VALUES(?,?,?,?,?)", (analysis_id, "", 1, json_dumps(result), utc_now()))
        return result
    baseline = evaluate_reasoning(db, baseline_analysis_id)
    checks = []
    def check(name: str, passed: bool, current_value: Any, baseline_value: Any, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "current": current_value, "baseline": baseline_value, "detail": detail})
    check("top3_family_accuracy", current["top3_family_accuracy"] + 0.001 >= baseline["top3_family_accuracy"] - 0.05, current["top3_family_accuracy"], baseline["top3_family_accuracy"], "Top-3 family accuracy may not regress by more than 5 percentage points.")
    check("strong_precision_proxy", current["strong_precision_proxy"] + 0.001 >= baseline["strong_precision_proxy"] - 0.10, current["strong_precision_proxy"], baseline["strong_precision_proxy"], "Strong-candidate precision proxy may not regress by more than 10 percentage points.")
    check("evidence_coverage", current["average_evidence_coverage"] + 0.001 >= baseline["average_evidence_coverage"] - 10, current["average_evidence_coverage"], baseline["average_evidence_coverage"], "Average evidence coverage may not fall by more than 10 points.")
    rate_limit = max(25.0, baseline["candidate_rate_per_1000_evidence"] * 1.5)
    check("candidate_noise_rate", current["candidate_rate_per_1000_evidence"] <= rate_limit, current["candidate_rate_per_1000_evidence"], baseline["candidate_rate_per_1000_evidence"], "Candidate rate must remain inside the 1.5x noise budget.")
    baseline_run = db.one("SELECT source_run_id FROM analysis_runs WHERE id=?", (baseline_analysis_id,))
    same_source_run = bool(baseline_run and str(baseline_run["source_run_id"] or "") == str(current_run["source_run_id"] or ""))
    baseline_confirmed = {str(row[0]) for row in db.all("SELECT candidate_fingerprint FROM bug_candidates WHERE analysis_id=? AND analyst_decision='confirmed_by_analyst'", (baseline_analysis_id,))}
    current_fingerprints = {str(row[0]) for row in db.all("SELECT candidate_fingerprint FROM bug_candidates WHERE analysis_id=?", (analysis_id,))}
    lost = sorted(baseline_confirmed - current_fingerprints) if same_source_run else []
    check(
        "confirmed_candidate_retention",
        not lost,
        len(baseline_confirmed) - len(lost) if same_source_run else "not_applicable",
        len(baseline_confirmed),
        "Confirmed-fingerprint retention is enforced only when replaying the same source run; different runs may legitimately contain different evidence.",
    )
    passed = all(item["passed"] for item in checks)
    result = {"analysis_id": analysis_id, "baseline_analysis_id": baseline_analysis_id, "passed": passed, "status": "passed" if passed else "failed", "checks": checks, "current": current, "baseline": baseline, "lost_confirmed_fingerprints": lost}
    if persist:
        db.execute("INSERT INTO reasoning_regression_gates(analysis_id,baseline_analysis_id,passed,checks_json,created_at) VALUES(?,?,?,?,?)", (analysis_id, baseline_analysis_id, 1 if passed else 0, json_dumps(result), utc_now()))
    return result


def reasoning_summary(db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    if not analysis_id:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
        analysis_id = str(row["id"]) if row else ""
    if not analysis_id:
        return {"analysis_id": ""}
    counts = dict(db.one("SELECT COUNT(*) total,SUM(candidate_state='strong_candidate') strong,SUM(candidate_state='insufficient_evidence') insufficient,ROUND(AVG(calibrated_likelihood),1) avg_likelihood,ROUND(AVG(exploitability_confidence),1) avg_exploitability,ROUND(AVG(evidence_coverage),1) avg_coverage FROM bug_candidates WHERE analysis_id=?", (analysis_id,)) or {})
    families = [dict(row) for row in db.all("SELECT bug_family,COUNT(*) count,ROUND(AVG(calibrated_likelihood),1) likelihood,ROUND(AVG(exploitability_confidence),1) exploitability,ROUND(AVG(evidence_coverage),1) coverage FROM bug_candidates WHERE analysis_id=? GROUP BY bug_family ORDER BY count DESC", (analysis_id,))]
    evaluation_row = db.one("SELECT metrics_json FROM reasoning_evaluations WHERE analysis_id=? ORDER BY id DESC LIMIT 1", (analysis_id,))
    return {
        "analysis_id": analysis_id,
        "counts": counts,
        "families": families,
        "evaluation": _loads(evaluation_row["metrics_json"], {}) if evaluation_row else evaluate_reasoning(db, analysis_id),
        "shadow_rules": shadow_rule_report(db, analysis_id),
        "regression_gate": reasoning_regression_gate(db, analysis_id, persist=False),
        "engine_version": REASONING_ENGINE_VERSION,
        "rule_version": REASONING_RULE_VERSION,
    }

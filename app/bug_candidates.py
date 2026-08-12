from __future__ import annotations

import json
import re
import uuid
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, ReconError, json_dumps, parse_int, sha256_text, utc_now
from hypothesis_admission import assess_admission, mark_promoted, record_hypothesis
from bola_intelligence import analyze_bola_signal
from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids
from raw_family_collectors import collect_authorization_observations, collect_injection_observations

CANDIDATE_ENGINE_VERSION = "6.17.0"
CANDIDATE_RULE_VERSION = "2026.08.12.6.17"

AUTO_STATES = ("weak_signal", "possible", "plausible", "strong_candidate")
ANALYST_DECISIONS = ("unreviewed", "needs_more_evidence", "confirmed_by_analyst", "rejected", "duplicate", "out_of_scope")
FEEDBACK_REASON_CODES = (
    "", "keyword_only", "expected_behavior", "duplicate", "protected_boundary", "non_reachable",
    "test_data_only", "parsing_error", "out_of_scope", "authorization_difference",
    "unexpected_response_shape", "role_boundary_failure", "sensitive_data_exposure", "needs_contract_context",
)
FAMILY_EVIDENCE_SCHEMAS: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {"required_any": (("object_identifier", "graphql_identifier"), ("object_operation", "graphql_operation"), ("cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch", "parent_child_scope_mismatch", "authorization_response_differential", "object_access_without_secondary_guard", "identity_object_relation_conflict", "unauthorized_object_response")), "label": "object identifier plus object operation plus object-level authorization-boundary evidence"},
    "broken_function_authorization": {"required_any": (("privileged_function", "privileged_classification"), ("state_change", "role_property")), "label": "privileged function plus role or state-changing context"},
    "mass_assignment": {"required_any": (("privileged_property", "privileged_fields", "privileged_contract_fields"), ("write_method", "state_change", "body_schema")), "label": "privileged property plus writable request contract"},
    "dom_xss": {"required_any": (("source_sink", "taint_flow"), ("dangerous_sink", "html_sink", "javascript_sink")), "label": "source-to-dangerous-DOM-sink relation"},
    "open_redirect": {"required_any": (("source_sink", "redirect_parameter"),), "label": "user-influenced navigation target"},
    "ssrf": {"required_any": (("url_parameter", "remote_destination", "remote_resource"), ("server_fetch_observed", "server_fetch_semantic", "server_request_function", "backend_fetch")), "label": "URL input plus server-side fetch evidence"},
    "file_upload": {"required_any": (("file_input",), ("upload_operation", "import_operation")), "label": "file input plus upload or import operation"},
    "path_traversal": {"required_any": (("path_parameter", "filename_field", "storage_path"), ("file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation")), "label": "user-influenced path or filename plus a file operation"},
    "graphql_authorization": {"required_any": (("graphql_identifier",), ("graphql_operation",)), "label": "GraphQL object identifier and operation"},
    "sql_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter", "path_parameter"), ("sql_query_surface", "database_query_semantic", "dynamic_query_surface"), ("sql_error_differential", "boolean_response_differential", "database_time_delay_observed", "query_structure_influence", "database_error_observed", "unsafe_query_construction")), "label": "input plus SQL query surface plus observed query-semantic influence"},
    "nosql_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter"), ("nosql_query_surface", "json_query_surface", "document_query_semantic"), ("nosql_operator_accepted", "query_operator_influence", "nosql_auth_bypass_observed", "nosql_response_differential", "nosql_error_observed")), "label": "structured input plus NoSQL query surface plus observed operator influence"},
    "command_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter", "path_parameter"), ("command_execution_surface", "shell_command_semantic", "process_execution_surface"), ("command_output_observed", "command_time_delay_observed", "shell_metacharacter_effect", "process_execution_reached", "unsafe_command_construction")), "label": "input plus command execution surface plus observed process effect"},
    "server_side_template_injection": {"required_any": (("input_parameter", "body_parameter", "template_input"), ("template_render_surface", "template_engine_semantic", "server_render_operation"), ("template_expression_evaluated", "template_output_differential", "template_engine_error_observed", "server_template_execution")), "label": "template input plus server render surface plus observed expression evaluation"},
    "ldap_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter"), ("ldap_query_surface", "directory_query_semantic", "ldap_filter_surface"), ("ldap_filter_influence", "ldap_response_differential", "ldap_auth_bypass_observed", "ldap_error_observed")), "label": "directory input plus LDAP filter surface plus observed filter influence"},
    "unrestricted_resource_consumption": {"required_any": (("resource_control_parameter", "batch_operation", "pagination_control", "upload_size_control", "expensive_operation", "paid_provider_operation"), ("rate_limit_absent_observed", "unbounded_page_size_observed", "batch_limit_absent_observed", "oversized_payload_accepted", "cost_amplification_observed", "timeout_limit_absent", "resource_exhaustion_differential")), "label": "resource-amplifying control plus observed ineffective resource limit"},
    "sensitive_business_flow_abuse": {"required_any": (("sensitive_business_flow", "purchase_flow", "reservation_flow", "posting_flow", "signup_flow", "redemption_flow"), ("automation_limit_absent", "anti_bot_control_absent", "per_user_limit_absent", "bulk_abuse_observed", "scalping_control_absent", "reservation_abuse_observed", "workflow_frequency_unrestricted", "business_flow_limit_bypass")), "label": "sensitive business flow plus observed missing/bypassable automation limit"},
    "security_misconfiguration": {"required_any": (("misconfiguration_surface", "debug_surface", "transport_surface", "http_method_surface", "deployment_configuration_surface"), ("stack_trace_exposed", "debug_mode_exposed", "insecure_http_enabled", "unnecessary_method_enabled", "directory_listing_observed", "security_header_missing_on_sensitive_response", "desync_processing_difference", "unsafe_default_configuration")), "label": "configuration surface plus directly observed insecure configuration"},
    "improper_inventory_management": {"required_any": (("api_version_surface", "legacy_endpoint_surface", "nonproduction_surface", "undocumented_host_surface"), ("deprecated_version_still_reachable", "older_version_weaker_controls", "undocumented_host_observed", "nonproduction_with_production_data", "retired_endpoint_active", "inventory_drift_observed", "unprotected_legacy_endpoint")), "label": "API inventory surface plus observed active legacy/undocumented exposure"},
    "unsafe_api_consumption": {"required_any": (("third_party_integration", "upstream_api_surface", "external_service_dependency"), ("upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink")), "label": "third-party API dependency plus observed unsafe upstream consumption"},
}

BUG_FAMILIES: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {"label": "BOLA / IDOR", "impact": 78, "category": "access_control"},
    "broken_function_authorization": {"label": "Broken Function Level Authorization", "impact": 84, "category": "access_control"},
    "mass_assignment": {"label": "Mass Assignment / Property Authorization", "impact": 78, "category": "access_control"},
    "authentication_session": {"label": "Authentication or Session Weakness", "impact": 82, "category": "authentication"},
    "account_enumeration": {"label": "Account Enumeration", "impact": 48, "category": "authentication"},
    "dom_xss": {"label": "DOM-based XSS", "impact": 72, "category": "client_injection"},
    "postmessage_trust": {"label": "Unsafe postMessage Trust", "impact": 68, "category": "client_injection"},
    "open_redirect": {"label": "Open Redirect / Navigation Injection", "impact": 52, "category": "redirect"},
    "ssrf": {"label": "Server-side Request Forgery Candidate", "impact": 88, "category": "server_request"},
    "file_upload": {"label": "Unsafe File Upload or Import", "impact": 82, "category": "file_handling"},
    "path_traversal": {"label": "Path Traversal Candidate", "impact": 80, "category": "file_handling"},
    "information_disclosure": {"label": "Sensitive Information Disclosure", "impact": 66, "category": "data_exposure"},
    "source_map_exposure": {"label": "Source-map Exposure", "impact": 48, "category": "data_exposure"},
    "secret_exposure": {"label": "Credential or Token Exposure", "impact": 90, "category": "data_exposure"},
    "graphql_authorization": {"label": "GraphQL Authorization Weakness", "impact": 80, "category": "graphql"},
    "graphql_data_exposure": {"label": "GraphQL Excessive Data Exposure", "impact": 68, "category": "graphql"},
    "business_logic": {"label": "Business Logic Weakness", "impact": 72, "category": "business_logic"},
    "race_condition": {"label": "Race Condition / Duplicate Operation", "impact": 80, "category": "business_logic"},
    "websocket_authorization": {"label": "WebSocket Authorization Weakness", "impact": 76, "category": "realtime"},
    "cors_misconfiguration": {"label": "CORS Misconfiguration", "impact": 64, "category": "headers"},
    "sensitive_caching": {"label": "Sensitive Response Caching", "impact": 62, "category": "headers"},
    "sql_injection": {"label": "SQL Injection", "impact": 92, "category": "server_injection"},
    "nosql_injection": {"label": "NoSQL Injection", "impact": 88, "category": "server_injection"},
    "command_injection": {"label": "OS Command Injection", "impact": 98, "category": "server_injection"},
    "server_side_template_injection": {"label": "Server-Side Template Injection", "impact": 96, "category": "server_injection"},
    "ldap_injection": {"label": "LDAP Injection", "impact": 82, "category": "server_injection"},
    "unrestricted_resource_consumption": {"label": "Unrestricted Resource Consumption", "impact": 76, "category": "api_resilience"},
    "sensitive_business_flow_abuse": {"label": "Unrestricted Sensitive Business Flow", "impact": 74, "category": "business_logic"},
    "security_misconfiguration": {"label": "Security Misconfiguration", "impact": 78, "category": "configuration"},
    "improper_inventory_management": {"label": "Improper API Inventory Management", "impact": 68, "category": "api_inventory"},
    "unsafe_api_consumption": {"label": "Unsafe Consumption of Third-Party APIs", "impact": 84, "category": "supply_chain"},
}

SAFE_ACTIONS = {
    "broken_object_authorization": "Document the expected ownership or tenant boundary. Compare only explicitly authorized test objects and stop if unrelated user data could be exposed.",
    "broken_function_authorization": "Document the expected role boundary and compare only roles and actions explicitly permitted by the program and your test accounts.",
    "mass_assignment": "Compare the documented writable fields with the client-visible schema. Use harmless values and do not attempt privilege changes outside authorized test accounts.",
    "authentication_session": "Map the intended login, recovery, token and session lifecycle. Compare only documented anonymous and authenticated states using authorized accounts.",
    "account_enumeration": "Compare response metadata and timing using only test identities you control; avoid probing real user identifiers.",
    "dom_xss": "Confirm that the source can reach the sink and inspect visible sanitization. During authorized validation use only a harmless non-executing marker.",
    "postmessage_trust": "Review origin and source checks in the message handler and document accepted message shapes without sending harmful payloads.",
    "open_redirect": "Trace how the navigation target is constructed and whether an allow-list or same-origin restriction is visible. Use a harmless controlled destination only if active validation is authorized.",
    "ssrf": "Confirm whether the server, rather than the browser, fetches the supplied destination. Do not target internal, metadata or third-party systems without explicit authorization.",
    "file_upload": "Review accepted type, size, name and storage controls. Use only a benign inert test file if active validation is explicitly permitted.",
    "path_traversal": "Review path construction and canonicalization using source evidence first. Do not request sensitive filesystem paths.",
    "information_disclosure": "Confirm whether exposed fields are intended to be public. Capture the minimum evidence and redact personal data and secrets.",
    "source_map_exposure": "Confirm the source map is publicly reachable and review only the minimum source metadata needed to establish impact.",
    "secret_exposure": "Keep the value redacted. Confirm context and whether it is a placeholder; do not attempt online credential validation without explicit authorization.",
    "graphql_authorization": "Map operation arguments, object identifiers and expected role or ownership boundaries using only authorized test objects.",
    "graphql_data_exposure": "Compare the intended schema with observed sensitive fields and capture only the minimum response shape needed.",
    "business_logic": "Document the intended workflow, invariants and state transitions before any test. Use only reversible actions and authorized test data.",
    "race_condition": "Record whether the operation is intended to be single-use or idempotent. Do not run concurrent requests unless explicitly authorized.",
    "websocket_authorization": "Map channel, room and identity boundaries. Do not subscribe to channels belonging to other users or tenants.",
    "cors_misconfiguration": "Review actual response headers and credential behavior from an authorized origin. Do not infer exploitability from a header alone.",
    "sensitive_caching": "Review Cache-Control, Vary and authentication context without storing sensitive response bodies.",
    "sql_injection": "Trace whether controlled input reaches dynamic SQL construction. Prefer stored error/boolean/timing evidence; do not extract unrelated database data.",
    "nosql_injection": "Map JSON/operator inputs to document-query construction using controlled test data. Avoid querying records outside your authorized test scope.",
    "command_injection": "Establish whether input reaches a shell or process API from stored evidence. Do not execute destructive commands; use only harmless markers when active validation is explicitly authorized.",
    "server_side_template_injection": "Confirm whether user-controlled text reaches a server-side template/expression engine. Use only non-destructive arithmetic/string markers during authorized validation.",
    "ldap_injection": "Compare controlled directory-search behavior using authorized test identities and harmless filter changes; do not enumerate real directory users.",
    "unrestricted_resource_consumption": "Document the intended size, batch, timeout, frequency, and cost limits. Do not intentionally exhaust resources or generate third-party charges.",
    "sensitive_business_flow_abuse": "Document business abuse limits and anti-automation controls. Validate only with reversible authorized test actions and never consume scarce inventory for real users.",
    "security_misconfiguration": "Capture the minimum configuration evidence needed (headers, transport, methods, errors). Do not exploit exposed administrative/debug functionality.",
    "improper_inventory_management": "Compare documented/current API versions with observed legacy or non-production endpoints. Do not access unrelated environments or production data beyond authorization.",
    "unsafe_api_consumption": "Trace upstream service trust boundaries, transport, redirects, response limits, and validation. Do not target or manipulate third-party systems without explicit authorization.",
}

PRIVILEGED_FIELDS = {"role", "roles", "isadmin", "admin", "permissions", "permission", "ownerid", "tenantid", "accounttype", "status", "verified", "isstaff"}
OBJECT_MARKERS = {"id", "userid", "accountid", "customerid", "tenantid", "orgid", "orderid", "invoiceid", "profileid", "objectid", "ownerid"}
SENSITIVE_CONTEXTS = {"payment", "identity", "customer_data", "administration", "partner_portal"}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _words(value: Any) -> set[str]:
    return {word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{1,80}", str(value or ""))}


def _contains_any(text: str, tokens: Iterable[str]) -> list[str]:
    lower = text.lower()
    return [token for token in tokens if token.lower() in lower]




def _truthy_evidence_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return str(value or "").strip().lower() in {"true", "yes", "1", "observed", "accepted", "allowed", "succeeded", "success"}


def _explicit_flag(details: Mapping[str, Any], *names: str) -> str:
    wanted = {re.sub(r"[^a-z0-9]", "", name.lower()): name for name in names}
    stack: list[Any] = [details]
    seen = 0
    while stack and seen < 1500:
        current = stack.pop(); seen += 1
        if isinstance(current, Mapping):
            for key, value in list(current.items())[:400]:
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized in wanted and _truthy_evidence_flag(value):
                    return wanted[normalized]
                if isinstance(value, (Mapping, list, tuple)):
                    stack.append(value)
        elif isinstance(current, (list, tuple)):
            stack.extend(list(current)[:100])
    return ""


def _stored_contexts(details: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = details.get("context_observations") or details.get("observations") or details.get("contexts")
    if isinstance(raw, Mapping):
        return [value for value in raw.values() if isinstance(value, Mapping)]
    if isinstance(raw, list):
        return [value for value in raw if isinstance(value, Mapping)]
    return []


def _header_maps(details: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    response: dict[str, str] = {}
    request: dict[str, str] = {}
    def absorb(value: Any, destination: dict[str, str]) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items(): destination[str(key).strip().lower()] = str(item).strip()
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and ":" in item:
                    key, body = item.split(":", 1); destination[key.strip().lower()] = body.strip()
    for key in ("headers", "response_headers", "headers_json", "new_headers", "current_headers"):
        absorb(details.get(key), response)
    for key in ("request_headers", "request_headers_json"):
        absorb(details.get(key), request)
    for key in ("new", "current", "after", "response"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            for hkey in ("headers", "response_headers", "headers_json"): absorb(nested.get(hkey), response)
    for key in ("request", "before_request"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            for hkey in ("headers", "request_headers", "headers_json"): absorb(nested.get(hkey), request)
    return response, request


def _state(likelihood: int, evidence_strength: int) -> str:
    if likelihood >= 75 and evidence_strength >= 60:
        return "strong_candidate"
    if likelihood >= 55:
        return "plausible"
    if likelihood >= 35:
        return "possible"
    return "weak_signal"


def _impact(base: int, context: str, method: str = "") -> int:
    adjustment = 10 if context in {"payment", "customer_data", "administration", "identity"} else 4 if context == "partner_portal" else -6 if context == "marketing" else 0
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        adjustment += 5
    return _clamp(base + adjustment, 10, 98)


def _evidence_strength(analysis_confidence: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], *, direct: bool = False) -> int:
    sources = {str(item.get("source") or item.get("type") or "rule") for item in support}
    value = 18 + min(32, analysis_confidence * 0.34) + min(30, len(support) * 8) + min(12, len(sources) * 4)
    if direct:
        value += 12
    value -= min(16, len(contradict) * 4)
    return _clamp(value, 10, 96)


def _candidate_fingerprint(target: str, alert_id: int | None, family: str, variant: str, endpoint: str, source_ref: str) -> str:
    del alert_id, source_ref
    normalized_endpoint = re.sub(r"\b\d{2,}\b", "{n}", endpoint.lower())
    normalized_endpoint = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", normalized_endpoint, flags=re.I)
    return sha256_text("|".join([target, family, variant, normalized_endpoint]))


def _merge_evidence_lists(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        key = json_dumps(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _previous_decision(db: Database, fingerprint: str, analysis_id: str) -> tuple[str, str]:
    row = db.one(
        "SELECT analyst_decision,analyst_note FROM bug_candidates WHERE candidate_fingerprint=? AND analysis_id<>? AND analyst_decision<>'unreviewed' ORDER BY updated_at DESC LIMIT 1",
        (fingerprint, analysis_id),
    )
    return (str(row["analyst_decision"]), str(row["analyst_note"] or "")) if row else ("unreviewed", "")


def _family_schema_gate(family: str, support: list[dict[str, Any]], missing: list[str]) -> tuple[int, list[str]]:
    schema = FAMILY_EVIDENCE_SCHEMAS.get(family)
    if not schema:
        return 0, missing
    types = {str(item.get("type") or "") for item in support}
    absent = []
    for group in schema.get("required_any", ()):
        if not any(value in types for value in group):
            absent.append(" / ".join(group))
    if not absent:
        return 0, missing
    updated = list(missing)
    updated.append(f"Family-specific evidence gate is incomplete: {schema.get('label')}; missing {', '.join(absent)}")
    return -18, updated


def _insert_candidate(
    db: Database,
    *,
    analysis_id: str,
    source_run_id: str,
    target: str,
    alert_id: int | None,
    asset: str,
    endpoint: str,
    source_ref: str,
    family: str,
    variant: str,
    likelihood: int,
    evidence_strength: int,
    impact_potential: int,
    support: list[dict[str, Any]],
    contradict: list[dict[str, Any]],
    missing: list[str],
    rule_ids: list[str],
    summary: str,
) -> str:
    if family not in BUG_FAMILIES:
        raise ReconError(f"Unknown bug family: {family}")
    extraction = evaluate_family_detector(family, support, contradict, channel="candidate")
    support = extraction["support"]
    contradict = extraction["contradict"]
    rule_ids = list(dict.fromkeys([*rule_ids, *detector_rule_ids(family)]))
    admission = assess_admission(family, support, contradict)
    if not admission["admitted"]:
        record_hypothesis(
            db, analysis_id=analysis_id, source_run_id=source_run_id, target=target, alert_id=alert_id, asset=asset,
            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant, support=support, contradict=contradict,
            missing=missing, rule_ids=rule_ids, summary=summary,
        )
        return ""
    gate_adjustment, missing = _family_schema_gate(family, support, missing)
    likelihood = _clamp(likelihood + gate_adjustment)
    evidence_strength = _clamp(evidence_strength)
    impact_potential = _clamp(impact_potential)
    auto_state = _state(likelihood, evidence_strength)
    fingerprint = _candidate_fingerprint(target, alert_id, family, variant, endpoint, source_ref)
    existing = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND candidate_fingerprint=?", (analysis_id, fingerprint))
    if existing:
        support = _merge_evidence_lists(_loads(existing["supporting_evidence_json"], []), support)
        contradict = _merge_evidence_lists(_loads(existing["contradicting_evidence_json"], []), contradict)
        missing = list(dict.fromkeys([*_loads(existing["missing_evidence_json"], []), *missing]))
        rule_ids = list(dict.fromkeys([*_loads(existing["rule_ids_json"], []), *rule_ids]))
        likelihood = max(likelihood, parse_int(existing["likelihood_score"], 0))
        evidence_strength = max(evidence_strength, parse_int(existing["evidence_strength"], 0))
        impact_potential = max(impact_potential, parse_int(existing["impact_potential"], 0))
        alert_id = existing["alert_id"]
        source_ref = str(existing["source_ref"] or source_ref)
    decision, note = _previous_decision(db, fingerprint, analysis_id)
    state = "confirmed_by_analyst" if decision == "confirmed_by_analyst" else "rejected" if decision == "rejected" else auto_state
    candidate_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:{analysis_id}:{fingerprint}"))
    priority_score = _clamp(likelihood * 0.45 + evidence_strength * 0.30 + impact_potential * 0.25)
    now = utc_now()
    db.execute(
        """INSERT OR REPLACE INTO bug_candidates(
        candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,
        bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,
        candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,
        rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            candidate_id, fingerprint, analysis_id, source_run_id, alert_id, target, asset, endpoint, source_ref,
            family, variant, BUG_FAMILIES[family]["label"], summary, likelihood, evidence_strength, impact_potential,
            priority_score, state, json_dumps(support), json_dumps(contradict), json_dumps(missing), SAFE_ACTIONS[family],
            json_dumps(sorted(set(rule_ids))), CANDIDATE_RULE_VERSION, decision, note, now, now,
        ),
    )
    return candidate_id


def _alert_candidates(db: Database, analysis_id: str, run_id: str, row: Mapping[str, Any]) -> int:
    alert_id = int(row["alert_id"])
    target = str(row["target"])
    endpoint_schema = _loads(row.get("endpoint_schema_json"), {})
    details = _loads(row.get("details_json"), {})
    evidence_for = _loads(row.get("evidence_for_json"), [])
    evidence_against = _loads(row.get("evidence_against_json"), [])
    confidence = parse_int(row.get("confidence"), 0)
    context = str(row.get("business_context") or "general")
    category = str(row.get("category") or "")
    item = str(row.get("item") or "")
    endpoint = str(endpoint_schema.get("endpoint") or item)
    method = str(endpoint_schema.get("method") or details.get("method") or "UNKNOWN").upper()
    if endpoint_schema.get("is_endpoint") is False or category in {"dns_change", "new_subdomain", "new_port"}:
        return 0
    body_fields = [str(x) for x in _list(endpoint_schema.get("body_fields"))]
    query_fields = [str(x) for x in _list(endpoint_schema.get("query_parameters"))]
    path_fields = [str(x) for x in _list(endpoint_schema.get("path_parameters"))]
    object_ids = [str(x) for x in _list(endpoint_schema.get("object_identifiers"))]
    auth_hints = [str(x) for x in _list(endpoint_schema.get("authentication_hints"))]
    haystack = " ".join([endpoint, item, category, context, json_dumps(details), " ".join(body_fields + query_fields + path_fields)]).lower()
    source_ref = f"alert:{alert_id}"
    asset = ""
    if "://" in endpoint:
        try:
            from urllib.parse import urlsplit
            asset = urlsplit(endpoint).hostname or ""
        except Exception:
            asset = ""
    execution_map = execute_detector_intelligence(
        target=target, endpoint=endpoint, method=method, endpoint_schema=endpoint_schema, details=details,
        evidence_for=evidence_for, evidence_against=evidence_against, category=category, business_context=context,
    )
    emitted_execution_families: set[str] = set()
    count = 0

    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:
        nonlocal count
        execution_packet = execution_map.get(family, {})
        if execution_packet:
            support = _merge_evidence_lists(support, list(execution_packet.get("support", [])))
            contradict = _merge_evidence_lists(contradict, list(execution_packet.get("contradict", [])))
            rules = list(dict.fromkeys([*rules, *execution_packet.get("rule_ids", []), *execution_rule_ids(family)]))
        emitted_execution_families.add(family)
        extraction = evaluate_family_detector(family, support, contradict, channel="alert")
        support = extraction["support"]
        contradict = extraction["contradict"]
        rules = list(dict.fromkeys([*rules, *detector_rule_ids(family)]))
        hypothesis = record_hypothesis(
            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,
            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant, support=support,
            contradict=contradict, missing=missing, rule_ids=rules, summary=summary,
        )
        support = hypothesis["support"]
        contradict = hypothesis["contradict"]
        missing = hypothesis["missing"]
        rules = hypothesis["rule_ids"]
        if not hypothesis["assessment"]["admitted"]:
            return
        # Admission decides family-specific sufficiency. This generic quality guard still
        # protects against a single duplicated source while retaining all weaker signals
        # in analysis_hypotheses for future correlation.
        independent = {str(x.get("source") or x.get("source_group") or x.get("type") or "rule") for x in support}
        if len(support) < 2 or (len(independent) < 2 and not direct):
            return
        likelihood = base + sum(parse_int(x.get("weight"), 0) for x in support) + sum(parse_int(x.get("weight"), 0) for x in contradict)
        strength = _evidence_strength(confidence, support, contradict, direct=direct)
        candidate_id = _insert_candidate(
            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,
            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant,
            likelihood=likelihood, evidence_strength=strength,
            impact_potential=_impact(impact if impact is not None else BUG_FAMILIES[family]["impact"], context, method),
            support=support, contradict=contradict, missing=missing, rule_ids=rules, summary=summary,
        )
        if candidate_id:
            mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
            count += 1

    # Analysis 6.16 — physical raw collector ownership for server-side injection families.
    # The collector contributes emission metadata only; target evidence is still owned
    # by execute_detector_intelligence() and merged inside emit().
    for observation in collect_injection_observations(execution_map):
        emit(
            observation.family,
            observation.variant,
            observation.base,
            [],
            [],
            list(observation.missing),
            list(observation.rules),
            observation.summary,
            direct=observation.direct,
            impact=observation.impact,
        )

    # Analysis 6.17 — physical raw collector ownership for function/property authorization.
    # The collector contributes emission metadata only; target evidence remains owned
    # by execute_detector_intelligence() and raw-condition reconstruction.
    for observation in collect_authorization_observations(execution_map):
        emit(
            observation.family,
            observation.variant,
            observation.base,
            [],
            [],
            list(observation.missing),
            list(observation.rules),
            observation.summary,
            direct=observation.direct,
            impact=observation.impact,
        )

    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.
    # Promotion requires stored target evidence that the identity/scope-to-object authorization relation failed.
    structural_fields = [str(field) for field in path_fields + query_fields + body_fields]
    bola = analyze_bola_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        method=method,
        object_ids=object_ids,
        structural_fields=structural_fields,
        details=details,
        business_context=context,
    )
    if bola:
        emit(
            "broken_object_authorization",
            str(bola["variant"]),
            int(bola["base"]),
            list(bola["support"]),
            list(bola["contradict"]),
            list(bola["missing"]),
            list(bola["rule_ids"]),
            str(bola["summary"]),
            direct=bool(bola["direct"]),
        )

    # Analysis 6.17: Function Authorization and Mass Assignment legacy collection was physically
    # removed after equivalent execution/admission coverage moved to raw_family_collectors.authorization.

    # Authentication / recovery / enumeration
    auth_markers = _contains_any(haystack, ("login", "signin", "password", "reset", "forgot", "otp", "mfa", "token", "refresh", "session", "oauth", "sso"))
    if auth_markers:
        support = [
            {"type": "authentication_surface", "source": "semantic", "weight": 16, "text": f"Authentication or recovery markers observed: {', '.join(auth_markers[:6])}"},
            {"type": "client_operation", "source": "endpoint", "weight": 9, "text": "The operation is exposed in client-observable application behavior"},
        ]
        if method in {"POST", "PUT", "PATCH"}:
            support.append({"type": "state_change", "source": "method", "weight": 7, "text": f"Authentication state may change through {method}"})
        emit("authentication_session", "auth_lifecycle", 20, support, [],
             ["Expected authentication state machine", "Token rotation and expiration behavior", "Rate limiting and recovery verification behavior"],
             ["candidate-auth-surface", "candidate-auth-lifecycle"],
             "The collected endpoint and client context expose an authentication or session lifecycle that warrants controlled review.")
        if any(token in haystack for token in ("forgot", "reset", "recover", "lookup", "check-email", "username")):
            enum_support = support[:2] + [{"type": "identity_lookup", "source": "semantic", "weight": 12, "text": "The flow appears to accept an account identity or recovery identifier"}]
            for flag, signal in (("response_difference", "response_difference"), ("timing_difference", "timing_difference"), ("distinct_error", "distinct_error"), ("account_existence_differential", "account_existence_differential")):
                if _explicit_flag(details, flag):
                    enum_support.append({"type": signal, "source": "stored_behavior", "source_group": "enumeration_behavior", "weight": 24, "text": f"Stored controlled-account evidence records {signal.replace('_', ' ')}"})
            emit("account_enumeration", "identity_response_difference", 15, enum_support, [],
                 ["Response-shape consistency for test identities", "Timing consistency", "Rate limiting"],
                 ["candidate-recovery-identity", "candidate-response-difference"],
                 "An identity or recovery lookup may reveal whether a test account exists through response differences.", impact=48)

    # Redirect
    redirect_tokens = _contains_any(haystack, ("redirect", "returnurl", "return_url", "callbackurl", "callback_url", "continue", "nexturl", "next="))
    navigation = _contains_any(haystack, ("window.location", "location.href", "location.assign", "location.replace"))
    if redirect_tokens and (query_fields or navigation):
        support = [
            {"type": "redirect_parameter", "source": "endpoint_schema", "weight": 18, "text": f"Navigation parameter markers observed: {', '.join(redirect_tokens[:5])}"},
            {"type": "navigation_context", "source": "client", "weight": 14, "text": "The value appears in a client or callback navigation context"},
        ]
        if navigation or _explicit_flag(details, "navigation_sink", "redirect_response"):
            support.append({"type": "navigation_sink", "source": "stored_flow", "source_group": "navigation", "weight": 16, "text": "Stored evidence identifies a navigation/redirect sink"})
        for flag, signal in (("external_redirect_observed", "external_destination"), ("allowlist_bypass", "allowlist_bypass"), ("same_origin_bypass", "same_origin_bypass"), ("unrestricted_destination", "unrestricted_destination")):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "redirect_behavior", "weight": 26, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("open_redirect", "unvalidated_destination", 20, support, [],
             ["Destination allow-list or same-origin validation", "Whether the parameter reaches the final navigation sink"],
             ["candidate-redirect-parameter", "candidate-navigation-context"],
             "A user-influenced destination may be used for navigation; validation and allow-list behavior are not established.")

    # SSRF
    ssrf_tokens = _contains_any(haystack, ("webhook", "fetchurl", "fetch_url", "imageurl", "image_url", "importurl", "import_url", "previewurl", "proxyurl", "callbackurl", "destinationurl", "remoteurl"))
    generic_url_fields = [field for field in query_fields + body_fields if field.lower() in {"url", "uri", "endpoint", "destination", "callback", "webhook"}]
    if ssrf_tokens or generic_url_fields:
        support = [
            {"type": "remote_destination", "source": "schema", "weight": 18, "text": f"Remote destination input observed: {', '.join((ssrf_tokens + generic_url_fields)[:6])}"},
            {"type": "server_feature", "source": "semantic", "weight": 8, "text": "Import, preview, proxy, callback or webhook semantics may involve server-side fetching; execution location is not assumed"},
        ]
        for flag, signal in (("server_fetch_observed", "server_fetch_observed"), ("backend_fetch", "backend_fetch"), ("webhook_delivery_observed", "webhook_delivery_observed"), ("remote_import_fetch", "remote_import_fetch")):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "server_fetch", "weight": 30, "text": f"Stored target evidence explicitly records {signal.replace('_', ' ')}"})
        contradict = [{"type": "execution_location", "source": "missing", "weight": -8, "text": "The evidence does not establish whether the browser or server performs the request"}]
        emit("ssrf", "remote_fetch", 20, support, contradict,
             ["Whether the server performs the outbound request", "Destination validation and scheme restrictions", "Network egress policy"],
             ["candidate-remote-destination", "candidate-server-fetch"],
             "A remote-destination input may trigger server-side fetching, but execution location and destination controls are unknown.")

    # File handling. Hypothesis generation is deliberately recall-oriented, while
    # admission is based only on structural file/path evidence. Generic metadata such
    # as Content-Type is retained in the hidden hypothesis ledger but cannot promote.
    structured_fields = [str(value) for value in body_fields + query_fields + path_fields]
    normalized_fields = {re.sub(r"[^a-z0-9]", "", value.lower()): value for value in structured_fields}
    file_input_names = {"file", "files", "filename", "file_name", "attachment", "attachments", "avatar", "document", "documents", "upload", "uploadfile", "upload_file"}
    file_input_norm = {re.sub(r"[^a-z0-9]", "", value) for value in file_input_names}
    path_names = {"path", "filepath", "file_path", "filename", "file_name", "directory", "dir", "folder", "storage_path", "storagepath"}
    path_norm = {re.sub(r"[^a-z0-9]", "", value) for value in path_names}
    filename_norm = {"filename", "file_name"}
    filename_norm = {re.sub(r"[^a-z0-9]", "", value) for value in filename_norm}
    endpoint_lower = endpoint.lower()
    write_method = method in {"POST", "PUT", "PATCH"}
    upload_route = any(token in endpoint_lower for token in ("/upload", "/uploads", "/attachment", "/attachments", "/avatar", "/document", "/documents"))
    import_route = "/import" in endpoint_lower or endpoint_lower.rstrip("/").endswith("import")
    download_route = any(token in endpoint_lower for token in ("/download", "/downloads", "/file", "/files", "/attachment", "/export"))
    archive_route = any(token in endpoint_lower for token in ("/archive", "/zip", "/tar", "/extract", "/unpack"))
    multipart = "multipart/form-data" in haystack or "multipart/form-data" in str(details.get("content_type") or "").lower()
    generic_file_markers = _contains_any(haystack, ("upload", "attachment", "avatar", "document", "multipart", "filename", "file_name", "contenttype", "content_type", "import"))
    file_fields = [original for normalized, original in normalized_fields.items() if normalized in file_input_norm]
    path_fields_structured = [original for normalized, original in normalized_fields.items() if normalized in path_norm]
    filename_fields = [original for normalized, original in normalized_fields.items() if normalized in filename_norm]

    if generic_file_markers or file_fields or multipart or upload_route or import_route:
        support: list[dict[str, Any]] = []
        if generic_file_markers:
            support.append({"type": "file_surface", "source": "semantic", "weight": 7, "text": f"File-related markers observed: {', '.join(generic_file_markers[:6])}"})
        if file_fields:
            support.append({"type": "file_input", "source": "schema", "weight": 20, "text": f"Structured file input observed: {', '.join(file_fields[:6])}"})
        elif multipart and upload_route:
            support.append({"type": "file_input", "source": "http_contract", "weight": 18, "text": "Multipart request semantics are tied to an explicit upload route"})
        if multipart:
            support.append({"type": "content_type_field", "source": "http_contract", "weight": 7, "text": "multipart/form-data semantics are present"})
        elif "content_type" in haystack or "contenttype" in haystack:
            support.append({"type": "content_type_field", "source": "semantic", "weight": 3, "text": "Content-Type metadata is present; this does not by itself establish file upload"})
        if write_method and (upload_route or file_fields or multipart):
            support.append({"type": "upload_operation", "source": "endpoint", "weight": 18, "text": f"{method} operation is tied to an upload-capable route or structured file input"})
        if write_method and import_route:
            support.append({"type": "import_operation", "source": "endpoint", "weight": 18, "text": f"{method} operation is tied to an import route"})
        if write_method:
            support.append({"type": "write_method", "source": "method", "weight": 5, "text": f"State-changing method observed: {method}"})
        for flag, signal in (("dangerous_type_accepted", "dangerous_type_accepted"), ("content_type_mismatch_accepted", "content_type_mismatch_accepted"), ("active_content_served", "active_content_served"), ("unsafe_storage", "unsafe_storage"), ("executable_upload", "executable_upload"), ("filename_control_reaches_storage", "filename_control_reaches_storage"), ("upload_validation_bypass", "upload_validation_bypass")):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "upload_behavior", "weight": 28, "text": f"Stored target evidence explicitly records {signal.replace('_', ' ')}"})
        emit("file_upload", "file_validation", 18, support, [],
             ["Allowed file types and size", "Storage and serving behavior", "Server-generated filenames and content disposition"],
             ["candidate-file-surface", "candidate-file-validation", "admission-file-input-operation"],
             "File-handling evidence is retained for correlation; promotion requires an actual file input plus upload/import operation.")

    generic_path_markers = _contains_any(haystack, ("filepath", "file_path", "path", "directory", "folder", "download", "archive", "extract"))
    if generic_path_markers or path_fields_structured or download_route or archive_route:
        path_support: list[dict[str, Any]] = []
        if generic_path_markers:
            path_support.append({"type": "path_surface", "source": "semantic", "weight": 5, "text": f"Path/file markers observed: {', '.join(generic_path_markers[:6])}"})
        if filename_fields:
            path_support.append({"type": "filename_field", "source": "schema", "weight": 20, "text": f"Structured filename input observed: {', '.join(filename_fields[:5])}"})
        structured_nonfilename = [value for value in path_fields_structured if value not in filename_fields]
        if structured_nonfilename:
            path_support.append({"type": "path_parameter", "source": "schema", "weight": 20, "text": f"Structured path input observed: {', '.join(structured_nonfilename[:5])}"})
        if any(re.sub(r"[^a-z0-9]", "", value.lower()) == "storagepath" for value in path_fields_structured):
            path_support.append({"type": "storage_path", "source": "schema", "weight": 18, "text": "Structured storage path field is client-visible"})
        if method == "GET" and download_route:
            path_support.append({"type": "download_operation", "source": "endpoint", "weight": 18, "text": "GET operation is tied to an explicit download/file route"})
        if archive_route:
            path_support.append({"type": "archive_operation", "source": "endpoint", "weight": 17, "text": "Archive/extract operation is visible in the endpoint"})
        if write_method and import_route:
            path_support.append({"type": "import_operation", "source": "endpoint", "weight": 16, "text": f"{method} import operation may consume a path or archive entry"})
        if write_method and (upload_route or file_fields or multipart):
            path_support.append({"type": "upload_operation", "source": "endpoint", "weight": 15, "text": f"{method} upload operation may consume a client-controlled filename"})
        explicit_file_operation = download_route or archive_route or upload_route or import_route
        if explicit_file_operation and method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            path_support.append({"type": "file_operation", "source": "endpoint_contract", "weight": 10, "text": "Endpoint semantics identify an explicit file-related operation"})
        for flag, signal in (("filesystem_path_reachability", "filesystem_path_reachability"), ("path_escape_observed", "path_escape_observed"), ("canonicalization_bypass", "canonicalization_bypass"), ("base_directory_escape", "base_directory_escape"), ("archive_entry_escape", "archive_entry_escape"), ("path_join_user_controlled", "path_join_user_controlled")):
            if _explicit_flag(details, flag):
                path_support.append({"type": signal, "source": "stored_behavior", "source_group": "filesystem_behavior", "weight": 30, "text": f"Stored target evidence explicitly records {signal.replace('_', ' ')}"})
        emit("path_traversal", "path_construction", 16, path_support, [],
             ["Path canonicalization", "Base-directory enforcement", "Whether user-controlled path data reaches filesystem APIs"],
             ["candidate-path-input", "candidate-file-path", "admission-path-input-operation"],
             "Path/file clues are retained for correlation; promotion requires structured path/filename control plus a file-relevant operation.")


    # Analysis 6.16: SQL/NoSQL/Command/SSTI/LDAP legacy collection was physically
    # removed from this orchestrator. Dedicated raw_family_collectors now own emission
    # metadata while detector execution/reconstruction owns all target evidence.

    # API4:2023 — resource consumption.
    resource_fields = [field for field in query_fields + body_fields if field.lower().replace("_", "") in {"limit", "pagesize", "size", "count", "batch", "batchsize", "first", "take", "perpage", "maxresults", "filesize"}]
    resource_markers = _contains_any(haystack, ("batch", "bulk", "export", "report", "generate", "pdf", "upload", "download", "sms", "email", "otp", "biometric", "thumbnail"))
    if resource_fields or resource_markers:
        support = []
        if resource_fields:
            support.append({"type": "resource_control_parameter", "source": "endpoint_schema", "weight": 16, "text": f"Resource-amplifying controls are client visible: {', '.join(resource_fields[:8])}"})
            if any("page" in field.lower() or field.lower() in {"limit", "first", "take", "perpage"} for field in resource_fields):
                support.append({"type": "pagination_control", "source": "endpoint_schema", "weight": 10, "text": "Pagination/record-count control is client visible"})
        if any(token in resource_markers for token in ("batch", "bulk")):
            support.append({"type": "batch_operation", "source": "semantic", "weight": 12, "text": "Batch/bulk operation semantics are visible"})
        if any(token in resource_markers for token in ("sms", "email", "otp", "biometric")):
            support.append({"type": "paid_provider_operation", "source": "semantic", "weight": 14, "text": "The operation may trigger a per-request third-party service cost"})
        if any(token in resource_markers for token in ("export", "report", "generate", "pdf", "thumbnail", "upload", "download")):
            support.append({"type": "expensive_operation", "source": "semantic", "weight": 10, "text": "Potentially expensive processing/storage/bandwidth operation is visible"})
        for flag, signal in (
            ("rate_limit_absent_observed", "rate_limit_absent_observed"),
            ("unbounded_page_size_observed", "unbounded_page_size_observed"),
            ("batch_limit_absent_observed", "batch_limit_absent_observed"),
            ("oversized_payload_accepted", "oversized_payload_accepted"),
            ("cost_amplification_observed", "cost_amplification_observed"),
            ("timeout_limit_absent", "timeout_limit_absent"),
            ("resource_exhaustion_differential", "resource_exhaustion_differential"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "resource_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        if support:
            emit("unrestricted_resource_consumption", "missing_resource_limit", 16, support, [],
                 ["Maximum page/batch/payload size", "Per-client operation rate", "Execution timeout and provider spending limit"],
                 ["candidate-resource-surface", "admission-resource-limit-failure"],
                 "The API exposes a resource-amplifying control or costly operation; promotion requires observed missing or ineffective limits.")

    # API6:2023 — unrestricted access to sensitive business flows.
    flow_map = {
        "purchase_flow": ("purchase", "buy", "checkout", "ticket", "order"),
        "reservation_flow": ("reserve", "reservation", "booking", "slot"),
        "posting_flow": ("comment", "post", "message", "review"),
        "signup_flow": ("signup", "register", "invite", "create account"),
        "redemption_flow": ("redeem", "claim", "coupon", "promo"),
    }
    flow_signals = [(signal, _contains_any(haystack, tokens)) for signal, tokens in flow_map.items()]
    flow_signals = [(signal, tokens) for signal, tokens in flow_signals if tokens]
    if flow_signals:
        support = [{"type": "sensitive_business_flow", "source": "semantic", "weight": 12, "text": "A potentially abuse-sensitive business flow is exposed"}]
        for signal, tokens in flow_signals[:3]:
            support.append({"type": signal, "source": "semantic", "weight": 12, "text": f"Flow semantics observed: {', '.join(tokens[:5])}"})
        for flag, signal in (
            ("automation_limit_absent", "automation_limit_absent"),
            ("anti_bot_control_absent", "anti_bot_control_absent"),
            ("per_user_limit_absent", "per_user_limit_absent"),
            ("bulk_abuse_observed", "bulk_abuse_observed"),
            ("scalping_control_absent", "scalping_control_absent"),
            ("reservation_abuse_observed", "reservation_abuse_observed"),
            ("workflow_frequency_unrestricted", "workflow_frequency_unrestricted"),
            ("business_flow_limit_bypass", "business_flow_limit_bypass"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "business_flow_behavior", "weight": 28, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("sensitive_business_flow_abuse", "automation_abuse_boundary", 15, support, [],
             ["Per-user/business frequency limits", "Anti-automation controls", "Scarce-inventory or reservation abuse controls"],
             ["candidate-sensitive-business-flow", "admission-business-flow-limit"],
             "A sensitive business flow may be automatable at harmful scale; promotion requires observed missing or bypassable abuse controls.")

    # API8:2023 — security misconfiguration.
    misconfig_markers = _contains_any(haystack, ("debug", "stacktrace", "stack_trace", "traceback", "swagger", "actuator", "phpinfo", "directory listing", "server-status", "options method", "http://"))
    misconfig_flags = []
    for flag, signal in (
        ("stack_trace_exposed", "stack_trace_exposed"),
        ("debug_mode_exposed", "debug_mode_exposed"),
        ("insecure_http_enabled", "insecure_http_enabled"),
        ("unnecessary_method_enabled", "unnecessary_method_enabled"),
        ("directory_listing_observed", "directory_listing_observed"),
        ("security_header_missing_on_sensitive_response", "security_header_missing_on_sensitive_response"),
        ("desync_processing_difference", "desync_processing_difference"),
        ("unsafe_default_configuration", "unsafe_default_configuration"),
    ):
        if _explicit_flag(details, flag):
            misconfig_flags.append({"type": signal, "source": "stored_behavior", "source_group": "configuration_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
    if misconfig_markers or misconfig_flags:
        support = [{"type": "misconfiguration_surface", "source": "semantic", "weight": 10, "text": f"Configuration-sensitive surface observed: {', '.join(misconfig_markers[:6]) or 'explicit stored configuration evidence'}"}] + misconfig_flags
        if any(token in misconfig_markers for token in ("debug", "stacktrace", "stack_trace", "traceback", "phpinfo")):
            support.append({"type": "debug_surface", "source": "semantic", "weight": 10, "text": "Debug/error surface is externally observable"})
        if "http://" in haystack:
            support.append({"type": "transport_surface", "source": "endpoint", "weight": 10, "text": "Cleartext HTTP surface is present"})
        emit("security_misconfiguration", "deployment_hardening", 17, support, [],
             ["Expected hardening baseline", "Production transport/method policy", "Whether debug/default functionality is intentionally exposed"],
             ["candidate-misconfiguration-surface", "admission-direct-misconfiguration"],
             "A configuration-sensitive surface is visible; promotion requires directly observed insecure configuration behavior.")

    # API9:2023 — improper inventory management.
    version_tokens = re.findall(r"(?:^|[/_.-])(v\d+|v\d+\.\d+|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", haystack, re.I)
    if version_tokens:
        normalized = [str(x).lower() for x in version_tokens]
        support = [{"type": "api_version_surface", "source": "semantic", "weight": 14, "text": f"Version/non-production inventory markers observed: {', '.join(normalized[:8])}"}]
        if any(x in {"legacy", "old", "deprecated"} for x in normalized):
            support.append({"type": "legacy_endpoint_surface", "source": "semantic", "weight": 12, "text": "Legacy/deprecated endpoint naming is visible"})
        if any(x in {"staging", "stage", "dev", "test", "beta", "alpha"} for x in normalized):
            support.append({"type": "nonproduction_surface", "source": "semantic", "weight": 12, "text": "Non-production/pre-release deployment naming is visible"})
        for flag, signal in (
            ("deprecated_version_still_reachable", "deprecated_version_still_reachable"),
            ("older_version_weaker_controls", "older_version_weaker_controls"),
            ("undocumented_host_observed", "undocumented_host_observed"),
            ("nonproduction_with_production_data", "nonproduction_with_production_data"),
            ("retired_endpoint_active", "retired_endpoint_active"),
            ("inventory_drift_observed", "inventory_drift_observed"),
            ("unprotected_legacy_endpoint", "unprotected_legacy_endpoint"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "inventory_behavior", "weight": 28, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("improper_inventory_management", "legacy_or_nonproduction_exposure", 14, support, [],
             ["Current API inventory and retirement plan", "Control parity with current production API", "Whether non-production hosts use production data"],
             ["candidate-api-inventory-surface", "admission-inventory-drift"],
             "Version or non-production API surface is visible; promotion requires observed active legacy/undocumented exposure with security relevance.")

    # API10:2023 — unsafe consumption of third-party APIs.
    upstream_markers = _contains_any(haystack, ("third-party", "third_party", "provider", "integration", "upstream", "webhook", "external api", "external_api", "vendor", "partner api"))
    if upstream_markers:
        support = [{"type": "third_party_integration", "source": "semantic", "weight": 16, "text": f"External/upstream integration markers observed: {', '.join(upstream_markers[:6])}"}]
        if ssrf_tokens or generic_url_fields:
            support.append({"type": "upstream_api_surface", "source": "endpoint_schema", "weight": 10, "text": "A remote/upstream destination is client or application visible"})
        for flag, signal in (
            ("upstream_tls_missing", "upstream_tls_missing"),
            ("third_party_data_unsanitized", "third_party_data_unsanitized"),
            ("upstream_redirect_followed_unrestricted", "upstream_redirect_followed_unrestricted"),
            ("upstream_timeout_absent", "upstream_timeout_absent"),
            ("upstream_response_unbounded", "upstream_response_unbounded"),
            ("third_party_auth_weak", "third_party_auth_weak"),
            ("unsafe_upstream_data_reaches_sink", "unsafe_upstream_data_reaches_sink"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "upstream_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("unsafe_api_consumption", "upstream_trust_boundary", 17, support, [],
             ["TLS and authentication to upstream service", "Redirect/timeout/response-size controls", "Validation and sanitization of third-party response data"],
             ["candidate-upstream-integration", "admission-unsafe-api-consumption"],
             "A third-party/upstream API dependency is visible; promotion requires observed unsafe trust, transport, redirect, resource, auth, or validation behavior.")


    # Information exposure / headers
    disclosure_markers = _contains_any(haystack, ("debug", "internal", "stacktrace", "stack_trace", "exception", "sourceMappingURL", "apikey", "api_key", "secret", "token"))
    if disclosure_markers:
        support = [
            {"type": "sensitive_marker", "source": "semantic", "weight": 16, "text": f"Sensitive or internal markers observed: {', '.join(disclosure_markers[:6])}"},
            {"type": "stored_evidence", "source": "analysis", "weight": 8, "text": "The marker was preserved in normalized, redacted analysis evidence"},
        ]
        emit("information_disclosure", "sensitive_metadata", 18, support, [],
             ["Whether the information is publicly reachable", "Whether the value is intended or a placeholder", "Minimum affected data scope"],
             ["candidate-sensitive-marker", "candidate-public-metadata"],
             "Sensitive, debug or internal metadata may be exposed; public reachability and sensitivity remain unverified.")

    headers_text = json_dumps(details).lower()
    response_headers, request_headers = _header_maps(details)
    acao = response_headers.get("access-control-allow-origin", "").strip()
    acac = response_headers.get("access-control-allow-credentials", "").strip().lower()
    request_origin = request_headers.get("origin", "").strip()
    reflected = bool(request_origin and acao and acao == request_origin and _explicit_flag(details, "origin_reflection_observed", "reflected_origin"))
    wildcard = acao == "*"
    null_origin = acao.lower() == "null" and _explicit_flag(details, "null_origin_accepted")
    if wildcard or reflected or null_origin:
        support = [{"type": "cors_header", "source": "http_headers", "weight": 10, "text": f"Access-Control-Allow-Origin observed as {acao!r}"}]
        if wildcard: support.append({"type": "wildcard_origin", "source": "http_headers", "source_group": "cors_policy", "weight": 18, "text": "Wildcard ACAO policy observed"})
        if reflected: support.append({"type": "reflected_origin", "source": "stored_behavior", "source_group": "cors_policy", "weight": 22, "text": "Stored target evidence records request-origin reflection"})
        if null_origin: support.append({"type": "null_origin_accepted", "source": "stored_behavior", "source_group": "cors_policy", "weight": 22, "text": "Stored target evidence records null-origin acceptance"})
        if acac == "true": support.append({"type": "credentials_allowed", "source": "http_headers", "source_group": "cors_credentials", "weight": 24, "text": "Access-Control-Allow-Credentials: true observed"})
        if _explicit_flag(details, "sensitive_cross_origin_response"):
            support.append({"type": "sensitive_cross_origin_response", "source": "stored_behavior", "source_group": "cors_exposure", "weight": 28, "text": "Stored target evidence records sensitive cross-origin response readability"})
        emit("cors_misconfiguration", "origin_policy", 18, support, [],
             ["Exact origin allow-list policy", "Credential behavior", "Whether sensitive response data is readable cross-origin"],
             ["candidate-cors-header", "admission-cors-origin-exposure"],
             "An unsafe CORS origin pattern is retained; promotion requires credentialed or sensitive cross-origin exposure evidence.")
    if "cache-control" in headers_text and context in SENSITIVE_CONTEXTS and any(token in headers_text for token in ("public", "s-maxage", "max-age")):
        support = [
            {"type": "cache_header", "source": "http_headers", "weight": 18, "text": "Cacheable response directives were observed"},
            {"type": "sensitive_context", "source": "context", "weight": 14, "text": f"The response is associated with {context.replace('_',' ')} context"},
        ]
        for flag, signal in (("shared_cache_risk", "shared_cache_risk"), ("missing_vary", "missing_vary"), ("cdn_cache", "cdn_cache"), ("cache_key_missing_auth_context", "cache_key_missing_auth_context")):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "cache_behavior", "weight": 24, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("sensitive_caching", "cache_policy", 20, support, [],
             ["Authentication context", "Cache key and Vary behavior", "Whether response content is user-specific"],
             ["candidate-cache-header", "candidate-sensitive-response"],
             "A security-relevant response may be cacheable; user specificity and cache-key behavior are unknown.")

    # Business logic and race watchlist: deliberately low-confidence without behavior evidence.
    business_tokens = _contains_any(haystack, ("coupon", "discount", "price", "quantity", "balance", "refund", "checkout", "order", "redeem", "claim", "transfer", "withdraw", "reserve", "confirm"))
    if len(set(business_tokens)) >= 2:
        support = [
            {"type": "workflow_markers", "source": "semantic", "weight": 12, "text": f"Business workflow markers observed: {', '.join(business_tokens[:7])}"},
            {"type": "stateful_operation", "source": "method", "weight": 8, "text": f"The workflow is associated with {method} or client-visible state transitions"},
        ]
        for flag, signal in (("workflow_invariant_violation", "workflow_invariant_violation"), ("value_constraint_bypass", "value_constraint_bypass"), ("invalid_transition_accepted", "invalid_transition_accepted"), ("server_calculation_mismatch", "server_calculation_mismatch"), ("business_rule_bypass", "business_rule_bypass")):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "business_behavior", "weight": 28, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("business_logic", "workflow_invariant", 12, support, [],
             ["Intended workflow and invariants", "Server-side value calculation", "Allowed transition order"],
             ["candidate-business-workflow", "candidate-state-invariant"],
             "The endpoint participates in a business workflow where server-side invariants may be security-relevant.", impact=72)
        race_tokens = [x for x in business_tokens if x in {"redeem", "claim", "transfer", "withdraw", "reserve", "confirm", "refund"}]
        if race_tokens:
            support2 = support + [{"type": "single_use_semantics", "source": "semantic", "weight": 10, "text": f"Potential single-use or balance-changing actions observed: {', '.join(race_tokens)}"}]
            for flag, signal in (("duplicate_effect_observed", "duplicate_effect_observed"), ("atomicity_failure", "atomicity_failure"), ("concurrency_invariant_violation", "concurrency_invariant_violation"), ("double_spend_observed", "double_spend_observed")):
                if _explicit_flag(details, flag):
                    support2.append({"type": signal, "source": "stored_behavior", "source_group": "concurrency_behavior", "weight": 32, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            emit("race_condition", "duplicate_operation", 10, support2, [],
                 ["Idempotency key or transaction guard", "Atomic state transition behavior", "Whether the action is intended to be single-use"],
                 ["candidate-single-use-operation", "candidate-idempotency"],
                 "A balance-changing or single-use workflow may require idempotency and atomicity controls; no concurrency test has been performed.", impact=80)

    # Execution-only families still enter the hidden hypothesis ledger even when
    # legacy surface heuristics did not emit them. Admission remains the only promotion gate.
    for execution_family, execution_packet in execution_map.items():
        if execution_family in emitted_execution_families:
            continue
        if not execution_packet.get("support") and not execution_packet.get("contradict"):
            continue
        emit(
            execution_family,
            "raw_execution_intelligence",
            10,
            [],
            [],
            [
                "Correlate the execution signal with an independent target artifact",
                "Verify the family-specific vulnerability condition and blocking controls",
            ],
            ["detector-execution-fallback"],
            f"Stored raw artifacts produced family-specific {execution_family.replace('_', ' ')} evidence; admission remains evidence-gated.",
        )

    return count


def _static_candidates(db: Database, analysis_id: str, run_id: str, target: str | None) -> int:
    count = 0
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)

    # JavaScript data-flow candidates.
    rows = db.all(f"SELECT * FROM js_dataflows WHERE analysis_id=?{target_clause}", tuple(params))
    for row in rows:
        source = str(row["source_kind"]); sink = str(row["sink_kind"]); current_target = str(row["target"]); js_url = str(row["js_url"])
        confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "source_sink", "source": "javascript_dataflow", "source_group": "static_flow", "weight": 18, "text": f"Static source/sink proximity observed: {source} -> {sink}"},
        ]
        if sink in {"innerHTML", "eval"}: support.append({"type": "dangerous_sink", "source": "javascript_sink", "source_group": "static_sink", "weight": 20, "text": f"Dangerous DOM/JS sink observed: {sink}"})
        if sink == "navigation": support.append({"type": "navigation_sink", "source": "javascript_sink", "source_group": "static_sink", "weight": 18, "text": "Navigation sink observed in static flow"})
        if source == "postMessage": support.append({"type": "postmessage_handler", "source": "javascript_dataflow", "source_group": "message_source", "weight": 16, "text": "postMessage-controlled source observed"})
        contradict = [{"type": "static_only", "source": "analysis_limit", "weight": -8, "text": "Static proximity does not prove runtime reachability or missing sanitization"}]
        missing = ["Runtime reachability", "Sanitization or encoding behavior", "Whether the value is transformed before the sink"]
        family = ""
        variant = ""
        summary = ""
        if source == "postMessage":
            family, variant = "postmessage_trust", "message_to_sensitive_sink"
            summary = "A postMessage-controlled value appears near a sensitive client sink; origin validation and message schema checks are unknown."
        elif sink in {"innerHTML", "eval"}:
            family, variant = "dom_xss", "source_to_dom_sink"
            summary = "A user-influenced browser source appears near an executable or HTML-rendering sink; runtime reachability and sanitization are unknown."
        elif sink == "navigation":
            family, variant = "open_redirect", "source_to_navigation_sink"
            summary = "A user-influenced browser source appears near a navigation sink; destination validation is unknown."
        elif sink == "websocket":
            family, variant = "websocket_authorization", "client_channel_construction"
            summary = "User-influenced data appears in WebSocket construction or messaging; channel authorization remains unknown."
        if not family:
            continue
        _insert_candidate(
            db, analysis_id=analysis_id, source_run_id=run_id, target=current_target, alert_id=None, asset="", endpoint="",
            source_ref=f"js-dataflow:{js_url}:{source}:{sink}", family=family, variant=variant,
            likelihood=_clamp(28 + confidence * 0.45 + sum(parse_int(x.get("weight"), 0) for x in support + contradict)),
            evidence_strength=_evidence_strength(confidence, support, contradict, direct=True),
            impact_potential=_impact(BUG_FAMILIES[family]["impact"], "general"), support=support, contradict=contradict,
            missing=missing, rule_ids=["candidate-js-source-sink", f"candidate-{variant}"], summary=summary,
        )
        count += 1

    # Source maps.
    rows = db.all(f"SELECT * FROM source_map_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    for row in rows:
        internal_count = parse_int(row["internal_source_count"], 0)
        if internal_count <= 0:
            continue
        support = [
            {"type": "source_map", "source": "source_map", "weight": 22, "text": f"Publicly referenced source map contains {parse_int(row['source_count'],0)} source entries"},
            {"type": "internal_sources", "source": "source_paths", "weight": 16, "text": f"{internal_count} internal-looking source paths were identified"},
        ]
        _insert_candidate(db, analysis_id=analysis_id, source_run_id=run_id, target=str(row["target"]), alert_id=None, asset="", endpoint=str(row["source_map_url"]), source_ref=f"source-map:{row['js_url']}", family="source_map_exposure", variant="internal_source_paths", likelihood=62, evidence_strength=78, impact_potential=52, support=support, contradict=[], missing=["Direct public reachability of the source-map URL", "Whether the source contents include secrets or proprietary server logic"], rule_ids=["candidate-source-map", "candidate-internal-source-path"], summary="A referenced source map exposes internal-looking source paths and may reveal implementation details.")
        count += 1

    # Secret candidates.
    rows = db.all(f"SELECT * FROM secret_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    for row in rows:
        assessment = str(row["assessment"]); confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "secret_pattern", "source": "secret_intelligence", "weight": 26, "text": f"A redacted {row['secret_kind']} pattern was detected in production JavaScript"},
            {"type": "context", "source": "javascript", "weight": 10, "text": "The candidate was found in client-delivered code and stored only as a fingerprint"},
        ]
        support.append({"type": "production_javascript", "source": "javascript", "source_group": "client_context", "weight": 10, "text": "The secret-like material was observed in client-delivered JavaScript"})
        contradict = []
        if assessment == "likely_placeholder":
            contradict.append({"type": "placeholder", "source": "secret_intelligence", "weight": -24, "text": "Context suggests an example, test or placeholder value"})
        else:
            support.append({"type": "non_placeholder_secret", "source": "secret_intelligence", "source_group": "secret_assessment", "weight": 18, "text": "Secret intelligence did not classify the redacted value as a known placeholder"})
        _insert_candidate(db, analysis_id=analysis_id, source_run_id=run_id, target=str(row["target"]), alert_id=None, asset="", endpoint=str(row["js_url"]), source_ref=f"secret:{row['js_url']}:{row['value_fingerprint']}", family="secret_exposure", variant=str(row["secret_kind"]), likelihood=_clamp(24 + confidence * 0.5 + sum(parse_int(x.get("weight"),0) for x in contradict)), evidence_strength=_evidence_strength(confidence, support, contradict, direct=True), impact_potential=90, support=support, contradict=contradict, missing=["Whether the value is live or a placeholder", "Intended exposure and privilege", "Rotation or revocation status"], rule_ids=["candidate-secret-pattern", "candidate-client-secret"], summary="A redacted credential- or token-like value may be exposed in client-delivered JavaScript; validity has not been tested.")
        count += 1

    # GraphQL operations.
    rows = db.all(f"SELECT * FROM graphql_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    for row in rows:
        identifiers = [str(x) for x in _list(_loads(row["identifiers_json"], []))]
        sensitive = [str(x) for x in _list(_loads(row["sensitive_fields_json"], []))]
        confidence = parse_int(row["confidence"], 0)
        if identifiers:
            support = [
                {"type": "graphql_identifier", "source": "graphql", "weight": 20, "text": f"GraphQL object identifiers observed: {', '.join(identifiers[:6])}"},
                {"type": "graphql_operation", "source": "javascript", "weight": 12, "text": f"Client-visible {row['operation_type']} operation: {row['operation_name']}"},
            ]
            _insert_candidate(db, analysis_id=analysis_id, source_run_id=run_id, target=str(row["target"]), alert_id=None, asset="", endpoint="/graphql", source_ref=f"graphql:{row['js_url']}:{row['operation_name']}", family="graphql_authorization", variant="object_boundary", likelihood=_clamp(32 + confidence * 0.35 + len(identifiers)*3), evidence_strength=_evidence_strength(confidence, support, [], direct=True), impact_potential=80, support=support, contradict=[], missing=["Resolver-level authorization", "Expected object ownership or role boundary", "Behavior with authorized test objects"], rule_ids=["candidate-graphql-identifier", "candidate-graphql-authorization"], summary="A client-visible GraphQL operation accepts object identifiers; resolver-level authorization remains unknown.")
            count += 1
        if sensitive:
            support = [
                {"type": "sensitive_fields", "source": "graphql", "weight": 20, "text": f"Sensitive GraphQL fields observed: {', '.join(sensitive[:8])}"},
                {"type": "client_operation", "source": "javascript", "weight": 10, "text": f"The fields are referenced by client operation {row['operation_name']}"},
            ]
            _insert_candidate(db, analysis_id=analysis_id, source_run_id=run_id, target=str(row["target"]), alert_id=None, asset="", endpoint="/graphql", source_ref=f"graphql-data:{row['js_url']}:{row['operation_name']}", family="graphql_data_exposure", variant="sensitive_fields", likelihood=_clamp(24 + confidence * 0.32 + len(sensitive)*2), evidence_strength=_evidence_strength(confidence, support, [], direct=True), impact_potential=68, support=support, contradict=[], missing=["Field-level authorization", "Whether the fields are returned to the current role", "Intended minimum response shape"], rule_ids=["candidate-graphql-sensitive-field", "candidate-graphql-data"], summary="A GraphQL operation references sensitive fields; field-level authorization and actual response exposure are unknown.")
            count += 1
    return count


def generate_bug_candidates(db: Database, analysis_id: str, run_id: str, target: str | None = None) -> dict[str, Any]:
    db.execute("DELETE FROM bug_candidates WHERE analysis_id=?", (analysis_id,))
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND r.target=?"
        params.append(target)
    rows = db.all(
        f"""SELECT r.*,a.item,a.title,a.details_json,a.status,a.severity,a.occurrences
        FROM analysis_results r JOIN alerts a ON a.id=r.alert_id
        WHERE r.analysis_id=?{target_clause}
        ORDER BY r.adjusted_score DESC,r.confidence DESC""",
        tuple(params),
    )
    alert_candidates = sum(_alert_candidates(db, analysis_id, run_id, dict(row)) for row in rows)
    _static_candidates(db,analysis_id,run_id,target)
    static_row = db.one("SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=? AND alert_id IS NULL", (analysis_id,))
    static_candidates = int(static_row["count"] if static_row else 0)
    summary_rows = db.all(
        "SELECT bug_family,candidate_state,COUNT(*) count,ROUND(AVG(likelihood_score),1) avg_likelihood,ROUND(AVG(evidence_strength),1) avg_evidence,ROUND(AVG(impact_potential),1) avg_impact FROM bug_candidates WHERE analysis_id=? GROUP BY bug_family,candidate_state ORDER BY count DESC",
        (analysis_id,),
    )
    strong = int(db.one("SELECT COUNT(*) FROM bug_candidates WHERE analysis_id=? AND candidate_state='strong_candidate'", (analysis_id,))[0])
    return {
        "total": alert_candidates + static_candidates,
        "from_alerts": alert_candidates,
        "from_static_intelligence": static_candidates,
        "strong_candidates": strong,
        "families": [dict(row) for row in summary_rows],
        "engine_version": CANDIDATE_ENGINE_VERSION,
        "rule_version": CANDIDATE_RULE_VERSION,
    }


def list_bug_candidates(db: Database, *, analysis_id: str = "", target: str = "", family: str = "", state: str = "", limit: int = 100) -> list[dict[str, Any]]:
    if not analysis_id:
        latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
        analysis_id = str(latest["id"]) if latest else ""
    if not analysis_id:
        return []
    where = ["analysis_id=?"]
    params: list[Any] = [analysis_id]
    if target:
        where.append("target=?"); params.append(target)
    if family:
        where.append("bug_family=?"); params.append(family)
    if state:
        where.append("candidate_state=?"); params.append(state)
    params.append(max(1, min(5000, limit)))
    return [dict(row) for row in db.all(f"SELECT * FROM bug_candidates WHERE {' AND '.join(where)} ORDER BY priority_score DESC,likelihood_score DESC,evidence_strength DESC LIMIT ?", tuple(params))]


def get_bug_candidate(db: Database, candidate_id: str) -> dict[str, Any]:
    row = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
    if not row:
        raise ReconError(f"Bug candidate not found: {candidate_id}")
    return dict(row)


def set_bug_candidate_decision(db: Database, candidate_id: str, decision: str, note: str = "", actor: str = "cli", reason_code: str = "") -> dict[str, Any]:
    if decision not in ANALYST_DECISIONS:
        raise ReconError(f"Unsupported candidate decision: {decision}")
    if reason_code not in FEEDBACK_REASON_CODES:
        raise ReconError(f"Unsupported candidate feedback reason: {reason_code}")
    row = get_bug_candidate(db, candidate_id)
    state = "confirmed_by_analyst" if decision == "confirmed_by_analyst" else "rejected" if decision == "rejected" else _state(parse_int(row["likelihood_score"],0), parse_int(row["evidence_strength"],0))
    db.execute("UPDATE bug_candidates SET analyst_decision=?,analyst_note=?,feedback_reason=?,candidate_state=?,updated_at=? WHERE candidate_id=?", (decision, note.strip(), reason_code, state, utc_now(), candidate_id))
    from candidate_intelligence import record_candidate_feedback
    record_candidate_feedback(db, candidate_id, decision, reason_code, note.strip(), actor)
    db.audit("bug_candidate_decision", actor=actor, target=str(row["target"]), entity_type="bug_candidate", entity_value=candidate_id, details={"decision": decision, "reason_code": reason_code, "note": note})
    return get_bug_candidate(db, candidate_id)

from __future__ import annotations

import json
import re
import uuid
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, ReconError, json_dumps, parse_int, sha256_text, utc_now

CANDIDATE_ENGINE_VERSION = "5.0.0"
CANDIDATE_RULE_VERSION = "2026.08.7"

AUTO_STATES = ("weak_signal", "possible", "plausible", "strong_candidate")
ANALYST_DECISIONS = ("unreviewed", "needs_more_evidence", "confirmed_by_analyst", "rejected", "duplicate", "out_of_scope")
FEEDBACK_REASON_CODES = (
    "", "keyword_only", "expected_behavior", "duplicate", "protected_boundary", "non_reachable",
    "test_data_only", "parsing_error", "out_of_scope", "authorization_difference",
    "unexpected_response_shape", "role_boundary_failure", "sensitive_data_exposure", "needs_contract_context",
)
FAMILY_EVIDENCE_SCHEMAS: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {"required_any": (("object_identifier", "graphql_identifier"), ("object_operation", "graphql_operation")), "label": "object identifier plus object-specific operation"},
    "broken_function_authorization": {"required_any": (("privileged_function", "privileged_classification"), ("state_change", "role_property")), "label": "privileged function plus role or state-changing context"},
    "mass_assignment": {"required_any": (("privileged_fields",), ("write_method", "body_schema")), "label": "privileged property plus writable request contract"},
    "dom_xss": {"required_any": (("source_sink",),), "label": "static source-to-DOM-sink relation"},
    "open_redirect": {"required_any": (("source_sink", "redirect_parameter"),), "label": "user-influenced navigation target"},
    "ssrf": {"required_any": (("url_parameter",), ("server_fetch_semantic", "server_request_function")), "label": "URL input plus server-side fetch semantics"},
    "file_upload": {"required_any": (("file_input",), ("upload_operation", "import_operation")), "label": "file input plus upload or import operation"},
    "graphql_authorization": {"required_any": (("graphql_identifier",), ("graphql_operation",)), "label": "GraphQL object identifier and operation"},
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
    normalized_endpoint = re.sub(r"\b\d{2,}\b", "{n}", endpoint.lower())
    normalized_endpoint = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", normalized_endpoint, flags=re.I)
    return sha256_text("|".join([target, str(alert_id or 0), family, variant, normalized_endpoint, source_ref]))


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
    gate_adjustment, missing = _family_schema_gate(family, support, missing)
    likelihood = _clamp(likelihood + gate_adjustment)
    evidence_strength = _clamp(evidence_strength)
    impact_potential = _clamp(impact_potential)
    auto_state = _state(likelihood, evidence_strength)
    fingerprint = _candidate_fingerprint(target, alert_id, family, variant, endpoint, source_ref)
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
    count = 0

    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:
        nonlocal count
        # Two independent signals are required unless the evidence is a direct static relation.
        independent = {str(x.get("source") or x.get("type") or "rule") for x in support}
        if len(support) < 2 or (len(independent) < 2 and not direct):
            return
        likelihood = base + sum(parse_int(x.get("weight"), 0) for x in support) + sum(parse_int(x.get("weight"), 0) for x in contradict)
        strength = _evidence_strength(confidence, support, contradict, direct=direct)
        _insert_candidate(
            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,
            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant,
            likelihood=likelihood, evidence_strength=strength,
            impact_potential=_impact(impact if impact is not None else BUG_FAMILIES[family]["impact"], context, method),
            support=support, contradict=contradict, missing=missing, rule_ids=rules, summary=summary,
        )
        count += 1

    # BOLA / IDOR
    if object_ids or any(field.lower() in OBJECT_MARKERS for field in path_fields + query_fields + body_fields):
        support = [
            {"type": "object_identifier", "source": "endpoint_schema", "weight": 18, "text": f"Object identifier observed: {', '.join((object_ids or path_fields + query_fields)[:5])}"},
            {"type": "object_operation", "source": "endpoint", "weight": 10, "text": f"Object-specific {method} operation is exposed by the client"},
        ]
        if context in SENSITIVE_CONTEXTS:
            support.append({"type": "business_context", "source": "context", "weight": 12, "text": f"Endpoint is associated with {context.replace('_',' ')} data or workflow"})
        if any(token in haystack for token in ("export", "invoice", "order", "profile", "customer", "account")):
            support.append({"type": "sensitive_object", "source": "semantic", "weight": 8, "text": "Endpoint semantics indicate user, account, order or export data"})
        contradict = []
        status = details.get("status_code") or (_loads(details.get("new"), {}).get("status_code") if isinstance(details.get("new"), Mapping) else None)
        if status in {401, 403}:
            contradict.append({"type": "anonymous_boundary", "source": "http", "weight": -5, "text": f"Anonymous access returned {status}; object-level authorization remains untested"})
        emit("broken_object_authorization", "object_boundary", 24, support, contradict,
             ["Expected object ownership or tenant boundary", "Server-side binding between identity and object", "Behavior with a different authorized test object"],
             ["candidate-object-identifier", "candidate-sensitive-object-context"],
             "The endpoint may contain an object-level authorization boundary; the current evidence does not establish unauthorized access.")

    # Function / role authorization
    admin_markers = _contains_any(haystack, ("/admin", "admin/", "backoffice", "staff", "role", "permission", "privilege", "management"))
    if admin_markers:
        support = [
            {"type": "privileged_function", "source": "semantic", "weight": 20, "text": f"Privileged-function markers observed: {', '.join(admin_markers[:5])}"},
        ]
        classification_text = json_dumps(details.get("endpoint_classification") or details.get("diff_summary") or {}).lower()
        if "admin" in classification_text or "authorization" in classification_text:
            support.append({"type": "privileged_classification", "source": "classification", "weight": 14, "text": "Independent endpoint classification indicates an administrative or authorization function"})
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            support.append({"type": "state_change", "source": "method", "weight": 12, "text": f"The operation uses state-changing method {method}"})
        if any(field.lower().replace("_", "") in PRIVILEGED_FIELDS for field in body_fields):
            support.append({"type": "role_property", "source": "schema", "weight": 12, "text": "The client-visible schema includes role or privilege properties"})
        contradict = []
        if auth_hints:
            contradict.append({"type": "auth_hint", "source": "client", "weight": -4, "text": "Authentication hints are present, but server-side role enforcement is unknown"})
        emit("broken_function_authorization", "role_boundary", 22, support, contradict,
             ["Expected role matrix", "Server-side permission enforcement", "Behavior for an authorized lower-privilege test role"],
             ["candidate-privileged-function", "candidate-role-boundary"],
             "A privileged function may depend on role enforcement that is not visible in the collected evidence.")

    # Mass assignment / property-level authorization
    privileged = sorted({field for field in body_fields if field.lower().replace("_", "") in PRIVILEGED_FIELDS} | {token for token in PRIVILEGED_FIELDS if token in _words(haystack)})
    if method in {"POST", "PUT", "PATCH"} and privileged:
        support = [
            {"type": "write_method", "source": "method", "weight": 15, "text": f"Client-visible write operation uses {method}"},
            {"type": "privileged_property", "source": "schema", "weight": 24, "text": f"Privilege-sensitive properties are visible: {', '.join(privileged[:6])}"},
        ]
        if object_ids:
            support.append({"type": "object_update", "source": "endpoint_schema", "weight": 8, "text": "The update is associated with an object identifier"})
        emit("mass_assignment", "privileged_properties", 24, support, [],
             ["Server allow-list of writable fields", "Whether sensitive properties are ignored or rejected", "Expected property-level authorization"],
             ["candidate-write-schema", "candidate-privileged-property"],
             "A client-visible write schema includes privilege-sensitive properties; server-side field allow-listing remains unknown.")

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
            {"type": "server_feature", "source": "semantic", "weight": 12, "text": "Import, preview, proxy, callback or webhook semantics may involve server-side fetching"},
        ]
        contradict = [{"type": "execution_location", "source": "missing", "weight": -8, "text": "The evidence does not establish whether the browser or server performs the request"}]
        emit("ssrf", "remote_fetch", 20, support, contradict,
             ["Whether the server performs the outbound request", "Destination validation and scheme restrictions", "Network egress policy"],
             ["candidate-remote-destination", "candidate-server-fetch"],
             "A remote-destination input may trigger server-side fetching, but execution location and destination controls are unknown.")

    # File handling
    upload_tokens = _contains_any(haystack, ("upload", "attachment", "avatar", "document", "multipart", "filename", "file_name", "contenttype", "content_type", "import"))
    if upload_tokens:
        support = [
            {"type": "file_surface", "source": "semantic", "weight": 17, "text": f"File-handling markers observed: {', '.join(upload_tokens[:6])}"},
            {"type": "client_operation", "source": "endpoint", "weight": 9, "text": "The file operation is visible in a client endpoint or schema"},
        ]
        if method in {"POST", "PUT", "PATCH"}:
            support.append({"type": "write_method", "source": "method", "weight": 8, "text": f"The operation uses upload-capable method {method}"})
        emit("file_upload", "file_validation", 20, support, [],
             ["Allowed file types and size", "Storage and serving behavior", "Server-generated filenames and content disposition"],
             ["candidate-file-surface", "candidate-file-validation"],
             "A file upload or import surface is present; server-side validation and storage behavior are unknown.")
        path_markers = _contains_any(haystack, ("filepath", "file_path", "path", "directory", "folder", "download"))
        if path_markers:
            support2 = support[:2] + [{"type": "path_input", "source": "schema", "weight": 16, "text": f"Path-like input markers observed: {', '.join(path_markers[:5])}"}]
            emit("path_traversal", "path_construction", 18, support2, [],
                 ["Path canonicalization", "Base-directory enforcement", "Whether user input reaches filesystem APIs"],
                 ["candidate-path-input", "candidate-file-path"],
                 "A file-related operation accepts path-like input; filesystem reachability and canonicalization are unknown.")

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
    if "access-control-allow-origin" in headers_text and ("*" in headers_text or "origin" in headers_text):
        support = [
            {"type": "cors_header", "source": "http_headers", "weight": 18, "text": "CORS response-header evidence is present"},
            {"type": "sensitive_context", "source": "context", "weight": 10, "text": f"The endpoint is associated with {context.replace('_',' ')} context"},
        ]
        emit("cors_misconfiguration", "origin_policy", 18, support, [],
             ["Exact allowed-origin value", "Credential behavior", "Whether sensitive response data is readable cross-origin"],
             ["candidate-cors-header", "candidate-sensitive-cors"],
             "CORS headers on a security-relevant endpoint may permit an unintended origin; exact credential and origin behavior require review.")
    if "cache-control" in headers_text and context in SENSITIVE_CONTEXTS and any(token in headers_text for token in ("public", "s-maxage", "max-age")):
        support = [
            {"type": "cache_header", "source": "http_headers", "weight": 18, "text": "Cacheable response directives were observed"},
            {"type": "sensitive_context", "source": "context", "weight": 14, "text": f"The response is associated with {context.replace('_',' ')} context"},
        ]
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
        emit("business_logic", "workflow_invariant", 12, support, [],
             ["Intended workflow and invariants", "Server-side value calculation", "Allowed transition order"],
             ["candidate-business-workflow", "candidate-state-invariant"],
             "The endpoint participates in a business workflow where server-side invariants may be security-relevant.", impact=72)
        race_tokens = [x for x in business_tokens if x in {"redeem", "claim", "transfer", "withdraw", "reserve", "confirm", "refund"}]
        if race_tokens:
            support2 = support + [{"type": "single_use_semantics", "source": "semantic", "weight": 10, "text": f"Potential single-use or balance-changing actions observed: {', '.join(race_tokens)}"}]
            emit("race_condition", "duplicate_operation", 10, support2, [],
                 ["Idempotency key or transaction guard", "Atomic state transition behavior", "Whether the action is intended to be single-use"],
                 ["candidate-single-use-operation", "candidate-idempotency"],
                 "A balance-changing or single-use workflow may require idempotency and atomicity controls; no concurrency test has been performed.", impact=80)

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
            {"type": "dataflow_source", "source": "javascript_dataflow", "weight": 20, "text": f"User-influenced source observed: {source}"},
            {"type": "dataflow_sink", "source": "javascript_sink", "weight": 24, "text": f"Sensitive sink observed in nearby static flow: {sink}"},
        ]
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
        contradict = []
        if assessment == "likely_placeholder":
            contradict.append({"type": "placeholder", "source": "secret_intelligence", "weight": -24, "text": "Context suggests an example, test or placeholder value"})
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
    static_candidates = _static_candidates(db, analysis_id, run_id, target)
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

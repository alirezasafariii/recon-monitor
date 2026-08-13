from __future__ import annotations

import json
import re
import urllib.parse
from collections import defaultdict
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS

RECONSTRUCTION_ENGINE_VERSION = "1.2.0"
RECONSTRUCTION_RULE_VERSION = "2026.08.13.6.27"
EXECUTION_ENGINE_VERSION = "1.3.0"
EXECUTION_RULE_VERSION = "2026.08.13.6.27"

SUCCESS_STATUSES = set(range(200, 300))
DENY_WORDS = {"false", "0", "deny", "denied", "unauthorized", "forbidden", "blocked"}
PRIVILEGED_FIELDS = {
    "role", "roles", "isadmin", "is_admin", "admin", "permissions", "permission",
    "ownerid", "owner_id", "tenantid", "tenant_id", "accounttype", "account_type",
    "verified", "isstaff", "is_staff", "is_superuser", "superuser",
}
AUTH_TERMS = ("login", "signin", "password", "reset", "forgot", "otp", "mfa", "token", "refresh", "session", "oauth", "sso", "saml", "auth")
IDENTITY_FIELDS = {"username", "email", "login", "user", "user_id", "account", "account_id", "phone"}
STACK_TRACE_PATTERNS = (
    re.compile(r"(?im)\btraceback\s*:"),
    re.compile(r"(?im)\btraceback\s*\(most recent call last\)"),
    re.compile(r"(?im)\bfile\s+[\"'][^\"']+[\"']\s*,\s*line\s+\d+"),
    re.compile(r"(?im)(?:^|\n)\s*at\s+[A-Za-z0-9_.$]+\([^\n)]*:\d+\)"),
)
DIAGNOSTIC_PATTERNS = (
    "sensitive diagnostic material",
    "internal diagnostic material",
    "debug diagnostic material",
    "application path",
    "internal stack trace",
    "debug information",
)
REDACTED_SECRET_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_]*(?:secret|token|api[_-]?key|password|passwd)[A-Za-z0-9_]*\b\s*[:=]\s*[\"']<(?:redacted|masked|hidden)>[\"']"
)
TRAVERSAL_RE = re.compile(r"(?i)(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c)|%252e%252e)")
DANGEROUS_UPLOAD_EXTENSIONS = {
    ".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl",
    ".py", ".rb", ".sh", ".bat", ".cmd", ".ps1", ".exe", ".dll", ".svg", ".html", ".htm",
}
DANGEROUS_UPLOAD_MIMES = {
    "application/x-httpd-php", "application/x-php", "application/x-sh", "application/x-executable",
    "text/html", "image/svg+xml",
}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _flatten(value: Any, *, depth: int = 0, max_depth: int = 6) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = defaultdict(list)
    if depth > max_depth:
        return out
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:500]:
            nk = _norm(key)
            out[nk].append(child)
            if isinstance(child, (Mapping, list, tuple)):
                nested = _flatten(child, depth=depth + 1, max_depth=max_depth)
                for nkey, values in nested.items():
                    out[nkey].extend(values)
    elif isinstance(value, (list, tuple)):
        for child in list(value)[:200]:
            if isinstance(child, (Mapping, list, tuple)):
                nested = _flatten(child, depth=depth + 1, max_depth=max_depth)
                for nkey, values in nested.items():
                    out[nkey].extend(values)
    return out


def _status(details: Mapping[str, Any]) -> int:
    flat = _flatten(details)
    for key in ("status_code", "status", "http_status"):
        for raw in flat.get(key, []):
            try:
                value = int(raw)
            except (TypeError, ValueError):
                continue
            if 100 <= value <= 599:
                return value
    return 0


def _body_text(details: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "response_body", "response_text", "body_preview", "response_preview", "snippet",
        "javascript", "js", "source", "source_code", "graphql_query", "error", "error_message",
        "stacktrace", "stack_trace",
    ):
        value = details.get(key)
        if isinstance(value, str):
            parts.append(value[:65536])
        elif isinstance(value, (Mapping, list)):
            try:
                parts.append(json.dumps(value, sort_keys=True, ensure_ascii=False)[:65536])
            except (TypeError, ValueError):
                pass
    return "\n".join(parts)[:65536]


def _contexts(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("context_observations", "observations", "contexts", "behavioral_observations"):
        raw = details.get(key)
        if isinstance(raw, list):
            return [dict(row) for row in raw if isinstance(row, Mapping)][:100]
        if isinstance(raw, Mapping):
            rows: list[dict[str, Any]] = []
            for name, value in list(raw.items())[:100]:
                if isinstance(value, Mapping):
                    row = dict(value)
                    row.setdefault("context", str(name))
                    rows.append(row)
            return rows
    return []


def _schema_fields(endpoint_schema: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    all_fields: set[str] = set()
    auth_hints: set[str] = set()
    for key in ("query_parameters", "body_fields", "path_parameters", "object_identifiers"):
        raw = endpoint_schema.get(key)
        if isinstance(raw, list):
            all_fields.update(_norm(value) for value in raw if str(value).strip())
    raw_auth = endpoint_schema.get("authentication_hints")
    if isinstance(raw_auth, list):
        auth_hints.update(_norm(value) for value in raw_auth if str(value).strip())
    return all_fields, auth_hints


def _mapping(details: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = details.get(key)
        if isinstance(value, Mapping):
            return {_norm(k): v for k, v in value.items()}
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(parsed, Mapping):
                return {_norm(k): v for k, v in parsed.items()}
    return {}


def _allowed(family: str, signal_type: str) -> bool:
    spec = DETECTOR_SPECS[family]
    return signal_type in (spec.identity_signals | spec.condition_signals | spec.blocking_controls)


def _signal(family: str, signal_type: str, source: str, text: str, *, source_group: str, weight: int, basis: str) -> dict[str, Any] | None:
    if not _allowed(family, signal_type):
        return None
    return {
        "type": signal_type,
        "source": source,
        "source_group": source_group,
        "weight": weight,
        "text": text,
        "execution_engine_version": EXECUTION_ENGINE_VERSION,
        "execution_rule_version": EXECUTION_RULE_VERSION,
        "execution_family": family,
        "execution_strategy": DETECTOR_SPECS[family].strategy,
        "execution_basis": basis,
        "execution_passive_only": True,
        "reconstruction_engine_version": RECONSTRUCTION_ENGINE_VERSION,
        "reconstruction_rule_version": RECONSTRUCTION_RULE_VERSION,
    }


def _emit(result: dict[str, dict[str, Any]], family: str, signal_type: str, source: str, text: str, *, source_group: str, weight: int, basis: str, side: str = "support") -> None:
    item = _signal(family, signal_type, source, text, source_group=source_group, weight=weight, basis=basis)
    if item is None:
        return
    packet = result.setdefault(family, {"support": [], "contradict": []})
    key = (signal_type, source_group, text)
    if any((row.get("type"), row.get("source_group"), row.get("text")) == key for row in packet[side]):
        return
    packet[side].append(item)


def _expected_denied(context: Mapping[str, Any]) -> bool:
    flat = _flatten(context)
    for key in ("expected_access", "authorization_expected", "should_allow", "expected_result"):
        for value in flat.get(key, []):
            if str(value).strip().lower() in DENY_WORDS:
                return True
    return False


def _context_observable(context: Mapping[str, Any]) -> tuple[Any, ...]:
    flat = _flatten(context)
    status = 0
    for key in ("status_code", "status", "http_status"):
        for raw in flat.get(key, []):
            try:
                status = int(raw)
                break
            except (TypeError, ValueError):
                pass
        if status:
            break
    text = ""
    for key in ("response_text", "response_body", "body", "message", "error", "error_message"):
        values = flat.get(key, [])
        if values:
            text = str(values[0])[:4096]
            break
    length = None
    for key in ("response_length", "body_length", "content_length"):
        values = flat.get(key, [])
        if values:
            try:
                length = int(values[0])
            except (TypeError, ValueError):
                pass
            break
    timing = None
    for key in ("duration_ms", "elapsed_ms", "response_time_ms"):
        values = flat.get(key, [])
        if values:
            try:
                timing = round(float(values[0]), 1)
            except (TypeError, ValueError):
                pass
            break
    return status, text, length, timing


def _is_auth_surface(endpoint: str, category: str, business_context: str, auth_hints: set[str]) -> bool:
    hay = " ".join((endpoint, category, business_context)).lower()
    return bool(auth_hints) or any(term in hay for term in AUTH_TERMS)


def _auth_denial_context(context: Mapping[str, Any]) -> bool:
    flat = _flatten(context)
    values: list[str] = []
    for key in ("context", "auth_state", "authentication_state", "session_state", "token_state", "credential_state"):
        values.extend(str(value).strip().lower() for value in flat.get(key, []) if str(value).strip())
    hay = " ".join(values)
    auth_state_markers = (
        "unauthenticated", "anonymous", "invalid_session", "expired_session", "missing_session",
        "invalid_token", "expired_token", "missing_token", "invalid_credential", "bad_password",
        "logged_out", "no_session", "no_token", "invalid_auth", "authentication_failed",
    )
    object_scope_markers = ("other_account", "other_object", "other_tenant", "low_privilege", "channel", "room", "resolver")
    if any(marker in hay for marker in object_scope_markers):
        return False
    return any(marker in hay for marker in auth_state_markers)


def _identity_context_class(context: Mapping[str, Any]) -> str:
    flat = _flatten(context)
    values: list[str] = []
    for key in ("context", "identity_state", "account_state", "existence", "user_state", "expected_identity"):
        values.extend(str(value).strip().lower() for value in flat.get(key, []) if str(value).strip())
    hay = " ".join(values)
    absent = ("absent", "nonexistent", "non_existent", "missing_user", "unknown_user", "invalid_user", "does_not_exist")
    present = ("existing", "known_user", "valid_user", "present_user", "account_exists")
    if any(token in hay for token in absent):
        return "absent"
    if any(token in hay for token in present):
        return "present"
    return ""


def _material_identity_difference(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if {_identity_context_class(left), _identity_context_class(right)} != {"present", "absent"}:
        return False
    a = _context_observable(left)
    b = _context_observable(right)
    if a[0] != b[0] and a[0] and b[0]:
        return True
    if a[1] != b[1] and (a[1] or b[1]):
        return True
    if a[2] != b[2] and a[2] is not None and b[2] is not None:
        return True
    if a[3] is not None and b[3] is not None and a[3] > 0 and b[3] > 0:
        slower, faster = max(a[3], b[3]), min(a[3], b[3])
        return (slower - faster) >= 10.0 and (slower / faster) >= 2.0
    return False


def _number(flat: Mapping[str, list[Any]], *keys: str) -> float | None:
    for key in keys:
        for value in flat.get(_norm(key), []):
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


def reconstruct_raw_evidence(
    *,
    target: str,
    endpoint: str,
    method: str,
    endpoint_schema: Mapping[str, Any] | None,
    details: Mapping[str, Any] | None,
    category: str = "",
    business_context: str = "general",
) -> dict[str, dict[str, Any]]:
    """Reconstruct family evidence only from stored target artifacts.

    This layer is deliberately conservative: names, schemas, categories and the
    absence of an observed blocker can create family identity/context, but never
    by themselves create a decisive vulnerability condition.
    """
    del target  # The target name is lineage/context only; it never proves a condition.
    endpoint_schema = dict(endpoint_schema or {})
    details = dict(details or {})
    result: dict[str, dict[str, Any]] = {}
    all_fields, auth_hints = _schema_fields(endpoint_schema)
    text = _body_text(details)
    text_lower = text.lower()
    status = _status(details)
    contexts = _contexts(details)
    method = str(method or "UNKNOWN").upper()
    category_lower = str(category or "").lower()
    business_context = str(business_context or "general").lower()
    surface = " ".join((endpoint.lower(), category_lower, business_context, text_lower[:16000]))

    # Security misconfiguration: generic, directly observed stack traces.
    if text and any(pattern.search(text) for pattern in STACK_TRACE_PATTERNS):
        _emit(result, "security_misconfiguration", "debug_surface", "raw_response", "Stored target response contains stack-trace/debug structure.", source_group="configuration_surface", weight=16, basis="raw_stack_structure")
        _emit(result, "security_misconfiguration", "stack_trace_exposed", "raw_response", "Stored target response directly exposes a stack trace or exception frame.", source_group="configuration_behavior", weight=32, basis="raw_stack_structure")

    # Information disclosure: public response plus concrete sensitive diagnostic material.
    diagnostic_material = any(marker in text_lower for marker in DIAGNOSTIC_PATTERNS) or any(pattern.search(text) for pattern in STACK_TRACE_PATTERNS)
    if diagnostic_material:
        _emit(result, "information_disclosure", "debug_information", "raw_response", "Stored response contains concrete diagnostic/internal material.", source_group="sensitive_material", weight=18, basis="raw_diagnostic_material")
        if status in SUCCESS_STATUSES and not auth_hints:
            _emit(result, "information_disclosure", "public_observation", "http_response", "Sensitive diagnostic/internal material was observed in a successful response with no stored authentication requirement.", source_group="exposure_context", weight=28, basis="public_sensitive_response")

    # Secret exposure: a redacted assignment proves only a credential-shaped surface,
    # never entropy or a usable secret condition.
    if REDACTED_SECRET_RE.search(text):
        _emit(result, "secret_exposure", "secret_pattern", "raw_client_artifact", "Stored client/source artifact contains a redacted credential-shaped assignment.", source_group="secret_pattern", weight=18, basis="redacted_secret_shape")
        _emit(result, "secret_exposure", "production_javascript", "raw_client_artifact", "Credential-shaped assignment occurs in stored client/source material.", source_group="client_context", weight=10, basis="redacted_secret_shape")

    # Authentication/session: an explicit expected-deny context that succeeds is a
    # stored boundary regression; route names alone are never enough.
    if _is_auth_surface(endpoint, category_lower, business_context, auth_hints):
        _emit(result, "authentication_session", "authentication_surface", "endpoint_semantic", "Authentication/session lifecycle surface is present.", source_group="authentication_surface", weight=14, basis="raw_auth_surface")
        if any(_expected_denied(row) and _auth_denial_context(row) and _context_observable(row)[0] in SUCCESS_STATUSES for row in contexts):
            _emit(result, "authentication_session", "authentication_boundary_regression", "stored_context", "A stored authentication/session lifecycle context expected to be denied received a successful response.", source_group="authentication_behavior", weight=34, basis="auth_lifecycle_expected_deny_success")

    # Account enumeration requires opposite identity-existence contexts plus a material observable differential.
    if (all_fields & IDENTITY_FIELDS) and any(term in surface for term in ("login", "signin", "forgot", "reset", "recover", "lookup", "username", "email")):
        controlled_pair = any(
            _material_identity_difference(left, right)
            for index, left in enumerate(contexts)
            for right in contexts[index + 1:]
        )
        if controlled_pair:
            _emit(result, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity input is observed across controlled present-versus-absent identity contexts.", source_group="identity_lookup", weight=15, basis="controlled_identity_surface")
            _emit(result, "account_enumeration", "response_difference", "stored_context", "Controlled present-versus-absent identity contexts have a material status/body/length/timing differential.", source_group="identity_differential", weight=34, basis="material_identity_differential")

    # Mass assignment requires the privileged property to be visible in both the
    # stored request and a successful response or post-write state.
    privileged = all_fields & {_norm(value) for value in PRIVILEGED_FIELDS}
    if method in {"POST", "PUT", "PATCH"} and privileged:
        request = _mapping(details, "request_json", "request_body", "request_payload", "submitted_body", "input")
        response = _mapping(details, "response_json", "response_body", "resource_after", "persisted_state", "stored_state", "after")
        before = _mapping(details, "resource_before", "previous_state", "before")
        for field in sorted(privileged):
            if field not in request or field not in response:
                continue
            same = response.get(field) == request.get(field)
            changed = field in before and before.get(field) != response.get(field)
            if same and status in SUCCESS_STATUSES and (changed or field not in before):
                _emit(result, "mass_assignment", "privileged_property_accepted", "stored_write_observation", "Stored successful write shows a privilege-sensitive request property reflected/applied in the resulting resource state.", source_group="property_write_behavior", weight=36, basis="request_response_property_application")
                break

    # SSRF: reconstruct only when an outbound request is itself stored, not from a URL field alone.
    flat = _flatten(details)
    outbound_values: list[str] = []
    for key in ("outbound_request_url", "backend_request_url", "server_request_url", "requested_upstream_url", "outbound_url"):
        outbound_values.extend(str(value) for value in flat.get(key, []) if isinstance(value, str))
    if outbound_values and any(field in all_fields for field in ("url", "uri", "destination", "callback", "webhook", "remote_url", "fetch_url")):
        if any(urllib.parse.urlsplit(value).scheme in {"http", "https"} for value in outbound_values):
            _emit(result, "ssrf", "server_fetch_observed", "stored_outbound_request", "Stored target artifacts record a backend HTTP(S) request to a client-influenced destination.", source_group="server_fetch", weight=36, basis="stored_outbound_request")

    # File upload: a dangerous file type must be present in the stored request and a
    # successful acceptance/storage/processing observation must exist.
    request = _mapping(details, "request_json", "request_body", "request_payload", "multipart_fields", "upload")
    request_flat = _flatten(request)
    filenames = [str(v) for key in ("filename", "file_name", "name") for v in request_flat.get(key, []) if isinstance(v, str)]
    mimes = [str(v).lower() for key in ("content_type", "mime", "mime_type") for v in request_flat.get(key, []) if isinstance(v, str)]
    dangerous_name = any(any(name.lower().endswith(ext) for ext in DANGEROUS_UPLOAD_EXTENSIONS) for name in filenames)
    dangerous_mime = any(value.split(";", 1)[0].strip() in DANGEROUS_UPLOAD_MIMES for value in mimes)
    accepted_marker = any(key in flat for key in ("stored_path", "uploaded_file_url", "attachment_id", "file_id", "processed_file"))
    if (dangerous_name or dangerous_mime) and status in SUCCESS_STATUSES and accepted_marker:
        _emit(result, "file_upload", "dangerous_type_accepted", "stored_upload_observation", "Stored upload artifacts show a dangerous file type accepted and stored/processed successfully.", source_group="upload_behavior", weight=36, basis="dangerous_type_success")

    # Path traversal: require traversal syntax plus a stored resolution outside the base path.
    requested_paths = [str(v) for key in ("requested_path", "file_path", "path", "filename") for v in flat.get(key, []) if isinstance(v, str)]
    resolved_paths = [str(v) for key in ("resolved_path", "real_path", "filesystem_path") for v in flat.get(key, []) if isinstance(v, str)]
    base_paths = [str(v) for key in ("base_path", "root_path", "allowed_root", "storage_root") for v in flat.get(key, []) if isinstance(v, str)]
    if requested_paths and any(TRAVERSAL_RE.search(value) for value in requested_paths) and resolved_paths and base_paths and status in SUCCESS_STATUSES:
        escaped = any(not resolved.startswith(base.rstrip("/\\") + "/") and resolved != base for resolved in resolved_paths for base in base_paths)
        if escaped:
            _emit(result, "path_traversal", "path_escape_observed", "stored_path_resolution", "Stored path-resolution evidence shows traversal input resolving outside the configured base path.", source_group="filesystem_behavior", weight=38, basis="stored_path_escape")

    # Command injection: passive static data-flow into a process execution primitive.
    # No command is executed; this only records direct client-input-to-sink reachability in stored source.
    if all_fields and text:
        for match in re.finditer(r"(?i)(?:child_process\.)?(?:exec|execsync|system)\s*\(\s*([A-Za-z_$][A-Za-z0-9_.$]*)", text):
            variable = _norm(match.group(1).split(".")[-1])
            client_related = (
                variable in {"userinput", "user_input", "input", "payload", "requestinput", "request_input", "cmd", "command"}
                or any(field and (field == variable or field in variable or variable in field) for field in all_fields)
            )
            if client_related:
                _emit(result, "command_injection", "process_execution_surface", "raw_source", "Stored source contains a process execution primitive.", source_group="execution_surface", weight=18, basis="stored_process_sink")
                _emit(result, "command_injection", "input_parameter", "endpoint_schema", "Client-controlled input exists on the process execution surface.", source_group="input_surface", weight=10, basis="stored_process_sink")
                _emit(result, "command_injection", "process_execution_reached", "raw_source_dataflow", "Stored source directly passes a client-related input variable into a process execution primitive.", source_group="command_behavior", weight=38, basis="passive_direct_input_to_process_sink")
                break

    # Race condition: require explicit stored evidence that multiple concurrent attempts both succeeded.
    concurrency_surface = any(token in surface for token in ("concurrent", "parallel", "simultaneous", "race", "single-use", "single use", "redeem", "claim", "transfer", "refund"))
    duplicate_success = bool(re.search(r"(?is)\b(?:two|both|multiple|duplicate)\b.{0,120}\b(?:concurrent|parallel|simultaneous)\b.{0,160}\b(?:success|succeeded|accepted)\b", text)) or bool(re.search(r"(?is)\b(?:concurrent|parallel|simultaneous)\b.{0,160}\b(?:both|two|multiple)\b.{0,120}\b(?:success|succeeded|accepted)\b", text))
    if concurrency_surface and method in {"POST", "PUT", "PATCH", "DELETE"} and status in SUCCESS_STATUSES and duplicate_success:
        _emit(result, "race_condition", "state_change", "endpoint_contract", "Stored operation is state-changing.", source_group="state_change", weight=12, basis="concurrent_state_change")
        _emit(result, "race_condition", "single_use_semantics", "endpoint_semantic", "Stored operation has single-use or duplicate-sensitive business semantics.", source_group="single_use", weight=14, basis="concurrent_state_change")
        _emit(result, "race_condition", "duplicate_effect_observed", "raw_response", "Stored artifact explicitly records multiple concurrent attempts both succeeding on a duplicate-sensitive operation.", source_group="concurrency_behavior", weight=38, basis="stored_duplicate_concurrent_success")

    # Resource consumption: require successful high amplification plus a material stored cost signal.
    requested_amplifier = _number(flat, "requested_limit", "requested_count", "requested_size", "batch_size", "page_size", "limit")
    duration_ms = _number(flat, "duration_ms", "elapsed_ms", "response_time_ms")
    response_length = _number(flat, "response_length", "body_length", "content_length")
    high_request = requested_amplifier is not None and requested_amplifier >= 10000
    high_latency = duration_ms is not None and duration_ms >= 5000
    high_output = response_length is not None and response_length >= 1000000
    if status in SUCCESS_STATUSES and high_request and (high_latency or high_output):
        _emit(result, "unrestricted_resource_consumption", "resource_control_parameter", "endpoint_schema", "Stored request exposes a high-amplification resource control parameter.", source_group="resource_surface", weight=16, basis="stored_resource_amplifier")
        _emit(result, "unrestricted_resource_consumption", "resource_exhaustion_differential", "stored_resource_observation", "A successful high-amplification request is paired with a material stored latency or response-size cost signal.", source_group="resource_behavior", weight=36, basis="high_amplification_material_cost")

    # Routing-only family identity from semantically strong stored raw context. These
    # never create a final vulnerability condition.
    if any(token in category_lower for token in ("command", "shell", "process execution", "exec")):
        _emit(result, "command_injection", "process_execution_surface", "category_semantic", "Stored category identifies a process/shell execution surface.", source_group="execution_surface", weight=16, basis="routing_semantic")
        if all_fields:
            _emit(result, "command_injection", "input_parameter", "endpoint_schema", "Client-controlled input exists on the process-execution surface.", source_group="input_surface", weight=10, basis="routing_semantic")
    if any(token in category_lower for token in ("template", "ssti", "server-side render", "server side render", "server render", "template render")):
        _emit(result, "server_side_template_injection", "template_render_surface", "category_semantic", "Stored category identifies a server-side rendering/template surface.", source_group="render_surface", weight=16, basis="routing_semantic")
        if all_fields:
            _emit(result, "server_side_template_injection", "template_input", "endpoint_schema", "Client-controlled input exists on the rendering/template surface.", source_group="template_input", weight=10, basis="routing_semantic")
    if any(token in category_lower for token in ("debug", "deployment configuration", "stack trace", "misconfiguration")):
        _emit(result, "security_misconfiguration", "debug_surface", "category_semantic", "Stored category identifies a debug/configuration review surface.", source_group="configuration_surface", weight=10, basis="routing_semantic")
    if any(token in category_lower for token in ("diagnostic", "information disclosure", "sensitive response", "internal data")):
        _emit(result, "information_disclosure", "debug_information", "category_semantic", "Stored category identifies a diagnostic/sensitive-response surface.", source_group="sensitive_material", weight=10, basis="routing_semantic")

    return {family: packet for family, packet in result.items() if packet["support"] or packet["contradict"]}

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_condition_reconstruction import reconstruct_raw_evidence

EXECUTION_ENGINE_VERSION = "1.2.0"
EXECUTION_RULE_VERSION = "2026.08.12.6.14"
MAX_TEXT_CHARS = 65536
SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {401, 403, 404}
EXTERNAL_KNOWLEDGE_MARKERS = {
    "owasp", "wstg", "cwe", "mitre", "writeup", "securitylab.github.com",
    "knowledge", "standards", "capec",
}
SENSITIVE_FIELD_WORDS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key",
    "apikey", "authorization", "cookie", "session", "credit_card", "card_number", "cvv",
    "ssn", "national_id", "iban", "balance", "email", "phone", "address", "role", "permission",
}
PRIVILEGED_FIELD_WORDS = {
    "role", "roles", "isadmin", "admin", "permissions", "permission", "ownerid",
    "tenantid", "accounttype", "verified", "isstaff",
}
RESOURCE_FIELDS = {
    "limit", "pagesize", "page_size", "size", "count", "batch", "batchsize", "batch_size",
    "first", "take", "perpage", "per_page", "maxresults", "max_results", "filesize", "file_size",
}
URL_FIELDS = {"url", "uri", "endpoint", "destination", "callback", "webhook", "remote_url", "fetch_url"}
PATH_FIELDS = {"path", "filepath", "file_path", "filename", "file_name", "directory", "dir", "folder", "storage_path"}
FILE_FIELDS = {"file", "files", "filename", "file_name", "attachment", "attachments", "avatar", "document", "documents", "upload", "upload_file"}
IDENTITY_FIELDS = {"username", "email", "login", "user", "user_id", "account", "account_id", "phone"}
SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}\b")),
    ("api_key_assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*['\"]([A-Za-z0-9._~+/-]{16,})['\"]")),
)
SQL_ERROR_PATTERNS = (
    "sql syntax", "syntax error at or near", "unterminated quoted string",
    "mysql", "postgresql", "sqlite", "ora-", "odbc sql", "sqlstate",
)
NOSQL_ERROR_PATTERNS = (
    "mongoerror", "mongodb error", "mongodb exception", "unknown operator",
    "badvalue", "bson error", "bsonexception", "failed to parse query",
    "failed to parse filter", "invalid mongodb operator",
)
LDAP_ERROR_PATTERNS = ("ldap", "invalid dn syntax", "bad search filter", "filter error", "directory service")
TEMPLATE_ERROR_PATTERNS = (
    "jinja2", "templatesyntaxerror", "twig", "freemarker", "velocity", "template error",
    "undefinederror", "expression language",
)
STACK_TRACE_PATTERNS = (
    "traceback (most recent call last)", "stack trace", "exception in thread",
    " at org.", " at com.", "fatal error:", "uncaught exception",
)
DIRECTORY_LISTING_PATTERNS = ("index of /", "directory listing for", "<title>index of")
DOM_SOURCES = ("location.hash", "location.search", "document.url", "document.referrer", "postmessage", "event.data")
DOM_SINKS = ("innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "eval(", "new function(", "settimeout(")
SERVER_FETCH_MARKERS = (
    "requests.get(", "requests.post(", "urllib.request", "httpclient", "http.get(",
    "http.request(", "fetch_remote", "server_fetch", "backend_fetch",
)
PROCESS_MARKERS = ("subprocess.", "os.system(", "child_process.", "exec(", "spawn(", "shell=true")
TEMPLATE_MARKERS = ("render_template", "template(", "jinja", "twig", "freemarker", "velocity", "handlebars")
LDAP_MARKERS = ("ldap", "directory search", "distinguishedname", "dn=", "ou=", "memberof", "search_filter")
GRAPHQL_MARKERS = ("graphql", "query ", "mutation ", "__typename", "__schema")
WEBSOCKET_MARKERS = ("ws://", "wss://", "websocket", "subscribe", "subscription")
THIRD_PARTY_MARKERS = ("third-party", "third_party", "integration", "upstream", "vendor", "partner api", "external api", "webhook")
BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "invite", "create account", "redeem", "claim", "coupon", "promo", "comment", "post", "message", "review")
SINGLE_USE_MARKERS = ("redeem", "claim", "transfer", "withdraw", "reserve", "confirm", "refund")
AUTH_MARKERS = ("login", "signin", "password", "reset", "forgot", "otp", "mfa", "token", "refresh", "session", "oauth", "sso", "saml")
VERSION_MARKERS = ("legacy", "deprecated", "staging", "stage", "beta", "alpha", "/dev/", "/test/")
CONFIG_SURFACE_MARKERS = ("debug", "stacktrace", "stack_trace", "traceback", "swagger", "actuator", "phpinfo", "directory listing", "server-status", "options method", "http://")
FILE_OPERATION_MARKERS = ("/download", "/upload", "/import", "/archive", "/extract", "/unpack", "/files", "/attachment")
PATH_OPERATION_MARKERS = ("/download", "/archive", "/extract", "/unpack", "/files")
CLI_EXECUTION_MARKERS = ("npm ", "npx ", "node ", "python ", "python3 ", "bash ", "sh ", "powershell ", "cmd.exe ", "git ", "curl ", "wget ", "jsii-diff ")


@dataclass(frozen=True)
class ExecutionProfile:
    family: str
    strategy: str
    condition_signals: frozenset[str]
    blocking_controls: frozenset[str]
    identity_signals: frozenset[str]


EXECUTION_PROFILES = {
    family: ExecutionProfile(
        family=family,
        strategy=spec.strategy,
        condition_signals=spec.condition_signals,
        blocking_controls=spec.blocking_controls,
        identity_signals=spec.identity_signals,
    )
    for family, spec in DETECTOR_SPECS.items()
}


def validate_execution_profiles() -> list[str]:
    errors: list[str] = []
    if set(EXECUTION_PROFILES) != set(DETECTOR_SPECS):
        errors.append("execution coverage must exactly match physical detector coverage")
    for family, profile in EXECUTION_PROFILES.items():
        if not profile.strategy:
            errors.append(f"{family}:missing_strategy")
        if not profile.condition_signals:
            errors.append(f"{family}:missing_condition_signals")
    return errors


_PROFILE_ERRORS = validate_execution_profiles()
if _PROFILE_ERRORS:
    raise RuntimeError("Detector execution registry invalid: " + "; ".join(_PROFILE_ERRORS))


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _flatten(value: Any, *, depth: int = 0, max_depth: int = 5) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = defaultdict(list)
    if depth > max_depth:
        return out
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:500]:
            nk = _norm(str(key))
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


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, (int, float)) and value == 1:
        return True
    return str(value or "").strip().lower() in {"true", "yes", "1", "observed", "present", "accepted", "enabled"}


def _flag(flat: Mapping[str, list[Any]], *names: str) -> bool:
    return any(_truthy(value) for name in names for value in flat.get(_norm(name), []))


def _status(details: Mapping[str, Any]) -> int:
    flat = _flatten(details)
    for key in ("status_code", "status", "http_status"):
        for value in flat.get(key, []):
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if 100 <= number <= 599:
                return number
    return 0


def _headers(details: Mapping[str, Any], *, request: bool) -> dict[str, str]:
    keys = ("request_headers", "request_header", "headers_in") if request else ("response_headers", "response_header", "headers_out", "headers")
    candidates = []
    for key in keys:
        value = details.get(key)
        if value is not None:
            candidates.append(_loads(value, value))
    out: dict[str, str] = {}
    for candidate in candidates:
        if isinstance(candidate, Mapping):
            for key, value in candidate.items():
                out[str(key).strip().lower()] = str(value).strip()
        elif isinstance(candidate, list):
            for row in candidate:
                if isinstance(row, Mapping):
                    name = str(row.get("name") or row.get("key") or "").strip().lower()
                    value = str(row.get("value") or "").strip()
                    if name:
                        out[name] = value
    return out


def _body_text(details: Mapping[str, Any]) -> str:
    parts: list[str] = []
    keys = (
        "response_body", "response_text", "body", "body_preview", "response_preview",
        "snippet", "javascript", "js", "source", "source_code", "graphql_query",
        "error", "error_message", "stacktrace", "stack_trace",
    )
    for key in keys:
        value = details.get(key)
        if isinstance(value, str):
            parts.append(value[:MAX_TEXT_CHARS])
        elif isinstance(value, (Mapping, list)):
            try:
                parts.append(json.dumps(value, ensure_ascii=False, sort_keys=True)[:MAX_TEXT_CHARS])
            except (TypeError, ValueError):
                pass
    return "\n".join(parts)[:MAX_TEXT_CHARS]


def _contexts(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("context_observations", "observations", "contexts", "behavioral_observations"):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, list):
            return [dict(x) for x in decoded if isinstance(x, Mapping)][:100]
        if isinstance(decoded, Mapping):
            result: list[dict[str, Any]] = []
            for name, value in list(decoded.items())[:100]:
                if isinstance(value, Mapping):
                    row = dict(value)
                    row.setdefault("context", str(name))
                    result.append(row)
            return result
    return []


def _field_sets(endpoint_schema: Mapping[str, Any]) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    def values(key: str) -> set[str]:
        raw = endpoint_schema.get(key) or []
        if not isinstance(raw, list):
            return set()
        return {_norm(str(x)) for x in raw if str(x).strip()}
    return (
        values("query_parameters"), values("body_fields"), values("path_parameters"),
        values("object_identifiers"), values("authentication_hints"),
    )


def _external_knowledge(item: Mapping[str, Any]) -> bool:
    hay = " ".join(str(item.get(key) or "") for key in ("source", "source_group", "provenance", "url", "ref")).lower()
    return any(marker in hay for marker in EXTERNAL_KNOWLEDGE_MARKERS)


def _signal(family: str, signal_type: str, source: str, text: str, *, source_group: str, weight: int, basis: str) -> dict[str, Any]:
    return {
        "type": signal_type,
        "source": source,
        "source_group": source_group,
        "weight": weight,
        "text": text,
        "execution_engine_version": EXECUTION_ENGINE_VERSION,
        "execution_rule_version": EXECUTION_RULE_VERSION,
        "execution_family": family,
        "execution_strategy": EXECUTION_PROFILES[family].strategy,
        "execution_basis": basis,
        "execution_passive_only": True,
    }


def _add(packet: dict[str, list[dict[str, Any]]], side: str, item: dict[str, Any]) -> None:
    key = (str(item.get("type") or ""), str(item.get("source_group") or item.get("source") or ""), str(item.get("text") or ""))
    if any((str(existing.get("type") or ""), str(existing.get("source_group") or existing.get("source") or ""), str(existing.get("text") or "")) == key for existing in packet[side]):
        return
    packet[side].append(item)


def _packet_for(result: dict[str, dict[str, Any]], family: str) -> dict[str, Any]:
    if family not in result:
        result[family] = {"support": [], "contradict": [], "rule_ids": execution_rule_ids(family)}
    return result[family]


def execution_rule_ids(family: str) -> list[str]:
    profile = EXECUTION_PROFILES[family]
    return [f"detector-execution:{family}:{EXECUTION_RULE_VERSION}", f"detector-execution-strategy:{profile.strategy}"]


def _typed_evidence(result: dict[str, dict[str, Any]], evidence_for: Iterable[Any], evidence_against: Iterable[Any]) -> None:
    for family, profile in EXECUTION_PROFILES.items():
        packet = _packet_for(result, family)
        allowed_support = profile.identity_signals | profile.condition_signals
        for raw in evidence_for:
            if not isinstance(raw, Mapping) or _external_knowledge(raw):
                continue
            signal = str(raw.get("type") or "")
            if signal not in allowed_support:
                continue
            item = dict(raw)
            item.update({"execution_engine_version": EXECUTION_ENGINE_VERSION, "execution_rule_version": EXECUTION_RULE_VERSION, "execution_family": family, "execution_strategy": profile.strategy, "execution_basis": "typed_stored_target_evidence", "execution_passive_only": True})
            _add(packet, "support", item)
        for raw in evidence_against:
            if not isinstance(raw, Mapping) or _external_knowledge(raw):
                continue
            signal = str(raw.get("type") or "")
            if signal not in profile.blocking_controls:
                continue
            item = dict(raw)
            item.update({"execution_engine_version": EXECUTION_ENGINE_VERSION, "execution_rule_version": EXECUTION_RULE_VERSION, "execution_family": family, "execution_strategy": profile.strategy, "execution_basis": "typed_stored_target_control", "execution_passive_only": True})
            _add(packet, "contradict", item)


def _explicit_contract_flags(result: dict[str, dict[str, Any]], flat: Mapping[str, list[Any]]) -> None:
    for family, profile in EXECUTION_PROFILES.items():
        packet = _packet_for(result, family)
        for signal in sorted(profile.condition_signals):
            if _flag(flat, signal):
                _add(packet, "support", _signal(family, signal, "stored_behavior", f"Stored raw target artifacts explicitly record {signal.replace('_', ' ')}.", source_group=f"{family}_behavior", weight=30, basis="explicit_target_flag"))
        for signal in sorted(profile.blocking_controls):
            if _flag(flat, signal):
                _add(packet, "contradict", _signal(family, signal, "stored_control", f"Stored raw target artifacts explicitly record control {signal.replace('_', ' ')}.", source_group=f"{family}_control", weight=-28, basis="explicit_target_control"))


def _add_identity(packet: dict[str, Any], family: str, signal_type: str, source: str, text: str, group: str, weight: int = 12) -> None:
    _add(packet, "support", _signal(family, signal_type, source, text, source_group=group, weight=weight, basis="passive_raw_structure"))


def _passive_raw_heuristics(result: dict[str, dict[str, Any]], *, target: str, endpoint: str, method: str, endpoint_schema: Mapping[str, Any], details: Mapping[str, Any], category: str, business_context: str) -> None:
    query_fields, body_fields, path_fields, object_ids, auth_hints = _field_sets(endpoint_schema)
    all_fields = query_fields | body_fields | path_fields
    text = _body_text(details)
    text_lower = text.lower()
    surface_text = " ".join((endpoint, category, business_context, text[:24000])).lower()
    flat = _flatten(details)
    status = _status(details)
    response_headers = _headers(details, request=False)
    request_headers = _headers(details, request=True)
    target_host = urllib.parse.urlsplit(target if "://" in target else f"https://{target}").hostname or ""
    endpoint_host = urllib.parse.urlsplit(endpoint if "://" in endpoint else f"https://{target_host}{endpoint if endpoint.startswith('/') else '/' + endpoint}").hostname or target_host
    method = str(method or "UNKNOWN").upper()

    if object_ids or any(field.endswith("_id") or field == "id" for field in all_fields):
        packet = _packet_for(result, "broken_object_authorization")
        _add_identity(packet, "broken_object_authorization", "object_identifier", "endpoint_schema", "Client-controlled object identifier is present in the endpoint contract.", "object_reference", 14)
        _add_identity(packet, "broken_object_authorization", "object_operation", "endpoint_contract", f"{method} operates on the referenced object surface.", "object_operation", 9)
        for context in _contexts(details):
            cflat = _flatten(context); cstatus = _status(context)
            expected_false = any(str(v).strip().lower() in {"false", "0", "deny", "denied", "unauthorized"} for key in ("expected_access", "authorization_expected", "should_allow") for v in cflat.get(key, []))
            if expected_false and cstatus in SUCCESS_STATUSES:
                _add(packet, "support", _signal("broken_object_authorization", "unauthorized_object_response", "stored_context", "A stored context expected to be denied received a successful object response.", source_group="authorization_context", weight=34, basis="context_expectation_vs_response"))
            elif expected_false and cstatus in DENY_STATUSES:
                _add(packet, "contradict", _signal("broken_object_authorization", "cross_context_denied", "stored_context", "A stored unauthorized object context was denied.", source_group="authorization_context", weight=-26, basis="context_expectation_vs_response"))

    admin = any(token in surface_text for token in ("/admin", "backoffice", "permission", "privilege", "management", "staff"))
    if admin:
        packet = _packet_for(result, "broken_function_authorization")
        _add_identity(packet, "broken_function_authorization", "privileged_function", "endpoint_semantic", "Privileged or administrative function semantics are present.", "function_surface", 16)
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            _add_identity(packet, "broken_function_authorization", "state_change", "endpoint_contract", f"Privileged operation uses state-changing method {method}.", "operation_surface", 10)
        for context in _contexts(details):
            cflat = _flatten(context); cstatus = _status(context)
            expected_false = any(str(v).strip().lower() in {"false", "0", "deny", "denied", "unauthorized"} for key in ("expected_access", "authorization_expected", "should_allow") for v in cflat.get(key, []))
            role = " ".join(str(v) for key in ("role", "auth_state", "context") for v in cflat.get(key, [])).lower()
            if expected_false and cstatus in SUCCESS_STATUSES:
                _add(packet, "support", _signal("broken_function_authorization", "unauthorized_function_response", "stored_context", "Stored lower-privilege/unauthorized context successfully executed the privileged function.", source_group="role_behavior", weight=34, basis="context_expectation_vs_response"))
                if any(token in role for token in ("low", "user", "member", "viewer", "anonymous", "unpriv")):
                    _add(packet, "support", _signal("broken_function_authorization", "lower_privilege_success", "stored_context", "Stored lower-privilege context successfully executed the privileged function.", source_group="role_behavior", weight=32, basis="role_context_success"))
            elif expected_false and cstatus in DENY_STATUSES:
                _add(packet, "contradict", _signal("broken_function_authorization", "lower_privilege_denied", "stored_context", "Stored lower-privilege context was denied the privileged function.", source_group="role_behavior", weight=-28, basis="role_context_denial"))

    privileged_fields = {field for field in body_fields if field.replace("_", "") in PRIVILEGED_FIELD_WORDS or field in PRIVILEGED_FIELD_WORDS}
    if method in {"POST", "PUT", "PATCH"} and privileged_fields:
        packet = _packet_for(result, "mass_assignment")
        _add_identity(packet, "mass_assignment", "write_method", "endpoint_contract", f"Writable endpoint uses {method}.", "write_surface", 12)
        _add_identity(packet, "mass_assignment", "privileged_property", "endpoint_schema", "Writable request contract contains privilege-sensitive properties.", "property_surface", 18)

    if any(token in surface_text for token in AUTH_MARKERS) or auth_hints:
        packet = _packet_for(result, "authentication_session")
        _add_identity(packet, "authentication_session", "authentication_surface", "endpoint_semantic", "Authentication/session lifecycle surface is present.", "authentication_surface", 14)
    context_labels = " ".join(str(row.get("context") or "") for row in _contexts(details)).lower()
    enum_present = any(token in context_labels for token in ("existing", "known_user", "valid_user", "present_user"))
    enum_absent = any(token in context_labels for token in ("absent", "nonexistent", "non_existent", "missing_user", "unknown_user", "invalid_user"))
    explicit_enum_surface = any(token in surface_text for token in ("forgot", "reset", "recover", "lookup", "enumerat", "account exists", "username availability", "email availability"))
    if (all_fields & IDENTITY_FIELDS) and (explicit_enum_surface or (enum_present and enum_absent)):
        packet = _packet_for(result, "account_enumeration")
        _add_identity(packet, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity field participates in a controlled existence/lookup surface.", "identity_lookup", 15)

    if any(source in text_lower for source in DOM_SOURCES) and any(sink in text_lower for sink in DOM_SINKS):
        packet = _packet_for(result, "dom_xss")
        _add_identity(packet, "dom_xss", "source_sink", "raw_javascript", "Stored JavaScript contains both a browser-controlled source and an executable/HTML sink.", "static_flow", 18)
        _add_identity(packet, "dom_xss", "dangerous_sink", "raw_javascript", "Stored JavaScript contains a dangerous DOM/JavaScript sink.", "static_sink", 18)
    if ("addEventListener" in text or "addeventlistener" in text_lower) and "message" in text_lower:
        packet = _packet_for(result, "postmessage_trust")
        _add_identity(packet, "postmessage_trust", "postmessage_handler", "raw_javascript", "Stored JavaScript registers a message event handler.", "message_source", 18)
        if any(sink in text_lower for sink in DOM_SINKS) or any(token in text_lower for token in ("location.href", "location.assign", "fetch(", "postmessage(")):
            _add_identity(packet, "postmessage_trust", "message_sink", "raw_javascript", "Message-controlled data is adjacent to a sensitive browser action.", "message_sink", 14)

    redirect_fields = {field for field in all_fields if field in {"redirect", "redirect_uri", "return", "return_url", "next", "next_url", "continue", "callback", "callback_url", "destination"}}
    location = response_headers.get("location", "")
    if redirect_fields or any(token in surface_text for token in ("redirect", "return_url", "next_url", "location.href", "location.assign", "location.replace")):
        packet = _packet_for(result, "open_redirect")
        _add_identity(packet, "open_redirect", "redirect_parameter", "endpoint_schema", "User-influenced redirect/navigation parameter is present.", "navigation_input", 16)
        if location or any(token in text_lower for token in ("location.href", "location.assign", "location.replace")):
            _add_identity(packet, "open_redirect", "navigation_sink", "raw_navigation", "Stored raw artifacts contain a redirect/navigation sink.", "navigation_sink", 16)
        if location:
            parsed_location = urllib.parse.urlsplit(location)
            if parsed_location.scheme in {"http", "https"} and parsed_location.hostname and endpoint_host and parsed_location.hostname.lower() != endpoint_host.lower():
                _add(packet, "support", _signal("open_redirect", "external_destination", "http_headers", "Stored redirect response points to an external host.", source_group="redirect_behavior", weight=28, basis="response_location_external_host"))

    url_fields = all_fields & URL_FIELDS
    if url_fields or any(token in surface_text for token in ("webhook", "fetch_url", "import_url", "preview_url", "proxy_url", "remote_url")):
        packet = _packet_for(result, "ssrf")
        _add_identity(packet, "ssrf", "remote_destination", "endpoint_schema", "Client-visible remote destination input is present.", "remote_destination", 17)
    if any(token in text_lower for token in SERVER_FETCH_MARKERS) and url_fields:
        packet = _packet_for(result, "ssrf")
        _add_identity(packet, "ssrf", "server_request_function", "raw_source", "Stored source artifact contains a server-request primitive near a remote-destination surface.", "server_fetch", 20)

    if any(token in surface_text for token in THIRD_PARTY_MARKERS):
        packet = _packet_for(result, "unsafe_api_consumption")
        _add_identity(packet, "unsafe_api_consumption", "third_party_integration", "endpoint_semantic", "Third-party/upstream integration semantics are present.", "upstream_boundary", 16)
        upstream_urls = [str(v) for key in ("upstream_url", "provider_url", "external_api_url") for v in flat.get(key, []) if isinstance(v, str)]
        if any(url.lower().startswith("http://") for url in upstream_urls):
            _add(packet, "support", _signal("unsafe_api_consumption", "upstream_tls_missing", "stored_configuration", "Stored upstream service URL uses cleartext HTTP.", source_group="upstream_transport", weight=30, basis="explicit_upstream_url_scheme"))

    # Analysis 6.18 recall-preserving surface signals. These clues intentionally
    # remain surface-only: they keep hidden hypotheses alive without satisfying
    # file/path admission identity or vulnerability-condition requirements.
    if flat.get("content_type") or flat.get("contenttype"):
        packet = _packet_for(result, "file_upload")
        _add(
            packet,
            "support",
            _signal(
                "file_upload",
                "content_type_field",
                "raw_metadata",
                "Stored metadata contains a Content-Type field; this is only a file-handling clue.",
                source_group="file_surface_metadata",
                weight=3,
                basis="passive_raw_surface_metadata",
            ),
        )
    raw_path_metadata = sorted(set(flat) & PATH_FIELDS)
    if raw_path_metadata:
        packet = _packet_for(result, "path_traversal")
        _add(
            packet,
            "support",
            _signal(
                "path_traversal",
                "path_surface",
                "raw_metadata",
                "Stored metadata contains path/file terminology without structured filesystem reachability.",
                source_group="path_surface_metadata",
                weight=3,
                basis="passive_raw_surface_metadata",
            ),
        )

    if (all_fields & FILE_FIELDS) or "multipart/form-data" in surface_text or any(token in endpoint.lower() for token in ("/upload", "/attachment", "/import")):
        packet = _packet_for(result, "file_upload")
        _add_identity(packet, "file_upload", "file_input", "endpoint_schema", "Structured file input or multipart upload contract is present.", "file_input", 18)
        if method in {"POST", "PUT", "PATCH"}:
            signal = "import_operation" if "/import" in endpoint.lower() else "upload_operation"
            _add_identity(packet, "file_upload", signal, "endpoint_contract", f"{method} is tied to a file upload/import surface.", "file_operation", 18)
    if (all_fields & PATH_FIELDS) or any(token in endpoint.lower() for token in PATH_OPERATION_MARKERS):
        packet = _packet_for(result, "path_traversal")
        signal = "filename_field" if (all_fields & {"filename", "file_name"}) else "path_parameter"
        _add_identity(packet, "path_traversal", signal, "endpoint_schema", "Client-controlled path/filename input is present.", "path_input", 18)
        if any(token in endpoint.lower() for token in PATH_OPERATION_MARKERS):
            _add_identity(packet, "path_traversal", "file_operation", "endpoint_contract", "Endpoint semantics identify a file-related operation.", "file_operation", 14)

    if any(marker in surface_text for marker in GRAPHQL_MARKERS) or endpoint.lower().rstrip("/").endswith("graphql"):
        identifiers = {field for field in all_fields if field == "id" or field.endswith("_id")}
        packet = _packet_for(result, "graphql_authorization")
        _add_identity(packet, "graphql_authorization", "graphql_operation", "raw_graphql", "GraphQL operation surface is present.", "graphql_operation", 16)
        if identifiers:
            _add_identity(packet, "graphql_authorization", "graphql_identifier", "endpoint_schema", "GraphQL operation exposes object identifiers.", "graphql_identifier", 16)
        sensitive_fields = {field for field in all_fields if any(word in field for word in SENSITIVE_FIELD_WORDS)}
        if sensitive_fields:
            packet = _packet_for(result, "graphql_data_exposure")
            _add_identity(packet, "graphql_data_exposure", "graphql_operation", "raw_graphql", "GraphQL operation surface is present.", "graphql_operation", 14)
            _add_identity(packet, "graphql_data_exposure", "sensitive_fields", "endpoint_schema", "GraphQL contract references sensitive-looking fields.", "graphql_fields", 18)

    if any(marker in surface_text for marker in WEBSOCKET_MARKERS):
        packet = _packet_for(result, "websocket_authorization")
        _add_identity(packet, "websocket_authorization", "websocket_channel", "raw_realtime", "WebSocket/subscription channel surface is present.", "realtime_channel", 16)
        channel_fields = {field for field in all_fields if any(word in field for word in ("room", "channel", "tenant", "user", "topic", "id"))}
        if channel_fields:
            _add_identity(packet, "websocket_authorization", "room_identifier", "endpoint_schema", "WebSocket/subscription contract includes identity/channel selectors.", "channel_scope", 16)

    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()
    if acao:
        packet = _packet_for(result, "cors_misconfiguration")
        unsafe_origin_policy = False
        if acao == "*":
            unsafe_origin_policy = True
            _add_identity(packet, "cors_misconfiguration", "wildcard_origin", "http_headers", "Access-Control-Allow-Origin wildcard is present.", "cors_policy", 22)
        elif origin and acao == origin:
            unsafe_origin_policy = True
            _add_identity(packet, "cors_misconfiguration", "reflected_origin", "http_headers", "Stored response reflects the supplied Origin value.", "cors_policy", 24)
        elif acao.lower() == "null":
            unsafe_origin_policy = True
            _add_identity(packet, "cors_misconfiguration", "null_origin_accepted", "http_headers", "Stored CORS policy accepts the null origin.", "cors_policy", 22)
        if unsafe_origin_policy and acac == "true":
            _add(packet, "support", _signal("cors_misconfiguration", "credentials_allowed", "http_headers", "Unsafe observed origin policy is combined with Access-Control-Allow-Credentials: true.", source_group="cors_credentials", weight=26, basis="unsafe_origin_with_credentials"))
        if unsafe_origin_policy and (auth_hints or business_context in {"identity", "customer_data", "payment", "administration"}):
            _add(packet, "support", _signal("cors_misconfiguration", "authenticated_context", "endpoint_context", "Unsafe observed CORS origin policy is associated with an authenticated or sensitive application context.", source_group="cors_sensitive_context", weight=18, basis="unsafe_origin_with_sensitive_context"))

    cache_control = response_headers.get("cache-control", "").lower(); vary = response_headers.get("vary", "").lower()
    if cache_control and any(token in cache_control for token in ("public", "s-maxage", "max-age")):
        packet = _packet_for(result, "sensitive_caching")
        _add_identity(packet, "sensitive_caching", "cache_header", "http_headers", "Cacheable response directive is present.", "cache_policy", 16)
        sensitive_context = bool(auth_hints) or business_context in {"identity", "customer_data", "payment", "administration"} or any(word in surface_text for word in SENSITIVE_FIELD_WORDS)
        if sensitive_context:
            _add_identity(packet, "sensitive_caching", "sensitive_context", "endpoint_context", "Cacheable response is associated with sensitive/authenticated context.", "cache_context", 16)
            if "authorization" not in vary and "cookie" not in vary: _add(packet, "support", _signal("sensitive_caching", "missing_vary", "http_headers", "Sensitive cacheable response lacks Vary on Authorization/Cookie.", source_group="shared_cache_behavior", weight=24, basis="cache_header_interaction"))
        if _flag(flat, "cdn_cache") or any(header in response_headers for header in ("age", "x-cache", "cf-cache-status")): _add(packet, "support", _signal("sensitive_caching", "cdn_cache", "http_headers", "Stored response contains shared/CDN cache evidence.", source_group="shared_cache_behavior", weight=22, basis="cache_header_interaction"))

    if all_fields and any(token in surface_text for token in ("query", "search", "filter", "where", "sort", "sql", "database")):
        packet = _packet_for(result, "sql_injection")
        _add_identity(packet, "sql_injection", "input_parameter", "endpoint_schema", "Client-controlled input fields are present.", "input_surface", 10); _add_identity(packet, "sql_injection", "sql_query_surface", "endpoint_semantic", "Database/query semantics are present.", "query_surface", 14)
        if any(pattern in text_lower for pattern in SQL_ERROR_PATTERNS): _add(packet, "support", _signal("sql_injection", "database_error_observed", "raw_response", "Stored response contains a database/SQL error signature.", source_group="database_behavior", weight=30, basis="passive_error_signature"))
    if all_fields and any(token in surface_text for token in ("mongo", "mongodb", "nosql", "documentdb", "aggregate", "$where", "$regex", "json filter")):
        packet = _packet_for(result, "nosql_injection")
        _add_identity(packet, "nosql_injection", "input_parameter", "endpoint_schema", "Client-controlled structured input is present.", "input_surface", 10); _add_identity(packet, "nosql_injection", "nosql_query_surface", "endpoint_semantic", "NoSQL/document-query semantics are present.", "query_surface", 14)
        if any(pattern in text_lower for pattern in NOSQL_ERROR_PATTERNS): _add(packet, "support", _signal("nosql_injection", "nosql_error_observed", "raw_response", "Stored response contains a NoSQL/document-query error signature.", source_group="database_behavior", weight=28, basis="passive_error_signature"))
    if all_fields and (any(marker in text_lower for marker in PROCESS_MARKERS) or any(marker in text_lower for marker in CLI_EXECUTION_MARKERS)):
        packet = _packet_for(result, "command_injection"); _add_identity(packet, "command_injection", "input_parameter", "endpoint_schema", "Client-controlled input is present near a process-execution surface.", "input_surface", 10); _add_identity(packet, "command_injection", "process_execution_surface", "raw_source", "Stored source artifact contains process/shell or CLI execution semantics.", "execution_surface", 18)
    if all_fields and any(marker in text_lower for marker in TEMPLATE_MARKERS):
        packet = _packet_for(result, "server_side_template_injection"); _add_identity(packet, "server_side_template_injection", "template_input", "endpoint_schema", "Client-controlled input participates in a template/rendering surface.", "template_input", 10); _add_identity(packet, "server_side_template_injection", "template_render_surface", "raw_source", "Stored source artifact contains server-side template/render semantics.", "render_surface", 18)
        if any(pattern in text_lower for pattern in TEMPLATE_ERROR_PATTERNS): _add(packet, "support", _signal("server_side_template_injection", "template_engine_error_observed", "raw_response", "Stored response contains a server-side template-engine error signature.", source_group="render_behavior", weight=30, basis="passive_error_signature"))
    if all_fields and any(marker in surface_text for marker in LDAP_MARKERS):
        packet = _packet_for(result, "ldap_injection"); _add_identity(packet, "ldap_injection", "input_parameter", "endpoint_schema", "Client-controlled directory/search input is present.", "input_surface", 10); _add_identity(packet, "ldap_injection", "ldap_query_surface", "endpoint_semantic", "LDAP/directory query semantics are present.", "query_surface", 16)
        if any(pattern in text_lower for pattern in LDAP_ERROR_PATTERNS): _add(packet, "support", _signal("ldap_injection", "ldap_error_observed", "raw_response", "Stored response contains an LDAP/directory error signature.", source_group="ldap_behavior", weight=28, basis="passive_error_signature"))

    if all_fields & RESOURCE_FIELDS or any(token in surface_text for token in ("batch", "bulk", "export", "report", "generate", "pdf", "thumbnail", "upload", "download", "sms", "email", "otp", "biometric")):
        packet = _packet_for(result, "unrestricted_resource_consumption")
        if all_fields & RESOURCE_FIELDS: _add_identity(packet, "unrestricted_resource_consumption", "resource_control_parameter", "endpoint_schema", "Client-visible resource amplification parameter is present.", "resource_surface", 16)
        else: _add_identity(packet, "unrestricted_resource_consumption", "expensive_operation", "endpoint_semantic", "Potentially expensive operation is exposed.", "resource_surface", 12)
        if status == 429: _add(packet, "contradict", _signal("unrestricted_resource_consumption", "rate_limit_enforced", "http_response", "Stored response returned HTTP 429 rate limiting.", source_group="resource_control", weight=-30, basis="http_status_control"))
        if status == 413: _add(packet, "contradict", _signal("unrestricted_resource_consumption", "payload_size_rejected", "http_response", "Stored response returned HTTP 413 payload rejection.", source_group="resource_control", weight=-30, basis="http_status_control"))

    flow_hits = [token for token in BUSINESS_FLOW_MARKERS if token in surface_text]
    if flow_hits:
        packet = _packet_for(result, "sensitive_business_flow_abuse"); _add_identity(packet, "sensitive_business_flow_abuse", "sensitive_business_flow", "endpoint_semantic", "Sensitive business flow semantics are present.", "business_flow", 14)
    if any(token in surface_text for token in SINGLE_USE_MARKERS) and method in {"POST", "PUT", "PATCH", "DELETE"}:
        packet = _packet_for(result, "race_condition"); _add_identity(packet, "race_condition", "state_change", "endpoint_contract", "State-changing business operation is present.", "state_change", 12); _add_identity(packet, "race_condition", "single_use_semantics", "endpoint_semantic", "Operation has single-use/balance-changing semantics.", "single_use", 14)
    if flow_hits and method in {"POST", "PUT", "PATCH", "DELETE"}:
        packet = _packet_for(result, "business_logic"); _add_identity(packet, "business_logic", "business_operation", "endpoint_semantic", "State-changing business workflow operation is present.", "business_operation", 14)

    config_hits = [marker for marker in CONFIG_SURFACE_MARKERS if marker in surface_text]
    explicit_misconfig = any(_flag(flat, signal) for signal in EXECUTION_PROFILES["security_misconfiguration"].condition_signals)
    if config_hits or explicit_misconfig:
        packet = _packet_for(result, "security_misconfiguration")
        _add_identity(packet, "security_misconfiguration", "misconfiguration_surface", "raw_configuration", "Stored artifacts expose configuration-sensitive deployment/application behavior.", "configuration_surface", 10)
        if any(token in config_hits for token in ("debug", "stacktrace", "stack_trace", "traceback", "phpinfo")):
            _add_identity(packet, "security_misconfiguration", "debug_surface", "raw_configuration", "Stored artifacts expose a debug/error configuration surface.", "configuration_surface", 10)
        if "http://" in config_hits:
            _add_identity(packet, "security_misconfiguration", "transport_surface", "raw_configuration", "Stored artifacts contain a cleartext HTTP configuration surface.", "configuration_surface", 10)

    if endpoint.lower().startswith("http://"):
        packet = _packet_for(result, "security_misconfiguration"); _add_identity(packet, "security_misconfiguration", "transport_surface", "endpoint", "Cleartext HTTP endpoint is present.", "configuration_surface", 14); _add(packet, "support", _signal("security_misconfiguration", "insecure_http_enabled", "endpoint", "Stored target endpoint uses cleartext HTTP.", source_group="configuration_behavior", weight=28, basis="endpoint_scheme"))
    if any(pattern in text_lower for pattern in STACK_TRACE_PATTERNS):
        packet = _packet_for(result, "security_misconfiguration"); _add_identity(packet, "security_misconfiguration", "debug_surface", "raw_response", "Stored response contains stack-trace/debug semantics.", "configuration_surface", 14); _add(packet, "support", _signal("security_misconfiguration", "stack_trace_exposed", "raw_response", "Stored response exposes a stack trace.", source_group="configuration_behavior", weight=30, basis="passive_error_signature"))
    if any(pattern in text_lower for pattern in DIRECTORY_LISTING_PATTERNS):
        packet = _packet_for(result, "security_misconfiguration"); _add_identity(packet, "security_misconfiguration", "misconfiguration_surface", "raw_response", "Stored response resembles a directory listing.", "configuration_surface", 14); _add(packet, "support", _signal("security_misconfiguration", "directory_listing_observed", "raw_response", "Stored response exposes directory-listing behavior.", source_group="configuration_behavior", weight=30, basis="passive_response_signature"))

    if text and any(pattern in text_lower for pattern in STACK_TRACE_PATTERNS):
        packet = _packet_for(result, "information_disclosure"); _add_identity(packet, "information_disclosure", "debug_information", "raw_response", "Stored response contains debug/stack-trace material.", "sensitive_material", 18)
        if status in SUCCESS_STATUSES and not auth_hints: _add(packet, "support", _signal("information_disclosure", "public_observation", "http_response", "Debug material was stored from a successful response without an authentication hint.", source_group="exposure_context", weight=22, basis="anonymous_success_context"))

    source_map_surface = endpoint.lower().endswith(".map") or "sourcemappingurl" in text_lower
    if source_map_surface:
        packet = _packet_for(result, "source_map_exposure"); _add_identity(packet, "source_map_exposure", "source_map", "raw_asset", "Source-map asset or sourceMappingURL reference is present.", "source_map", 18)
        if '"sources"' in text_lower or '"sourcescontent"' in text_lower: _add_identity(packet, "source_map_exposure", "internal_sources", "raw_response", "Stored source-map response contains source path/content metadata.", "source_contents", 18)
        if status in SUCCESS_STATUSES: _add(packet, "support", _signal("source_map_exposure", "direct_reachability", "http_response", "Stored source-map request returned a successful response.", source_group="public_reachability", weight=22, basis="http_status"))

    for kind, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if not match: continue
        raw = match.group(1) if match.lastindex else match.group(0); fingerprint = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]
        packet = _packet_for(result, "secret_exposure"); _add_identity(packet, "secret_exposure", "secret_pattern", "raw_client_artifact", f"Credential-like material detected and redacted; kind={kind}, fingerprint={fingerprint}.", "secret_pattern", 22); _add_identity(packet, "secret_exposure", "production_javascript", "raw_client_artifact", "Credential-like material occurs in a stored client-delivered/source artifact.", "client_context", 12)
        entropy = 0.0
        if raw:
            counts: dict[str, int] = defaultdict(int)
            for char in raw: counts[char] += 1
            for count in counts.values():
                p = count / len(raw); entropy -= p * math.log2(p)
        if len(raw) >= 16 and entropy >= 3.0: _add(packet, "support", _signal("secret_exposure", "high_entropy_value", "secret_fingerprint", "Redacted credential-like material has non-trivial length and character entropy.", source_group="secret_assessment", weight=18, basis="redacted_entropy"))
        break

    version_hits = re.findall(r"(?:^|[/_.-])(v\d+(?:\.\d+)?|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", surface_text, re.I)
    normalized_versions = {str(token).lower() for token in version_hits}
    risky_inventory_markers = normalized_versions & {"legacy", "old", "deprecated", "staging", "stage", "dev", "test", "beta", "alpha"}
    explicit_inventory_condition = any(
        _flag(flat, signal)
        for signal in EXECUTION_PROFILES["improper_inventory_management"].condition_signals
    )
    if version_hits and (risky_inventory_markers or explicit_inventory_condition):
        packet = _packet_for(result, "improper_inventory_management")
        _add_identity(packet, "improper_inventory_management", "api_version_surface", "endpoint", "Versioned inventory is combined with legacy/non-production semantics or explicit stored drift evidence.", "inventory_surface", 16)
        if normalized_versions & {"legacy", "old", "deprecated"}:
            _add_identity(packet, "improper_inventory_management", "legacy_endpoint_surface", "endpoint", "Legacy/deprecated API inventory semantics are present.", "inventory_surface", 12)
        if normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add_identity(packet, "improper_inventory_management", "nonproduction_surface", "endpoint", "Non-production/pre-release API inventory semantics are present.", "inventory_surface", 12)
        if status in SUCCESS_STATUSES and normalized_versions & {"legacy", "old", "deprecated"}:
            _add(packet, "support", _signal("improper_inventory_management", "deprecated_version_still_reachable", "http_response", "Stored legacy/deprecated API endpoint remains reachable.", source_group="inventory_behavior", weight=28, basis="legacy_route_success"))
        if status in SUCCESS_STATUSES and normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add(packet, "support", _signal("improper_inventory_management", "undocumented_host_observed", "http_response", "Stored non-production/pre-release API surface is reachable.", source_group="inventory_behavior", weight=22, basis="nonproduction_route_success"))


def execute_detector_intelligence(*, target: str, endpoint: str, method: str, endpoint_schema: Mapping[str, Any] | None, details: Mapping[str, Any] | None, evidence_for: Iterable[Any] | None = None, evidence_against: Iterable[Any] | None = None, category: str = "", business_context: str = "general") -> dict[str, dict[str, Any]]:
    """Execute all family detectors against stored raw/normalized artifacts.

    Passive/offline only: no payload generation, requests, redirect following, state
    mutation, identifier guessing, or external knowledge counted as target evidence.
    """
    endpoint_schema = dict(endpoint_schema or {}); details = dict(details or {}); result: dict[str, dict[str, Any]] = {}
    _typed_evidence(result, evidence_for or (), evidence_against or ()); _explicit_contract_flags(result, _flatten(details))
    _passive_raw_heuristics(result, target=str(target or ""), endpoint=str(endpoint or ""), method=str(method or "UNKNOWN"), endpoint_schema=endpoint_schema, details=details, category=str(category or ""), business_context=str(business_context or "general"))
    reconstructed = reconstruct_raw_evidence(
        target=str(target or ""), endpoint=str(endpoint or ""), method=str(method or "UNKNOWN"),
        endpoint_schema=endpoint_schema, details=details, category=str(category or ""),
        business_context=str(business_context or "general"),
    )
    for family, packet in reconstructed.items():
        target_packet = _packet_for(result, family)
        for side in ("support", "contradict"):
            for item in packet.get(side) or []:
                _add(target_packet, side, dict(item))
    return {family: packet for family, packet in result.items() if packet["support"] or packet["contradict"]}

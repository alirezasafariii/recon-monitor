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

EXECUTION_ENGINE_VERSION = "1.3.0"
EXECUTION_RULE_VERSION = "2026.08.13.6.27"
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
BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "invite", "create account", "password reset", "password-reset", "account recovery", "recover account", "redeem", "claim", "coupon", "promo", "comment", "post", "message", "review")
SINGLE_USE_MARKERS = ("redeem", "claim", "transfer", "withdraw", "reserve", "confirm", "refund")
AUTH_MARKERS = ("login", "signin", "password", "reset", "forgot", "otp", "mfa", "token", "refresh", "session", "oauth", "sso", "saml")
VERSION_MARKERS = ("legacy", "deprecated", "staging", "stage", "beta", "alpha", "/dev/", "/test/")
CONFIG_SURFACE_MARKERS = ("debug", "stacktrace", "stack_trace", "traceback", "swagger", "actuator", "phpinfo", "directory listing", "server-status", "options method", "http://")
FILE_OPERATION_MARKERS = ("/download", "/upload", "/import", "/archive", "/extract", "/unpack", "/files", "/attachment")
PATH_OPERATION_MARKERS = ("/download", "/archive", "/extract", "/unpack", "/files")
CLI_EXECUTION_MARKERS = ("npm ", "npx ", "node ", "python ", "python3 ", "bash ", "sh ", "powershell ", "cmd.exe ", "git ", "curl ", "wget ", "jsii-diff ")

SUPPLY_CHAIN_SURFACE_MARKERS = ("package-lock", "yarn.lock", "pnpm-lock", "requirements.txt", "poetry.lock", "pom.xml", "build.gradle", "sbom", "dependency", "dependencies", "github actions", ".github/workflows", "ci/cd", "artifact registry", "container image")
CRYPTO_SURFACE_MARKERS = ("tls", "ssl", "cipher", "crypto", "encrypt", "decrypt", "signature", "nonce", "random", "md5", "sha1", "sha-1", "aes", "rsa", "ecdsa")
INTEGRITY_SURFACE_MARKERS = ("deserialize", "deserialization", "objectinputstream", "readobject", "pickle.loads", "yaml.load(", "fastjson", "autotype", "enabledefaulttyping", "firmware update", "software update", "plugin update", "signature verification", "checksum", "integrity")
LOGGING_SURFACE_MARKERS = ("audit log", "audit_log", "security log", "logger", "logging", "alerting", "telemetry", "monitoring", "security event")
EXCEPTION_SURFACE_MARKERS = ("uncaught exception", "unhandled exception", "nullpointerexception", "panic:", "segmentation fault", "fatal exception", "rollback", "fail open", "fail-open")
LOG_CONTENT_KEYS = {"log_entry", "log_message", "logger_output", "audit_log", "audit_entry", "debug_log", "telemetry_event", "security_event"}


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


def _falsey(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)) and value == 0:
        return True
    return str(value or "").strip().lower() in {"false", "no", "0", "absent", "missing", "disabled", "rejected"}


def _flag_false(flat: Mapping[str, list[Any]], *names: str) -> bool:
    return any(_falsey(value) for name in names for value in flat.get(_norm(name), []))


def _number(flat: Mapping[str, list[Any]], *names: str) -> float | None:
    for name in names:
        for value in flat.get(_norm(name), []):
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


def _explicit_denial_payload(context: Mapping[str, Any]) -> bool:
    response = context.get("response_json")
    if not isinstance(response, Mapping):
        return False
    errors = response.get("errors")
    if not errors:
        return False
    data = response.get("data")
    if data is None or data == {}:
        return True
    if isinstance(data, Mapping) and all(value is None for value in data.values()):
        return True
    return False


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

    is_graphql_surface = any(marker in surface_text for marker in GRAPHQL_MARKERS) or endpoint.lower().rstrip("/").endswith("graphql")
    route_object_fields = query_fields | path_fields
    explicit_object_surface = bool(object_ids) or any(field.endswith("_id") or field == "id" for field in route_object_fields)
    if explicit_object_surface:
        packet = _packet_for(result, "broken_object_authorization")
        _add_identity(packet, "broken_object_authorization", "object_identifier", "endpoint_schema", "Client-controlled object selector is explicitly declared or appears in a path/query object reference.", "object_reference", 14)
        _add_identity(packet, "broken_object_authorization", "object_operation", "endpoint_contract", f"{method} operates on the referenced object surface.", "object_operation", 9)
        for context in _contexts(details):
            cflat = _flatten(context); cstatus = _status(context)
            expected_false = any(str(v).strip().lower() in {"false", "0", "deny", "denied", "unauthorized"} for key in ("expected_access", "authorization_expected", "should_allow") for v in cflat.get(key, []))
            explicit_denial = _explicit_denial_payload(context)
            if expected_false and cstatus in SUCCESS_STATUSES and not explicit_denial and not is_graphql_surface:
                _add(packet, "support", _signal("broken_object_authorization", "unauthorized_object_response", "stored_context", "A stored context expected to be denied received a successful object response.", source_group="authorization_context", weight=34, basis="context_expectation_vs_response"))
            elif expected_false and (cstatus in DENY_STATUSES or explicit_denial):
                _add(packet, "contradict", _signal("broken_object_authorization", "cross_context_denied", "stored_context", "A stored unauthorized object context was denied or returned an explicit authorization error payload.", source_group="authorization_context", weight=-26, basis="context_expectation_vs_response"))

    auth_surface = any(token in surface_text for token in AUTH_MARKERS)
    admin = any(token in surface_text for token in ("/admin", "backoffice", "permission", "privilege", "management", "staff")) and not auth_surface
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

    browser_observation = details.get("browser_observation") if isinstance(details.get("browser_observation"), Mapping) else {}
    observed_browser_source = str(browser_observation.get("input_channel") or "").lower()
    observed_render_target = str(browser_observation.get("render_target") or "").strip()
    has_dom_source = any(source in text_lower for source in DOM_SOURCES) or any(source in observed_browser_source for source in DOM_SOURCES)
    has_dangerous_dom_sink = any(sink in text_lower for sink in DOM_SINKS)
    if has_dom_source and (has_dangerous_dom_sink or observed_render_target):
        packet = _packet_for(result, "dom_xss")
        _add_identity(packet, "dom_xss", "source_sink", "stored_browser_flow", "Stored browser artifacts trace a browser-controlled input channel to a concrete DOM render target.", "static_flow", 18)
        if has_dangerous_dom_sink:
            _add_identity(packet, "dom_xss", "dangerous_sink", "raw_javascript", "Stored JavaScript contains a dangerous DOM/JavaScript sink.", "static_sink", 18)
        else:
            _add(packet, "contradict", _signal("dom_xss", "text_only_sink", "stored_browser_observation", "Stored browser flow uses a non-executable/text-only rendering path rather than an HTML/JavaScript sink.", source_group="dom_control", weight=-28, basis="stored_safe_render_path"))
        if _truthy(browser_observation.get("rendered_as_html")) and not _truthy(browser_observation.get("sanitized")) and has_dangerous_dom_sink:
            input_channel = str(browser_observation.get("input_channel") or "").lower()
            if any(source in input_channel or source in text_lower for source in DOM_SOURCES):
                _add(packet, "support", _signal("dom_xss", "runtime_reachable_flow", "stored_browser_observation", "Stored browser observation confirms attacker-influenced DOM input reaches an HTML/executable sink without effective sanitization.", source_group="dom_runtime_behavior", weight=34, basis="stored_browser_source_sink_observation"))
    if ("addEventListener" in text or "addeventlistener" in text_lower) and "message" in text_lower:
        packet = _packet_for(result, "postmessage_trust")
        _add_identity(packet, "postmessage_trust", "postmessage_handler", "raw_javascript", "Stored JavaScript registers a message event handler.", "message_source", 18)
        if "event.data" in text_lower:
            _add_identity(packet, "postmessage_trust", "message_source", "raw_javascript", "Stored message handler consumes event.data from the sender-controlled message.", "message_source", 14)
        if any(sink in text_lower for sink in DOM_SINKS) or any(token in text_lower for token in ("location.href", "location.assign", "fetch(", "postmessage(")):
            _add_identity(packet, "postmessage_trust", "message_sink", "raw_javascript", "Message-controlled data is adjacent to a sensitive browser action.", "message_sink", 14)
        message_observation = details.get("message_observation") if isinstance(details.get("message_observation"), Mapping) else {}
        if _truthy(message_observation.get("accepted")) and _falsey(message_observation.get("origin_checked")) and "event.data" in text_lower:
            _add(packet, "support", _signal("postmessage_trust", "missing_origin_check", "stored_message_observation", "Stored cross-window message observation shows an accepted sender-controlled message with no origin check before sensitive handling.", source_group="message_validation_behavior", weight=34, basis="stored_message_acceptance_without_origin_check"))
        if _truthy(message_observation.get("origin_checked")) or "event.origin" in text_lower:
            _add(packet, "contradict", _signal("postmessage_trust", "strict_origin_check", "stored_message_observation", "Stored handler/observation enforces an origin check before accepting the message.", source_group="message_validation_control", weight=-30, basis="stored_origin_validation"))

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
        upstream_urls = [str(v) for key in ("upstream_url", "provider_url", "external_api_url", "url") for v in flat.get(key, []) if isinstance(v, str)]
        if any(url.lower().startswith("http://") for url in upstream_urls):
            _add(packet, "support", _signal("unsafe_api_consumption", "upstream_tls_missing", "stored_configuration", "Stored upstream service URL uses cleartext HTTP.", source_group="upstream_transport", weight=30, basis="explicit_upstream_url_scheme"))
        cert_present = _flag(flat, "tls_certificate_present", "certificate_present")
        hostname_mismatch = _flag_false(flat, "hostname_matches_certificate", "certificate_hostname_matches")
        upstream_accepted = _flag(flat, "response_accepted", "upstream_response_accepted")
        trusted_upstream = _flag(flat, "trusted_upstream", "trusted_provider")
        if cert_present and hostname_mismatch and upstream_accepted and trusted_upstream:
            _add(packet, "support", _signal("unsafe_api_consumption", "upstream_certificate_validation_failure", "stored_upstream_observation", "Stored upstream observation shows a trusted provider response accepted despite certificate-hostname validation failure.", source_group="upstream_transport", weight=34, basis="accepted_trusted_upstream_with_hostname_mismatch"))
        if cert_present and _flag(flat, "hostname_matches_certificate", "certificate_hostname_matches"):
            _add(packet, "contradict", _signal("unsafe_api_consumption", "upstream_tls_enforced", "stored_upstream_observation", "Stored upstream TLS observation validates the provider certificate hostname.", source_group="upstream_transport_control", weight=-28, basis="validated_upstream_certificate_hostname"))

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
        identifiers = object_ids | {field for field in all_fields if field == "id" or field.endswith("_id")}
        packet = _packet_for(result, "graphql_authorization")
        _add_identity(packet, "graphql_authorization", "graphql_operation", "raw_graphql", "GraphQL operation surface is present.", "graphql_operation", 16)
        if identifiers:
            _add_identity(packet, "graphql_authorization", "graphql_identifier", "endpoint_schema", "GraphQL operation exposes object identifiers.", "graphql_identifier", 16)
        for context in _contexts(details):
            cflat = _flatten(context)
            expected_false = any(str(v).strip().lower() in {"false", "0", "deny", "denied", "unauthorized"} for key in ("expected_access", "authorization_expected", "should_allow") for v in cflat.get(key, []))
            if not expected_false:
                continue
            if _explicit_denial_payload(context):
                _add(packet, "contradict", _signal("graphql_authorization", "cross_context_denied", "stored_graphql_context", "Stored GraphQL cross-context request was denied by resolver/object authorization.", source_group="graphql_authorization_control", weight=-30, basis="graphql_denial_payload"))
            elif _status(context) in SUCCESS_STATUSES and isinstance(context.get("response_json"), Mapping):
                response_json = context.get("response_json") or {}
                if response_json.get("data"):
                    _add(packet, "support", _signal("graphql_authorization", "resolver_authorization_failure", "stored_graphql_context", "Stored GraphQL context expected to be denied returned object data from the resolver.", source_group="graphql_authorization_behavior", weight=36, basis="expected_denial_with_graphql_data"))
        response_json = details.get("response_json") if isinstance(details.get("response_json"), Mapping) else {}
        response_flat = _flatten(response_json)
        sensitive_response_fields = {
            key for key in response_flat
            if any(word.replace("_", "") in key.replace("_", "") for word in SENSITIVE_FIELD_WORDS)
        }
        if sensitive_response_fields:
            data_packet = _packet_for(result, "graphql_data_exposure")
            _add_identity(data_packet, "graphql_data_exposure", "graphql_operation", "raw_graphql", "GraphQL operation surface is present.", "graphql_operation", 14)
            _add_identity(data_packet, "graphql_data_exposure", "sensitive_fields", "stored_graphql_response", "Stored GraphQL response contains sensitive credential/data fields.", "graphql_fields", 18)
            if status in SUCCESS_STATUSES and response_json.get("data") and not response_json.get("errors"):
                _add(data_packet, "support", _signal("graphql_data_exposure", "sensitive_expansion", "stored_graphql_response", "Stored successful GraphQL response expands sensitive fields into returned data without a field-policy denial.", source_group="graphql_data_behavior", weight=34, basis="sensitive_fields_in_successful_graphql_data"))

    if any(marker in surface_text for marker in WEBSOCKET_MARKERS):
        packet = _packet_for(result, "websocket_authorization")
        _add_identity(packet, "websocket_authorization", "websocket_channel", "raw_realtime", "WebSocket/subscription channel surface is present.", "realtime_channel", 16)
        channel_fields = {field for field in all_fields if any(word in field for word in ("room", "channel", "tenant", "user", "topic", "id"))}
        if channel_fields:
            _add_identity(packet, "websocket_authorization", "room_identifier", "endpoint_schema", "WebSocket/subscription contract includes identity/channel selectors.", "channel_scope", 16)
        for context in _contexts(details):
            cflat = _flatten(context)
            expected_false = any(str(v).strip().lower() in {"false", "0", "deny", "denied", "unauthorized"} for key in ("expected_access", "authorization_expected", "should_allow") for v in cflat.get(key, []))
            if expected_false and _flag(cflat, "subscription_accepted") and _flag(cflat, "message_received"):
                _add(packet, "support", _signal("websocket_authorization", "unauthorized_subscription", "stored_websocket_context", "Stored unauthorized WebSocket context successfully subscribed and received a message outside its expected scope.", source_group="websocket_authorization_behavior", weight=36, basis="expected_denial_but_subscription_and_message_succeeded"))
            elif expected_false and _flag_false(cflat, "subscription_accepted"):
                _add(packet, "contradict", _signal("websocket_authorization", "cross_context_denied", "stored_websocket_context", "Stored unauthorized WebSocket context was denied subscription.", source_group="websocket_authorization_control", weight=-30, basis="stored_subscription_denial"))

    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()
    if acao:
        packet = _packet_for(result, "cors_misconfiguration")
        _add_identity(packet, "cors_misconfiguration", "cors_policy_surface", "http_headers", "Stored response contains an explicit CORS origin policy.", "cors_surface", 18)
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
        else:
            _add(packet, "contradict", _signal("cors_misconfiguration", "strict_origin_allowlist", "http_headers", "Stored CORS response uses a fixed origin policy that does not reflect the supplied untrusted Origin.", source_group="cors_control", weight=-28, basis="fixed_non_reflective_origin_policy"))
        if unsafe_origin_policy and acac == "true":
            _add(packet, "support", _signal("cors_misconfiguration", "credentials_allowed", "http_headers", "Unsafe observed origin policy is combined with Access-Control-Allow-Credentials: true.", source_group="cors_credentials", weight=26, basis="unsafe_origin_with_credentials"))
        if unsafe_origin_policy and auth_hints:
            _add(packet, "support", _signal("cors_misconfiguration", "authenticated_context", "endpoint_schema", "Unsafe observed CORS origin policy is tied to an authenticated/session-bearing request context.", source_group="cors_sensitive_context", weight=18, basis="unsafe_origin_with_authenticated_context"))

    cache_control = response_headers.get("cache-control", "").lower(); vary = response_headers.get("vary", "").lower()
    cacheable_directive = bool(cache_control and any(token in cache_control for token in ("public", "s-maxage", "max-age")))
    shared_cache_directive = bool(cache_control and any(token in cache_control for token in ("public", "s-maxage")))
    sensitive_body = bool(text_lower and any(word in text_lower for word in SENSITIVE_FIELD_WORDS))
    explicit_sensitive = _flag(flat, "sensitive_context") or _flag(flat, "sensitive_response") or _flag(flat, "response_data")
    actual_auth = bool(request_headers.get("authorization") or request_headers.get("cookie")) or _flag(flat, "authenticated_request", "authenticated_context")
    sensitive_response = sensitive_body or explicit_sensitive
    stored_cache_observation = _flag(flat, "shared_cache_store", "browser_cache_store", "cache_reused_across_context")
    cache_surface = cacheable_directive or stored_cache_observation
    if cache_surface:
        packet = _packet_for(result, "sensitive_caching")
        if cacheable_directive:
            _add_identity(packet, "sensitive_caching", "cache_header", "http_headers", "Observed response carries an explicit cacheability directive.", "cache_policy", 16)
        if actual_auth:
            _add_identity(packet, "sensitive_caching", "authenticated_context", "stored_request", "Stored request contains actual authentication/session context.", "cache_context", 18)
        if sensitive_response:
            _add_identity(packet, "sensitive_caching", "sensitive_context", "raw_response", "Stored response contains sensitive data/context indicators.", "cache_context", 18)
        if stored_cache_observation and (actual_auth or sensitive_response):
            _add(packet, "support", _signal("sensitive_caching", "shared_cache_risk", "stored_cache_observation", "Stored cache observation shows authenticated/sensitive response material entering or being reused by a cache.", source_group="shared_cache_behavior", weight=34, basis="stored_sensitive_cache_reuse"))
        if actual_auth and sensitive_response and cacheable_directive and "no-store" not in cache_control:
            _add(packet, "support", _signal("sensitive_caching", "browser_cache_no_store_missing", "http_headers", "Observed authenticated sensitive response is explicitly cacheable and lacks Cache-Control: no-store.", source_group="browser_cache_behavior", weight=24, basis="observed_authenticated_sensitive_cacheability"))
        if (actual_auth or sensitive_response) and shared_cache_directive and "authorization" not in vary and "cookie" not in vary:
            _add(packet, "support", _signal("sensitive_caching", "missing_vary", "http_headers", "Sensitive/authenticated shared-cacheable response lacks Vary on Authorization/Cookie.", source_group="shared_cache_behavior", weight=24, basis="shared_cache_header_interaction"))
        if _flag(flat, "cdn_cache") or any(header in response_headers for header in ("age", "x-cache", "cf-cache-status")):
            if actual_auth or sensitive_response:
                _add(packet, "support", _signal("sensitive_caching", "cdn_cache", "http_headers", "Stored sensitive/authenticated response contains shared/CDN cache evidence.", source_group="shared_cache_behavior", weight=22, basis="cache_header_interaction"))
        if "no-store" in cache_control:
            _add(packet, "contradict", _signal("sensitive_caching", "no_store", "http_headers", "Cache-Control: no-store is present.", source_group="cache_control", weight=-30, basis="cache_control_header"))
        if "private" in cache_control:
            _add(packet, "contradict", _signal("sensitive_caching", "private_cache", "http_headers", "Cache-Control marks the response private.", source_group="cache_control", weight=-22, basis="cache_control_header"))
        if "authorization" in vary or "cookie" in vary:
            _add(packet, "contradict", _signal("sensitive_caching", "vary_authorization", "http_headers", "Vary includes Authorization or Cookie context.", source_group="cache_control", weight=-22, basis="vary_header"))

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
        attempts = _number(flat, "same_identity_attempts", "attempts", "request_count")
        accepted_attempts = _number(flat, "accepted_attempts", "successful_attempts")
        if attempts is not None and attempts >= 10 and accepted_attempts is not None and accepted_attempts >= attempts * 0.8 and _flag_false(flat, "rate_limit_response_seen", "rate_limit_enforced") and _flag_false(flat, "challenge_present", "anti_bot_control_enforced"):
            _add(packet, "support", _signal("sensitive_business_flow_abuse", "automation_limit_absent", "stored_automation_observation", "Stored high-volume business-flow observation shows nearly all repeated attempts accepted with no rate-limit or anti-automation challenge.", source_group="business_flow_behavior", weight=36, basis="high_volume_acceptance_without_automation_controls"))
        if _flag(flat, "rate_limit_response_seen", "rate_limit_enforced") or _flag(flat, "challenge_present", "anti_bot_control_enforced"):
            _add(packet, "contradict", _signal("sensitive_business_flow_abuse", "anti_bot_control_enforced", "stored_automation_observation", "Stored business-flow observation shows an automation/rate-limit control being enforced.", source_group="business_flow_control", weight=-30, basis="stored_automation_control"))
    if any(token in surface_text for token in SINGLE_USE_MARKERS) and method in {"POST", "PUT", "PATCH", "DELETE"}:
        packet = _packet_for(result, "race_condition"); _add_identity(packet, "race_condition", "state_change", "endpoint_contract", "State-changing business operation is present.", "state_change", 12); _add_identity(packet, "race_condition", "single_use_semantics", "endpoint_semantic", "Operation has single-use/balance-changing semantics.", "single_use", 14)
    if flow_hits and method in {"POST", "PUT", "PATCH", "DELETE"}:
        packet = _packet_for(result, "business_logic"); _add_identity(packet, "business_logic", "business_operation", "endpoint_semantic", "State-changing business workflow operation is present.", "business_operation", 14)
        workflow = details.get("workflow_observation") if isinstance(details.get("workflow_observation"), Mapping) else {}
        before = str(workflow.get("order_state_before") or workflow.get("state_before") or "").lower()
        after = str(workflow.get("order_state_after") or workflow.get("state_after") or "").lower()
        requested = str(workflow.get("requested_transition") or workflow.get("transition") or "").lower()
        payment_confirmed = workflow.get("payment_confirmed")
        rejected = _truthy(workflow.get("transition_rejected"))
        if before and after and before != after and requested and not rejected and _falsey(payment_confirmed) and any(token in after for token in ("enabled", "complete", "completed", "fulfilled", "download")):
            _add(packet, "support", _signal("business_logic", "workflow_invariant_violation", "stored_workflow_observation", "Stored workflow observation shows a protected/fulfilled state transition accepted while its prerequisite payment/authorization invariant is false.", source_group="business_logic_behavior", weight=36, basis="accepted_transition_with_failed_prerequisite"))

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

    disclosure_surface_hits = [marker for marker in ("debug", "internal", "stacktrace", "stack_trace", "exception", "apikey", "api_key", "secret", "token") if marker in surface_text]
    if text and disclosure_surface_hits:
        packet = _packet_for(result, "information_disclosure")
        _add_identity(packet, "information_disclosure", "sensitive_marker", "stored_semantic", "Stored artifacts contain sensitive/debug disclosure terminology; this is a hypothesis surface only.", "sensitive_material", 6)
    if text and any(pattern in text_lower for pattern in STACK_TRACE_PATTERNS):
        packet = _packet_for(result, "information_disclosure"); _add_identity(packet, "information_disclosure", "debug_information", "raw_response", "Stored response contains debug/stack-trace material.", "sensitive_material", 18)
        if status in SUCCESS_STATUSES and not auth_hints: _add(packet, "support", _signal("information_disclosure", "public_observation", "http_response", "Debug material was stored from a successful response without an authentication hint.", source_group="exposure_context", weight=22, basis="anonymous_success_context"))

    source_map_surface = endpoint.lower().endswith(".map") or "sourcemappingurl" in text_lower or isinstance(details.get("source_map"), Mapping)
    if source_map_surface:
        packet = _packet_for(result, "source_map_exposure"); _add_identity(packet, "source_map_exposure", "source_map", "raw_asset", "Source-map asset or sourceMappingURL reference is present.", "source_map", 18)
        source_map = details.get("source_map") if isinstance(details.get("source_map"), Mapping) else {}
        if not source_map:
            raw_body = details.get("response_body")
            if isinstance(raw_body, str):
                try:
                    parsed_map = json.loads(raw_body)
                except (TypeError, ValueError, json.JSONDecodeError):
                    parsed_map = {}
                if isinstance(parsed_map, Mapping):
                    source_map = parsed_map
        source_contents = source_map.get("sourcesContent") if isinstance(source_map.get("sourcesContent"), list) else []
        source_paths = source_map.get("sources") if isinstance(source_map.get("sources"), list) else []
        if source_contents or source_paths or '"sources"' in text_lower or '"sourcescontent"' in text_lower:
            _add_identity(packet, "source_map_exposure", "internal_sources", "stored_source_map", "Stored source-map response contains source path/content metadata.", "source_contents", 18)
        if source_contents:
            _add_identity(packet, "source_map_exposure", "source_contents", "stored_source_map", "Stored source map embeds source content.", "source_contents", 20)
        meaningful_internal_paths = any(str(path).startswith(("../", "..\\", "/")) for path in source_paths)
        if status in SUCCESS_STATUSES and (source_contents or meaningful_internal_paths):
            _add(packet, "support", _signal("source_map_exposure", "direct_reachability", "http_response", "Stored source-map request successfully returned meaningful embedded/internal source material.", source_group="public_reachability", weight=22, basis="successful_map_with_meaningful_source_material"))
        if status in SUCCESS_STATUSES and _flag(flat, "public_fetch") and source_contents:
            _add(packet, "support", _signal("source_map_exposure", "public_observation", "stored_source_map", "Stored target observation confirms the source map with embedded source content is publicly fetchable.", source_group="public_reachability", weight=32, basis="public_fetch_with_embedded_source_content"))
        if status in SUCCESS_STATUSES and _flag(flat, "public_fetch") and not source_contents:
            _add(packet, "contradict", _signal("source_map_exposure", "empty_map", "stored_source_map", "Stored publicly reachable source map contains no embedded source content; reachability alone is not treated as sensitive source exposure.", source_group="source_map_control", weight=-32, basis="public_map_without_embedded_source_content"))

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

    # Analysis 6.25: OWASP Top 10:2025 completion families. These rules remain
    # passive/offline and only use stored target artifacts. In particular, missing
    # client-visible logging is never interpreted as a logging failure.
    supply_dependency_keys = {"package", "package_name", "package_version", "dependency", "dependencies", "component", "component_version", "sbom", "artifact", "repository", "image"}
    supply_keys = sorted(set(flat) & supply_dependency_keys)
    supply_surface = bool(supply_keys) or any(marker in surface_text for marker in SUPPLY_CHAIN_SURFACE_MARKERS)
    if supply_surface:
        packet = _packet_for(result, "software_supply_chain_failure")
        if any(marker in surface_text for marker in ("github actions", ".github/workflows", "ci/cd", "workflow", "pipeline")):
            _add_identity(packet, "software_supply_chain_failure", "build_pipeline", "stored_build_artifact", "Stored artifacts expose a build/CI pipeline trust surface.", "supply_chain_surface", 14)
        else:
            _add_identity(packet, "software_supply_chain_failure", "component_inventory", "stored_component_artifact", "Stored dependency/component metadata exposes a supply-chain inventory surface.", "supply_chain_surface", 14)
        deployed = _flag(flat, "deployed", "component_deployed")
        advisory_present = _flag(flat, "security_advisory_present", "known_vulnerability_present")
        affected_version = _flag(flat, "affected_version", "version_affected")
        if deployed and advisory_present and affected_version:
            _add(packet, "support", _signal("software_supply_chain_failure", "known_vulnerable_component_observed", "stored_component_observation", "Stored deployed component inventory is explicitly matched to an affected version of a known security advisory.", source_group="supply_chain_behavior", weight=36, basis="deployed_component_matches_known_affected_version"))
        if deployed and advisory_present and _flag_false(flat, "affected_version", "version_affected"):
            _add(packet, "contradict", _signal("software_supply_chain_failure", "component_current_and_supported", "stored_component_observation", "Stored component observation indicates the deployed version is not affected by the referenced advisory.", source_group="supply_chain_control", weight=-30, basis="component_version_not_affected"))

    crypto_surface = any(marker in surface_text for marker in CRYPTO_SURFACE_MARKERS) or endpoint.lower().startswith("http://")
    if crypto_surface:
        packet = _packet_for(result, "cryptographic_failure")
        _add_identity(packet, "cryptographic_failure", "cryptographic_surface", "stored_crypto_artifact", "Stored artifacts contain cryptographic/TLS/key-generation semantics.", "crypto_surface", 12)
        if endpoint.lower().startswith("http://"):
            _add_identity(packet, "cryptographic_failure", "transport_crypto_surface", "endpoint", "Stored target endpoint uses cleartext HTTP transport.", "crypto_surface", 14)
        security_sensitive_transport = bool(auth_hints) or bool(all_fields & SENSITIVE_FIELD_WORDS) or any(word in text_lower for word in SENSITIVE_FIELD_WORDS)
        if endpoint.lower().startswith("http://") and security_sensitive_transport:
            _add_identity(packet, "cryptographic_failure", "sensitive_transport", "endpoint_context", "Cleartext endpoint carries an authentication or sensitive-data context.", "crypto_context", 16)
            _add(packet, "support", _signal("cryptographic_failure", "plaintext_sensitive_transport", "endpoint_transport", "Stored target evidence shows security-sensitive traffic exposed over cleartext HTTP.", source_group="crypto_behavior", weight=30, basis="sensitive_cleartext_endpoint"))
        weak_algo = any(token in text_lower for token in ("md5(", "md5.new", "sha1(", "sha-1")) and any(token in text_lower for token in ("password", "secret", "token", "signature", "key", "credential", "auth"))
        if weak_algo:
            _add(packet, "support", _signal("cryptographic_failure", "weak_crypto_algorithm_observed", "stored_source", "Stored source uses MD5/SHA-1 in a security-sensitive credential/key/signature context.", source_group="crypto_behavior", weight=28, basis="security_context_weak_algorithm"))
        weak_random = any(token in text_lower for token in ("math.random", "random.random(", "rand()")) and any(token in text_lower for token in ("token", "secret", "key", "nonce", "session", "password reset"))
        if weak_random:
            _add_identity(packet, "cryptographic_failure", "key_generation_surface", "stored_source", "Stored source uses a random generator in a security-token/key/nonce context.", "crypto_context", 14)
            _add(packet, "support", _signal("cryptographic_failure", "predictable_randomness_observed", "stored_source", "Stored source ties a non-cryptographic random primitive to a security-token/key/nonce context.", source_group="crypto_behavior", weight=28, basis="security_context_weak_randomness"))
        tls_protocols = {str(v).strip().lower() for v in flat.get("protocol", []) if isinstance(v, str)}
        tls_ciphers = {str(v).strip().lower() for v in flat.get("cipher", []) if isinstance(v, str)}
        weak_tls = any(value in {"tlsv1", "tlsv1.0", "ssl3", "sslv3"} for value in tls_protocols) or any(token in value for value in tls_ciphers for token in ("3des", "rc4", "des_cbc", "null"))
        if weak_tls:
            _add(packet, "support", _signal("cryptographic_failure", "weak_tls_observed", "stored_tls_observation", "Stored TLS observation negotiates a deprecated protocol or weak cipher suite.", source_group="crypto_behavior", weight=34, basis="stored_weak_tls_protocol_or_cipher"))
        elif tls_protocols and any(value in {"tlsv1.2", "tlsv1.3"} for value in tls_protocols):
            _add(packet, "contradict", _signal("cryptographic_failure", "strong_tls_enforced", "stored_tls_observation", "Stored TLS observation uses a modern TLS protocol without a known weak cipher marker.", source_group="crypto_control", weight=-28, basis="stored_modern_tls_observation"))

    unsafe_deser = any(marker in text_lower for marker in ("objectinputstream", "readobject(", "pickle.loads", "yaml.load(", "fastjson", "autotype", "enabledefaulttyping"))
    integrity_surface = unsafe_deser or any(marker in surface_text for marker in INTEGRITY_SURFACE_MARKERS)
    if integrity_surface:
        packet = _packet_for(result, "software_data_integrity_failure")
        if unsafe_deser:
            _add_identity(packet, "software_data_integrity_failure", "serialized_input", "stored_source", "Stored source exposes an object deserialization boundary.", "integrity_surface", 16)
            _add_identity(packet, "software_data_integrity_failure", "integrity_boundary", "stored_source", "Deserialized data crosses a code/data trust boundary.", "integrity_context", 12)
            if all_fields:
                _add(packet, "support", _signal("software_data_integrity_failure", "unsafe_deserialization_observed", "stored_source_relation", "Client-controlled request fields are present on an endpoint whose stored source uses an unsafe deserialization primitive.", source_group="integrity_behavior", weight=30, basis="client_input_to_unsafe_deserialization_surface"))
        else:
            signal = "update_artifact" if any(token in surface_text for token in ("update", "firmware", "plugin")) else "integrity_boundary"
            _add_identity(packet, "software_data_integrity_failure", signal, "stored_integrity_artifact", "Stored artifacts expose an update/code/data integrity trust boundary.", "integrity_surface", 14)
            unsigned = _flag_false(flat, "signature_present") and _flag_false(flat, "signature_verified")
            accepted = _flag(flat, "installation_accepted", "update_accepted")
            if unsigned and accepted:
                _add(packet, "support", _signal("software_data_integrity_failure", "unsigned_update_accepted", "stored_update_observation", "Stored update observation shows an unsigned/unverified software artifact accepted for installation.", source_group="integrity_behavior", weight=36, basis="accepted_update_without_signature_verification"))
            if _flag(flat, "signature_verified"):
                _add(packet, "contradict", _signal("software_data_integrity_failure", "signature_verified", "stored_update_observation", "Stored update observation confirms signature verification.", source_group="integrity_control", weight=-30, basis="verified_update_signature"))

    log_values: list[str] = []
    for key in LOG_CONTENT_KEYS:
        for value in flat.get(key, []):
            if isinstance(value, str):
                log_values.append(value[:16384])
            elif isinstance(value, Mapping):
                try:
                    log_values.append(json.dumps(value, ensure_ascii=False, sort_keys=True)[:16384])
                except (TypeError, ValueError):
                    pass
    log_text = "\n".join(log_values).lower()
    logging_surface = bool(log_values) or any(marker in surface_text for marker in LOGGING_SURFACE_MARKERS)
    if logging_surface:
        packet = _packet_for(result, "security_logging_alerting_failure")
        _add_identity(packet, "security_logging_alerting_failure", "logging_surface", "stored_logging_artifact", "Stored target artifacts expose a logging/audit/alerting/telemetry surface.", "logging_surface", 14)
        if any(token in surface_text for token in AUTH_MARKERS) or admin or flow_hits:
            _add_identity(packet, "security_logging_alerting_failure", "auditable_security_event", "endpoint_semantic", "The stored endpoint represents an authentication, privileged, or sensitive business event that should be auditable.", "security_event_surface", 10)
        if log_text and any(token in log_text for token in ("authorization: bearer", "bearer eyj", "password=", "password:", "access_token=", "refresh_token=", "api_key=", "client_secret=")):
            _add(packet, "support", _signal("security_logging_alerting_failure", "sensitive_data_logged", "stored_log_content", "Stored log/telemetry content contains credential- or secret-bearing material.", source_group="logging_behavior", weight=30, basis="stored_sensitive_log_content"))
        matching_entries = _number(flat, "matching_log_entries")
        log_store_checked = _flag(flat, "log_store_checked")
        security_event_present = bool(details.get("security_event")) or _flag(flat, "security_control_event")
        if security_event_present and log_store_checked and matching_entries == 0:
            _add_identity(packet, "security_logging_alerting_failure", "auditable_security_event", "stored_security_event", "Stored target telemetry records a concrete security event whose audit trail can be checked.", "security_event_surface", 14)
            _add(packet, "support", _signal("security_logging_alerting_failure", "security_event_not_logged", "stored_audit_observation", "Stored audit observation explicitly checked the log store and found zero matching entries for the security event.", source_group="logging_behavior", weight=36, basis="checked_log_store_with_zero_event_entries"))
        elif security_event_present and log_store_checked and matching_entries is not None and matching_entries > 0:
            _add(packet, "contradict", _signal("security_logging_alerting_failure", "security_event_logged", "stored_audit_observation", "Stored audit observation found matching log entries for the security event.", source_group="logging_control", weight=-30, basis="checked_log_store_with_matching_event_entries"))

    exception_observation = details.get("exception_observation") if isinstance(details.get("exception_observation"), Mapping) else {}
    exception_surface = bool(exception_observation) or any(marker in surface_text for marker in EXCEPTION_SURFACE_MARKERS) or _flag(flat, "exception_unhandled") or _flag(flat, "process_crashed")
    if exception_surface:
        packet = _packet_for(result, "exceptional_condition_mishandling")
        _add_identity(packet, "exceptional_condition_mishandling", "exception_surface", "stored_error_artifact", "Stored target artifacts expose an exceptional/error-handling surface.", "exception_surface", 14)
        if exception_observation and _truthy(exception_observation.get("handled")):
            if _truthy(exception_observation.get("rollback_completed")):
                _add(packet, "contradict", _signal("exceptional_condition_mishandling", "transaction_rollback_observed", "stored_exception_observation", "Stored exceptional-condition observation confirms the failed transaction was rolled back safely.", source_group="exception_control", weight=-30, basis="stored_exception_rollback"))
            elif not _truthy(exception_observation.get("process_crashed")):
                _add(packet, "contradict", _signal("exceptional_condition_mishandling", "centralized_error_handling", "stored_exception_observation", "Stored exceptional-condition observation confirms the exception was handled without process crash.", source_group="exception_control", weight=-26, basis="stored_handled_exception"))
        if exception_observation and _falsey(exception_observation.get("handled")) and _truthy(exception_observation.get("process_crashed")):
            _add(packet, "support", _signal("exceptional_condition_mishandling", "crash_on_exception", "stored_exception_observation", "Stored target observation explicitly records an unhandled exception causing the process to crash.", source_group="exception_behavior", weight=36, basis="stored_unhandled_exception_process_crash"))
        if method in {"POST", "PUT", "PATCH", "DELETE"} and flow_hits:
            _add_identity(packet, "exceptional_condition_mishandling", "transactional_operation", "endpoint_contract", "Exceptional behavior occurs on a state-changing business operation.", "exception_context", 12)
        strong_unhandled = any(marker in text_lower for marker in ("uncaught exception", "unhandled exception", "nullpointerexception", "panic:", "segmentation fault", "fatal exception"))
        if status >= 500 and strong_unhandled:
            _add(packet, "support", _signal("exceptional_condition_mishandling", "unhandled_exception_observed", "stored_error_response", "Stored server-error response records an unhandled/fatal exceptional condition.", source_group="exception_behavior", weight=28, basis="server_error_with_unhandled_exception"))
        if status >= 500 and any(marker in text_lower for marker in ("panic:", "segmentation fault")):
            _add(packet, "support", _signal("exceptional_condition_mishandling", "crash_on_exception", "stored_error_response", "Stored error artifact contains a process-crash signature under an exceptional condition.", source_group="exception_behavior", weight=30, basis="crash_signature_in_server_error"))

    version_hits = re.findall(r"(?:^|[/_.-])(v\d+(?:\.\d+)?|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", surface_text, re.I)
    normalized_versions = {str(token).lower() for token in version_hits}
    lifecycle_markers = normalized_versions & {"legacy", "old", "deprecated"}
    exact_nonproduction_path = bool(re.search(r"(?:^|/)(?:staging|stage|dev|test|beta|alpha)(?:/|$)", endpoint.lower()))
    explicit_nonproduction_context = any(token in (category + " " + business_context).lower() for token in ("non-production", "nonproduction", "staging deployment", "test deployment", "development deployment", "pre-release"))
    risky_inventory_markers = lifecycle_markers | ((normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}) if (exact_nonproduction_path or explicit_nonproduction_context) else set())
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

from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing replacement anchor in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Version lineage.
replace_once(
    "app/raw_condition_reconstruction.py",
    'RECONSTRUCTION_ENGINE_VERSION = "1.0.0"\nRECONSTRUCTION_RULE_VERSION = "2026.08.11.6.12"\nEXECUTION_ENGINE_VERSION = "1.1.0"\nEXECUTION_RULE_VERSION = "2026.08.11.6.12"',
    'RECONSTRUCTION_ENGINE_VERSION = "1.1.0"\nRECONSTRUCTION_RULE_VERSION = "2026.08.12.6.14"\nEXECUTION_ENGINE_VERSION = "1.2.0"\nEXECUTION_RULE_VERSION = "2026.08.12.6.14"',
)
replace_once(
    "app/family_detectors/execution.py",
    'EXECUTION_ENGINE_VERSION = "1.1.0"\nEXECUTION_RULE_VERSION = "2026.08.11.6.12"',
    'EXECUTION_ENGINE_VERSION = "1.2.0"\nEXECUTION_RULE_VERSION = "2026.08.12.6.14"',
)
replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.12.0"\nRULE_VERSION = "2026.08.11.6.12"',
    'ENGINE_VERSION = "6.14.0"\nRULE_VERSION = "2026.08.12.6.14"',
)
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.12.0"\nCANDIDATE_RULE_VERSION = "2026.08.11.6.12"',
    'CANDIDATE_ENGINE_VERSION = "6.14.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.14"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.12.0"\nREASONING_RULE_VERSION = "2026.08.11.6.12"',
    'REASONING_ENGINE_VERSION = "6.14.0"\nREASONING_RULE_VERSION = "2026.08.12.6.14"',
)

# Precise NoSQL error signatures. Generic database/query prose is not a condition.
replace_once(
    "app/family_detectors/execution.py",
    'NOSQL_ERROR_PATTERNS = ("mongoerror", "mongodb", "unknown operator", "badvalue", "bson", "document query")',
    '''NOSQL_ERROR_PATTERNS = (
    "mongoerror", "mongodb error", "mongodb exception", "unknown operator",
    "badvalue", "bson error", "bsonexception", "failed to parse query",
    "failed to parse filter", "invalid mongodb operator",
)''',
)

# Account-enumeration routing: generic login fields alone must not outrank authentication.
replace_once(
    "app/family_detectors/execution.py",
    '''    if (all_fields & IDENTITY_FIELDS) and any(token in surface_text for token in ("forgot", "reset", "recover", "lookup", "login", "signin", "username", "email")):
        packet = _packet_for(result, "account_enumeration")
        _add_identity(packet, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity field participates in a lookup/authentication flow.", "identity_lookup", 15)
''',
    '''    context_labels = " ".join(str(row.get("context") or "") for row in _contexts(details)).lower()
    enum_present = any(token in context_labels for token in ("existing", "known_user", "valid_user", "present_user"))
    enum_absent = any(token in context_labels for token in ("absent", "nonexistent", "non_existent", "missing_user", "unknown_user", "invalid_user"))
    explicit_enum_surface = any(token in surface_text for token in ("forgot", "reset", "recover", "lookup", "enumerat", "account exists", "username availability", "email availability"))
    if (all_fields & IDENTITY_FIELDS) and (explicit_enum_surface or (enum_present and enum_absent)):
        packet = _packet_for(result, "account_enumeration")
        _add_identity(packet, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity field participates in a controlled existence/lookup surface.", "identity_lookup", 15)
''',
)

# CORS: sensitivity/authentication is condition evidence only after an unsafe origin policy is observed.
replace_once(
    "app/family_detectors/execution.py",
    '''    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()
    if acao:
        packet = _packet_for(result, "cors_misconfiguration")
        if acao == "*": _add_identity(packet, "cors_misconfiguration", "wildcard_origin", "http_headers", "Access-Control-Allow-Origin wildcard is present.", "cors_policy", 22)
        elif origin and acao == origin: _add_identity(packet, "cors_misconfiguration", "reflected_origin", "http_headers", "Stored response reflects the supplied Origin value.", "cors_policy", 24)
        elif acao.lower() == "null": _add_identity(packet, "cors_misconfiguration", "null_origin_accepted", "http_headers", "Stored CORS policy accepts the null origin.", "cors_policy", 22)
        if acac == "true": _add(packet, "support", _signal("cors_misconfiguration", "credentials_allowed", "http_headers", "Access-Control-Allow-Credentials: true is present.", source_group="cors_credentials", weight=26, basis="response_header"))
        if auth_hints or business_context in {"identity", "customer_data", "payment", "administration"}: _add(packet, "support", _signal("cors_misconfiguration", "authenticated_context", "endpoint_context", "CORS response is associated with an authenticated or sensitive application context.", source_group="cors_credentials", weight=18, basis="endpoint_auth_or_sensitive_context"))
''',
    '''    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()
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
''',
)

# Helpers for controlled identity comparison and numeric observations.
replace_once(
    "app/raw_condition_reconstruction.py",
    '''def _is_auth_surface(endpoint: str, category: str, business_context: str, auth_hints: set[str]) -> bool:
    hay = " ".join((endpoint, category, business_context)).lower()
    return bool(auth_hints) or any(term in hay for term in AUTH_TERMS)


''',
    '''def _is_auth_surface(endpoint: str, category: str, business_context: str, auth_hints: set[str]) -> bool:
    hay = " ".join((endpoint, category, business_context)).lower()
    return bool(auth_hints) or any(term in hay for term in AUTH_TERMS)


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


''',
)

# Account enumeration requires present-vs-absent context and material difference.
replace_once(
    "app/raw_condition_reconstruction.py",
    '''    # Account enumeration requires a controlled stored response differential.
    if (all_fields & IDENTITY_FIELDS) and any(term in surface for term in ("login", "signin", "forgot", "reset", "recover", "lookup", "username", "email")):
        _emit(result, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity input participates in a stored lookup/authentication surface.", source_group="identity_lookup", weight=15, basis="raw_identity_surface")
        observables = [_context_observable(row) for row in contexts]
        meaningful = [value for value in observables if any(part not in (0, "", None) for part in value)]
        if len(meaningful) >= 2 and len(set(meaningful)) >= 2:
            _emit(result, "account_enumeration", "response_difference", "stored_context", "Stored controlled identity contexts have a directly observable response/status/length/timing differential.", source_group="identity_differential", weight=34, basis="stored_context_differential")
''',
    '''    # Account enumeration requires opposite identity-existence contexts plus a material observable differential.
    if (all_fields & IDENTITY_FIELDS) and any(term in surface for term in ("login", "signin", "forgot", "reset", "recover", "lookup", "username", "email")):
        controlled_pair = any(
            _material_identity_difference(left, right)
            for index, left in enumerate(contexts)
            for right in contexts[index + 1:]
        )
        if controlled_pair:
            _emit(result, "account_enumeration", "identity_lookup", "endpoint_schema", "Account identity input is observed across controlled present-versus-absent identity contexts.", source_group="identity_lookup", weight=15, basis="controlled_identity_surface")
            _emit(result, "account_enumeration", "response_difference", "stored_context", "Controlled present-versus-absent identity contexts have a material status/body/length/timing differential.", source_group="identity_differential", weight=34, basis="material_identity_differential")
''',
)

# Add missing conservative raw conditions for Command, Race, and Resource Consumption.
replace_once(
    "app/raw_condition_reconstruction.py",
    '''    # Routing-only family identity from semantically strong stored raw context. These
    # never create a final vulnerability condition.
''',
    '''    # Command injection: passive static data-flow into a process execution primitive.
    # No command is executed; this only records direct client-input-to-sink reachability in stored source.
    if all_fields and text:
        for match in re.finditer(r"(?i)(?:child_process\\.)?(?:exec|execsync|system)\\s*\\(\\s*([A-Za-z_$][A-Za-z0-9_.$]*)", text):
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
    duplicate_success = bool(re.search(r"(?is)\\b(?:two|both|multiple|duplicate)\\b.{0,120}\\b(?:concurrent|parallel|simultaneous)\\b.{0,160}\\b(?:success|succeeded|accepted)\\b", text)) or bool(re.search(r"(?is)\\b(?:concurrent|parallel|simultaneous)\\b.{0,160}\\b(?:both|two|multiple)\\b.{0,120}\\b(?:success|succeeded|accepted)\\b", text))
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
''',
)

print("Analysis 6.14 patch applied")

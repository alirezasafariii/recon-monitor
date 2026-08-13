from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
execution = ROOT / "app" / "family_detectors" / "execution.py"
reconstruction = ROOT / "app" / "raw_condition_reconstruction.py"
admission = ROOT / "app" / "hypothesis_admission.py"
reasoners = ROOT / "app" / "family_reasoners.py"
extractors = ROOT / "app" / "family_evidence_extractors.py"


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing patch marker: {label}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# --- raw condition reconstruction: false-condition boundaries ---
replace_once(
    reconstruction,
    'RECONSTRUCTION_ENGINE_VERSION = "1.1.0"\nRECONSTRUCTION_RULE_VERSION = "2026.08.12.6.14"\nEXECUTION_ENGINE_VERSION = "1.2.0"\nEXECUTION_RULE_VERSION = "2026.08.12.6.14"\n',
    'RECONSTRUCTION_ENGINE_VERSION = "1.2.0"\nRECONSTRUCTION_RULE_VERSION = "2026.08.13.6.27"\nEXECUTION_ENGINE_VERSION = "1.3.0"\nEXECUTION_RULE_VERSION = "2026.08.13.6.27"\n',
    "reconstruction lineage",
)
replace_once(
    reconstruction,
    '    re.compile(r"(?im)\\b(?:uncaught|unhandled)\\s+(?:exception|error)\\b"),\n',
    '',
    "bare unhandled exception is not a stack trace",
)
replace_once(
    reconstruction,
    '''def _is_auth_surface(endpoint: str, category: str, business_context: str, auth_hints: set[str]) -> bool:\n    hay = " ".join((endpoint, category, business_context)).lower()\n    return bool(auth_hints) or any(term in hay for term in AUTH_TERMS)\n\n\ndef _identity_context_class(context: Mapping[str, Any]) -> str:\n''',
    '''def _is_auth_surface(endpoint: str, category: str, business_context: str, auth_hints: set[str]) -> bool:\n    hay = " ".join((endpoint, category, business_context)).lower()\n    return bool(auth_hints) or any(term in hay for term in AUTH_TERMS)\n\n\ndef _auth_denial_context(context: Mapping[str, Any]) -> bool:\n    flat = _flatten(context)\n    values: list[str] = []\n    for key in ("context", "auth_state", "authentication_state", "session_state", "token_state", "credential_state"):\n        values.extend(str(value).strip().lower() for value in flat.get(key, []) if str(value).strip())\n    hay = " ".join(values)\n    auth_state_markers = (\n        "unauthenticated", "anonymous", "invalid_session", "expired_session", "missing_session",\n        "invalid_token", "expired_token", "missing_token", "invalid_credential", "bad_password",\n        "logged_out", "no_session", "no_token", "invalid_auth", "authentication_failed",\n    )\n    object_scope_markers = ("other_account", "other_object", "other_tenant", "low_privilege", "channel", "room", "resolver")\n    if any(marker in hay for marker in object_scope_markers):\n        return False\n    return any(marker in hay for marker in auth_state_markers)\n\n\ndef _identity_context_class(context: Mapping[str, Any]) -> str:\n''',
    "auth context classifier",
)
replace_once(
    reconstruction,
    '''        if any(_expected_denied(row) and _context_observable(row)[0] in SUCCESS_STATUSES for row in contexts):\n            _emit(result, "authentication_session", "authentication_boundary_regression", "stored_context", "A stored authentication/session context expected to be denied received a successful response.", source_group="authentication_behavior", weight=34, basis="expected_deny_success")\n''',
    '''        if any(_expected_denied(row) and _auth_denial_context(row) and _context_observable(row)[0] in SUCCESS_STATUSES for row in contexts):\n            _emit(result, "authentication_session", "authentication_boundary_regression", "stored_context", "A stored authentication/session lifecycle context expected to be denied received a successful response.", source_group="authentication_behavior", weight=34, basis="auth_lifecycle_expected_deny_success")\n''',
    "auth condition ownership",
)
replace_once(
    reconstruction,
    '''    if any(token in category_lower for token in ("template", "render", "ssti")):\n        _emit(result, "server_side_template_injection", "template_render_surface", "category_semantic", "Stored category identifies a server-side rendering/template surface.", source_group="render_surface", weight=16, basis="routing_semantic")\n        if all_fields:\n            _emit(result, "server_side_template_injection", "template_input", "endpoint_schema", "Client-controlled input exists on the rendering/template surface.", source_group="template_input", weight=10, basis="routing_semantic")\n''',
    '''    if any(token in category_lower for token in ("template", "ssti", "server-side render", "server side render", "server render", "template render")):\n        _emit(result, "server_side_template_injection", "template_render_surface", "category_semantic", "Stored category identifies a server-side rendering/template surface.", source_group="render_surface", weight=16, basis="routing_semantic")\n        if all_fields:\n            _emit(result, "server_side_template_injection", "template_input", "endpoint_schema", "Client-controlled input exists on the rendering/template surface.", source_group="template_input", weight=10, basis="routing_semantic")\n''',
    "SSTI routing semantic precision",
)

# --- execution: ownership and routing surfaces ---
replace_once(
    execution,
    '''    if object_ids or any(field.endswith("_id") or field == "id" for field in all_fields):\n        packet = _packet_for(result, "broken_object_authorization")\n        _add_identity(packet, "broken_object_authorization", "object_identifier", "endpoint_schema", "Client-controlled object identifier is present in the endpoint contract.", "object_reference", 14)\n        _add_identity(packet, "broken_object_authorization", "object_operation", "endpoint_contract", f"{method} operates on the referenced object surface.", "object_operation", 9)\n        for context in _contexts(details):\n''',
    '''    is_graphql_surface = any(marker in surface_text for marker in GRAPHQL_MARKERS) or endpoint.lower().rstrip("/").endswith("graphql")\n    route_object_fields = query_fields | path_fields\n    explicit_object_surface = bool(object_ids) or any(field.endswith("_id") or field == "id" for field in route_object_fields)\n    if explicit_object_surface:\n        packet = _packet_for(result, "broken_object_authorization")\n        _add_identity(packet, "broken_object_authorization", "object_identifier", "endpoint_schema", "Client-controlled object selector is explicitly declared or appears in a path/query object reference.", "object_reference", 14)\n        _add_identity(packet, "broken_object_authorization", "object_operation", "endpoint_contract", f"{method} operates on the referenced object surface.", "object_operation", 9)\n        for context in _contexts(details):\n''',
    "BOLA object selector precision",
)
replace_once(
    execution,
    '''            explicit_denial = _explicit_denial_payload(context)\n            if expected_false and cstatus in SUCCESS_STATUSES and not explicit_denial:\n                _add(packet, "support", _signal("broken_object_authorization", "unauthorized_object_response", "stored_context", "A stored context expected to be denied received a successful object response.", source_group="authorization_context", weight=34, basis="context_expectation_vs_response"))\n            elif expected_false and (cstatus in DENY_STATUSES or explicit_denial):\n''',
    '''            explicit_denial = _explicit_denial_payload(context)\n            if expected_false and cstatus in SUCCESS_STATUSES and not explicit_denial and not is_graphql_surface:\n                _add(packet, "support", _signal("broken_object_authorization", "unauthorized_object_response", "stored_context", "A stored context expected to be denied received a successful object response.", source_group="authorization_context", weight=34, basis="context_expectation_vs_response"))\n            elif expected_false and (cstatus in DENY_STATUSES or explicit_denial):\n''',
    "GraphQL owns resolver object authorization condition",
)

replace_once(
    execution,
    '''    if any(source in text_lower for source in DOM_SOURCES) and any(sink in text_lower for sink in DOM_SINKS):\n        packet = _packet_for(result, "dom_xss")\n        _add_identity(packet, "dom_xss", "source_sink", "raw_javascript", "Stored JavaScript contains both a browser-controlled source and an executable/HTML sink.", "static_flow", 18)\n        _add_identity(packet, "dom_xss", "dangerous_sink", "raw_javascript", "Stored JavaScript contains a dangerous DOM/JavaScript sink.", "static_sink", 18)\n        browser_observation = details.get("browser_observation") if isinstance(details.get("browser_observation"), Mapping) else {}\n        if _truthy(browser_observation.get("rendered_as_html")) and not _truthy(browser_observation.get("sanitized")):\n''',
    '''    browser_observation = details.get("browser_observation") if isinstance(details.get("browser_observation"), Mapping) else {}\n    observed_browser_source = str(browser_observation.get("input_channel") or "").lower()\n    observed_render_target = str(browser_observation.get("render_target") or "").strip()\n    has_dom_source = any(source in text_lower for source in DOM_SOURCES) or any(source in observed_browser_source for source in DOM_SOURCES)\n    has_dangerous_dom_sink = any(sink in text_lower for sink in DOM_SINKS)\n    if has_dom_source and (has_dangerous_dom_sink or observed_render_target):\n        packet = _packet_for(result, "dom_xss")\n        _add_identity(packet, "dom_xss", "source_sink", "stored_browser_flow", "Stored browser artifacts trace a browser-controlled input channel to a concrete DOM render target.", "static_flow", 18)\n        if has_dangerous_dom_sink:\n            _add_identity(packet, "dom_xss", "dangerous_sink", "raw_javascript", "Stored JavaScript contains a dangerous DOM/JavaScript sink.", "static_sink", 18)\n        else:\n            _add(packet, "contradict", _signal("dom_xss", "text_only_sink", "stored_browser_observation", "Stored browser flow uses a non-executable/text-only rendering path rather than an HTML/JavaScript sink.", source_group="dom_control", weight=-28, basis="stored_safe_render_path"))\n        if _truthy(browser_observation.get("rendered_as_html")) and not _truthy(browser_observation.get("sanitized")) and has_dangerous_dom_sink:\n''',
    "DOM safe flow identity",
)

replace_once(
    execution,
    '''    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()\n    if acao:\n        packet = _packet_for(result, "cors_misconfiguration")\n        unsafe_origin_policy = False\n''',
    '''    acao = response_headers.get("access-control-allow-origin", "").strip(); acac = response_headers.get("access-control-allow-credentials", "").strip().lower(); origin = request_headers.get("origin", "").strip()\n    if acao:\n        packet = _packet_for(result, "cors_misconfiguration")\n        _add_identity(packet, "cors_misconfiguration", "cors_policy_surface", "http_headers", "Stored response contains an explicit CORS origin policy.", "cors_surface", 18)\n        unsafe_origin_policy = False\n''',
    "generic CORS policy surface",
)
replace_once(
    execution,
    '''        elif acao.lower() == "null":\n            unsafe_origin_policy = True\n            _add_identity(packet, "cors_misconfiguration", "null_origin_accepted", "http_headers", "Stored CORS policy accepts the null origin.", "cors_policy", 22)\n        if unsafe_origin_policy and acac == "true":\n''',
    '''        elif acao.lower() == "null":\n            unsafe_origin_policy = True\n            _add_identity(packet, "cors_misconfiguration", "null_origin_accepted", "http_headers", "Stored CORS policy accepts the null origin.", "cors_policy", 22)\n        else:\n            _add(packet, "contradict", _signal("cors_misconfiguration", "strict_origin_allowlist", "http_headers", "Stored CORS response uses a fixed origin policy that does not reflect the supplied untrusted Origin.", source_group="cors_control", weight=-28, basis="fixed_non_reflective_origin_policy"))\n        if unsafe_origin_policy and acac == "true":\n''',
    "safe CORS blocker",
)

replace_once(
    execution,
    '''    source_map_surface = endpoint.lower().endswith(".map") or "sourcemappingurl" in text_lower or isinstance(details.get("source_map"), Mapping)\n    if source_map_surface:\n        packet = _packet_for(result, "source_map_exposure"); _add_identity(packet, "source_map_exposure", "source_map", "raw_asset", "Source-map asset or sourceMappingURL reference is present.", "source_map", 18)\n        source_map = details.get("source_map") if isinstance(details.get("source_map"), Mapping) else {}\n        source_contents = source_map.get("sourcesContent") if isinstance(source_map.get("sourcesContent"), list) else []\n        source_paths = source_map.get("sources") if isinstance(source_map.get("sources"), list) else []\n''',
    '''    source_map_surface = endpoint.lower().endswith(".map") or "sourcemappingurl" in text_lower or isinstance(details.get("source_map"), Mapping)\n    if source_map_surface:\n        packet = _packet_for(result, "source_map_exposure"); _add_identity(packet, "source_map_exposure", "source_map", "raw_asset", "Source-map asset or sourceMappingURL reference is present.", "source_map", 18)\n        source_map = details.get("source_map") if isinstance(details.get("source_map"), Mapping) else {}\n        if not source_map:\n            raw_body = details.get("response_body")\n            if isinstance(raw_body, str):\n                try:\n                    parsed_map = json.loads(raw_body)\n                except (TypeError, ValueError, json.JSONDecodeError):\n                    parsed_map = {}\n                if isinstance(parsed_map, Mapping):\n                    source_map = parsed_map\n        source_contents = source_map.get("sourcesContent") if isinstance(source_map.get("sourcesContent"), list) else []\n        source_paths = source_map.get("sources") if isinstance(source_map.get("sources"), list) else []\n''',
    "parse stored source map body",
)
replace_once(
    execution,
    '''        if status in SUCCESS_STATUSES:\n            _add(packet, "support", _signal("source_map_exposure", "direct_reachability", "http_response", "Stored source-map request returned a successful response.", source_group="public_reachability", weight=22, basis="http_status"))\n''',
    '''        meaningful_internal_paths = any(str(path).startswith(("../", "..\\\\", "/")) for path in source_paths)\n        if status in SUCCESS_STATUSES and (source_contents or meaningful_internal_paths):\n            _add(packet, "support", _signal("source_map_exposure", "direct_reachability", "http_response", "Stored source-map request successfully returned meaningful embedded/internal source material.", source_group="public_reachability", weight=22, basis="successful_map_with_meaningful_source_material"))\n''',
    "source map condition precision",
)

replace_once(
    execution,
    '''    exception_surface = any(marker in surface_text for marker in EXCEPTION_SURFACE_MARKERS) or _flag(flat, "exception_unhandled") or _flag(flat, "process_crashed")\n    if exception_surface:\n        packet = _packet_for(result, "exceptional_condition_mishandling")\n        _add_identity(packet, "exceptional_condition_mishandling", "exception_surface", "stored_error_artifact", "Stored target artifacts expose an exceptional/error-handling surface.", "exception_surface", 14)\n''',
    '''    exception_observation = details.get("exception_observation") if isinstance(details.get("exception_observation"), Mapping) else {}\n    exception_surface = bool(exception_observation) or any(marker in surface_text for marker in EXCEPTION_SURFACE_MARKERS) or _flag(flat, "exception_unhandled") or _flag(flat, "process_crashed")\n    if exception_surface:\n        packet = _packet_for(result, "exceptional_condition_mishandling")\n        _add_identity(packet, "exceptional_condition_mishandling", "exception_surface", "stored_error_artifact", "Stored target artifacts expose an exceptional/error-handling surface.", "exception_surface", 14)\n        if exception_observation and _truthy(exception_observation.get("handled")):\n            if _truthy(exception_observation.get("rollback_completed")):\n                _add(packet, "contradict", _signal("exceptional_condition_mishandling", "transaction_rollback_observed", "stored_exception_observation", "Stored exceptional-condition observation confirms the failed transaction was rolled back safely.", source_group="exception_control", weight=-30, basis="stored_exception_rollback"))\n            elif not _truthy(exception_observation.get("process_crashed")):\n                _add(packet, "contradict", _signal("exceptional_condition_mishandling", "centralized_error_handling", "stored_exception_observation", "Stored exceptional-condition observation confirms the exception was handled without process crash.", source_group="exception_control", weight=-26, basis="stored_handled_exception"))\n        if exception_observation and _falsey(exception_observation.get("handled")) and _truthy(exception_observation.get("process_crashed")):\n            _add(packet, "support", _signal("exceptional_condition_mishandling", "crash_on_exception", "stored_exception_observation", "Stored target observation explicitly records an unhandled exception causing the process to crash.", source_group="exception_behavior", weight=36, basis="stored_unhandled_exception_process_crash"))\n''',
    "structured exceptional condition routing and crash",
)

# --- CORS admission/reasoning: explicit surface -> unsafe policy -> sensitive exposure ---
replace_once(
    admission,
    '''    "cors_misconfiguration": {\n        "required": [\n            {"wildcard_origin", "reflected_origin", "null_origin_accepted", "unsafe_origin_policy"},\n            {"credentials_allowed", "sensitive_cross_origin_response", "authenticated_context"},\n        ],\n''',
    '''    "cors_misconfiguration": {\n        "required": [\n            {"cors_policy_surface"},\n            {"wildcard_origin", "reflected_origin", "null_origin_accepted", "unsafe_origin_policy"},\n            {"credentials_allowed", "sensitive_cross_origin_response", "authenticated_context"},\n        ],\n''',
    "CORS three-stage admission",
)
replace_once(
    reasoners,
    '    "cors_misconfiguration": (0,),\n',
    '    "cors_misconfiguration": (0,),\n',
    "CORS identity gate marker",
)
replace_once(
    reasoners,
    '''    "cors_misconfiguration": FamilyReasonerProfile(\n        "Does an unsafe CORS origin policy expose credentialed or sensitive cross-origin data?",\n        (0.30, 0.50),\n        ("information_disclosure", "security_misconfiguration"),\n        confounder_penalty=0.20,\n    ),\n''',
    '''    "cors_misconfiguration": FamilyReasonerProfile(\n        "Does an explicit CORS policy accept an unsafe origin and expose credentialed or sensitive cross-origin data?",\n        (0.34, 0.14, 0.32),\n        ("information_disclosure", "security_misconfiguration"),\n        confounder_penalty=0.20,\n    ),\n''',
    "CORS reasoner weights",
)

# DOM safe source-to-render flow participates in routing, but admission still requires
# a dangerous sink and runtime/sanitization condition.
replace_once(
    reasoners,
    '    "dom_xss": (0, 1),\n',
    '    "dom_xss": (0,),\n',
    "DOM identity gate",
)
replace_once(
    extractors,
    '    "dom_xss": (0, 1),\n',
    '    "dom_xss": (0,),\n',
    "DOM extractor identity gate",
)

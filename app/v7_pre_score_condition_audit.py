from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS

VERSION = "1.0.1"
RULE_VERSION = "2026.08.15.6.32.v7.7"

# Pre-score source-text label anchors. These are generic proof phrases derived
# from the family security contracts and research lessons. They are not detector
# outputs and do not inspect v6 benchmark results or case errors.
CONDITION_ANCHORS: dict[str, dict[str, tuple[str, ...]]] = {
    "account_enumeration": {
        "account_existence_differential": (
            "user enumeration", "account enumeration", "account existence", "user existence",
            "existing user", "registered email", "different response", "distinguish",
        ),
    },
    "authentication_session": {
        "authentication_boundary_regression": (
            "authentication bypass", "login bypass", "session fixation", "session reuse",
            "impersonation", "impersonate", "token forgery", "mfa bypass",
        ),
    },
    "broken_function_authorization": {
        "authorization_response_differential": (
            "low privilege", "lower privilege", "non-admin", "non admin", "unauthorized admin",
            "authorization bypass", "access control bypass", "missing permission",
        ),
    },
    "broken_object_authorization": {
        "cross_identity_object_access": (
            "idor", "other user", "another user", "different user", "cross account", "ownership bypass",
        ),
        "cross_tenant_object_access": (
            "cross tenant", "other tenant", "another tenant", "tenant isolation", "tenant boundary",
        ),
    },
    "business_logic": {
        "workflow_invariant_violation": (
            "business logic", "workflow bypass", "invalid state transition", "state transition",
            "payment status", "order status", "without payment", "invariant",
        ),
    },
    "command_injection": {
        "process_execution_reached": (
            "command injection", "os command", "shell command", "command execution", "process execution",
        ),
    },
    "cors_misconfiguration": {
        "authenticated_context": (
            "allow-credentials", "allow credentials", "credentialed", "credentials", "authenticated cross-origin",
        ),
        "credentials_allowed": (
            "access-control-allow-credentials", "allow-credentials", "credentials true", "credentials: true",
        ),
    },
    "cryptographic_failure": {
        "weak_crypto_algorithm_observed": (
            "weak cipher", "insecure cipher", "weak cryptography", "weak hash", "md5", "sha1", "des", "rc4",
        ),
        "predictable_randomness_observed": (
            "predictable random", "weak random", "insufficient entropy", "guessable nonce", "deterministic random",
        ),
    },
    "dom_xss": {
        "runtime_reachable_flow": (
            "dom xss", "dom-based xss", "innerhtml", "outerhtml", "document.write",
            "insertadjacenthtml", "location.hash", "location.search", "dom sink",
        ),
    },
    "exceptional_condition_mishandling": {
        "unhandled_exception_observed": (
            "unhandled exception", "uncaught exception", "panic", "crash", "fail open", "fail-open",
        ),
    },
    "file_upload": {
        "dangerous_type_accepted": (
            "arbitrary file upload", "unrestricted upload", "executable upload", "php upload",
            "extension validation", "mime validation", "dangerous file",
        ),
        "active_content_served": (
            "uploaded file served", "uploaded html", "uploaded svg", "active content", "served upload",
        ),
    },
    "graphql_authorization": {
        "resolver_authorization_failure": (
            "graphql authorization", "unauthorized resolver", "resolver access control", "graphql permission",
            "unauthorized mutation", "unauthorized query",
        ),
    },
    "graphql_data_exposure": {
        "unauthorized_data_response": (
            "graphql data exposure", "graphql information disclosure", "sensitive graphql data",
            "unauthorized graphql data", "graphql response exposes", "private data exposure",
            "cross-user private data exposure", "cross user private data exposure",
            "private field over-exposure", "private field over exposure",
        ),
    },
    "improper_inventory_management": {
        "deprecated_version_still_reachable": (
            "deprecated endpoint", "deprecated api", "legacy endpoint", "old api version", "retired endpoint",
            "legacy api", "still reachable", "remained accessible",
        ),
    },
    "information_disclosure": {
        "unauthorized_data_response": (
            "information disclosure", "sensitive information exposed", "data exposure", "unauthorized data",
            "leaked response", "sensitive response",
        ),
    },
    "ldap_injection": {
        "ldap_auth_bypass_observed": (
            "ldap injection", "ldap filter injection", "ldap authentication bypass", "ldap auth bypass",
        ),
    },
    "mass_assignment": {
        "privileged_property_accepted": (
            "mass assignment", "over-posting", "overposting", "privileged field", "admin field",
            "role field", "property accepted",
        ),
    },
    "nosql_injection": {
        "nosql_auth_bypass_observed": (
            "nosql injection", "mongodb injection", "mongo injection", "mongo operator", "authentication bypass",
        ),
    },
    "open_redirect": {
        "allowlist_bypass": (
            "open redirect", "unvalidated redirect", "redirect allowlist", "allowlist bypass",
        ),
        "external_destination": (
            "external redirect", "external destination", "attacker controlled url", "arbitrary redirect",
        ),
    },
    "path_traversal": {
        "path_escape_observed": (
            "path traversal", "directory traversal", "zip slip", "outside destination", "outside root",
            "parent directory", "../",
        ),
    },
    "postmessage_trust": {
        "missing_origin_check": (
            "postmessage", "post message", "missing origin", "origin not validated", "origin validation",
            "e.origin", "message origin",
        ),
        "missing_source_window_check": (
            "message source", "source window", "event.source", "iframe source",
        ),
        "message_schema_unvalidated": (
            "message data", "event.data", "message schema", "message content", "unvalidated message",
        ),
    },
    "race_condition": {
        "atomicity_failure": (
            "race condition", "toctou", "time-of-check", "time of check", "concurrent", "simultaneous",
            "double spend", "duplicate", "atomic",
        ),
    },
    "secret_exposure": {
        "credential_context": (
            "credential", "password", "api key", "access token", "authentication token", "private key",
        ),
        "non_placeholder_secret": (
            "hardcoded", "hard-coded", "embedded secret", "production secret", "real token",
        ),
    },
    "security_logging_alerting_failure": {
        "sensitive_data_logged": (
            "password logged", "token logged", "secret logged", "sensitive data logged", "plaintext password",
            "credential in log", "trace file",
        ),
        "alerting_absent_observed": (
            "no alert", "missing alert", "alerting absent", "not logged", "missing log", "no audit event",
        ),
    },
    "security_misconfiguration": {
        "debug_mode_exposed": (
            "debug mode", "debug enabled", "debug exposed", "stack trace", "development mode",
        ),
        "unsafe_default_configuration": (
            "insecure default", "unsafe default", "default configuration", "misconfiguration", "directory listing",
        ),
    },
    "sensitive_business_flow_abuse": {
        "per_user_limit_absent": (
            "no rate limit", "missing rate limit", "rate limit", "per-user limit", "per user limit",
        ),
        "workflow_frequency_unrestricted": (
            "unrestricted", "multiple", "bulk", "automation", "abuse", "repeat", "repeated",
        ),
    },
    "sensitive_caching": {
        "browser_cache_no_store_missing": (
            "cache-control", "no-store", "no store", "shared cache", "public cache", "authenticated cache",
            "sensitive caching",
        ),
    },
    "server_side_template_injection": {
        "server_template_execution": (
            "server-side template injection", "server side template injection", "ssti", "template injection",
            "template expression", "jinja", "twig", "freemarker",
        ),
    },
    "software_data_integrity_failure": {
        "integrity_check_missing": (
            "signature verification", "integrity verification", "unsigned update", "unsigned firmware",
            "missing signature", "without verification", "tampered update",
        ),
    },
    "software_supply_chain_failure": {
        "known_vulnerable_component_observed": (
            "malicious dependency", "compromised dependency", "vulnerable dependency", "malicious package",
            "supply chain", "compromised package",
        ),
    },
    "source_map_exposure": {
        "direct_reachability": (
            "source map", "sourcemap", ".js.map", ".mjs.map", "sourcescontent", "served", "public",
        ),
    },
    "sql_injection": {
        "database_error_observed": (
            "sql injection", "sqli", "sql error", "database error", "query error",
        ),
        "boolean_response_differential": (
            "boolean-based", "boolean based", "true false", "response difference", "blind sql",
        ),
    },
    "ssrf": {
        "backend_fetch": (
            "ssrf", "server-side request forgery", "server side request forgery", "backend fetch",
            "server-side fetch", "internal url", "metadata url",
        ),
        "server_fetch_observed": (
            "server request", "outbound request", "server fetch", "internal request", "localhost request",
        ),
    },
    "unrestricted_resource_consumption": {
        "batch_limit_absent_observed": (
            "unbounded", "resource exhaustion", "memory exhaustion", "large batch", "unbounded batch",
        ),
        "rate_limit_absent_observed": (
            "no rate limit", "missing rate limit", "unlimited requests", "request flood",
        ),
    },
    "unsafe_api_consumption": {
        "third_party_auth_weak": (
            "third-party api", "third party api", "upstream api", "external api", "certificate validation",
            "hostname validation", "tls validation",
        ),
        "unsafe_upstream_data_reaches_sink": (
            "upstream response", "external service", "malicious data", "untrusted response", "trusted upstream",
        ),
    },
    "websocket_authorization": {
        "unauthorized_subscription": (
            "websocket", "unauthorized subscription", "subscription authorization", "subscribe without",
        ),
        "channel_authorization_failure": (
            "websocket authorization", "socket authorization", "channel authorization", "unauthorized message",
        ),
    },
}


def audit_conditions(family: str, row: Mapping[str, Any]) -> tuple[list[str], dict[str, list[str]]]:
    if family not in DETECTOR_SPECS:
        raise KeyError(f"unknown family: {family}")
    text = "\n".join(
        str(row.get(key) or "")
        for key in ("summary", "description", "patch_text")
    ).casefold()
    anchors = CONDITION_ANCHORS.get(family, {})
    allowed = set(DETECTOR_SPECS[family].condition_signals)
    signals: list[str] = []
    hits: dict[str, list[str]] = {}
    for signal, phrases in anchors.items():
        if signal not in allowed:
            raise RuntimeError(f"condition audit signal is not canonical for {family}: {signal}")
        matched = sorted({phrase for phrase in phrases if phrase.casefold() in text})
        if matched:
            signals.append(signal)
            hits[signal] = matched
    return sorted(signals), hits


__all__ = ["VERSION", "RULE_VERSION", "CONDITION_ANCHORS", "audit_conditions"]

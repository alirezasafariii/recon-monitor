from __future__ import annotations

"""Canonical metadata for OWASP expansion phase 1."""

NEW_FAMILY_ORDER = (
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "ssti",
    "ldap_injection",
    "unrestricted_resource_consumption",
    "sensitive_business_flow_abuse",
    "security_misconfiguration",
    "improper_inventory_management",
    "unsafe_api_consumption",
)

BUG_FAMILY_METADATA = {
    "sql_injection": {"label": "SQL Injection", "impact": 92, "category": "server_injection"},
    "nosql_injection": {"label": "NoSQL Injection", "impact": 88, "category": "server_injection"},
    "command_injection": {"label": "OS Command Injection", "impact": 96, "category": "server_injection"},
    "ssti": {"label": "Server-Side Template Injection", "impact": 94, "category": "server_injection"},
    "ldap_injection": {"label": "LDAP Injection", "impact": 84, "category": "server_injection"},
    "unrestricted_resource_consumption": {"label": "Unrestricted Resource Consumption", "impact": 78, "category": "api_abuse"},
    "sensitive_business_flow_abuse": {"label": "Sensitive Business Flow Abuse", "impact": 76, "category": "api_abuse"},
    "security_misconfiguration": {"label": "Security Misconfiguration", "impact": 72, "category": "configuration"},
    "improper_inventory_management": {"label": "Improper API Inventory Management", "impact": 66, "category": "api_inventory"},
    "unsafe_api_consumption": {"label": "Unsafe Consumption of APIs", "impact": 82, "category": "api_supply_chain"},
}

SAFE_ACTIONS = {
    "sql_injection": "Trace user-controlled input to database query construction. Prefer code/query evidence; do not send destructive or data-extracting SQL payloads.",
    "nosql_injection": "Trace user-controlled structures/operators into NoSQL query construction. Do not test against real records or use destructive operators.",
    "command_injection": "Trace user input to OS command construction. Do not execute shell commands; use only previously captured benign controlled evidence.",
    "ssti": "Trace user input into server-side template compilation/rendering. Do not use code-execution payloads; only harmless expression evidence is acceptable.",
    "ldap_injection": "Trace user-controlled values into LDAP filter construction and escaping. Do not enumerate directory records outside controlled test identities.",
    "unrestricted_resource_consumption": "Document intended quotas, limits, timeouts and cost controls. Do not perform load, concurrency, large-allocation or cost-amplification tests without explicit authorization.",
    "sensitive_business_flow_abuse": "Document why the flow is business-sensitive and its intended per-user/device/transaction limits. Do not automate purchases, reservations, registrations or other real business actions.",
    "security_misconfiguration": "Capture the exact observable configuration and expected secure baseline. Prefer passive metadata and avoid changing server or platform configuration.",
    "improper_inventory_management": "Compare observed API hosts, versions and debug surfaces against an authoritative inventory. Do not probe unrelated hosts or undocumented third-party assets.",
    "unsafe_api_consumption": "Map third-party trust boundaries, transport, redirect, timeout, size and validation controls. Do not probe or compromise upstream third-party services.",
}

DIRECT_TYPES = {
    "sql_injection": {"sql_query_influence_observed", "sql_behavior_differential"},
    "nosql_injection": {"nosql_query_influence_observed", "nosql_operator_injection_observed"},
    "command_injection": {"command_execution_influence_observed", "command_argument_boundary_bypass_observed"},
    "ssti": {"template_expression_evaluated", "template_sandbox_escape_observed"},
    "ldap_injection": {"ldap_filter_influence_observed", "ldap_query_differential"},
    "unrestricted_resource_consumption": {"resource_limit_not_enforced", "unbounded_batch_accepted", "cost_amplification_observed"},
    "sensitive_business_flow_abuse": {"business_limit_bypass_observed", "excessive_flow_access_accepted"},
    "security_misconfiguration": {
        "debug_mode_publicly_exposed",
        "directory_listing_observed",
        "dangerous_http_method_enabled",
        "management_interface_publicly_exposed",
        "insecure_transport_configuration_observed",
    },
    "improper_inventory_management": {
        "deprecated_api_publicly_reachable",
        "undocumented_api_publicly_reachable",
        "debug_api_publicly_reachable",
        "stale_api_host_publicly_reachable",
    },
    "unsafe_api_consumption": {
        "untrusted_upstream_data_reaches_sensitive_sink",
        "unencrypted_upstream_observed",
        "cross_trust_upstream_redirect_followed",
        "upstream_response_limit_bypass_observed",
    },
}

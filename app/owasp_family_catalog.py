from __future__ import annotations

"""Canonical metadata for OWASP expansion phase 1.

Taxonomy identifiers in this module are the single authoritative mapping for
phase-one families.  Individual analyzers may keep local descriptive metadata
for readability, but emitted analyzer metadata and knowledge profiles consume
this canonical map so WSTG/CWE/CAPEC identifiers cannot drift independently.
"""

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

CANONICAL_TAXONOMY = {
    "sql_injection": {
        "owasp": ["Injection"],
        "wstg": ["WSTG-INPV-05"],
        "cwe": ["CWE-89"],
        "capec": ["CAPEC-66"],
    },
    "nosql_injection": {
        "owasp": ["Injection"],
        # NoSQL is section 4.7.5.6 of the SQL Injection WSTG scenario; the
        # stable scenario identifier remains WSTG-INPV-05 (not INPV-05.6).
        "wstg": ["WSTG-INPV-05"],
        "cwe": ["CWE-943"],
        "capec": [],
    },
    "command_injection": {
        "owasp": ["Injection"],
        "wstg": ["WSTG-INPV-12"],
        "cwe": ["CWE-78"],
        "capec": ["CAPEC-88"],
    },
    "ssti": {
        "owasp": ["Injection"],
        "wstg": ["WSTG-INPV-18"],
        "cwe": ["CWE-1336"],
        "capec": [],
    },
    "ldap_injection": {
        "owasp": ["Injection"],
        "wstg": ["WSTG-INPV-06"],
        "cwe": ["CWE-90"],
        "capec": ["CAPEC-136"],
    },
    "unrestricted_resource_consumption": {
        "owasp": ["API4:2023 Unrestricted Resource Consumption"],
        "wstg": ["WSTG-BUSL-05"],
        "cwe": ["CWE-770", "CWE-400"],
        "capec": [],
    },
    "sensitive_business_flow_abuse": {
        "owasp": ["API6:2023 Unrestricted Access to Sensitive Business Flows"],
        "wstg": ["WSTG-BUSL-05", "WSTG-BUSL-07"],
        "cwe": ["CWE-841"],
        "capec": [],
    },
    "security_misconfiguration": {
        "owasp": ["A02:2025 Security Misconfiguration", "API8:2023 Security Misconfiguration"],
        "wstg": ["WSTG-CONF-02", "WSTG-CONF-06", "WSTG-CRYP-01"],
        # CWE-16 is a category and is prohibited for vulnerability mapping.
        # These base weaknesses correspond to the concrete subtypes emitted by
        # this analyzer: active debug, directory listing, exposed dangerous
        # methods/management functions, and cleartext transport.
        "cwe": ["CWE-489", "CWE-548", "CWE-749", "CWE-319"],
        "capec": [],
    },
    "improper_inventory_management": {
        "owasp": ["API9:2023 Improper Inventory Management"],
        "wstg": ["WSTG-APIT-01"],
        "cwe": [],
        "capec": [],
    },
    "unsafe_api_consumption": {
        "owasp": ["API10:2023 Unsafe Consumption of APIs"],
        # There is no single WSTG scenario equivalent to API10. Do not invent
        # a generic WSTG-APIT identifier; map specific observed subtypes to CWE.
        "wstg": [],
        "cwe": ["CWE-319", "CWE-400"],
        "capec": [],
    },
}

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

assert tuple(CANONICAL_TAXONOMY) == NEW_FAMILY_ORDER

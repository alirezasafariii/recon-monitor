from __future__ import annotations

"""Canonical target-evidence contracts for OWASP expansion phase 1."""

from owasp_family_catalog import NEW_FAMILY_ORDER

FAMILY_REASONING_EXTENSION_VERSION = "1.0.0"
FAMILY_REASONING_RULE_VERSION = "2026.08.12.4"


def _req(key: str, label: str, why: str) -> dict[str, str]:
    return {"key": key, "label": label, "why": why}


def _groups(groups):
    return tuple(frozenset(group) for group in groups)


def _policy(label, category, promotion, blockers, overrides, confirmation, requirements, next_evidence, validation, min_sources=2):
    return {
        "label": label, "category": category, "promotion_required": _groups(promotion),
        "min_independent_sources": min_sources, "blocking_contradictions": frozenset(blockers),
        "override_signals": frozenset(overrides), "confirmation_required": _groups([confirmation]),
        "case_requirements": requirements, "next_evidence": tuple(next_evidence), "validation_level": validation,
    }

INJECTION_REQ = (
    _req("input_source", "User-controlled input source", "Identify the exact untrusted request/stored input."),
    _req("server_sink", "Server-side interpreter/query sink", "Identify the exact database, command, template, or directory-processing boundary."),
    _req("controlled_observation", "Controlled non-destructive observation", "Confirmation requires authorized benign stored behavior evidence; payload knowledge is not evidence."),
    _req("expected_safe_behavior", "Expected safe handling", "Document parameterization, escaping, typing, literal rendering, or allow-list behavior."),
)
RESOURCE_REQ = (
    _req("resource_operation", "Resource-consuming operation", "Identify the operation consuming bounded server/provider resources."),
    _req("intended_limit", "Intended quota or limit", "Document expected rate, size, batch, timeout, or cost boundaries."),
    _req("bounded_test_context", "Bounded authorized context", "Behavior evidence must stay inside an explicit request/resource/cost budget."),
)
BUSINESS_REQ = (
    _req("sensitive_flow", "Sensitive business flow", "Document why excessive automated access creates material business harm."),
    _req("expected_abuse_control", "Expected abuse-control policy", "Document identity/device/velocity/quota/queue/inventory controls."),
    _req("reversible_test_context", "Reversible test context", "Use test-owned reversible actions without consuming real scarce inventory."),
)
CONFIG_REQ = (
    _req("configuration_surface", "Affected configuration surface", "Identify the concrete production server/framework/gateway/management configuration."),
    _req("secure_baseline", "Expected secure baseline", "Document the expected production configuration."),
    _req("observable_deviation", "Observable deviation", "Require a concrete target observation, not a generic best-practice checklist miss."),
)
INVENTORY_REQ = (
    _req("inventory_baseline", "Authoritative API inventory", "Compare observed hosts/versions/environments with an authoritative lifecycle record."),
    _req("observed_surface", "Observed API surface", "Identify the concrete host/version/route/debug surface."),
    _req("lifecycle_status", "Lifecycle/documentation status", "Establish deprecated, undocumented, stale, or debug status."),
)
UPSTREAM_REQ = (
    _req("upstream_dependency", "Third-party API dependency", "Identify the external service and target-side trust boundary."),
    _req("consumption_path", "Upstream response consumption path", "Map how upstream data/redirects/resources reach downstream processing."),
    _req("upstream_safety_policy", "Upstream safety policy", "Document transport, validation, redirect, timeout, size, and sanitization expectations."),
)

EXTENDED_FAMILY_REASONING = {
    "sql_injection": _policy("SQL Injection", "server_injection",
        [{"sql_input"}, {"sql_query_sink"}, {"unsafe_sql_concatenation_observed", "sql_error_signature_observed", "sql_query_influence_observed", "sql_behavior_differential"}],
        {"parameterized_query_observed", "query_parameter_binding_observed", "input_not_reaching_query"},
        {"sql_query_influence_observed", "sql_behavior_differential"}, {"sql_query_influence_observed", "sql_behavior_differential"}, INJECTION_REQ,
        ["Map the exact input to SQL construction.", "Establish bound-parameter behavior.", "Use benign controlled observations; never extract/modify database data."], "manual_only"),
    "nosql_injection": _policy("NoSQL Injection", "server_injection",
        [{"nosql_input"}, {"nosql_query_sink"}, {"unsafe_nosql_query_construction_observed", "nosql_operator_surface_observed", "nosql_query_influence_observed", "nosql_operator_injection_observed"}],
        {"typed_schema_enforced", "nosql_operator_allowlist_enforced", "input_not_reaching_query"},
        {"nosql_query_influence_observed", "nosql_operator_injection_observed"}, {"nosql_query_influence_observed", "nosql_operator_injection_observed"}, INJECTION_REQ,
        ["Map scalar/object input to NoSQL query construction.", "Check type/operator enforcement.", "Use benign test-owned records only."], "manual_only"),
    "command_injection": _policy("OS Command Injection", "server_injection",
        [{"command_input"}, {"os_command_sink"}, {"unsafe_command_construction_observed", "command_execution_influence_observed", "command_argument_boundary_bypass_observed"}],
        {"argument_array_enforced", "command_allowlist_enforced", "input_not_reaching_command"},
        {"command_execution_influence_observed", "command_argument_boundary_bypass_observed"}, {"command_execution_influence_observed", "command_argument_boundary_bypass_observed"}, INJECTION_REQ,
        ["Trace input to process/shell invocation.", "Establish argument-array/allow-list/shell-avoidance controls.", "Never execute system commands automatically."], "manual_only"),
    "ssti": _policy("Server-Side Template Injection", "server_injection",
        [{"template_input"}, {"server_template_sink"}, {"unsafe_template_interpolation_observed", "template_expression_evaluated", "template_sandbox_escape_observed"}],
        {"literal_template_rendering_observed", "template_sandbox_enforced", "input_not_reaching_template"},
        {"template_expression_evaluated", "template_sandbox_escape_observed"}, {"template_expression_evaluated", "template_sandbox_escape_observed"}, INJECTION_REQ,
        ["Trace input to server-side template compilation/rendering.", "Establish literal rendering/sandbox controls.", "Never use code-execution template payloads."], "manual_only"),
    "ldap_injection": _policy("LDAP Injection", "server_injection",
        [{"ldap_input"}, {"ldap_filter_sink"}, {"unsafe_ldap_filter_construction_observed", "ldap_filter_influence_observed", "ldap_query_differential"}],
        {"ldap_filter_escaping_observed", "ldap_parameterization_observed", "input_not_reaching_ldap"},
        {"ldap_filter_influence_observed", "ldap_query_differential"}, {"ldap_filter_influence_observed", "ldap_query_differential"}, INJECTION_REQ,
        ["Map input to LDAP filter/DN construction.", "Establish escaping/parameterization/search-scope controls.", "Use controlled directory identities only."], "manual_only"),
    "unrestricted_resource_consumption": _policy("Unrestricted Resource Consumption", "api_abuse",
        [{"resource_consuming_operation"}, {"resource_limit_missing", "resource_limit_weak", "resource_limit_not_enforced", "unbounded_batch_accepted", "cost_amplification_observed"}],
        {"rate_limit_enforced", "pagination_limit_enforced", "upload_size_limit_enforced", "execution_timeout_enforced", "batch_limit_enforced", "cost_quota_enforced"},
        {"resource_limit_not_enforced", "unbounded_batch_accepted", "cost_amplification_observed"}, {"resource_limit_not_enforced", "unbounded_batch_accepted", "cost_amplification_observed"}, RESOURCE_REQ,
        ["Document intended rate/size/batch/timeout/cost boundaries.", "Use bounded authorized observations only.", "Never automate load, concurrency, DoS, or cost amplification."], "manual_only"),
    "sensitive_business_flow_abuse": _policy("Sensitive Business Flow Abuse", "api_abuse",
        [{"sensitive_business_flow"}, {"abuse_control_missing", "abuse_control_weak", "business_limit_bypass_observed", "excessive_flow_access_accepted"}],
        {"anti_automation_enforced", "business_limit_enforced", "queue_or_quota_enforced", "scarce_inventory_protected"},
        {"business_limit_bypass_observed", "excessive_flow_access_accepted"}, {"business_limit_bypass_observed", "excessive_flow_access_accepted"}, BUSINESS_REQ,
        ["Document why the flow is business-sensitive.", "Document expected abuse-control limits.", "Use reversible test-owned actions; never consume real inventory."], "manual_only"),
    "security_misconfiguration": _policy("Security Misconfiguration", "configuration",
        [{"configuration_surface"}, {"debug_mode_publicly_exposed", "directory_listing_observed", "dangerous_http_method_enabled", "management_interface_publicly_exposed", "insecure_transport_configuration_observed"}],
        {"secure_configuration_observed", "debug_disabled", "directory_listing_disabled", "dangerous_methods_disabled", "management_interface_restricted"},
        {"debug_mode_publicly_exposed", "directory_listing_observed", "dangerous_http_method_enabled", "management_interface_publicly_exposed", "insecure_transport_configuration_observed"},
        {"debug_mode_publicly_exposed", "directory_listing_observed", "dangerous_http_method_enabled", "management_interface_publicly_exposed", "insecure_transport_configuration_observed"}, CONFIG_REQ,
        ["Capture exact observable configuration and production baseline.", "Keep CORS/cache/source-map in specialized families.", "Prefer passive metadata; never change target configuration."], "passive_live", 1),
    "improper_inventory_management": _policy("Improper API Inventory Management", "api_inventory",
        [{"api_inventory_surface"}, {"inventory_drift_signal", "deprecated_api_publicly_reachable", "undocumented_api_publicly_reachable", "debug_api_publicly_reachable", "stale_api_host_publicly_reachable"}],
        {"inventory_documented", "version_decommissioned", "debug_endpoint_restricted", "stale_host_not_reachable"},
        {"deprecated_api_publicly_reachable", "undocumented_api_publicly_reachable", "debug_api_publicly_reachable", "stale_api_host_publicly_reachable"},
        {"deprecated_api_publicly_reachable", "undocumented_api_publicly_reachable", "debug_api_publicly_reachable", "stale_api_host_publicly_reachable"}, INVENTORY_REQ,
        ["Compare surfaces with authoritative inventory.", "Establish lifecycle status and public reachability.", "Never expand scope to similar-looking unrelated hosts."], "passive_live"),
    "unsafe_api_consumption": _policy("Unsafe Consumption of APIs", "api_supply_chain",
        [{"third_party_api_integration"}, {"upstream_data_trust_boundary"}, {"upstream_validation_missing", "upstream_tls_missing", "upstream_timeout_missing", "upstream_size_limit_missing", "upstream_redirect_unrestricted", "untrusted_upstream_data_reaches_sensitive_sink", "unencrypted_upstream_observed", "cross_trust_upstream_redirect_followed", "upstream_response_limit_bypass_observed"}],
        {"upstream_validation_enforced", "upstream_tls_enforced", "upstream_timeout_enforced", "upstream_size_limit_enforced", "upstream_redirect_policy_enforced"},
        {"untrusted_upstream_data_reaches_sensitive_sink", "unencrypted_upstream_observed", "cross_trust_upstream_redirect_followed", "upstream_response_limit_bypass_observed"},
        {"untrusted_upstream_data_reaches_sensitive_sink", "unencrypted_upstream_observed", "cross_trust_upstream_redirect_followed", "upstream_response_limit_bypass_observed"}, UPSTREAM_REQ,
        ["Map the third-party dependency and downstream consumption path.", "Document transport/validation/redirect/timeout/size controls.", "Never probe the upstream service; use target-side evidence only."], "manual_only"),
}

assert tuple(EXTENDED_FAMILY_REASONING) == NEW_FAMILY_ORDER

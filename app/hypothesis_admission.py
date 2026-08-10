from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, sha256_text, utc_now
from analysis_standards import standards_for_family, validate_family_standards

ADMISSION_ENGINE_VERSION = "2.2.0"
ADMISSION_RULE_VERSION = "2026.08.10.6.3"

# External knowledge informs detection criteria only. It is never counted as target evidence.
KNOWLEDGE_REFERENCES: dict[str, list[dict[str, str]]] = {
    "broken_object_authorization": [
        {
            "source": "OWASP API Security Top 10",
            "ref": "API1:2023 Broken Object Level Authorization",
            "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "principle": "An object identifier is only the attack surface; object-level authorization must verify that the logged-in identity may perform the requested action on the requested object.",
        },
        {
            "source": "OWASP WSTG",
            "ref": "WSTG-APIT-02 / WSTG-ATHZ-04",
            "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization",
            "principle": "BOLA evidence requires an object reference plus an authorization-boundary comparison; IDs alone do not establish unauthorized access.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-639",
            "url": "https://cwe.mitre.org/data/definitions/639.html",
            "principle": "The weakness requires a user-controlled key to select a record while the authorization decision fails to enforce the caller's entitlement to that record.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-029 / Spree",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-029_Spree/",
            "principle": "A real IDOR may involve a valid object key being accepted without a secondary ownership or access guard that should bind the request to the object.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-049 / Zammad",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-049_Zammad/",
            "principle": "Fetching an object by ID becomes security-relevant when the resulting operation bypasses the role or group boundary that should authorize access to that object.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-044 / Wekan",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-044_Wekan/",
            "principle": "Authorizing a parent object is insufficient when a separately supplied child object identifier is not verified to belong to that parent.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2025-130 / Sentry",
            "url": "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/",
            "principle": "A tenant or organization context must be bound to the referenced object; a valid scope on one tenant does not authorize an object belonging to another tenant.",
        },
    ],
    "file_upload": [
        {
            "source": "OWASP",
            "ref": "Unrestricted File Upload",
            "url": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "principle": "Upload risk depends on actual file handling, including file metadata, content, storage, and processing behavior.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-434",
            "url": "https://cwe.mitre.org/data/definitions/434.html",
            "principle": "The weakness concerns a product accepting an uploaded file of a dangerous type without sufficient restriction.",
        },
        {
            "source": "PortSwigger Web Security Academy",
            "ref": "File upload vulnerabilities",
            "url": "https://portswigger.net/web-security/file-upload",
            "principle": "A file-upload surface requires an actual upload capability; generic Content-Type metadata alone is not evidence of an upload function.",
        },
    ],
    "path_traversal": [
        {
            "source": "OWASP",
            "ref": "Path Traversal",
            "url": "https://owasp.org/www-community/attacks/Path_Traversal",
            "principle": "Path traversal requires attacker-influenced path data to affect access to a file or directory outside the intended location.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-22",
            "url": "https://cwe.mitre.org/data/definitions/22.html",
            "principle": "External input must participate in construction of a pathname whose restriction to an intended directory is not properly enforced.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "CVE-2024-36116 / archive path traversal",
            "url": "https://github.blog/security/vulnerability-research/attacks-on-maven-proxy-repositories/",
            "principle": "Real path-traversal findings connect attacker-controlled archive or filename data to a filesystem write/read operation, rather than relying on path words alone.",
        },
    ],
}

# Analysis 6.0 expands the knowledge map to the families that previously relied
# mostly on generic scoring. These references are explanatory context only.
KNOWLEDGE_REFERENCES.update({
    "broken_function_authorization": [{
        "source": "OWASP API Security Top 10", "ref": "API5:2023 Broken Function Level Authorization",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "principle": "A privileged-looking route is an attack surface; a candidate needs evidence that an unauthorized or lower-privilege identity can execute the protected function.",
    }],
    "mass_assignment": [{
        "source": "OWASP API Security Top 10", "ref": "API3:2023 Broken Object Property Level Authorization",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "principle": "Client-visible privileged properties are only a surface; the server must accept, return, or apply a property outside the caller's permitted property set.",
    }],
    "account_enumeration": [{
        "source": "OWASP WSTG", "ref": "Account Enumeration",
        "url": "https://owasp.org/www-project-web-security-testing-guide/",
        "principle": "Enumeration depends on an observable response, error, or timing differential between controlled existing and non-existing identities.",
    }],
    "dom_xss": [{
        "source": "OWASP WSTG", "ref": "Testing for DOM-based Cross Site Scripting",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting",
        "principle": "Source/sink proximity is a clue; a candidate needs a traceable user-controlled flow into an executable/HTML sink with runtime or sanitization evidence.",
    }],
    "postmessage_trust": [{
        "source": "OWASP WSTG", "ref": "Testing Web Messaging",
        "url": "https://owasp.org/www-project-web-security-testing-guide/",
        "principle": "A message handler becomes a candidate when attacker-controllable messages reach sensitive behavior without strict origin/source/schema validation.",
    }],
    "open_redirect": [{
        "source": "OWASP WSTG", "ref": "Testing for Client-side URL Redirect",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        "principle": "Redirect parameter names are not findings; the destination must be user controlled and able to reach an unintended external location or bypass destination restrictions.",
    }, {
        "source": "GitHub Security Lab", "ref": "GHSL-2025-121 / NocoDB",
        "url": "https://securitylab.github.com/advisories/",
        "principle": "A real redirect weakness includes an attacker-controlled external destination accepted without the expected origin/domain restriction.",
    }],
    "ssrf": [{
        "source": "OWASP API Security Top 10", "ref": "API7:2023 Server Side Request Forgery",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
        "principle": "SSRF requires both a user-controlled destination and evidence that the server performs or attempts the outbound request.",
    }, {
        "source": "GitHub Security Lab", "ref": "SSRF write-up pattern",
        "url": "https://securitylab.github.com/advisories/",
        "principle": "Real SSRF write-ups connect a controllable URL to a backend fetch primitive; URL-looking fields alone are insufficient.",
    }],
    "graphql_authorization": [{
        "source": "OWASP API Security Top 10", "ref": "API1/API3 authorization principles applied to GraphQL",
        "url": "https://owasp.org/API-Security/editions/2023/en/0x00-toc/",
        "principle": "GraphQL operations and IDs are authorization surfaces; resolver/object/role boundary failure is the decisive evidence.",
    }],
    "graphql_data_exposure": [{
        "source": "OWASP API Security Top 10", "ref": "API3:2023 Broken Object Property Level Authorization",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "principle": "Sensitive GraphQL field names are not enough; the current role must actually receive fields outside the intended field policy.",
    }],
    "cors_misconfiguration": [{
        "source": "OWASP WSTG", "ref": "Cross Origin Resource Sharing",
        "url": "https://owasp.org/www-project-web-security-testing-guide/",
        "principle": "The presence of Access-Control-Allow-Origin is not a weakness; an unsafe origin policy must combine with credentialed or sensitive cross-origin exposure.",
    }],
    "business_logic": [{
        "source": "OWASP WSTG", "ref": "Business Logic Testing",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
        "principle": "Business-operation names define hypotheses; a candidate needs an observed violation of a workflow, value, state, or authorization invariant.",
    }],
})


# Analysis 6.1 coverage expansion: OWASP/WSTG and representative write-ups
# define what counts as decisive evidence for newly modeled families. These
# references never count as target evidence.
KNOWLEDGE_REFERENCES.update({
    "sql_injection": [{
        "source": "OWASP Top 10 / WSTG", "ref": "A03:2021 Injection / WSTG-INPV-05 SQL Injection",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
        "principle": "A parameter or search endpoint is only an injection surface; a candidate needs evidence that user-controlled input changes SQL query semantics, database errors, boolean results, or database timing."
    }, {
        "source": "GitHub Security Lab", "ref": "GHSL-2023-141 NocoDB SQL injection",
        "url": "https://securitylab.github.com/advisories/GHSL-2023-141_nocodb_nocodb/",
        "principle": "A real SQL injection connects a user-controlled value to dynamic SQL construction and observes query execution through output, errors, or timing."
    }],
    "nosql_injection": [{
        "source": "OWASP WSTG", "ref": "Testing for NoSQL Injection",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
        "principle": "JSON/operator-shaped input is only a surface until attacker-controlled operators or query structure measurably alter the database operation."
    }],
    "command_injection": [{
        "source": "OWASP WSTG", "ref": "WSTG-INPV-12 Command Injection",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
        "principle": "A diagnostic or command-like parameter is only a surface; decisive evidence links attacker-controlled input to operating-system command execution or a command-specific output/timing effect."
    }, {
        "source": "GitHub Security Lab", "ref": "GHSL-2020-112 systeminformation command injection",
        "url": "https://securitylab.github.com/advisories/GHSL-2020-112-systeminformation/",
        "principle": "Real command injection findings show untrusted data reaching a shell/interpreter and producing a process side effect."
    }],
    "server_side_template_injection": [{
        "source": "OWASP WSTG", "ref": "Testing for Server-Side Template Injection",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection",
        "principle": "Template or preview functionality is only a surface; a candidate requires evidence that user-controlled template syntax is evaluated server-side."
    }, {
        "source": "GitHub Security Lab", "ref": "GHSL-2020-227 SCIMono SSTI",
        "url": "https://securitylab.github.com/advisories/GHSL-2020-227-scimono-ssti/",
        "principle": "A real SSTI connects untrusted text to a template/expression engine and observes expression evaluation or execution."
    }],
    "ldap_injection": [{
        "source": "OWASP WSTG", "ref": "Testing for LDAP Injection",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection",
        "principle": "Directory search parameters are only surfaces; promotion requires evidence that user input changes the LDAP filter or authentication/search result."
    }],
    "unrestricted_resource_consumption": [{
        "source": "OWASP API Security Top 10", "ref": "API4:2023 Unrestricted Resource Consumption",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "principle": "Pagination, batching, upload, expensive processing, or paid-provider operations are surfaces; a candidate requires stored evidence that a relevant size/frequency/cost/timeout limit is absent or ineffective."
    }],
    "sensitive_business_flow_abuse": [{
        "source": "OWASP API Security Top 10", "ref": "API6:2023 Unrestricted Access to Sensitive Business Flows",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
        "principle": "Purchasing, reservation, posting, signup, redemption, or similar sensitive flows are surfaces; promotion requires evidence that automation/frequency/business limits are absent or bypassed."
    }],
    "security_misconfiguration": [{
        "source": "OWASP API Security Top 10", "ref": "API8:2023 Security Misconfiguration",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "principle": "Configuration markers are not enough; a candidate requires a directly observed insecure configuration such as stack traces, debug mode, cleartext transport, unnecessary methods, directory listing, or inconsistent HTTP processing."
    }],
    "improper_inventory_management": [{
        "source": "OWASP API Security Top 10", "ref": "API9:2023 Improper Inventory Management",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
        "principle": "Version, beta, staging, or legacy naming is only inventory surface; promotion requires evidence that an old/retired/undocumented deployment remains reachable with weaker controls, real data, or inventory drift."
    }],
    "unsafe_api_consumption": [{
        "source": "OWASP API Security Top 10", "ref": "API10:2023 Unsafe Consumption of APIs",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
        "principle": "Third-party integrations are surfaces; a candidate requires evidence that upstream transport, redirects, response validation, resource limits, authentication, or downstream sanitization is unsafe."
    }],
})

# Admission is intentionally stricter than hypothesis generation. Signals that fail
# admission remain persisted in analysis_hypotheses so recall is preserved.
FAMILY_ADMISSION_POLICIES: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {
        "required": [
            {"object_identifier", "graphql_identifier"},
            {"object_operation", "graphql_operation"},
            {"cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch", "parent_child_scope_mismatch", "authorization_response_differential", "object_access_without_secondary_guard", "identity_object_relation_conflict", "unauthorized_object_response"},
        ],
        "min_independent_sources": 2,
        "label": "object reference + operation + object-level authorization failure evidence",
        "blocking_contradictions": {"ownership_enforcement_observed", "cross_context_denied", "scope_binding_observed", "secondary_guard_enforced"},
        "override_signals": {"cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch", "parent_child_scope_mismatch", "authorization_response_differential", "object_access_without_secondary_guard", "identity_object_relation_conflict", "unauthorized_object_response"},
    },
    "broken_function_authorization": {
        "required": [
            {"privileged_function", "privileged_classification", "sensitive_operation"},
            {"state_change", "role_property", "role_hint"},
            {"lower_privilege_success", "unauthorized_function_response", "role_boundary_failure", "authorization_response_differential", "function_access_without_role", "role_boundary_regression"},
        ],
        "min_independent_sources": 2,
        "label": "privileged function + role context + observed function-level authorization failure",
        "blocking_contradictions": {"confirmed_role_enforcement", "lower_privilege_denied", "role_boundary_enforced"},
    },
    "mass_assignment": {
        "required": [
            {"write_method", "state_change"},
            {"privileged_property", "privileged_fields", "privileged_contract_fields"},            {"privileged_property_accepted", "unauthorized_property_change", "property_authorization_differential", "response_reflects_privileged_change"},
        ],
        "min_independent_sources": 2,
        "label": "writable privileged property + evidence the server accepted/applied it outside the property policy",
        "blocking_contradictions": {"field_allowlist", "privileged_fields_removed", "privileged_property_rejected", "read_only_contract"},
    },
    "authentication_session": {
        "required": [
            {"authentication_surface", "authentication_semantic", "auth_boundary", "oauth_parameter", "token_storage", "authentication_boundary_regression"},
            {"authentication_boundary_regression", "boundary_regression", "protected_to_public", "session_validation_failure", "token_rotation_failure", "missing_state", "token_exposure"},
        ],
        "min_independent_sources": 2,
        "label": "authentication/session surface + observed control regression or lifecycle failure",
        "blocking_contradictions": {"stable_boundary", "pkce_present", "state_present"},
    },
    "account_enumeration": {
        "required": [
            {"identity_lookup", "account_identifier", "identity_field"},
            {"response_difference", "timing_difference", "distinct_error", "error_schema", "account_existence_differential"},
        ],
        "min_independent_sources": 2,
        "label": "identity lookup + observable existing/non-existing account differential",
        "blocking_contradictions": {"uniform_response", "generic_error"},
    },
    "dom_xss": {
        "required": [
            {"source_sink", "taint_flow"},
            {"dangerous_sink", "html_sink", "javascript_sink"},
            {"runtime_reachable_flow", "javascript_runtime", "reachable_route", "no_sanitizer"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled source-to-dangerous-sink flow with runtime/sanitization evidence",
        "blocking_contradictions": {"recognized_sanitizer", "text_only_sink", "constant_value", "non_reachable"},
    },
    "postmessage_trust": {
        "required": [
            {"postmessage_handler", "message_source"},
            {"message_sink", "sensitive_message_action", "dangerous_sink"},
            {"missing_origin_check", "wildcard_origin", "missing_source_window_check", "message_schema_unvalidated"},
        ],
        "min_independent_sources": 2,
        "label": "attacker-controllable message + sensitive action + missing origin/source/schema enforcement",
        "blocking_contradictions": {"strict_origin_check", "source_window_check", "schema_validation"},
    },
    "open_redirect": {
        "required": [
            {"redirect_parameter", "user_controlled_destination", "source_sink"},
            {"navigation_sink", "client_navigation", "redirect_response"},
            {"external_url", "external_destination", "allowlist_bypass", "same_origin_bypass", "unrestricted_destination"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled destination + navigation sink + evidence an unintended external destination is accepted",
        "blocking_contradictions": {"same_origin_only", "relative_path_only", "host_allowlist", "constant_value"},
    },
    "ssrf": {
        "required": [
            {"url_parameter", "remote_destination", "remote_resource"},
            {"server_fetch_observed", "server_fetch_semantic", "server_request_function", "backend_fetch", "webhook_delivery_observed", "remote_import_fetch"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled remote destination + evidence the server performs the outbound request",
        "blocking_contradictions": {"browser_side_only", "relative_path_only", "host_allowlist", "predefined_destination"},
    },
    "file_upload": {
        "required": [
            {"file_input"},
            {"upload_operation", "import_operation"},
            {"dangerous_type_accepted", "content_type_mismatch_accepted", "active_content_served", "unsafe_storage", "executable_upload", "filename_control_reaches_storage", "upload_validation_bypass"},
        ],
        "min_independent_sources": 2,
        "label": "actual file input + upload/import operation + observed unsafe file-handling behavior",
        "blocking_contradictions": {"strict_type_allowlist", "inert_storage", "server_generated_filename", "upload_rejected"},
    },
    "path_traversal": {
        "required": [
            {"path_parameter", "filename_field", "storage_path"},
            {"file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation"},
            {"filesystem_path_reachability", "path_escape_observed", "canonicalization_bypass", "base_directory_escape", "archive_entry_escape", "path_join_user_controlled"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled path/filename + file operation + filesystem/confinement-failure evidence",
        "blocking_contradictions": {"canonicalization", "fixed_directory", "opaque_file_id", "path_rejected"},
    },
    "information_disclosure": {
        "required": [
            {"sensitive_fields", "secret_pattern", "debug_information", "sensitive_marker", "sensitive_expansion"},
            {"public_observation", "unauthorized_data_response", "protected_to_data", "error_to_data", "response_data"},
        ],
        "min_independent_sources": 2,
        "label": "sensitive/debug material + observed response exposure in a public or unintended context",
        "blocking_contradictions": {"redacted_only", "placeholder", "authentication_required", "intended_public"},
    },
    "graphql_authorization": {
        "required": [
            {"graphql_operation"},
            {"graphql_identifier", "parameter_relation"},
            {"cross_context", "authorization_response_differential", "unauthorized_object_response", "resolver_authorization_failure", "cross_identity_object_access", "cross_tenant_object_access"},
        ],
        "min_independent_sources": 2,
        "label": "GraphQL object operation + identifier + resolver/object authorization failure evidence",
        "blocking_contradictions": {"resolver_authorization", "cross_context_denied", "schema_only"},
    },
    "graphql_data_exposure": {
        "required": [
            {"graphql_operation", "client_operation"},
            {"sensitive_fields", "nested_sensitive_fields"},
            {"response_data", "field_expansion", "unauthorized_data_response", "cross_context", "sensitive_expansion"},
        ],
        "min_independent_sources": 2,
        "label": "GraphQL sensitive fields + evidence those fields are actually exposed outside the intended field policy",
        "blocking_contradictions": {"schema_only", "field_authorization", "minimal_projection"},
    },
    "websocket_authorization": {
        "required": [
            {"websocket_channel", "websocket_url", "subscribe_operation"},
            {"object_identifier", "identity_relation", "room_identifier", "tenant_channel", "user_channel"},
            {"unauthorized_subscription", "cross_context", "channel_authorization_failure", "message_received_outside_scope"},
        ],
        "min_independent_sources": 2,
        "label": "channel/object surface + identity scope + observed subscription/message authorization failure",
        "blocking_contradictions": {"channel_authorization", "authenticated_handshake", "cross_context_denied"},
    },
    "cors_misconfiguration": {
        "required": [
            {"wildcard_origin", "reflected_origin", "null_origin_accepted", "unsafe_origin_policy"},
            {"credentials_allowed", "sensitive_cross_origin_response", "authenticated_context"},
        ],
        "min_independent_sources": 2,
        "label": "unsafe CORS origin policy + credentialed or sensitive cross-origin exposure",
        "blocking_contradictions": {"strict_origin_allowlist", "credentials_disabled", "public_intended"},
    },
    "sensitive_caching": {
        "required": [
            {"cache_header", "public_cache", "cacheable_response_context"},
            {"sensitive_fields", "authenticated_context", "response_data", "sensitive_context"},
            {"shared_cache_risk", "missing_vary", "cdn_cache", "cache_key_missing_auth_context"},
        ],
        "min_independent_sources": 2,
        "label": "cacheable response + sensitive/authenticated data + shared-cache isolation weakness",
        "blocking_contradictions": {"no_store", "private_cache", "vary_authorization"},
    },
    "business_logic": {
        "required": [
            {"business_operation", "workflow_transition", "state_change", "stateful_operation"},
            {"workflow_invariant_violation", "value_constraint_bypass", "invalid_transition_accepted", "server_calculation_mismatch", "business_rule_bypass"},
        ],
        "min_independent_sources": 2,        "label": "business operation + observed violation of the intended workflow/value/state invariant",
        "blocking_contradictions": {"state_machine_enforced", "server_side_calculation_enforced", "read_only_contract"},
    },
    "race_condition": {
        "required": [
            {"state_change", "stateful_operation"},
            {"single_use_operation", "balance_operation", "duplicate_operation", "single_use_semantics"},
            {"duplicate_effect_observed", "atomicity_failure", "concurrency_invariant_violation", "double_spend_observed"},
        ],
        "min_independent_sources": 2,
        "label": "state-changing single-use/balance operation + observed duplicate or atomicity failure",
        "blocking_contradictions": {"idempotency_control", "transaction_lock", "duplicate_rejected"},
    },

    "sql_injection": {
        "required": [
            {"input_parameter", "query_parameter", "body_parameter", "path_parameter"},
            {"sql_query_surface", "database_query_semantic", "dynamic_query_surface"},
            {"sql_error_differential", "boolean_response_differential", "database_time_delay_observed", "query_structure_influence", "database_error_observed", "unsafe_query_construction"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled input + SQL query surface + observed SQL semantic/error/boolean/timing influence",
        "blocking_contradictions": {"parameterized_query", "query_builder_binding", "input_not_used_in_query", "uniform_database_behavior"},
    },
    "nosql_injection": {
        "required": [
            {"input_parameter", "query_parameter", "body_parameter"},
            {"nosql_query_surface", "json_query_surface", "document_query_semantic"},
            {"nosql_operator_accepted", "query_operator_influence", "nosql_auth_bypass_observed", "nosql_response_differential", "nosql_error_observed"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled structured input + NoSQL query surface + observed operator/query influence",
        "blocking_contradictions": {"operator_allowlist", "typed_query_schema", "input_not_used_in_query", "nosql_operator_rejected"},
    },
    "command_injection": {
        "required": [
            {"input_parameter", "query_parameter", "body_parameter", "path_parameter"},
            {"command_execution_surface", "shell_command_semantic", "process_execution_surface"},
            {"command_output_observed", "command_time_delay_observed", "shell_metacharacter_effect", "process_execution_reached", "unsafe_command_construction"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled input + OS/process execution surface + observed command execution effect",
        "blocking_contradictions": {"exec_file_argument_array", "shell_disabled", "command_allowlist", "input_not_used_in_command"},
    },
    "server_side_template_injection": {
        "required": [
            {"input_parameter", "body_parameter", "template_input"},
            {"template_render_surface", "template_engine_semantic", "server_render_operation"},
            {"template_expression_evaluated", "template_output_differential", "template_engine_error_observed", "server_template_execution"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled template input + server-side rendering surface + observed expression evaluation",
        "blocking_contradictions": {"literal_template_rendering", "template_sandbox_enforced", "template_input_escaped", "client_side_only"},
    },
    "ldap_injection": {
        "required": [
            {"input_parameter", "query_parameter", "body_parameter"},
            {"ldap_query_surface", "directory_query_semantic", "ldap_filter_surface"},
            {"ldap_filter_influence", "ldap_response_differential", "ldap_auth_bypass_observed", "ldap_error_observed"},
        ],
        "min_independent_sources": 2,
        "label": "user-controlled directory input + LDAP filter/search surface + observed filter/result influence",
        "blocking_contradictions": {"ldap_filter_escaped", "ldap_parameter_binding", "ldap_input_rejected"},
    },
    "unrestricted_resource_consumption": {
        "required": [
            {"resource_control_parameter", "batch_operation", "pagination_control", "upload_size_control", "expensive_operation", "paid_provider_operation"},
            {"rate_limit_absent_observed", "unbounded_page_size_observed", "batch_limit_absent_observed", "oversized_payload_accepted", "cost_amplification_observed", "timeout_limit_absent", "resource_exhaustion_differential"},
        ],
        "min_independent_sources": 2,
        "label": "resource-amplifying API control + observed missing/ineffective size, frequency, timeout, or cost limit",
        "blocking_contradictions": {"rate_limit_enforced", "page_size_capped", "batch_limit_enforced", "payload_size_rejected", "spending_limit_enforced", "timeout_enforced"},
    },
    "sensitive_business_flow_abuse": {
        "required": [
            {"sensitive_business_flow", "purchase_flow", "reservation_flow", "posting_flow", "signup_flow", "redemption_flow"},
            {"automation_limit_absent", "anti_bot_control_absent", "per_user_limit_absent", "bulk_abuse_observed", "scalping_control_absent", "reservation_abuse_observed", "workflow_frequency_unrestricted", "business_flow_limit_bypass"},
        ],
        "min_independent_sources": 2,
        "label": "sensitive business flow + observed missing/bypassable automation or frequency restriction",
        "blocking_contradictions": {"anti_bot_control_enforced", "per_user_limit_enforced", "inventory_limit_enforced", "reservation_limit_enforced", "workflow_frequency_limited"},
    },
    "security_misconfiguration": {
        "required": [
            {"misconfiguration_surface", "debug_surface", "transport_surface", "http_method_surface", "deployment_configuration_surface"},
            {"stack_trace_exposed", "debug_mode_exposed", "insecure_http_enabled", "unnecessary_method_enabled", "directory_listing_observed", "security_header_missing_on_sensitive_response", "desync_processing_difference", "unsafe_default_configuration"},
        ],
        "min_independent_sources": 2,
        "label": "configuration surface + directly observed insecure deployment/application-stack configuration",
        "blocking_contradictions": {"hardening_observed", "tls_enforced", "method_rejected", "debug_disabled", "security_headers_present"},
    },
    "improper_inventory_management": {
        "required": [
            {"api_version_surface", "legacy_endpoint_surface", "nonproduction_surface", "undocumented_host_surface"},
            {"deprecated_version_still_reachable", "older_version_weaker_controls", "undocumented_host_observed", "nonproduction_with_production_data", "retired_endpoint_active", "inventory_drift_observed", "unprotected_legacy_endpoint"},
        ],
        "min_independent_sources": 2,
        "label": "version/deployment inventory surface + observed active legacy, undocumented, or non-production exposure with security relevance",
        "blocking_contradictions": {"retired_endpoint_unreachable", "legacy_controls_equivalent", "nonproduction_isolated", "inventory_documented"},
    },
    "unsafe_api_consumption": {
        "required": [
            {"third_party_integration", "upstream_api_surface", "external_service_dependency"},
            {"upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink"},
        ],
        "min_independent_sources": 2,
        "label": "third-party/upstream API dependency + observed unsafe transport, trust, redirect, resource, auth, or validation behavior",
        "blocking_contradictions": {"upstream_tls_enforced", "third_party_schema_validation", "upstream_redirect_restricted", "upstream_timeout_enforced", "upstream_response_capped"},
    },
    "source_map_exposure": {
        "required": [{"source_map"}, {"internal_sources", "source_contents"}, {"public_observation", "direct_reachability"}],
        "min_independent_sources": 2,
        "label": "source map + meaningful source content + verified public reachability",
        "blocking_contradictions": {"non_reachable", "empty_map", "intended_public"},
    },
    "secret_exposure": {
        "required": [{"secret_pattern"}, {"production_javascript", "client_operation", "javascript_runtime"}, {"high_entropy_value", "credential_context", "token_exposure", "non_placeholder_secret"}],
        "min_independent_sources": 2,
        "label": "secret-like material in production client context + evidence it is non-placeholder credential material",
        "blocking_contradictions": {"placeholder", "example_value", "redacted_only"},
    },
}

_STANDARD_GROUNDING_ERRORS = validate_family_standards(FAMILY_ADMISSION_POLICIES)
if _STANDARD_GROUNDING_ERRORS:
    raise RuntimeError("Analysis standard grounding is incomplete: " + ", ".join(_STANDARD_GROUNDING_ERRORS))


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _merge(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        item = dict(raw)
        key = json_dumps(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def hypothesis_fingerprint(target: str, family: str, variant: str, endpoint: str) -> str:
    normalized_endpoint = re.sub(r"\b\d{2,}\b", "{n}", str(endpoint or "").lower())
    normalized_endpoint = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", normalized_endpoint, flags=re.I)
    return sha256_text("|".join([target, family, variant, normalized_endpoint]))


def knowledge_for_family(family: str) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = [dict(item) for item in KNOWLEDGE_REFERENCES.get(family, [])]
    standards = standards_for_family(family)
    for item in standards.get("wstg", []):
        refs.append({
            "source": "OWASP WSTG",
            "ref": str(item.get("id") or ""),
            "url": str(item.get("url") or ""),
            "principle": str(standards.get("principle") or ""),
        })
    for item in standards.get("cwe", []):
        refs.append({
            "source": "MITRE CWE",
            "ref": f"{item.get('id')} / {item.get('title')}",
            "url": str(item.get("url") or ""),
            "principle": str(standards.get("principle") or ""),
        })
    return refs


def assess_admission(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    types = {str(item.get("type") or "") for item in support_items}
    contradiction_types = {str(item.get("type") or "") for item in contradict_items}
    sources = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in support_items
    }
    policy = FAMILY_ADMISSION_POLICIES.get(family)
    if not policy:
        return {
            "state": "admitted",
            "admitted": True,
            "policy": "existing-family-gate",
            "required_satisfied": [],
            "required_missing": [],
            "independent_sources": len(sources),
            "decisive_signals": sorted(types),
            "blocking_contradictions": [],
            "reason": "No Analysis 6.0 admission policy is defined for this family; the existing family-specific reasoning gate remains authoritative.",
            "knowledge_references": knowledge_for_family(family),
            "standards": standards_for_family(family, admitted=True, decisive_signals=types),
        }

    satisfied: list[list[str]] = []
    missing: list[list[str]] = []
    decisive: set[str] = set()
    for group in policy.get("required", []):
        matches = sorted(set(group) & types)
        if matches:
            satisfied.append(matches)
            decisive.update(matches)
        else:
            missing.append(sorted(group))

    source_ok = len(sources) >= int(policy.get("min_independent_sources", 1))
    blocking = sorted(set(policy.get("blocking_contradictions", set())) & contradiction_types)
    override = bool(set(policy.get("override_signals", set())) & types)
    blocked = bool(blocking) and not override
    complete = not missing and source_ok and not blocked

    if complete:
        state = "admitted"
        reason = f"Admission complete: {policy.get('label')}."
    elif blocked:
        state = "shadow_contradicted"
        reason = f"Retained as a hidden hypothesis because stored target evidence supports enforcement: {', '.join(blocking)}."
    elif satisfied:
        state = "shadow_partial"
        reason = f"Retained as a hidden hypothesis: attack-surface/partial evidence exists for {policy.get('label')}, but decisive vulnerability-condition evidence is incomplete."
    else:
        state = "shadow_signal"
        reason = f"Retained as a hidden hypothesis: no decisive family-specific evidence yet for {policy.get('label')}."
    if not source_ok:
        reason += f" Independent-source requirement is not yet met ({len(sources)}/{policy.get('min_independent_sources', 1)})."

    return {
        "state": state,
        "admitted": complete,
        "policy": policy.get("label"),
        "required_satisfied": satisfied,
        "required_missing": missing,
        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
        "reason": reason,
        "knowledge_references": knowledge_for_family(family),
        "standards": standards_for_family(family, admitted=complete, decisive_signals=decisive),
    }


def record_hypothesis(
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
    support: list[dict[str, Any]],
    contradict: list[dict[str, Any]],
    missing: list[str],
    rule_ids: list[str],
    summary: str,
) -> dict[str, Any]:
    fingerprint = hypothesis_fingerprint(target, family, variant, endpoint)
    existing = db.one(
        "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (analysis_id, fingerprint),
    )
    first_seen = utc_now()
    seen_count = 1
    promoted_candidate_id = ""
    if existing:
        support = _merge([*_loads(existing["supporting_evidence_json"], []), *support])
        contradict = _merge([*_loads(existing["contradicting_evidence_json"], []), *contradict])
        missing = list(dict.fromkeys([*_loads(existing["missing_evidence_json"], []), *missing]))
        rule_ids = list(dict.fromkeys([*_loads(existing["rule_ids_json"], []), *rule_ids]))
        first_seen = str(existing["first_seen_at"] or first_seen)
        seen_count = int(existing["seen_count"] or 0) + 1
        promoted_candidate_id = str(existing["promoted_candidate_id"] or "")
        alert_id = existing["alert_id"] if existing["alert_id"] is not None else alert_id
        source_ref = str(existing["source_ref"] or source_ref)

    assessment = assess_admission(family, support, contradict)
    state = "promoted" if promoted_candidate_id else assessment["state"]
    hypothesis_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:hypothesis:{analysis_id}:{fingerprint}"))
    now = utc_now()
    db.execute(
        """INSERT OR REPLACE INTO analysis_hypotheses(
        hypothesis_id,hypothesis_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,
        bug_family,bug_variant,state,summary,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,
        decisive_signals_json,admission_json,knowledge_references_json,rule_ids_json,rule_version,seen_count,
        first_seen_at,last_seen_at,promoted_candidate_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            hypothesis_id, fingerprint, analysis_id, source_run_id, alert_id, target, asset, endpoint, source_ref,
            family, variant, state, summary, json_dumps(support), json_dumps(contradict), json_dumps(missing),
            json_dumps(assessment["decisive_signals"]), json_dumps(assessment), json_dumps(assessment["knowledge_references"]),
            json_dumps(rule_ids), ADMISSION_RULE_VERSION, seen_count, first_seen, now, promoted_candidate_id, first_seen, now,
        ),
    )
    return {
        "hypothesis_id": hypothesis_id,
        "hypothesis_fingerprint": fingerprint,
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": rule_ids,
        "assessment": assessment,
        "seen_count": seen_count,
    }


def mark_promoted(db: Database, analysis_id: str, hypothesis_fingerprint_value: str, candidate_id: str) -> None:
    db.execute(
        "UPDATE analysis_hypotheses SET state='promoted',promoted_candidate_id=?,updated_at=? WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (candidate_id, utc_now(), analysis_id, hypothesis_fingerprint_value),
    )


def hypothesis_summary(db: Database, analysis_id: str) -> dict[str, Any]:
    rows = db.all(
        "SELECT state,COUNT(*) count FROM analysis_hypotheses WHERE analysis_id=? GROUP BY state ORDER BY state",
        (analysis_id,),
    )
    counts = {str(row["state"]): int(row["count"]) for row in rows}
    return {
        "analysis_id": analysis_id,
        "total": sum(counts.values()),
        "promoted": counts.get("promoted", 0),
        "hidden": sum(value for key, value in counts.items() if key != "promoted"),
        "states": counts,
        "engine_version": ADMISSION_ENGINE_VERSION,
        "rule_version": ADMISSION_RULE_VERSION,
    }

from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load(path):
    return (ROOT / path).read_text(encoding="utf-8")

def save(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")

def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f"anchor not found: {label}")
    return text.replace(old, new, 1)

# ---------------------------------------------------------------------------
# hypothesis_admission.py
# ---------------------------------------------------------------------------
p = "app/hypothesis_admission.py"
s = load(p)
s = replace_once(s, 'ADMISSION_ENGINE_VERSION = "2.0.0"', 'ADMISSION_ENGINE_VERSION = "2.1.0"', "admission version")
s = replace_once(s, 'ADMISSION_RULE_VERSION = "2026.08.10.6.0"', 'ADMISSION_RULE_VERSION = "2026.08.10.6.1"', "admission rule version")

knowledge_block = r'''
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
'''
anchor = '# Admission is intentionally stricter than hypothesis generation.'
s = replace_once(s, anchor, knowledge_block + "\n" + anchor, "knowledge insertion")

policy_block = r'''
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
'''
anchor = '    "source_map_exposure": {'
s = replace_once(s, anchor, policy_block + anchor, "coverage admission policies")
save(p, s)

# ---------------------------------------------------------------------------
# bug_candidates.py
# ---------------------------------------------------------------------------
p = "app/bug_candidates.py"
s = load(p)
s = replace_once(s, 'CANDIDATE_ENGINE_VERSION = "6.0.0"', 'CANDIDATE_ENGINE_VERSION = "6.1.0"', "candidate version")
s = replace_once(s, 'CANDIDATE_RULE_VERSION = "2026.08.10.6.0"', 'CANDIDATE_RULE_VERSION = "2026.08.10.6.1"', "candidate rule version")

schema_block = r'''    "sql_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter", "path_parameter"), ("sql_query_surface", "database_query_semantic", "dynamic_query_surface"), ("sql_error_differential", "boolean_response_differential", "database_time_delay_observed", "query_structure_influence", "database_error_observed", "unsafe_query_construction")), "label": "input plus SQL query surface plus observed query-semantic influence"},
    "nosql_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter"), ("nosql_query_surface", "json_query_surface", "document_query_semantic"), ("nosql_operator_accepted", "query_operator_influence", "nosql_auth_bypass_observed", "nosql_response_differential", "nosql_error_observed")), "label": "structured input plus NoSQL query surface plus observed operator influence"},
    "command_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter", "path_parameter"), ("command_execution_surface", "shell_command_semantic", "process_execution_surface"), ("command_output_observed", "command_time_delay_observed", "shell_metacharacter_effect", "process_execution_reached", "unsafe_command_construction")), "label": "input plus command execution surface plus observed process effect"},
    "server_side_template_injection": {"required_any": (("input_parameter", "body_parameter", "template_input"), ("template_render_surface", "template_engine_semantic", "server_render_operation"), ("template_expression_evaluated", "template_output_differential", "template_engine_error_observed", "server_template_execution")), "label": "template input plus server render surface plus observed expression evaluation"},
    "ldap_injection": {"required_any": (("input_parameter", "query_parameter", "body_parameter"), ("ldap_query_surface", "directory_query_semantic", "ldap_filter_surface"), ("ldap_filter_influence", "ldap_response_differential", "ldap_auth_bypass_observed", "ldap_error_observed")), "label": "directory input plus LDAP filter surface plus observed filter influence"},
    "unrestricted_resource_consumption": {"required_any": (("resource_control_parameter", "batch_operation", "pagination_control", "upload_size_control", "expensive_operation", "paid_provider_operation"), ("rate_limit_absent_observed", "unbounded_page_size_observed", "batch_limit_absent_observed", "oversized_payload_accepted", "cost_amplification_observed", "timeout_limit_absent", "resource_exhaustion_differential")), "label": "resource-amplifying control plus observed ineffective resource limit"},
    "sensitive_business_flow_abuse": {"required_any": (("sensitive_business_flow", "purchase_flow", "reservation_flow", "posting_flow", "signup_flow", "redemption_flow"), ("automation_limit_absent", "anti_bot_control_absent", "per_user_limit_absent", "bulk_abuse_observed", "scalping_control_absent", "reservation_abuse_observed", "workflow_frequency_unrestricted", "business_flow_limit_bypass")), "label": "sensitive business flow plus observed missing/bypassable automation limit"},
    "security_misconfiguration": {"required_any": (("misconfiguration_surface", "debug_surface", "transport_surface", "http_method_surface", "deployment_configuration_surface"), ("stack_trace_exposed", "debug_mode_exposed", "insecure_http_enabled", "unnecessary_method_enabled", "directory_listing_observed", "security_header_missing_on_sensitive_response", "desync_processing_difference", "unsafe_default_configuration")), "label": "configuration surface plus directly observed insecure configuration"},
    "improper_inventory_management": {"required_any": (("api_version_surface", "legacy_endpoint_surface", "nonproduction_surface", "undocumented_host_surface"), ("deprecated_version_still_reachable", "older_version_weaker_controls", "undocumented_host_observed", "nonproduction_with_production_data", "retired_endpoint_active", "inventory_drift_observed", "unprotected_legacy_endpoint")), "label": "API inventory surface plus observed active legacy/undocumented exposure"},
    "unsafe_api_consumption": {"required_any": (("third_party_integration", "upstream_api_surface", "external_service_dependency"), ("upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink")), "label": "third-party API dependency plus observed unsafe upstream consumption"},
'''
anchor = '}\n\nBUG_FAMILIES: dict[str, dict[str, Any]] = {'
s = replace_once(s, anchor, schema_block + anchor, "candidate family schemas")

families_block = r'''    "sql_injection": {"label": "SQL Injection", "impact": 92, "category": "server_injection"},
    "nosql_injection": {"label": "NoSQL Injection", "impact": 88, "category": "server_injection"},
    "command_injection": {"label": "OS Command Injection", "impact": 98, "category": "server_injection"},
    "server_side_template_injection": {"label": "Server-Side Template Injection", "impact": 96, "category": "server_injection"},
    "ldap_injection": {"label": "LDAP Injection", "impact": 82, "category": "server_injection"},
    "unrestricted_resource_consumption": {"label": "Unrestricted Resource Consumption", "impact": 76, "category": "api_resilience"},
    "sensitive_business_flow_abuse": {"label": "Unrestricted Sensitive Business Flow", "impact": 74, "category": "business_logic"},
    "security_misconfiguration": {"label": "Security Misconfiguration", "impact": 78, "category": "configuration"},
    "improper_inventory_management": {"label": "Improper API Inventory Management", "impact": 68, "category": "api_inventory"},
    "unsafe_api_consumption": {"label": "Unsafe Consumption of Third-Party APIs", "impact": 84, "category": "supply_chain"},
'''
anchor = '}\n\nSAFE_ACTIONS = {'
s = replace_once(s, anchor, families_block + anchor, "bug family registration")

safe_block = r'''    "sql_injection": "Trace whether controlled input reaches dynamic SQL construction. Prefer stored error/boolean/timing evidence; do not extract unrelated database data.",
    "nosql_injection": "Map JSON/operator inputs to document-query construction using controlled test data. Avoid querying records outside your authorized test scope.",
    "command_injection": "Establish whether input reaches a shell or process API from stored evidence. Do not execute destructive commands; use only harmless markers when active validation is explicitly authorized.",
    "server_side_template_injection": "Confirm whether user-controlled text reaches a server-side template/expression engine. Use only non-destructive arithmetic/string markers during authorized validation.",
    "ldap_injection": "Compare controlled directory-search behavior using authorized test identities and harmless filter changes; do not enumerate real directory users.",
    "unrestricted_resource_consumption": "Document the intended size, batch, timeout, frequency, and cost limits. Do not intentionally exhaust resources or generate third-party charges.",
    "sensitive_business_flow_abuse": "Document business abuse limits and anti-automation controls. Validate only with reversible authorized test actions and never consume scarce inventory for real users.",
    "security_misconfiguration": "Capture the minimum configuration evidence needed (headers, transport, methods, errors). Do not exploit exposed administrative/debug functionality.",
    "improper_inventory_management": "Compare documented/current API versions with observed legacy or non-production endpoints. Do not access unrelated environments or production data beyond authorization.",
    "unsafe_api_consumption": "Trace upstream service trust boundaries, transport, redirects, response limits, and validation. Do not target or manipulate third-party systems without explicit authorization.",
'''
anchor = '}\n\nPRIVILEGED_FIELDS ='
s = replace_once(s, anchor, safe_block + anchor, "safe actions")

coverage_detection = r'''
    # Analysis 6.1 — OWASP A03 Injection coverage. Surface clues remain hidden
    # until stored target evidence shows interpreter/query semantics were affected.
    input_fields = [str(x) for x in (query_fields + body_fields + path_fields)]
    if input_fields:
        generic_input = {"type": "input_parameter", "source": "endpoint_schema", "weight": 8, "text": f"Client-controlled input fields are present: {', '.join(input_fields[:8])}"}

        sql_markers = _contains_any(haystack, ("sql", "query", "where", "filter", "search", "sort", "order", "table", "column", "report"))
        if sql_markers:
            support = [generic_input, {"type": "sql_query_surface", "source": "semantic", "weight": 14, "text": f"Database/query semantics observed: {', '.join(sql_markers[:6])}"}]
            for flag, signal in (
                ("sql_error_differential", "sql_error_differential"),
                ("boolean_response_differential", "boolean_response_differential"),
                ("database_time_delay_observed", "database_time_delay_observed"),
                ("query_structure_influence", "query_structure_influence"),
                ("database_error_observed", "database_error_observed"),
                ("unsafe_query_construction", "unsafe_query_construction"),
            ):
                if _explicit_flag(details, flag):
                    support.append({"type": signal, "source": "stored_behavior", "source_group": "sql_behavior", "weight": 32, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            contradict = []
            if _explicit_flag(details, "parameterized_query"):
                contradict.append({"type": "parameterized_query", "source": "stored_code_evidence", "weight": -30, "text": "Stored evidence shows parameterized query binding"})
            emit("sql_injection", "query_semantic_influence", 18, support, contradict,
                 ["Whether input reaches dynamic SQL construction", "Controlled error/boolean/timing differential", "Parameter binding behavior"],
                 ["candidate-sql-query-surface", "admission-sql-query-influence"],
                 "A client-controlled input reaches a database/query-shaped surface; promotion requires stored evidence that SQL semantics are influenced.")

        nosql_markers = _contains_any(haystack, ("mongo", "mongodb", "nosql", "documentdb", "findone", "aggregate", "operator", "$where", "$regex", "json filter", "json_query"))
        if nosql_markers:
            support = [generic_input, {"type": "nosql_query_surface", "source": "semantic", "weight": 15, "text": f"NoSQL/document-query semantics observed: {', '.join(nosql_markers[:6])}"}]
            for flag, signal in (
                ("nosql_operator_accepted", "nosql_operator_accepted"),
                ("query_operator_influence", "query_operator_influence"),
                ("nosql_auth_bypass_observed", "nosql_auth_bypass_observed"),
                ("nosql_response_differential", "nosql_response_differential"),
                ("nosql_error_observed", "nosql_error_observed"),
            ):
                if _explicit_flag(details, flag):
                    support.append({"type": signal, "source": "stored_behavior", "source_group": "nosql_behavior", "weight": 32, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            emit("nosql_injection", "operator_influence", 18, support, [],
                 ["Whether structured input is interpreted as query operators", "Typed schema/operator allowlist", "Controlled result differential"],
                 ["candidate-nosql-query-surface", "admission-nosql-operator-influence"],
                 "Structured client input appears in a NoSQL/document-query surface; promotion requires observed operator or query-result influence.")

        cmd_markers = _contains_any(haystack, ("cmd", "command", "exec", "shell", "ping", "traceroute", "nslookup", "diagnostic", "convert", "ffmpeg", "imagemagick", "process"))
        if cmd_markers:
            support = [generic_input, {"type": "command_execution_surface", "source": "semantic", "weight": 17, "text": f"Process/command semantics observed: {', '.join(cmd_markers[:6])}"}]
            for flag, signal in (
                ("command_output_observed", "command_output_observed"),
                ("command_time_delay_observed", "command_time_delay_observed"),
                ("shell_metacharacter_effect", "shell_metacharacter_effect"),
                ("process_execution_reached", "process_execution_reached"),
                ("unsafe_command_construction", "unsafe_command_construction"),
            ):
                if _explicit_flag(details, flag):
                    support.append({"type": signal, "source": "stored_behavior", "source_group": "command_behavior", "weight": 36, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            emit("command_injection", "process_execution_influence", 20, support, [],
                 ["Whether input reaches a shell/process API", "Argument-array vs shell-string construction", "Harmless output/timing execution evidence"],
                 ["candidate-command-surface", "admission-command-execution-effect"],
                 "Client-controlled input appears in process/diagnostic functionality; promotion requires an observed command-execution effect.")

        template_markers = _contains_any(haystack, ("template", "render", "preview", "freemarker", "velocity", "mustache", "handlebars", "jinja", "twig", "expression", "email body", "theme"))
        if template_markers:
            support = [generic_input, {"type": "template_render_surface", "source": "semantic", "weight": 16, "text": f"Server-render/template semantics observed: {', '.join(template_markers[:6])}"}]
            if any("template" in field.lower() or "body" == field.lower() for field in input_fields):
                support.append({"type": "template_input", "source": "endpoint_schema", "weight": 10, "text": "A client-controlled template/content field is visible"})
            for flag, signal in (
                ("template_expression_evaluated", "template_expression_evaluated"),
                ("template_output_differential", "template_output_differential"),
                ("template_engine_error_observed", "template_engine_error_observed"),
                ("server_template_execution", "server_template_execution"),
            ):
                if _explicit_flag(details, flag):
                    support.append({"type": signal, "source": "stored_behavior", "source_group": "template_behavior", "weight": 36, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            emit("server_side_template_injection", "server_expression_evaluation", 20, support, [],
                 ["Whether rendering occurs server-side", "Expression evaluation behavior", "Template sandbox/escaping controls"],
                 ["candidate-template-render-surface", "admission-template-evaluation"],
                 "Client-controlled content appears in a template/rendering surface; promotion requires observed server-side expression evaluation.")

        ldap_markers = _contains_any(haystack, ("ldap", "directory", "distinguishedname", "dn=", "ou=", "memberOf", "directory search", "ldap filter"))
        if ldap_markers:
            support = [generic_input, {"type": "ldap_query_surface", "source": "semantic", "weight": 16, "text": f"LDAP/directory-query semantics observed: {', '.join(ldap_markers[:6])}"}]
            for flag, signal in (
                ("ldap_filter_influence", "ldap_filter_influence"),
                ("ldap_response_differential", "ldap_response_differential"),
                ("ldap_auth_bypass_observed", "ldap_auth_bypass_observed"),
                ("ldap_error_observed", "ldap_error_observed"),
            ):
                if _explicit_flag(details, flag):
                    support.append({"type": signal, "source": "stored_behavior", "source_group": "ldap_behavior", "weight": 32, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
            emit("ldap_injection", "filter_influence", 18, support, [],
                 ["Whether input changes an LDAP filter", "Filter escaping/binding", "Controlled search/authentication differential"],
                 ["candidate-ldap-surface", "admission-ldap-filter-influence"],
                 "Client-controlled input appears in a directory/LDAP surface; promotion requires observed filter or result influence.")

    # API4:2023 — resource consumption.
    resource_fields = [field for field in query_fields + body_fields if field.lower().replace("_", "") in {"limit", "pagesize", "size", "count", "batch", "batchsize", "first", "take", "perpage", "maxresults", "filesize"}]
    resource_markers = _contains_any(haystack, ("batch", "bulk", "export", "report", "generate", "pdf", "upload", "download", "sms", "email", "otp", "biometric", "thumbnail"))
    if resource_fields or resource_markers:
        support = []
        if resource_fields:
            support.append({"type": "resource_control_parameter", "source": "endpoint_schema", "weight": 16, "text": f"Resource-amplifying controls are client visible: {', '.join(resource_fields[:8])}"})
            if any("page" in field.lower() or field.lower() in {"limit", "first", "take", "perpage"} for field in resource_fields):
                support.append({"type": "pagination_control", "source": "endpoint_schema", "weight": 10, "text": "Pagination/record-count control is client visible"})
        if any(token in resource_markers for token in ("batch", "bulk")):
            support.append({"type": "batch_operation", "source": "semantic", "weight": 12, "text": "Batch/bulk operation semantics are visible"})
        if any(token in resource_markers for token in ("sms", "email", "otp", "biometric")):
            support.append({"type": "paid_provider_operation", "source": "semantic", "weight": 14, "text": "The operation may trigger a per-request third-party service cost"})
        if any(token in resource_markers for token in ("export", "report", "generate", "pdf", "thumbnail", "upload", "download")):
            support.append({"type": "expensive_operation", "source": "semantic", "weight": 10, "text": "Potentially expensive processing/storage/bandwidth operation is visible"})
        for flag, signal in (
            ("rate_limit_absent_observed", "rate_limit_absent_observed"),
            ("unbounded_page_size_observed", "unbounded_page_size_observed"),
            ("batch_limit_absent_observed", "batch_limit_absent_observed"),
            ("oversized_payload_accepted", "oversized_payload_accepted"),
            ("cost_amplification_observed", "cost_amplification_observed"),
            ("timeout_limit_absent", "timeout_limit_absent"),
            ("resource_exhaustion_differential", "resource_exhaustion_differential"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "resource_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        if support:
            emit("unrestricted_resource_consumption", "missing_resource_limit", 16, support, [],
                 ["Maximum page/batch/payload size", "Per-client operation rate", "Execution timeout and provider spending limit"],
                 ["candidate-resource-surface", "admission-resource-limit-failure"],
                 "The API exposes a resource-amplifying control or costly operation; promotion requires observed missing or ineffective limits.")

    # API6:2023 — unrestricted access to sensitive business flows.
    flow_map = {
        "purchase_flow": ("purchase", "buy", "checkout", "ticket", "order"),
        "reservation_flow": ("reserve", "reservation", "booking", "slot"),
        "posting_flow": ("comment", "post", "message", "review"),
        "signup_flow": ("signup", "register", "invite", "create account"),
        "redemption_flow": ("redeem", "claim", "coupon", "promo"),
    }
    flow_signals = [(signal, _contains_any(haystack, tokens)) for signal, tokens in flow_map.items()]
    flow_signals = [(signal, tokens) for signal, tokens in flow_signals if tokens]
    if flow_signals:
        support = [{"type": "sensitive_business_flow", "source": "semantic", "weight": 12, "text": "A potentially abuse-sensitive business flow is exposed"}]
        for signal, tokens in flow_signals[:3]:
            support.append({"type": signal, "source": "semantic", "weight": 12, "text": f"Flow semantics observed: {', '.join(tokens[:5])}"})
        for flag, signal in (
            ("automation_limit_absent", "automation_limit_absent"),
            ("anti_bot_control_absent", "anti_bot_control_absent"),
            ("per_user_limit_absent", "per_user_limit_absent"),
            ("bulk_abuse_observed", "bulk_abuse_observed"),
            ("scalping_control_absent", "scalping_control_absent"),
            ("reservation_abuse_observed", "reservation_abuse_observed"),
            ("workflow_frequency_unrestricted", "workflow_frequency_unrestricted"),
            ("business_flow_limit_bypass", "business_flow_limit_bypass"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "business_flow_behavior", "weight": 28, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("sensitive_business_flow_abuse", "automation_abuse_boundary", 15, support, [],
             ["Per-user/business frequency limits", "Anti-automation controls", "Scarce-inventory or reservation abuse controls"],
             ["candidate-sensitive-business-flow", "admission-business-flow-limit"],
             "A sensitive business flow may be automatable at harmful scale; promotion requires observed missing or bypassable abuse controls.")

    # API8:2023 — security misconfiguration.
    misconfig_markers = _contains_any(haystack, ("debug", "stacktrace", "stack_trace", "traceback", "swagger", "actuator", "phpinfo", "directory listing", "server-status", "options method", "http://"))
    misconfig_flags = []
    for flag, signal in (
        ("stack_trace_exposed", "stack_trace_exposed"),
        ("debug_mode_exposed", "debug_mode_exposed"),
        ("insecure_http_enabled", "insecure_http_enabled"),
        ("unnecessary_method_enabled", "unnecessary_method_enabled"),
        ("directory_listing_observed", "directory_listing_observed"),
        ("security_header_missing_on_sensitive_response", "security_header_missing_on_sensitive_response"),
        ("desync_processing_difference", "desync_processing_difference"),
        ("unsafe_default_configuration", "unsafe_default_configuration"),
    ):
        if _explicit_flag(details, flag):
            misconfig_flags.append({"type": signal, "source": "stored_behavior", "source_group": "configuration_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
    if misconfig_markers or misconfig_flags:
        support = [{"type": "misconfiguration_surface", "source": "semantic", "weight": 10, "text": f"Configuration-sensitive surface observed: {', '.join(misconfig_markers[:6]) or 'explicit stored configuration evidence'}"}] + misconfig_flags
        if any(token in misconfig_markers for token in ("debug", "stacktrace", "stack_trace", "traceback", "phpinfo")):
            support.append({"type": "debug_surface", "source": "semantic", "weight": 10, "text": "Debug/error surface is externally observable"})
        if "http://" in haystack:
            support.append({"type": "transport_surface", "source": "endpoint", "weight": 10, "text": "Cleartext HTTP surface is present"})
        emit("security_misconfiguration", "deployment_hardening", 17, support, [],
             ["Expected hardening baseline", "Production transport/method policy", "Whether debug/default functionality is intentionally exposed"],
             ["candidate-misconfiguration-surface", "admission-direct-misconfiguration"],
             "A configuration-sensitive surface is visible; promotion requires directly observed insecure configuration behavior.")

    # API9:2023 — improper inventory management.
    version_tokens = re.findall(r"(?:^|[/_.-])(v\d+|v\d+\.\d+|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", haystack, re.I)
    if version_tokens:
        normalized = [str(x).lower() for x in version_tokens]
        support = [{"type": "api_version_surface", "source": "semantic", "weight": 14, "text": f"Version/non-production inventory markers observed: {', '.join(normalized[:8])}"}]
        if any(x in {"legacy", "old", "deprecated"} for x in normalized):
            support.append({"type": "legacy_endpoint_surface", "source": "semantic", "weight": 12, "text": "Legacy/deprecated endpoint naming is visible"})
        if any(x in {"staging", "stage", "dev", "test", "beta", "alpha"} for x in normalized):
            support.append({"type": "nonproduction_surface", "source": "semantic", "weight": 12, "text": "Non-production/pre-release deployment naming is visible"})
        for flag, signal in (
            ("deprecated_version_still_reachable", "deprecated_version_still_reachable"),
            ("older_version_weaker_controls", "older_version_weaker_controls"),
            ("undocumented_host_observed", "undocumented_host_observed"),
            ("nonproduction_with_production_data", "nonproduction_with_production_data"),
            ("retired_endpoint_active", "retired_endpoint_active"),
            ("inventory_drift_observed", "inventory_drift_observed"),
            ("unprotected_legacy_endpoint", "unprotected_legacy_endpoint"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "inventory_behavior", "weight": 28, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("improper_inventory_management", "legacy_or_nonproduction_exposure", 14, support, [],
             ["Current API inventory and retirement plan", "Control parity with current production API", "Whether non-production hosts use production data"],
             ["candidate-api-inventory-surface", "admission-inventory-drift"],
             "Version or non-production API surface is visible; promotion requires observed active legacy/undocumented exposure with security relevance.")

    # API10:2023 — unsafe consumption of third-party APIs.
    upstream_markers = _contains_any(haystack, ("third-party", "third_party", "provider", "integration", "upstream", "webhook", "external api", "external_api", "vendor", "partner api"))
    if upstream_markers:
        support = [{"type": "third_party_integration", "source": "semantic", "weight": 16, "text": f"External/upstream integration markers observed: {', '.join(upstream_markers[:6])}"}]
        if ssrf_tokens or generic_url_fields:
            support.append({"type": "upstream_api_surface", "source": "endpoint_schema", "weight": 10, "text": "A remote/upstream destination is client or application visible"})
        for flag, signal in (
            ("upstream_tls_missing", "upstream_tls_missing"),
            ("third_party_data_unsanitized", "third_party_data_unsanitized"),
            ("upstream_redirect_followed_unrestricted", "upstream_redirect_followed_unrestricted"),
            ("upstream_timeout_absent", "upstream_timeout_absent"),
            ("upstream_response_unbounded", "upstream_response_unbounded"),
            ("third_party_auth_weak", "third_party_auth_weak"),
            ("unsafe_upstream_data_reaches_sink", "unsafe_upstream_data_reaches_sink"),
        ):
            if _explicit_flag(details, flag):
                support.append({"type": signal, "source": "stored_behavior", "source_group": "upstream_behavior", "weight": 30, "text": f"Stored target evidence records {signal.replace('_', ' ')}"})
        emit("unsafe_api_consumption", "upstream_trust_boundary", 17, support, [],
             ["TLS and authentication to upstream service", "Redirect/timeout/response-size controls", "Validation and sanitization of third-party response data"],
             ["candidate-upstream-integration", "admission-unsafe-api-consumption"],
             "A third-party/upstream API dependency is visible; promotion requires observed unsafe trust, transport, redirect, resource, auth, or validation behavior.")

'''
anchor = '    # Information exposure / headers'
s = replace_once(s, anchor, coverage_detection + "\n" + anchor, "coverage detection")
save(p, s)

# ---------------------------------------------------------------------------
# security_reasoning.py
# ---------------------------------------------------------------------------
p = "app/security_reasoning.py"
s = load(p)
s = replace_once(s, 'REASONING_ENGINE_VERSION = "6.0.0"', 'REASONING_ENGINE_VERSION = "6.1.0"', "reasoning version")
s = replace_once(s, 'REASONING_RULE_VERSION = "2026.08.10.6.0"', 'REASONING_RULE_VERSION = "2026.08.10.6.1"', "reasoning rule version")

reasoning_block = r'''    "sql_injection": {
        "label": "SQL Injection",
        "rank_gate": {"sql_query_surface", "database_query_semantic"},
        "required": [{"input_parameter", "query_parameter", "body_parameter", "path_parameter"}, {"sql_query_surface", "database_query_semantic", "dynamic_query_surface"}, {"sql_error_differential", "boolean_response_differential", "database_time_delay_observed", "query_structure_influence", "database_error_observed", "unsafe_query_construction"}],
        "support": {"database_error_observed", "query_structure_influence", "database_time_delay_observed"},
        "contradict": {"parameterized_query", "query_builder_binding", "input_not_used_in_query"},
        "unknowns": ["Exact user-input-to-query dataflow", "Parameterized binding behavior", "Controlled boolean/error/timing differential"],
        "variants": {"filter": "filter_query_injection", "search": "search_query_injection", "sort": "sort_or_identifier_injection"},
    },
    "nosql_injection": {
        "label": "NoSQL Injection",
        "rank_gate": {"nosql_query_surface", "json_query_surface"},
        "required": [{"input_parameter", "query_parameter", "body_parameter"}, {"nosql_query_surface", "json_query_surface", "document_query_semantic"}, {"nosql_operator_accepted", "query_operator_influence", "nosql_auth_bypass_observed", "nosql_response_differential", "nosql_error_observed"}],
        "support": {"query_operator_influence", "nosql_response_differential"},
        "contradict": {"operator_allowlist", "typed_query_schema", "nosql_operator_rejected"},
        "unknowns": ["Whether client structures become database operators", "Typed input schema", "Controlled result differential"],
        "variants": {"operator": "document_operator_injection", "auth": "nosql_authentication_bypass"},
    },
    "command_injection": {
        "label": "OS Command Injection",
        "rank_gate": {"command_execution_surface", "process_execution_surface"},
        "required": [{"input_parameter", "query_parameter", "body_parameter", "path_parameter"}, {"command_execution_surface", "shell_command_semantic", "process_execution_surface"}, {"command_output_observed", "command_time_delay_observed", "shell_metacharacter_effect", "process_execution_reached", "unsafe_command_construction"}],
        "support": {"shell_metacharacter_effect", "command_output_observed", "process_execution_reached"},
        "contradict": {"exec_file_argument_array", "shell_disabled", "command_allowlist"},
        "unknowns": ["Exact input-to-process dataflow", "Shell-string vs argument-array construction", "Harmless process execution differential"],
        "variants": {"diagnostic": "diagnostic_command_injection", "convert": "conversion_command_injection"},
    },
    "server_side_template_injection": {
        "label": "Server-Side Template Injection",
        "rank_gate": {"template_render_surface", "template_engine_semantic"},
        "required": [{"input_parameter", "body_parameter", "template_input"}, {"template_render_surface", "template_engine_semantic", "server_render_operation"}, {"template_expression_evaluated", "template_output_differential", "template_engine_error_observed", "server_template_execution"}],
        "support": {"template_expression_evaluated", "template_engine_error_observed"},
        "contradict": {"literal_template_rendering", "template_sandbox_enforced", "template_input_escaped", "client_side_only"},
        "unknowns": ["Server-side template engine", "Expression evaluation behavior", "Sandbox/escaping policy"],
        "variants": {"preview": "template_preview_injection", "email": "email_template_injection"},
    },
    "ldap_injection": {
        "label": "LDAP Injection",
        "rank_gate": {"ldap_query_surface", "directory_query_semantic"},
        "required": [{"input_parameter", "query_parameter", "body_parameter"}, {"ldap_query_surface", "directory_query_semantic", "ldap_filter_surface"}, {"ldap_filter_influence", "ldap_response_differential", "ldap_auth_bypass_observed", "ldap_error_observed"}],
        "support": {"ldap_filter_influence", "ldap_response_differential"},
        "contradict": {"ldap_filter_escaped", "ldap_parameter_binding", "ldap_input_rejected"},
        "unknowns": ["Filter construction", "LDAP escaping/binding", "Controlled directory result differential"],
        "variants": {"search": "ldap_search_filter_injection", "auth": "ldap_auth_filter_injection"},
    },
    "unrestricted_resource_consumption": {
        "label": "Unrestricted Resource Consumption",
        "rank_gate": {"resource_control_parameter", "batch_operation", "expensive_operation"},
        "required": [{"resource_control_parameter", "batch_operation", "pagination_control", "upload_size_control", "expensive_operation", "paid_provider_operation"}, {"rate_limit_absent_observed", "unbounded_page_size_observed", "batch_limit_absent_observed", "oversized_payload_accepted", "cost_amplification_observed", "timeout_limit_absent", "resource_exhaustion_differential"}],
        "support": {"cost_amplification_observed", "resource_exhaustion_differential"},
        "contradict": {"rate_limit_enforced", "page_size_capped", "batch_limit_enforced", "payload_size_rejected", "timeout_enforced"},
        "unknowns": ["Rate/frequency limit", "Maximum payload/page/batch size", "Execution timeout and provider cost limit"],
        "variants": {"pagination": "unbounded_pagination", "batch": "unbounded_batch", "provider": "third_party_cost_amplification"},
    },
    "sensitive_business_flow_abuse": {
        "label": "Unrestricted Sensitive Business Flow",
        "rank_gate": {"sensitive_business_flow"},
        "required": [{"sensitive_business_flow", "purchase_flow", "reservation_flow", "posting_flow", "signup_flow", "redemption_flow"}, {"automation_limit_absent", "anti_bot_control_absent", "per_user_limit_absent", "bulk_abuse_observed", "scalping_control_absent", "reservation_abuse_observed", "workflow_frequency_unrestricted", "business_flow_limit_bypass"}],
        "support": {"bulk_abuse_observed", "business_flow_limit_bypass"},
        "contradict": {"anti_bot_control_enforced", "per_user_limit_enforced", "inventory_limit_enforced", "reservation_limit_enforced"},
        "unknowns": ["Business abuse threshold", "Per-user/frequency controls", "Anti-automation controls"],
        "variants": {"purchase": "purchase_scalping_abuse", "reservation": "reservation_exhaustion", "signup": "automated_account_creation"},
    },
    "security_misconfiguration": {
        "label": "Security Misconfiguration",
        "rank_gate": {"misconfiguration_surface", "debug_surface", "transport_surface"},
        "required": [{"misconfiguration_surface", "debug_surface", "transport_surface", "http_method_surface", "deployment_configuration_surface"}, {"stack_trace_exposed", "debug_mode_exposed", "insecure_http_enabled", "unnecessary_method_enabled", "directory_listing_observed", "security_header_missing_on_sensitive_response", "desync_processing_difference", "unsafe_default_configuration"}],
        "support": {"stack_trace_exposed", "debug_mode_exposed", "desync_processing_difference"},
        "contradict": {"hardening_observed", "tls_enforced", "method_rejected", "debug_disabled", "security_headers_present"},
        "unknowns": ["Expected production hardening baseline", "Transport/method policy", "Whether exposed defaults/debug behavior is intended"],
        "variants": {"debug": "debug_configuration_exposure", "transport": "cleartext_transport_configuration", "method": "unnecessary_http_method"},
    },
    "improper_inventory_management": {
        "label": "Improper API Inventory Management",
        "rank_gate": {"api_version_surface", "legacy_endpoint_surface", "nonproduction_surface"},
        "required": [{"api_version_surface", "legacy_endpoint_surface", "nonproduction_surface", "undocumented_host_surface"}, {"deprecated_version_still_reachable", "older_version_weaker_controls", "undocumented_host_observed", "nonproduction_with_production_data", "retired_endpoint_active", "inventory_drift_observed", "unprotected_legacy_endpoint"}],
        "support": {"older_version_weaker_controls", "nonproduction_with_production_data", "inventory_drift_observed"},
        "contradict": {"retired_endpoint_unreachable", "legacy_controls_equivalent", "nonproduction_isolated", "inventory_documented"},
        "unknowns": ["Authoritative API inventory", "Retirement status", "Control parity and data sensitivity of legacy/non-production deployment"],
        "variants": {"legacy": "active_legacy_api", "nonprod": "nonproduction_api_exposure", "undocumented": "undocumented_api_host"},
    },
    "unsafe_api_consumption": {
        "label": "Unsafe Consumption of Third-Party APIs",
        "rank_gate": {"third_party_integration", "upstream_api_surface"},
        "required": [{"third_party_integration", "upstream_api_surface", "external_service_dependency"}, {"upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink"}],
        "support": {"third_party_data_unsanitized", "unsafe_upstream_data_reaches_sink"},
        "contradict": {"upstream_tls_enforced", "third_party_schema_validation", "upstream_redirect_restricted", "upstream_timeout_enforced", "upstream_response_capped"},
        "unknowns": ["Upstream TLS/authentication", "Redirect/timeout/response-size controls", "Validation and sanitization before downstream processing"],
        "variants": {"redirect": "unrestricted_upstream_redirect", "validation": "unvalidated_third_party_data", "resource": "unbounded_upstream_response"},
    },
'''
anchor = '    "source_map_exposure": {'
s = replace_once(s, anchor, reasoning_block + anchor, "reasoning coverage schemas")
save(p, s)

# analysis engine version
p = "app/analysis_engine.py"
s = load(p)
s = replace_once(s, 'ENGINE_VERSION = "6.0.0"', 'ENGINE_VERSION = "6.1.0"', "analysis version")
s = replace_once(s, 'RULE_VERSION = "2026.08.10.6.0"', 'RULE_VERSION = "2026.08.10.6.1"', "analysis rule version")
save(p, s)

doc = r'''# Analysis Engine 6.1 — Coverage Expansion

Analysis 6.1 extends the vulnerability-condition admission model introduced in
6.0. Recon Monitor still preserves weak clues as hidden hypotheses. The new
families do not enter Potential Findings until family-specific decisive target
evidence is present.

## New vulnerability families

- SQL Injection
- NoSQL Injection
- OS Command Injection
- Server-Side Template Injection
- LDAP Injection
- API4:2023 Unrestricted Resource Consumption
- API6:2023 Unrestricted Access to Sensitive Business Flows
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs

## Admission invariant

`surface -> hidden hypothesis -> decisive target behavior -> candidate`

Examples:

- `filter` or `search` parameter alone is not SQL injection.
- a command-like endpoint alone is not command injection.
- `limit`, `page`, `batch`, SMS, email, export, or upload alone is not API4.
- purchase/reservation/signup endpoints alone are not API6.
- `/v1/`, `legacy`, `staging`, or `beta` naming alone is not API9.
- a third-party integration alone is not API10.

Promotion requires stored evidence matching the security condition defined by
OWASP/WSTG, such as query-semantic influence, command/template execution,
missing resource limits, unrestricted automation, directly observed insecure
configuration, active legacy exposure with weaker controls, or unsafe upstream
trust/validation behavior.

External knowledge is explanatory context only and never counts as target
evidence.
'''
save("docs/ANALYSIS_ENGINE_6_1_COVERAGE.md", doc)

test = r'''from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import ENGINE_VERSION, run_analysis
from bug_candidates import BUG_FAMILIES, CANDIDATE_ENGINE_VERSION, SAFE_ACTIONS
from core import AppPaths, Database, utc_now
from hypothesis_admission import ADMISSION_ENGINE_VERSION, assess_admission
from security_reasoning import FAMILY_SCHEMAS, REASONING_ENGINE_VERSION

NEW_FAMILIES = {
    "sql_injection", "nosql_injection", "command_injection", "server_side_template_injection", "ldap_injection",
    "unrestricted_resource_consumption", "sensitive_business_flow_abuse", "security_misconfiguration",
    "improper_inventory_management", "unsafe_api_consumption",
}

def ev(kind: str, source: str = "fixture") -> dict[str, str]:
    return {"type": kind, "source": source, "text": kind}

class AnalysisCoverageV610Tests(unittest.TestCase):
    def test_versions_and_registry(self):
        self.assertEqual(ENGINE_VERSION, "6.1.0")
        self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.1.0")
        self.assertEqual(REASONING_ENGINE_VERSION, "6.1.0")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.1.0")
        for family in NEW_FAMILIES:
            self.assertIn(family, BUG_FAMILIES)
            self.assertIn(family, SAFE_ACTIONS)
            self.assertIn(family, FAMILY_SCHEMAS)

    def test_sql_surface_stays_hidden_until_query_influence(self):
        surface = [ev("input_parameter", "schema"), ev("sql_query_surface", "semantic")]
        self.assertFalse(assess_admission("sql_injection", surface)["admitted"])
        decisive = surface + [ev("boolean_response_differential", "stored_behavior")]
        self.assertTrue(assess_admission("sql_injection", decisive)["admitted"])
        blocked = assess_admission("sql_injection", decisive, [ev("parameterized_query", "code")])
        self.assertFalse(blocked["admitted"])

    def test_injection_variants_need_execution_or_interpreter_effect(self):
        cases = {
            "nosql_injection": ([ev("input_parameter", "schema"), ev("nosql_query_surface", "semantic")], ev("nosql_operator_accepted", "stored_behavior")),
            "command_injection": ([ev("input_parameter", "schema"), ev("command_execution_surface", "semantic")], ev("command_output_observed", "stored_behavior")),
            "server_side_template_injection": ([ev("template_input", "schema"), ev("template_render_surface", "semantic")], ev("template_expression_evaluated", "stored_behavior")),
            "ldap_injection": ([ev("input_parameter", "schema"), ev("ldap_query_surface", "semantic")], ev("ldap_filter_influence", "stored_behavior")),
        }
        for family, (surface, decisive) in cases.items():
            with self.subTest(family=family):
                self.assertFalse(assess_admission(family, surface)["admitted"])
                self.assertTrue(assess_admission(family, surface + [decisive])["admitted"])

    def test_api_top10_surfaces_need_decisive_behavior(self):
        cases = {
            "unrestricted_resource_consumption": ([ev("resource_control_parameter", "schema")], ev("unbounded_page_size_observed", "stored_behavior")),
            "sensitive_business_flow_abuse": ([ev("sensitive_business_flow", "semantic")], ev("workflow_frequency_unrestricted", "stored_behavior")),
            "security_misconfiguration": ([ev("misconfiguration_surface", "semantic")], ev("stack_trace_exposed", "http")),
            "improper_inventory_management": ([ev("api_version_surface", "semantic")], ev("deprecated_version_still_reachable", "http")),
            "unsafe_api_consumption": ([ev("third_party_integration", "semantic")], ev("third_party_data_unsanitized", "stored_behavior")),
        }
        for family, (surface, decisive) in cases.items():
            with self.subTest(family=family):
                self.assertFalse(assess_admission(family, surface)["admitted"])
                self.assertTrue(assess_admission(family, surface + [decisive])["admitted"])

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run61','6.1.0','success',?,?,?,1)", (now, now, "example.com"))
        return temp, paths, db

    def test_surface_only_sql_is_hidden_in_real_analysis(self):
        temp, paths, db = self._project()
        try:
            details = {"status_code": 200, "method": "GET", "query_parameters": ["filter"]}
            db.upsert_alert("example.com", "sql-surface", "new_endpoint", "MEDIUM", 55, "Search endpoint", "/api/search?filter=x", details, "run61")
            result = run_analysis(paths, db, "run61", "example.com")
            candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='sql_injection'", (result["analysis_id"],))
            hypothesis = db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='sql_injection'", (result["analysis_id"],))
            self.assertIsNone(candidate)
            self.assertIsNotNone(hypothesis)
        finally:
            db.close(); temp.cleanup()

    def test_decisive_sql_and_api4_evidence_promote(self):
        temp, paths, db = self._project()
        try:
            sql_details = {"status_code": 200, "method": "GET", "query_parameters": ["filter"], "query_structure_influence": True}
            db.upsert_alert("example.com", "sql-decisive", "new_endpoint", "HIGH", 82, "Database search endpoint", "/api/search?filter=x", sql_details, "run61")
            resource_details = {"status_code": 200, "method": "GET", "query_parameters": ["limit"], "unbounded_page_size_observed": True}
            db.upsert_alert("example.com", "resource-decisive", "new_endpoint", "HIGH", 78, "Bulk export endpoint", "/api/export?limit=100", resource_details, "run61")
            result = run_analysis(paths, db, "run61", "example.com")
            families = {str(row["bug_family"]) for row in db.all("SELECT bug_family FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))}
            self.assertIn("sql_injection", families)
            self.assertIn("unrestricted_resource_consumption", families)
        finally:
            db.close(); temp.cleanup()

if __name__ == "__main__":
    unittest.main()
'''
save("tests/test_analysis_coverage_v610.py", test)

print("Analysis Engine 6.1 coverage patch applied")

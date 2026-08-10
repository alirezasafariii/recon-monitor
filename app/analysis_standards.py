from __future__ import annotations
from copy import deepcopy
from typing import Any, Iterable, Mapping

STANDARDS_ENGINE_VERSION = "1.1.0"
WSTG_REFERENCE_VERSION = "latest@2026-08-10"
CWE_REFERENCE_VERSION = "4.20"
WSTG_BASE_URL = 'https://owasp.org/www-project-web-security-testing-guide/latest/'
CWE_BASE_URL = "https://cwe.mitre.org/data/definitions/"

def _wstg(ref_id: str, title: str) -> dict[str, Any]:
    return {"id": ref_id, "title": title, "url": WSTG_BASE_URL, "source": "OWASP WSTG"}

def _cwe(ref_id: str, title: str, *, mapping: str = "direct", auto_assign: bool = True, when_any: Iterable[str] = ()) -> dict[str, Any]:
    number = ref_id.split("-", 1)[1]
    return {"id": ref_id, "title": title, "url": f"{CWE_BASE_URL}{number}.html", "source": "MITRE CWE", "mapping": mapping, "auto_assign": bool(auto_assign), "when_any": list(when_any)}

FAMILY_STANDARDS: dict[str, dict[str, Any]] = {
    'broken_object_authorization': {
        'principle': 'Object identifiers are only surfaces; promotion requires an observed object-level authorization boundary failure.',
        'wstg': [
            _wstg('WSTG-APIT-02', 'API Broken Object Level Authorization'),
            _wstg('WSTG-ATHZ-04', 'Insecure Direct Object References'),
        ],
        'cwe': [
            _cwe('CWE-639', 'Authorization Bypass Through User-Controlled Key', mapping='direct', auto_assign=True, when_any=()),
            _cwe('CWE-863', 'Incorrect Authorization', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'broken_function_authorization': {
        'principle': 'Privileged-looking functionality is only a surface; promotion requires an observed role/function authorization failure.',
        'wstg': [
            _wstg('WSTG-ATHZ-02', 'Bypassing Authorization Schema'),
            _wstg('WSTG-ATHZ-03', 'Privilege Escalation'),
        ],
        'cwe': [
            _cwe('CWE-862', 'Missing Authorization', mapping='contextual', auto_assign=False, when_any=()),
            _cwe('CWE-863', 'Incorrect Authorization', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'mass_assignment': {
        'principle': "Writable object properties are only a surface; promotion requires unauthorized modification of a property outside the caller's policy.",
        'wstg': [
            _wstg('WSTG-INPV-20', 'Mass Assignment'),
        ],
        'cwe': [
            _cwe('CWE-915', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'authentication_session': {
        'principle': 'Authentication/session artifacts are surfaces; promotion requires a demonstrated authentication or session lifecycle control failure.',
        'wstg': [
            _wstg('WSTG-ATHN-04', 'Bypassing Authentication Schema'),
            _wstg('WSTG-SESS-01', 'Session Management Schema'),
        ],
        'cwe': [
            _cwe('CWE-287', 'Improper Authentication', mapping='contextual', auto_assign=True, when_any=('authentication_boundary_regression', 'boundary_regression', 'protected_to_public', 'session_validation_failure')),
        ],
    },
    'account_enumeration': {
        'principle': 'Identity lookup becomes enumeration only when controlled existing/non-existing identities produce an observable discrepancy.',
        'wstg': [
            _wstg('WSTG-IDNT-04', 'Account Enumeration and Guessable User Account'),
        ],
        'cwe': [
            _cwe('CWE-204', 'Observable Response Discrepancy', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'dom_xss': {
        'principle': 'DOM sources and sinks are only clues; promotion requires a reachable user-controlled flow into a dangerous sink without effective sanitization.',
        'wstg': [
            _wstg('WSTG-CLNT-01', 'DOM-Based Cross Site Scripting'),
        ],
        'cwe': [
            _cwe('CWE-79', "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'postmessage_trust': {
        'principle': 'A message handler is only a surface; promotion requires attacker-controlled messaging to sensitive behavior without adequate origin/source validation.',
        'wstg': [
            _wstg('WSTG-CLNT-11', 'Web Messaging'),
        ],
        'cwe': [
            _cwe('CWE-346', 'Origin Validation Error', mapping='contextual', auto_assign=True, when_any=('missing_origin_check', 'wildcard_origin', 'missing_source_window_check')),
        ],
    },
    'open_redirect': {
        'principle': 'Redirect parameters are only surfaces; promotion requires user-controlled navigation to an unintended destination.',
        'wstg': [
            _wstg('WSTG-CLNT-04', 'Client-side URL Redirect'),
        ],
        'cwe': [
            _cwe('CWE-601', "URL Redirection to Untrusted Site ('Open Redirect')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'ssrf': {
        'principle': 'URL-like input is only a surface; promotion requires a user-controlled destination plus observed server-side request behavior.',
        'wstg': [
            _wstg('WSTG-INPV-19', 'Server-Side Request Forgery'),
        ],
        'cwe': [
            _cwe('CWE-918', 'Server-Side Request Forgery (SSRF)', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'file_upload': {
        'principle': 'Upload capability alone is not a weakness; promotion requires observed unsafe acceptance, storage, serving, or processing of attacker-controlled files.',
        'wstg': [
            _wstg('WSTG-BUSL-08', 'Upload of Unexpected File Types'),
            _wstg('WSTG-BUSL-09', 'Upload of Malicious Files'),
        ],
        'cwe': [
            _cwe('CWE-434', 'Unrestricted Upload of File with Dangerous Type', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'path_traversal': {
        'principle': 'Path/filename input is only a surface; promotion requires attacker-controlled path data to escape the intended filesystem boundary.',
        'wstg': [
            _wstg('WSTG-ATHZ-01', 'Directory Traversal File Include'),
        ],
        'cwe': [
            _cwe('CWE-22', "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'information_disclosure': {
        'principle': 'Sensitive-looking fields are only clues; promotion requires actual exposure to an unauthorized or unintended context.',
        'wstg': [
            _wstg('WSTG-ERRH-01', 'Improper Error Handling'),
            _wstg('WSTG-ERRH-02', 'Stack Traces'),
        ],
        'cwe': [
            _cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor', mapping='contextual', auto_assign=True, when_any=('sensitive_fields', 'secret_pattern', 'debug_information', 'sensitive_marker', 'sensitive_expansion')),
        ],
    },
    'source_map_exposure': {
        'principle': 'A source-map reference is only a surface; promotion requires meaningful source content plus verified public reachability.',
        'wstg': [
            _wstg('WSTG-CONF-04', 'Review Old Backup and Unreferenced Files for Sensitive Information'),
        ],
        'cwe': [
            _cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor', mapping='contextual', auto_assign=True, when_any=('internal_sources', 'source_contents')),
        ],
    },
    'secret_exposure': {
        'principle': 'Secret-like strings are only clues; promotion requires non-placeholder credential material in a production-reachable client context.',
        'wstg': [
            _wstg('WSTG-CONF-04', 'Review Old Backup and Unreferenced Files for Sensitive Information'),
        ],
        'cwe': [
            _cwe('CWE-798', 'Use of Hard-coded Credentials', mapping='contextual', auto_assign=True, when_any=('credential_context', 'token_exposure', 'non_placeholder_secret')),
            _cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'graphql_authorization': {
        'principle': 'GraphQL operations and IDs are surfaces; promotion requires resolver/object authorization boundary failure.',
        'wstg': [
            _wstg('WSTG-APIT-02', 'API Broken Object Level Authorization'),
            _wstg('WSTG-ATHZ-02', 'Bypassing Authorization Schema'),
        ],
        'cwe': [
            _cwe('CWE-862', 'Missing Authorization', mapping='contextual', auto_assign=False, when_any=()),
            _cwe('CWE-863', 'Incorrect Authorization', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'graphql_data_exposure': {
        'principle': "Sensitive GraphQL fields are only schema clues; promotion requires actual exposure beyond the caller's field policy.",
        'wstg': [
            _wstg('WSTG-APIT-03', 'API Excessive Data Exposure'),
        ],
        'cwe': [
            _cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor', mapping='contextual', auto_assign=True, when_any=('response_data', 'field_expansion', 'unauthorized_data_response', 'sensitive_expansion')),
        ],
    },
    'business_logic': {
        'principle': 'Business-operation names are only hypotheses; promotion requires an observed violation of a business workflow/value/state invariant.',
        'wstg': [
            _wstg('WSTG-BUSL-01', 'Business Logic Data Validation'),
            _wstg('WSTG-BUSL-06', 'Circumvention of Work Flows'),
        ],
        'cwe': [
            _cwe('CWE-841', 'Improper Enforcement of Behavioral Workflow', mapping='contextual', auto_assign=True, when_any=('workflow_invariant_violation', 'invalid_transition_accepted', 'business_rule_bypass')),
        ],
    },
    'race_condition': {
        'principle': 'State-changing operations are only surfaces; promotion requires an observed concurrency/atomicity failure.',
        'wstg': [
            _wstg('WSTG-BUSL-04', 'Process Timing'),
        ],
        'cwe': [
            _cwe('CWE-362', "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'websocket_authorization': {
        'principle': 'WebSocket channels are only surfaces; promotion requires an observed subscription/message authorization failure.',
        'wstg': [
            _wstg('WSTG-CLNT-10', 'WebSockets'),
            _wstg('WSTG-ATHZ-02', 'Bypassing Authorization Schema'),
        ],
        'cwe': [
            _cwe('CWE-862', 'Missing Authorization', mapping='contextual', auto_assign=False, when_any=()),
            _cwe('CWE-863', 'Incorrect Authorization', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'cors_misconfiguration': {
        'principle': 'CORS headers alone are not a vulnerability; promotion requires an unsafe origin policy combined with credentialed or sensitive cross-origin exposure.',
        'wstg': [
            _wstg('WSTG-CLNT-07', 'Cross Origin Resource Sharing'),
        ],
        'cwe': [
            _cwe('CWE-942', 'Permissive Cross-domain Security Policy with Untrusted Domains', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'sensitive_caching': {
        'principle': 'Cache headers alone are not a weakness; promotion requires sensitive/authenticated data plus a cache-isolation failure.',
        'wstg': [
            _wstg('WSTG-ATHN-06', 'Browser Cache Weaknesses'),
        ],
        'cwe': [
            _cwe('CWE-524', 'Use of Cache Containing Sensitive Information', mapping='contextual', auto_assign=True, when_any=('shared_cache_risk', 'cdn_cache', 'cache_key_missing_auth_context')),
            _cwe('CWE-525', 'Use of Web Browser Cache Containing Sensitive Information', mapping='contextual', auto_assign=True, when_any=('public_cache',)),
        ],
    },
    'sql_injection': {
        'principle': 'Query parameters are only surfaces; promotion requires observed SQL semantic, error, boolean, timing, or unsafe-construction influence.',
        'wstg': [
            _wstg('WSTG-INPV-05', 'SQL Injection'),
        ],
        'cwe': [
            _cwe('CWE-89', "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'nosql_injection': {
        'principle': 'Structured query input is only a surface; promotion requires observed operator or query-logic influence.',
        'wstg': [
            _wstg('WSTG-INPV-05.6', 'NoSQL Injection'),
        ],
        'cwe': [
            _cwe('CWE-943', 'Improper Neutralization of Special Elements in Data Query Logic', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'command_injection': {
        'principle': 'Command-like inputs are only surfaces; promotion requires observed OS/process command execution influence.',
        'wstg': [
            _wstg('WSTG-INPV-12', 'Command Injection'),
        ],
        'cwe': [
            _cwe('CWE-78', "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'server_side_template_injection': {
        'principle': 'Template/preview functionality is only a surface; promotion requires observed server-side template expression evaluation.',
        'wstg': [
            _wstg('WSTG-INPV-18', 'Server-Side Template Injection'),
        ],
        'cwe': [
            _cwe('CWE-1336', 'Improper Neutralization of Special Elements Used in a Template Engine', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'ldap_injection': {
        'principle': 'Directory search input is only a surface; promotion requires observed LDAP filter/query influence.',
        'wstg': [
            _wstg('WSTG-INPV-06', 'LDAP Injection'),
        ],
        'cwe': [
            _cwe('CWE-90', "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')", mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'unrestricted_resource_consumption': {
        'principle': 'Expensive or high-volume API controls are surfaces; promotion requires observed missing/ineffective size, frequency, timeout, or cost limits.',
        'wstg': [
            _wstg('WSTG-BUSL-05', 'Number of Times a Function Can Be Used Limits'),
            _wstg('WSTG-BUSL-07', 'Defenses Against Application Misuse'),
        ],
        'cwe': [
            _cwe('CWE-770', 'Allocation of Resources Without Limits or Throttling', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'sensitive_business_flow_abuse': {
        'principle': 'Sensitive business flows are surfaces; promotion requires observed missing or bypassable interaction-frequency/anti-automation controls.',
        'wstg': [
            _wstg('WSTG-BUSL-05', 'Number of Times a Function Can Be Used Limits'),
            _wstg('WSTG-BUSL-06', 'Circumvention of Work Flows'),
            _wstg('WSTG-BUSL-07', 'Defenses Against Application Misuse'),
        ],
        'cwe': [
            _cwe('CWE-799', 'Improper Control of Interaction Frequency', mapping='direct', auto_assign=True, when_any=()),
        ],
    },
    'security_misconfiguration': {
        'principle': 'Configuration markers are only surfaces; promotion requires a directly observed insecure configuration and CWE is selected from the decisive configuration condition.',
        'wstg': [
            _wstg('WSTG-CONF-02', 'Application Platform Configuration'),
            _wstg('WSTG-CONF-06', 'HTTP Methods'),
            _wstg('WSTG-CONF-07', 'HTTP Strict Transport Security'),
            _wstg('WSTG-CONF-14', 'Other HTTP Security Header Misconfigurations'),
            _wstg('WSTG-ERRH-02', 'Stack Traces'),
        ],
        'cwe': [
            _cwe('CWE-209', 'Generation of Error Message Containing Sensitive Information', mapping='contextual', auto_assign=True, when_any=('stack_trace_exposed',)),
            _cwe('CWE-489', 'Active Debug Code', mapping='contextual', auto_assign=True, when_any=('debug_mode_exposed',)),
            _cwe('CWE-319', 'Cleartext Transmission of Sensitive Information', mapping='contextual', auto_assign=True, when_any=('insecure_http_enabled',)),
            _cwe('CWE-749', 'Exposed Dangerous Method or Function', mapping='contextual', auto_assign=True, when_any=('unnecessary_method_enabled',)),
            _cwe('CWE-548', 'Exposure of Information Through Directory Listing', mapping='contextual', auto_assign=True, when_any=('directory_listing_observed',)),
            _cwe('CWE-444', "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')", mapping='contextual', auto_assign=True, when_any=('desync_processing_difference',)),
            _cwe('CWE-1188', 'Initialization of a Resource with an Insecure Default', mapping='contextual', auto_assign=True, when_any=('unsafe_default_configuration',)),
        ],
    },
    'improper_inventory_management': {
        'principle': 'Version/non-production naming is only inventory surface. CWE mapping is intentionally contextual and is assigned only when the observed legacy/non-production condition exposes a concrete weakness.',
        'wstg': [
            _wstg('WSTG-APIT-01', 'API Reconnaissance'),
            _wstg('WSTG-CONF-04', 'Review Old Backup and Unreferenced Files for Sensitive Information'),
        ],
        'cwe': [
            _cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor', mapping='contextual', auto_assign=True, when_any=('nonproduction_with_production_data',)),
            _cwe('CWE-862', 'Missing Authorization', mapping='contextual', auto_assign=True, when_any=('unprotected_legacy_endpoint',)),
            _cwe('CWE-1104', 'Use of Unmaintained Third Party Components', mapping='contextual', auto_assign=False, when_any=()),
        ],
    },
    'unsafe_api_consumption': {
        'principle': 'Third-party integration is only a trust-boundary surface. CWE is selected only from the concrete unsafe upstream handling that is observed.',
        'wstg': [
            _wstg('WSTG-BUSL-01', 'Business Logic Data Validation'),
            _wstg('WSTG-CRYP-01', 'Weak Transport Layer Security'),
            _wstg('WSTG-INPV-19', 'Server-Side Request Forgery'),
        ],
        'cwe': [
            _cwe('CWE-20', 'Improper Input Validation', mapping='contextual', auto_assign=True, when_any=('third_party_data_unsanitized', 'unsafe_upstream_data_reaches_sink')),
            _cwe('CWE-319', 'Cleartext Transmission of Sensitive Information', mapping='contextual', auto_assign=True, when_any=('upstream_tls_missing',)),
            _cwe('CWE-770', 'Allocation of Resources Without Limits or Throttling', mapping='contextual', auto_assign=True, when_any=('upstream_timeout_absent', 'upstream_response_unbounded')),
            _cwe('CWE-287', 'Improper Authentication', mapping='contextual', auto_assign=False, when_any=('third_party_auth_weak',)),
        ],
    },
}

def standards_for_family(
    family: str,
    *,
    admitted: bool = False,
    decisive_signals: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Return standards grounding without turning standards into target evidence.

    WSTG and CWE describe the security condition and taxonomy. They never satisfy
    an admission evidence group or independent-source requirement.
    """
    raw = FAMILY_STANDARDS.get(str(family) or "", {})
    data = deepcopy(raw) if raw else {"principle": "", "wstg": [], "cwe": []}
    signals = {str(item) for item in (decisive_signals or [])}
    assigned: list[str] = []
    if admitted:
        for item in data.get("cwe", []):
            if not item.get("auto_assign"):
                continue
            conditions = {str(value) for value in item.get("when_any", [])}
            if conditions and not (conditions & signals):
                continue
            assigned.append(str(item.get("id") or ""))
    data.update({
        "family": str(family),
        "standards_engine_version": STANDARDS_ENGINE_VERSION,
        "wstg_reference_version": WSTG_REFERENCE_VERSION,
        "cwe_reference_version": CWE_REFERENCE_VERSION,
        "assigned_cwe": [value for value in assigned if value],
        "assignment_state": "assigned" if assigned else ("manual_root_cause_review" if admitted else "not_admitted"),
    })
    return data


def validate_family_standards(families: Mapping[str, Any] | Iterable[str]) -> list[str]:
    names = set(families.keys()) if isinstance(families, Mapping) else {str(value) for value in families}
    errors: list[str] = []
    for family in sorted(names):
        entry = FAMILY_STANDARDS.get(family)
        if not entry:
            errors.append(f"{family}:missing_standard_profile")
            continue
        if not entry.get("wstg"):
            errors.append(f"{family}:missing_wstg")
        if not entry.get("cwe"):
            errors.append(f"{family}:missing_cwe")
        for item in entry.get("cwe", []):
            if not str(item.get("id") or "").startswith("CWE-"):
                errors.append(f"{family}:invalid_cwe_id")
            if item.get("mapping") not in {"direct", "contextual"}:
                errors.append(f"{family}:invalid_cwe_mapping_mode")
    extras = sorted(set(FAMILY_STANDARDS) - names)
    if extras:
        errors.extend(f"{family}:standard_profile_without_family" for family in extras)
    return errors

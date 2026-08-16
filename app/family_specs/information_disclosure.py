from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


INFORMATION_DISCLOSURE_STANDARD_SPEC = FamilyStandardSpec(
    family="information_disclosure",
    version="1.0.0",
    strategy="non_public_response_visibility_boundary",
    principle=(
        "Debug strings, stack traces, version banners, internal paths and sensitive-looking field names are discovery "
        "context only; promotion requires stored target evidence that non-public sensitive information crossed its "
        "intended visibility boundary to a public, anonymous or otherwise unauthorized actor/context."
    ),
    owasp=("A02:2025 Security Misconfiguration",),
    wstg=("WSTG-INFO-05", "WSTG-ERRH-01"),
    cwe=("CWE-209", "CWE-497", "CWE-1295", "CWE-200"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="INFO-01-surface-classification",
            basis=("WSTG-INFO-05", "A02:2025", "CWE-200"),
            principle="Classify debug, error, internal, build, version and sensitive-looking response markers as surface evidence only until sensitivity and intended visibility are known.",
        ),
        MethodologyStep(
            id="INFO-02-visibility-policy",
            basis=("CWE-200", "CWE-497"),
            principle="Establish whether the observed category or field is intended for the current actor/context before treating it as disclosure.",
        ),
        MethodologyStep(
            id="INFO-03-minimal-stored-observation",
            basis=("WSTG-INFO-05", "CWE-200"),
            principle="Use stored response metadata and redacted field/category descriptions only; do not copy credentials, personal values, tokens or unrelated private data into evidence output.",
        ),
        MethodologyStep(
            id="INFO-04-error-debug-boundary",
            basis=("WSTG-ERRH-01", "A10:2025", "CWE-209", "CWE-1295"),
            principle="A stack-trace/error marker becomes vulnerability evidence only when stored output exposes sensitive internal detail outside the intended audience.",
        ),
        MethodologyStep(
            id="INFO-05-policy-differential",
            basis=("CWE-200", "CWE-497"),
            principle="Potential-Finding admission requires an observed visibility-boundary failure: public/anonymous/unauthorized delivery of explicitly private or restricted information.",
        ),
        MethodologyStep(
            id="INFO-06-neighbor-separation",
            basis=("WSTG-INFO-05",),
            principle="Source maps, credential material and GraphQL field exposure retain their specialized families; generic marker overlap does not confirm Information Disclosure.",
        ),
    ),
    surface_terms=("debug", "stack trace", "traceback", "exception", "internal path", "server version", "framework", "build", "environment", "configuration"),
    surface_fields=("debug", "trace", "stack", "error", "exception", "server", "version", "build", "environment", "configuration"),
    confounders=("secret_exposure", "source_map_exposure", "graphql_data_exposure", "security_misconfiguration"),
    false_positive_checks=(
        "A server/framework/version banner is not automatically sensitive information disclosure.",
        "A stack trace marker or HTTP error status is surface evidence unless stored output contains sensitive/internal detail outside its intended audience.",
        "Private data returned only to its intended authorized owner is not public disclosure.",
        "Documented public metadata and deliberately public diagnostics are contradiction context, not findings.",
        "Observed redaction or filtering is contradiction evidence for the corresponding exposure hypothesis.",
        "Credential/token material and source maps remain in their specialized families unless an independent generic visibility-boundary failure is established.",
        "The analyzer stores categories, field names and booleans only and never echoes raw sensitive values.",
        "OWASP, WSTG, CWE and research write-ups define methodology but add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-wstg-information-leakage-boundary",
            source="OWASP WSTG",
            ref="WSTG-INFO-05 / WSTG-ERRH-01 information leakage boundary",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            relation="historical_knowledge_compatibility",
            lesson="Information-looking output is a finding only when stored target evidence shows sensitive or private information crossing an unintended visibility boundary.",
            signal_hints=("sensitive_marker", "sensitive_response_observed", "private_field_publicly_observed"),
        ),
        WriteupLesson(
            id="cwe-209-sensitive-error-message",
            source="MITRE CWE",
            ref="CWE-209 / Generation of Error Message Containing Sensitive Information",
            url="https://cwe.mitre.org/data/definitions/209.html",
            relation="sensitive_error_output_case",
            lesson="Error behavior becomes security-relevant when response content exposes sensitive application, environment or user information, not merely because an error occurred.",
            signal_hints=("error_detail_marker", "sensitive_response_observed", "error_detail_exposure_observed"),
        ),
        WriteupLesson(
            id="wstg-error-handling-and-page-content",
            source="OWASP WSTG",
            ref="WSTG-ERRH-01 / WSTG-INFO-05",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling",
            relation="error_and_page_content_review_method",
            lesson="Verbose errors and page content can reveal implementation detail; the engine still requires target-specific sensitivity and visibility evidence before promotion.",
            signal_hints=("error_detail_marker", "internal_detail_marker", "sensitive_marker"),
        ),
        WriteupLesson(
            id="ghsl-2024-008-openhab-information-disclosure",
            source="GitHub Security Lab",
            ref="GHSL-2024-005..008 / openHAB Web UI information disclosure",
            url="https://securitylab.github.com/advisories/GHSL-2024-005_GHSL-2024-008_openhab_webui/",
            relation="real_world_sensitive_information_disclosure",
            lesson="The reusable lesson is to identify the concrete information returned and the actor/context that receives it; technology or debug surface alone does not establish the finding.",
            signal_hints=("sensitive_response_observed", "private_field_publicly_observed"),
        ),
    ),
)

from __future__ import annotations

"""Canonical standards and real-world research grounding for BFLA."""

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


BFLA_STANDARD_SPEC = FamilyStandardSpec(
    family="broken_function_authorization",
    version="1.0.0",
    strategy="role_function_boundary",
    principle=(
        "Privileged-looking functions are only attack-surface clues; promotion "
        "requires stored target evidence that a role, permission or scope expected "
        "to be denied can actually invoke the function."
    ),
    owasp=(
        "Broken Access Control",
        "API5:2023 Broken Function Level Authorization",
    ),
    wstg=("WSTG-APIT-04", "WSTG-ATHZ-02", "WSTG-ATHZ-03"),
    cwe=("CWE-862", "CWE-863"),
    capec=("CAPEC-122",),
    methodology=(
        MethodologyStep(
            id="BFLA-01-function-inventory",
            basis=("OWASP API5:2023", "WSTG-APIT-04"),
            principle="Identify functions whose intended use is limited by role, group, permission, scope or administrative privilege; a privileged-looking route is only an attack-surface signal.",
        ),
        MethodologyStep(
            id="BFLA-02-role-function-matrix",
            basis=("CWE-862", "WSTG-ATHZ-02"),
            principle="Model the expected role-to-function matrix, including the exact operation and HTTP method, before interpreting a response as unauthorized.",
        ),
        MethodologyStep(
            id="BFLA-03-vertical-comparison",
            basis=("WSTG-ATHZ-02", "WSTG-APIT-04"),
            principle="Prefer like-for-like comparison between explicitly authorized lower- and higher-privilege test contexts for the same function and operation.",
        ),
        MethodologyStep(
            id="BFLA-04-method-and-scope-differential",
            basis=("OWASP API5:2023", "CWE-862"),
            principle="Check whether a weaker role, permission or scope can invoke a sensitive operation, including alternate methods that reach a more privileged effect.",
        ),
        MethodologyStep(
            id="BFLA-05-behavioral-decision",
            basis=("CWE-862", "WSTG-APIT-04"),
            principle="Treat successful execution by a context explicitly expected to be denied as decisive target evidence; route names, UI visibility and client-side checks are not confirmation.",
        ),
        MethodologyStep(
            id="BFLA-06-contradiction-check",
            basis=("WSTG-ATHZ-02",),
            principle="Look for server-side permission enforcement, lower-privilege denials, intentionally shared functions, no-op behavior and neighboring object/property authorization explanations before promotion.",
        ),
    ),
    surface_terms=("admin", "staff", "permission", "privilege", "management", "backoffice"),
    surface_fields=("role", "permission", "permissions", "is_admin", "scope"),
    confounders=(
        "broken_object_authorization",
        "mass_assignment",
        "authentication_session",
        "business_logic",
    ),
    false_positive_checks=(
        "The function is intentionally available to the lower role despite an administrative-looking route or label.",
        "Authentication presence does not establish or refute function-level authorization.",
        "A successful response is a harmless validation, preview or no-op and does not execute the privileged function.",
        "The apparent privilege difference is actually object-level authorization rather than access to the function itself.",
        "The apparent issue is property-level authorization or mass assignment rather than permission to invoke the function.",
        "A gateway, middleware, policy engine or server-side permission check consistently denies the lower-privilege context.",
        "Different HTTP methods intentionally expose different operations and the tested role is authorized for the observed method.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-outline-2025-117",
            source="GitHub Security Lab",
            ref="GHSL-2025-117 / Outline / CVE-2025-64487",
            url="https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/",
            relation="direct",
            lesson="A membership-management function used a weaker update permission where a stronger manage-users permission was required.",
            signal_hints=("privileged_function", "role_authorization_differential", "permission_scope_mismatch"),
        ),
        WriteupLesson(
            id="ghsl-sentry-2025-120",
            source="GitHub Security Lab",
            ref="GHSL-2025-120 / Sentry",
            url="https://securitylab.github.com/advisories/GHSL-2025-120_Sentry/",
            relation="direct",
            lesson="A destructive function required a weaker write permission than the stricter administrative permission used by the dedicated path.",
            signal_hints=("state_change", "permission_scope_mismatch", "unauthorized_function_success"),
        ),
        WriteupLesson(
            id="ghsl-openmetadata-2023-235",
            source="GitHub Security Lab",
            ref="GHSL-2023-235..237 / OpenMetadata",
            url="https://securitylab.github.com/advisories/GHSL-2023-235_GHSL-2023-237_Open_Metadata/",
            relation="direct",
            lesson="A sensitive function omitted the expected authorization call, allowing authenticated non-admin users to invoke privileged behavior.",
            signal_hints=("privileged_function", "unauthorized_function_success", "missing_authorization_check"),
        ),
    ),
)

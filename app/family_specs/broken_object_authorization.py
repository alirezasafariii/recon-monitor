from __future__ import annotations

"""Canonical standards and real-world research grounding for BOLA / IDOR.

This module contains no target observations and cannot satisfy admission.
"""

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


BOLA_STANDARD_SPEC = FamilyStandardSpec(
    family="broken_object_authorization",
    version="1.0.0",
    strategy="object_identity_boundary",
    principle=(
        "Object identifiers are only attack-surface clues; promotion requires "
        "stored target evidence of an object-level authorization boundary failure."
    ),
    owasp=(
        "Broken Access Control",
        "API1:2023 Broken Object Level Authorization",
    ),
    wstg=(
        "WSTG-APIT-02",
        "WSTG-ATHZ-04",
        "WSTG-ATHZ-02",
    ),
    cwe=(
        "CWE-639",
        "CWE-863",
    ),
    capec=("CAPEC-122",),
    methodology=(
        MethodologyStep(
            id="BOLA-01-object-reference",
            basis=("CWE-639", "WSTG-ATHZ-04", "WSTG-APIT-02"),
            principle=(
                "Identify a client-influenced key or object reference and the "
                "operation performed on that object."
            ),
        ),
        MethodologyStep(
            id="BOLA-02-authorization-boundary",
            basis=("OWASP API1:2023", "WSTG-ATHZ-02"),
            principle=(
                "Model the expected identity, tenant, role, sharing, parent/child "
                "or secondary-guard relationship for the referenced object."
            ),
        ),
        MethodologyStep(
            id="BOLA-03-horizontal-comparison",
            basis=("WSTG-ATHZ-02", "WSTG-ATHZ-04"),
            principle=(
                "Prefer like-for-like comparison between explicitly authorized "
                "identities with the same role and objects whose ownership is known."
            ),
        ),
        MethodologyStep(
            id="BOLA-04-behavioral-decision",
            basis=("CWE-639", "OWASP API1:2023"),
            principle=(
                "Treat successful access or mutation across the expected object "
                "boundary as decisive; an identifier alone is only an attack-surface signal."
            ),
        ),
        MethodologyStep(
            id="BOLA-05-contradiction-check",
            basis=("WSTG-ATHZ-02",),
            principle=(
                "Actively look for denials, ownership enforcement, scope binding, "
                "public/shared visibility and required secondary guards before promotion."
            ),
        ),
    ),
    surface_terms=(
        "id",
        "object",
        "resource",
        "record",
        "account",
        "user",
        "tenant",
        "project",
        "order",
    ),
    surface_fields=(
        "path",
        "query",
        "body",
        "graphql_variables",
        "response",
        "identity_context",
        "ownership_context",
    ),
    confounders=(
        "broken_function_authorization",
        "graphql_authorization",
        "information_disclosure",
    ),
    false_positive_checks=(
        "The object is intentionally public, shared or globally readable.",
        "The tested identifier is ignored, normalized to the caller's own object, or otherwise not used as the selected record key.",
        "A mismatched identity/object context is consistently denied or redirected without disclosing private object data.",
        "Tenant or parent/child binding is enforced before the object is read or mutated.",
        "A secondary object token or ownership guard is required and enforced.",
        "The apparent difference is caused by authentication or function-level authorization rather than object-level authorization.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-spree-2026-029",
            source="GitHub Security Lab",
            ref="GHSL-2026-029 / Spree",
            url="https://securitylab.github.com/advisories/GHSL-2026-029_Spree/",
            relation="direct",
            lesson=(
                "A valid object key is decisive only when access succeeds without the "
                "ownership or secondary guard that should bind the caller to the object."
            ),
            signal_hints=("object_identifier", "object_access_without_secondary_guard"),
        ),
        WriteupLesson(
            id="ghsl-zammad-2026-049",
            source="GitHub Security Lab",
            ref="GHSL-2026-049 / Zammad",
            url="https://securitylab.github.com/advisories/GHSL-2026-049_Zammad/",
            relation="direct",
            lesson=(
                "Fetching by identifier becomes BOLA when the expected group or role "
                "authorization for the selected object is not enforced."
            ),
            signal_hints=("object_identifier", "authorization_response_differential"),
        ),
        WriteupLesson(
            id="ghsl-wekan-2026-044",
            source="GitHub Security Lab",
            ref="GHSL-2026-044 / Wekan",
            url="https://securitylab.github.com/advisories/GHSL-2026-044_Wekan/",
            relation="direct",
            lesson=(
                "Authorizing a parent object is insufficient when a separately supplied "
                "child identifier is not bound to that parent."
            ),
            signal_hints=("parent_child_scope_mismatch", "object_identifier"),
        ),
        WriteupLesson(
            id="ghsl-sentry-2025-130",
            source="GitHub Security Lab",
            ref="GHSL-2025-130 / Sentry",
            url="https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/",
            relation="direct",
            lesson=(
                "Tenant context must be bound to the referenced object; a valid scope "
                "in one tenant does not authorize an object from another tenant."
            ),
            signal_hints=("cross_tenant_object_access", "identity_object_relation_conflict"),
        ),
    ),
)

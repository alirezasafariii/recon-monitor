from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


MASS_ASSIGNMENT_STANDARD_SPEC = FamilyStandardSpec(
    family="mass_assignment",
    version="1.0.0",
    strategy="object_property_authorization_boundary",
    principle=(
        "Sensitive-looking writable properties are attack-surface clues only; promotion requires "
        "stored target evidence that a property outside the caller's intended writable policy "
        "was accepted, persisted, or behaved differently across an authorization boundary."
    ),
    owasp=(
        "API3:2023 Broken Object Property Level Authorization",
        "API6:2019 Mass Assignment",
    ),
    wstg=("WSTG-INPV-20",),
    cwe=("CWE-915",),
    capec=(),
    methodology=(
        MethodologyStep(
            id="MA-01-property-surface",
            basis=("API3:2023", "WSTG-INPV-20", "CWE-915"),
            principle="Identify client-controlled write operations exposing security-sensitive properties; names alone are only surface evidence.",
        ),
        MethodologyStep(
            id="MA-02-writable-contract",
            basis=("WSTG-INPV-20", "CWE-915"),
            principle="Model the exact server-side writable-field contract for the current role, including DTO, serializer, schema or allow-list controls.",
        ),
        MethodologyStep(
            id="MA-03-property-authorization",
            basis=("API3:2023", "CWE-915"),
            principle="Separate property-level authorization from object ownership and function permission; determine whether this caller may modify this exact property.",
        ),
        MethodologyStep(
            id="MA-04-behavioral-decision",
            basis=("WSTG-INPV-20", "CWE-915"),
            principle="Potential-Finding admission requires stored target behavior showing unauthorized acceptance, mutation, or a property authorization differential.",
        ),
        MethodologyStep(
            id="MA-05-falsification",
            basis=("API3:2023", "CWE-915"),
            principle="Treat rejection, ignored protected fields, and enforced server writable-field allow-lists as contradiction evidence.",
        ),
    ),
    surface_terms=("mass assignment", "autobinding", "object binding", "property update", "serializer", "dto"),
    surface_fields=("role", "is_admin", "permissions", "owner_id", "tenant_id", "status", "verified", "balance"),
    confounders=("broken_object_authorization", "broken_function_authorization", "business_logic"),
    false_positive_checks=(
        "A sensitive-looking property may be intentionally writable by the current role or workflow.",
        "A property accepted syntactically but ignored and never persisted is not a property-authorization failure.",
        "An enforced server DTO, serializer or writable-field allow-list that excludes the protected property contradicts the hypothesis.",
        "A validation echo or response reflection is not proof that the protected property was persisted.",
        "Object ownership failures belong to BOLA and function permission failures belong to BFLA unless property-level authorization independently fails.",
        "OWASP, WSTG, CWE and research write-ups define the method but add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-api3-2023-property-authorization-case",
            source="OWASP API Security",
            ref="API3:2023 Broken Object Property Level Authorization",
            url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
            relation="canonical_case_study",
            lesson=(
                "The reusable pattern is that an otherwise authorized object operation becomes vulnerable "
                "when a client can read or change a sensitive property outside the caller's property policy."
            ),
            signal_hints=("privileged_property", "protected_property_accepted", "protected_property_mutated", "property_authorization_differential"),
        ),
        WriteupLesson(
            id="ghsl-liveql-druid-mass-assignment",
            source="GitHub Security Lab",
            ref="LiveQL Episode II / Apache Druid mass-assignment research",
            url="https://securitylab.github.com/resources/rhino-in-the-room/",
            relation="related_research",
            lesson=(
                "The Druid research shows why permissive object binding is security-relevant only when attacker-controlled "
                "properties cross an intended configuration or authorization boundary; research similarity is never target evidence."
            ),
            signal_hints=("body_schema", "protected_property_accepted", "server_allowlist_observed"),
        ),
    ),
)

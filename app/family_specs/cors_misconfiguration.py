from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


CORS_MISCONFIGURATION_STANDARD_SPEC = FamilyStandardSpec(
    family="cors_misconfiguration",
    version="1.0.0",
    strategy="cross_origin_read_authorization_boundary",
    principle=(
        "CORS response headers are policy surface, not a vulnerability verdict; promotion requires an independently "
        "security-sensitive response context plus stored controlled-origin evidence that an unintended origin is actually allowed. "
        "A credentialed readable sensitive response is the strongest condition."
    ),
    owasp=("A02:2025 Security Misconfiguration", "A01:2025 Broken Access Control"),
    wstg=("WSTG-CLNT-07",),
    cwe=("CWE-942",),
    capec=(),
    methodology=(
        MethodologyStep(
            id="CORS-01-policy-surface",
            basis=("WSTG-CLNT-07", "CWE-942"),
            principle="Record the exact CORS policy without treating wildcard or reflection-looking headers alone as browser-readable sensitive data.",
        ),
        MethodologyStep(
            id="CORS-02-sensitive-context",
            basis=("WSTG-CLNT-07", "A01:2025"),
            principle="Establish independently whether the response is authenticated, user-specific, private or otherwise security-sensitive.",
        ),
        MethodologyStep(
            id="CORS-03-controlled-origin",
            basis=("WSTG-CLNT-07", "CWE-942"),
            principle="Promotion requires stored behavior from an explicitly controlled origin outside the intended trust policy showing that origin is accepted.",
        ),
        MethodologyStep(
            id="CORS-04-browser-boundary",
            basis=("WSTG-CLNT-07", "CWE-942"),
            principle="Separate origin allowance from credentials and actual browser readability; blocked reads and trusted-origin-only behavior are contradictions.",
        ),
        MethodologyStep(
            id="CORS-05-decision",
            basis=("GHSL-2024-034", "CWE-942"),
            principle="Treat a credentialed sensitive response readable from an unintended origin as the strongest target-side condition; standards and write-ups add no evidence.",
        ),
    ),
    surface_terms=("access-control-allow-origin", "access-control-allow-credentials", "origin", "cors"),
    surface_fields=("origin", "acao", "acac", "allow-origin", "allow-credentials"),
    confounders=("information_disclosure", "csrf", "authentication_session"),
    false_positive_checks=(
        "Access-Control-Allow-Origin: * is not automatically exploitable and cannot by itself establish a credentialed browser-readable response.",
        "A reflected Origin string in logs or serialized headers does not prove arbitrary origins are accepted at runtime.",
        "Access-Control-Allow-Credentials must be interpreted with exact origin behavior and browser readability.",
        "Public static/API metadata may intentionally permit broad cross-origin reads.",
        "Trusted-origin allow-lists, disabled credentials and browser-blocked controlled reads are contradiction evidence.",
        "OWASP, WSTG, CWE and write-up similarity never count as target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-2024-034-memos-cors",
            source="GitHub Security Lab",
            ref="GHSL-2024-034 / memos CORS misconfiguration",
            url="https://securitylab.github.com/advisories/GHSL-2024-034_memos/",
            relation="direct_arbitrary_origin_with_credentials",
            lesson=(
                "memos reflected arbitrary Origin values and enabled credentials, exposing sensitive APIs cross-origin. "
                "The reusable lesson is to prove unintended-origin acceptance and sensitive browser-readable behavior, not score headers."
            ),
            signal_hints=("cors_header", "sensitive_context", "untrusted_origin_allowed", "credentialed_cross_origin_read"),
        ),
    ),
)

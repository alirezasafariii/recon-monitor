from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


OPEN_REDIRECT_STANDARD_SPEC = FamilyStandardSpec(
    family="open_redirect",
    version="1.0.0",
    strategy="user_controlled_navigation_origin_boundary",
    principle=(
        "Redirect-like parameters and static source-to-navigation flows are attack-surface context only; promotion requires "
        "stored target behavior proving that a user-controlled destination was accepted and navigation reached an external "
        "origin outside the intended trust policy."
    ),
    owasp=("A01:2025 Broken Access Control",),
    wstg=("WSTG-CLNT-04",),
    cwe=("CWE-601",),
    capec=(),
    methodology=(
        MethodologyStep(
            id="REDIR-01-input-surface",
            basis=("WSTG-CLNT-04", "CWE-601"),
            principle="Identify the exact user-influenced URL or path field and keep redirect-looking parameter names as structural evidence only.",
        ),
        MethodologyStep(
            id="REDIR-02-navigation-sink",
            basis=("WSTG-CLNT-04",),
            principle="Trace the destination into an actual browser or response navigation primitive; URL parsing, storage or link display is not redirection.",
        ),
        MethodologyStep(
            id="REDIR-03-destination-policy",
            basis=("A01:2025", "CWE-601"),
            principle="Model exact origin/host allow-lists, same-origin restrictions, relative-path-only handling, scheme restrictions and normalization before deciding whether an external destination is permitted.",
        ),
        MethodologyStep(
            id="REDIR-04-runtime-destination",
            basis=("WSTG-CLNT-04", "CWE-601", "GHSL-2025-122"),
            principle="Potential-Finding admission requires a stored observation that a user-controlled destination was accepted and the resulting navigation reached an external origin outside the intended trust boundary.",
        ),
        MethodologyStep(
            id="REDIR-05-falsification",
            basis=("WSTG-CLNT-04", "CWE-601"),
            principle="Treat same-origin, relative-only and enforced destination allow-list behavior as contradiction evidence and compare parsed scheme/host/port rather than substrings.",
        ),
    ),
    surface_terms=("redirect", "return url", "returnurl", "next", "continue", "callback", "destination", "location", "navigate"),
    surface_fields=("redirect", "redirect_url", "redirect_uri", "return_url", "returnurl", "next", "continue", "callback", "destination", "url"),
    confounders=("dom_xss", "authentication_session", "business_logic"),
    false_positive_checks=(
        "A parameter named next, url, redirect, returnUrl or redirect_uri is only a destination surface.",
        "A static source-to-navigation flow is one correlated evidence root and does not prove an external destination is accepted.",
        "Missing visible client-side validation does not establish that server or runtime destination policy is absent.",
        "Relative paths and same-origin absolute URLs are not external redirects.",
        "Exact origin/host allow-lists and relative-path-only controls contradict the open-redirect condition when enforced.",
        "Hostname checks must use parsed origin semantics; substring or prefix similarity is not a trusted-origin decision.",
        "OAuth redirect_uri and callback parameters often have registered-destination semantics and must not be promoted from names alone.",
        "OWASP, WSTG, CWE and research write-ups define detection methodology but add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-2025-122-nocodb-open-redirect",
            source="GitHub Security Lab",
            ref="GHSL-2025-122 / NocoDB unvalidated redirect in login",
            url="https://securitylab.github.com/advisories/GHSL-2025-121_GHSL-2025-123_nocodb/",
            relation="direct_unvalidated_external_redirect",
            lesson=(
                "NocoDB accepted a sign-in continuation value and navigated externally without domain/origin restriction. The reusable detector lesson is the full chain: user-controlled destination, navigation decision, and accepted external origin."
            ),
            signal_hints=("redirect_parameter", "user_controlled_destination", "external_destination_accepted", "destination_allowlist_observed"),
        ),
    ),
)

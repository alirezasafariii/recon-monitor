from __future__ import annotations

"""Canonical standards and real-world research grounding for SSRF."""

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


SSRF_STANDARD_SPEC = FamilyStandardSpec(
    family="ssrf",
    version="1.0.0",
    strategy="server_outbound_request_boundary",
    principle=(
        "URL-like input is only an attack-surface clue; promotion requires stored "
        "target evidence tying a user-controlled destination to a request performed "
        "by the server or a correlated controlled callback."
    ),
    owasp=(
        "Server-Side Request Forgery (SSRF)",
        "API7:2023 Server Side Request Forgery",
    ),
    wstg=("WSTG-INPV-19",),
    cwe=("CWE-918",),
    capec=("CAPEC-664",),
    methodology=(
        MethodologyStep(
            id="SSRF-01-destination-surface",
            basis=("WSTG-INPV-19", "CWE-918"),
            principle="Identify the exact user-controlled remote destination and keep URL-looking field names as structural surface evidence only.",
        ),
        MethodologyStep(
            id="SSRF-02-execution-location",
            basis=("WSTG-INPV-19",),
            principle="Separate browser-side network activity from a server, worker or backend component performing the outbound request.",
        ),
        MethodologyStep(
            id="SSRF-03-destination-policy",
            basis=("CWE-918",),
            principle="Model scheme/host allow-lists, private-network restrictions, redirect revalidation and egress controls before treating a remote fetch as a security-boundary failure.",
        ),
        MethodologyStep(
            id="SSRF-04-stored-outbound-observation",
            basis=("WSTG-INPV-19", "CWE-918"),
            principle="Potential-Finding evidence requires a stored observation tying a user-controlled destination to an outbound request performed by the server or a correlated controlled callback.",
        ),
        MethodologyStep(
            id="SSRF-05-boundary-failure",
            basis=("CWE-918",),
            principle="Confirmation remains stricter: stored evidence must show that an intended destination restriction was bypassed or a restricted destination was actually accepted.",
        ),
    ),
    surface_terms=("fetch url", "remote url", "webhook", "import url", "callback", "proxy", "attachment url"),
    surface_fields=("url", "uri", "webhook", "callback", "remote_url", "image_url", "attachment_url"),
    confounders=("open_redirect", "unsafe_api_consumption", "path_traversal"),
    false_positive_checks=(
        "A URL parameter plus webhook/import/preview/proxy wording is one structural surface, not proof of a server-side request.",
        "A browser fetch, client-side image load or JavaScript request is not SSRF.",
        "An application response status such as HTTP 200 does not prove that the backend fetched the supplied destination.",
        "A server feature intentionally fetching a fixed or allow-listed destination is not an SSRF boundary failure.",
        "A controlled callback must be correlated to the tested destination/request and attributed to server execution; unrelated DNS/HTTP noise is not target evidence.",
        "Private, loopback, link-local or metadata-looking destinations are never probed automatically by this analyzer.",
        "Observed scheme, host, private-network, redirect or egress enforcement is evidence against the vulnerable condition unless a concrete bypass is also observed.",
        "Hostname text is not resolved by the analyzer and no private/public routing claim is inferred from an unresolved hostname.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-wekan-2026-045",
            source="GitHub Security Lab",
            ref="GHSL-2026-045 / Wekan SSRF",
            url="https://securitylab.github.com/advisories/GHSL-2026-045_Wekan/",
            relation="direct",
            lesson="SSRF requires a user-controlled remote destination to reach a server-side fetch primitive without effective destination restrictions.",
            signal_hints=("remote_destination", "server_fetch_observed", "destination_policy_bypass_observed"),
        ),
    ),
)

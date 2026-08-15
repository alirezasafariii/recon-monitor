from __future__ import annotations

"""Canonical standards and real-world research grounding for DOM-based XSS.

The specification defines detection methodology only. OWASP, WSTG, CWE,
CAPEC and write-up material classify and explain target observations but never
satisfy admission, confirmation or independent target-evidence requirements.
"""

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


DOM_XSS_STANDARD_SPEC = FamilyStandardSpec(
    family="dom_xss",
    version="1.0.0",
    strategy="dom_source_sink_runtime_boundary",
    principle=(
        "Browser source and dangerous sink discovery is attack-surface context only; "
        "promotion requires stored target evidence that user-influenced data reaches "
        "a script-capable DOM/execution context with effective neutralization absent."
    ),
    owasp=("A05:2025 Injection",),
    wstg=("WSTG-CLNT-01",),
    cwe=("CWE-79",),
    capec=("CAPEC-63",),
    methodology=(
        MethodologyStep(
            id="DOMXSS-01-source-classification",
            basis=("WSTG-CLNT-01", "CWE-79"),
            principle=(
                "Identify the exact browser-side value that is user influenced. The "
                "mere presence of URL, location, storage or input APIs is source-surface context only."
            ),
        ),
        MethodologyStep(
            id="DOMXSS-02-flow-correlation",
            basis=("WSTG-CLNT-01",),
            principle=(
                "Preserve the concrete source-to-sink relationship. A source and sink "
                "derived from one static dataflow are one correlated evidence root, not two proofs."
            ),
        ),
        MethodologyStep(
            id="DOMXSS-03-sink-context",
            basis=("A05:2025 Injection", "CWE-79"),
            principle=(
                "Distinguish HTML-rendering and JavaScript execution contexts from safe "
                "text sinks, navigation-only behavior and neighboring postMessage trust issues."
            ),
        ),
        MethodologyStep(
            id="DOMXSS-04-neutralization-controls",
            basis=("A05:2025 Injection", "CWE-79"),
            principle=(
                "Treat context-appropriate sanitization or encoding, Trusted Types and "
                "safe text-only DOM APIs as contradiction/control evidence."
            ),
        ),
        MethodologyStep(
            id="DOMXSS-05-runtime-reachability",
            basis=("WSTG-CLNT-01",),
            principle=(
                "Require stored runtime evidence that a controlled harmless marker from "
                "the identified source reaches the identified dangerous sink. Reachability alone is not the bug condition."
            ),
        ),
        MethodologyStep(
            id="DOMXSS-06-vulnerability-condition",
            basis=("A05:2025 Injection", "CWE-79", "GHSL-2025-110"),
            principle=(
                "Potential-finding admission requires target-side evidence of an unsanitized "
                "runtime flow into a script-capable DOM/execution context. Standards and write-ups add zero evidence."
            ),
        ),
    ),
    surface_terms=(
        "location.search",
        "location.hash",
        "urlsearchparams",
        "document.referrer",
        "window.name",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "document.write",
        "eval",
        "settimeout",
    ),
    surface_fields=(
        "returnto",
        "next",
        "redirect",
        "url",
        "html",
        "content",
        "message",
        "query",
        "search",
    ),
    confounders=(
        "postmessage_trust",
        "open_redirect",
        "client_side_resource_manipulation",
        "reflected_xss",
        "stored_xss",
    ),
    false_positive_checks=(
        "A source token and a dangerous sink in the same JavaScript bundle do not prove runtime flow.",
        "Static source/sink facts from one dataflow are one correlated evidence root and cannot independently satisfy admission.",
        "A harmless marker reaching an HTML sink proves reachability, not a script-capable unsanitized condition.",
        "textContent, innerText and equivalent text-only DOM APIs are not HTML/executable sinks for this family.",
        "Navigation-only behavior belongs to redirect/client-resource families unless script execution context is independently established.",
        "postMessage input belongs primarily to postMessage Trust unless independent DOM-XSS condition evidence exists.",
        "Context-appropriate sanitization, encoding, Trusted Types or a safe DOM API contradict the vulnerability condition.",
        "OWASP, WSTG, CWE, CAPEC and write-up similarity never count as target evidence or an independent evidence source.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-2025-110-openlibrary-barcode-xss",
            source="GitHub Security Lab",
            ref="GHSL-2025-110 / OpenLibrary barcode scanner XSS",
            url="https://securitylab.github.com/advisories/GHSL-2025-110_openlibrary/",
            relation="direct_client_side",
            lesson=(
                "A query-string value was read through URLSearchParams and later assigned "
                "to a browser navigation sink where a javascript URL could execute. The reusable lesson is to preserve "
                "the concrete browser source-to-sink path and establish execution context rather than score source/sink keywords."
            ),
            signal_hints=(
                "dataflow_source",
                "dataflow_sink",
                "runtime_dom_sink_reached",
                "unsanitized_dom_flow",
            ),
        ),
        WriteupLesson(
            id="ghsl-2026-030-nocodb-rendering",
            source="GitHub Security Lab",
            ref="GHSL-2026-030 / NocoDB XSS rendering pattern",
            url="https://securitylab.github.com/advisories/GHSL-2026-030_nocodb/",
            relation="adjacent_rendering",
            lesson=(
                "User-controlled rich content reached an HTML-rendering sink without effective sanitization. "
                "For DOM-XSS reasoning this is an adjacent real-world lesson about sink context and neutralization, "
                "not evidence that any other target is vulnerable."
            ),
            signal_hints=(
                "dataflow_sink",
                "unsanitized_dom_flow",
                "sanitization_observed",
            ),
        ),
    ),
)

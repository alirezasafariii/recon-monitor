from __future__ import annotations

"""Dedicated Sensitive Response Caching analyzer.

Cacheable-looking headers on a sensitive endpoint create a policy hypothesis,
not proof of cross-user exposure. Direct evidence requires already-stored
redacted shared-cache observations using controlled identities/test data. This
analyzer never requests another identity's response and never stores response
bodies.
"""

from typing import Any, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, header_map, observations, scalar, truth


SENSITIVE_CACHING_FAMILY_ANALYZER_VERSION = "1.0.0"
SENSITIVE_CACHING_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

SENSITIVE_CACHING_TAXONOMY = {
    "owasp": ["Sensitive Data Exposure", "HTTP Caching"],
    "wstg": ["WSTG-ATHN-06"],
    "cwe": ["CWE-525"],
    "related_cwe": ["CWE-200"],
}

SENSITIVE_CACHING_METHOD = (
    {
        "id": "CACHE-01-cache-policy",
        "basis": ["WSTG-ATHN-06", "CWE-525"],
        "principle": "Record Cache-Control/Vary/shared-cache metadata while separating cacheability from cross-user or local sensitive-data exposure.",
    },
    {
        "id": "CACHE-02-sensitive-context",
        "basis": ["WSTG-ATHN-06"],
        "principle": "Determine independently whether the response is authenticated, user-specific or otherwise sensitive; public cacheable content is not a vulnerability.",
    },
    {
        "id": "CACHE-03-cache-key-controls",
        "basis": ["CWE-525"],
        "principle": "Treat private/no-store directives, user-specific Vary/cache-key behavior and explicit shared-cache bypass as contradiction evidence.",
    },
    {
        "id": "CACHE-04-controlled-shared-cache-observation",
        "basis": ["WSTG-ATHN-06", "CWE-525"],
        "principle": "Direct evidence requires already-stored redacted shared-cache behavior using controlled identities/test data; no sensitive response body is retained.",
    },
)

SENSITIVE_CACHING_FALSE_POSITIVE_CHECKS = (
    "Cache-Control: max-age or public on intentionally public content is not a sensitive-caching vulnerability.",
    "A response can be browser-cacheable yet safely excluded from shared caches; cache scope and authentication context matter.",
    "Vary headers must be interpreted as part of the actual cache key, not simply by their presence or absence.",
    "CDN HIT/MISS metadata does not prove two users receive the same sensitive representation.",
    "Direct evidence requires controlled test identities and redacted metadata only; unrelated-user responses and sensitive bodies are outside this analyzer contract.",
    "The analyzer performs no cache poisoning, cache deception, cross-user request, CDN purge or response-body persistence.",
)

SENSITIVE_CACHING_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-athn-06-browser-cache",
        "source": "OWASP WSTG",
        "ref": "WSTG-ATHN-06 / Testing for Browser Cache Weaknesses",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
        "principle": "Sensitive authenticated content requires cache directives and behavior appropriate to its confidentiality and user specificity.",
        "signals": ["cache_header", "sensitive_context", "shared_cache_sensitive_response"],
    },
    {
        "id": "cwe-525-browser-cache-sensitive-info",
        "source": "MITRE CWE",
        "ref": "CWE-525 / Use of Web Browser Cache Containing Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/525.html",
        "principle": "Improper caching of sensitive information can expose data beyond its intended authenticated context.",
        "signals": ["cache_header", "cross_user_cache_observed"],
    },
)

_SENSITIVE_CONTEXTS = {"payment", "identity", "customer_data", "administration", "partner_portal", "authentication", "account", "private"}


def analyze_sensitive_caching_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, semantic_text
    details = dict(details or {})
    headers = header_map(details)
    cache_control = str(headers.get("cache-control") or "").strip()
    vary = str(headers.get("vary") or "").strip()
    runtime = observations(details, "cache_observations", "sensitive_cache_observations", "shared_cache_observations")
    cache_surface = bool(cache_control or headers.get("age") or headers.get("x-cache") or headers.get("cf-cache-status") or truth(details.get("cache_header_observed")) is True)
    if not cache_surface and not runtime:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    if cache_surface:
        cache_summary = cache_control[:180] if cache_control else "stored cache metadata"
        add_unique(support, {
            "type": "cache_header", "source": "stored_http_headers", "source_group": "cache_response_policy", "weight": 20,
            "text": f"Stored response metadata includes cache policy or shared-cache indicators ({cache_summary}).",
        })

    context_sensitive = bool(
        str(business_context or "general").lower() in _SENSITIVE_CONTEXTS
        or truth(details.get("sensitive_context")) is True
        or truth(details.get("authenticated_response")) is True
        or truth(details.get("user_specific_response")) is True
    )
    if context_sensitive:
        add_unique(support, {
            "type": "sensitive_context", "source": "endpoint_business_context", "source_group": "cache_sensitive_response_context", "weight": 18,
            "text": "Stored endpoint context marks the response as authenticated, user-specific or security-sensitive.",
        })

    lower_cc = cache_control.lower()
    if any(token in lower_cc for token in ("no-store", "private")) or truth(details.get("private_cache_control_observed")) is True:
        add_unique(contradict, {
            "type": "private_cache_control_observed", "source": "stored_cache_policy", "source_group": "cache_scope_control", "weight": -44,
            "text": "Stored cache policy contains private/no-store behavior or equivalent private-cache enforcement.",
        })
    if truth(details.get("user_specific_vary_observed")) is True:
        add_unique(contradict, {
            "type": "user_specific_vary_observed", "source": "stored_cache_policy", "source_group": "cache_key_control", "weight": -36,
            "text": "Stored cache-key evidence includes a user-specific variation boundary for this response.",
        })
    elif vary and any(token in vary.lower() for token in ("authorization", "cookie")):
        add_unique(contradict, {
            "type": "user_specific_vary_observed", "source": "stored_http_headers", "source_group": "cache_key_control", "weight": -32,
            "text": "Stored Vary metadata includes Authorization or Cookie, indicating user-specific cache-key separation.",
        })
    if truth(details.get("shared_cache_bypass_observed")) is True:
        add_unique(contradict, {
            "type": "shared_cache_bypass_observed", "source": "stored_cache_policy", "source_group": "cache_scope_control", "weight": -40,
            "text": "Stored evidence indicates the relevant response bypasses shared caching.",
        })

    for index, obs in enumerate(runtime[:50]):
        controlled = truth(scalar(obs, ("controlled_test_context", "controlled_identities", "authorized_test_context"))) is True
        redacted = truth(scalar(obs, ("response_body_redacted", "sensitive_values_redacted", "metadata_only"))) is True
        group = f"cache_observation:{index}"
        if truth(scalar(obs, ("private_cache_control_observed", "private_cache_enforced"))) is True:
            add_unique(contradict, {
                "type": "private_cache_control_observed", "source": "stored_controlled_cache_observation", "source_group": group, "weight": -44,
                "text": "Stored controlled behavior shows the sensitive test response is restricted to private/non-shared caching.",
            })
        if truth(scalar(obs, ("user_specific_vary_observed", "cache_key_separates_users"))) is True:
            add_unique(contradict, {
                "type": "user_specific_vary_observed", "source": "stored_controlled_cache_observation", "source_group": group, "weight": -40,
                "text": "Stored controlled cache behavior separates the tested identities by cache key.",
            })
        if not (controlled and redacted):
            continue
        sensitive = truth(scalar(obs, ("sensitive_response", "authenticated_response", "user_specific_response"))) is True
        shared = truth(scalar(obs, ("shared_cache_hit", "shared_cache_sensitive_response", "response_served_from_shared_cache"))) is True
        if sensitive and shared:
            add_unique(support, {
                "type": "shared_cache_sensitive_response", "source": "stored_controlled_cache_observation", "source_group": group, "weight": 58,
                "text": "Redacted controlled evidence shows an authenticated/user-specific test response is served from a shared cache context.",
            })
        cross_user = truth(scalar(obs, ("cross_user_cache_observed", "second_controlled_identity_received_first_identity_representation"))) is True
        two_identities = truth(scalar(obs, ("two_controlled_test_identities", "controlled_identity_pair"))) is True
        if cross_user and two_identities:
            add_unique(support, {
                "type": "cross_user_cache_observed", "source": "stored_controlled_cache_observation", "source_group": group, "weight": 64,
                "text": "Redacted stored evidence using two controlled identities shows one test identity can receive the other's cached representation.",
            })

    observed = {item["type"] for item in support}
    if "cross_user_cache_observed" in observed:
        variant = "cross_controlled_identity_cache"
    elif "shared_cache_sensitive_response" in observed:
        variant = "sensitive_response_in_shared_cache"
    elif context_sensitive:
        variant = "sensitive_cache_policy_potential"
    else:
        variant = "cache_policy_surface"

    return finalize_result(
        analyzer=SensitiveCachingFamilyAnalyzer(),
        family="sensitive_caching",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=SENSITIVE_CACHING_TAXONOMY,
        methodology=SENSITIVE_CACHING_METHOD,
        false_positive_checks=SENSITIVE_CACHING_FALSE_POSITIVE_CHECKS,
        writeup_patterns=SENSITIVE_CACHING_WRITEUP_PATTERNS,
        direct_types={"shared_cache_sensitive_response", "cross_user_cache_observed"},
        rule_ids=("family-cache-policy-surface", "family-cache-sensitive-context", "family-cache-controlled-shared-cache"),
        summary="Sensitive caching hypothesis based on stored cache policy, independent sensitive-response context and redacted controlled shared-cache behavior when available.",
        base=20,
        extra_meta={
            "family_rule_version": SENSITIVE_CACHING_FAMILY_ANALYZER_RULE_VERSION,
            "cache_control": cache_control[:180],
            "vary": vary[:180],
            "runtime_observation_count": len(runtime),
            "response_body_stored": False,
            "cross_user_request_performed": False,
            "cache_poisoning_performed": False,
        },
    )


class SensitiveCachingFamilyAnalyzer(FamilyAnalyzer):
    family = "sensitive_caching"
    analyzer_version = SENSITIVE_CACHING_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_sensitive_caching_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

from __future__ import annotations

"""Dedicated CORS Misconfiguration analyzer.

CORS headers are policy surface, not exploitability. Promotion requires a
security-sensitive response context in a separate evidence root. Confirmation
requires already-stored controlled-origin behavior showing an unintended origin
is allowed or a credentialed sensitive response is cross-origin readable. The
analyzer performs no browser request or credentialed cross-origin fetch.
"""

from typing import Any, Mapping

from core import Database
from family_specs.registry import get_detection_spec
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, header_map, observations, scalar, truth


CORS_MISCONFIGURATION_FAMILY_ANALYZER_VERSION = "1.0.0"
CORS_MISCONFIGURATION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

CORS_MISCONFIGURATION_SPEC = get_detection_spec("cors_misconfiguration")

# Compatibility exports; canonical definitions live in family_specs.
CORS_MISCONFIGURATION_TAXONOMY = CORS_MISCONFIGURATION_SPEC.taxonomy()
CORS_MISCONFIGURATION_METHOD = tuple(step.as_dict() for step in CORS_MISCONFIGURATION_SPEC.standard.methodology)
CORS_MISCONFIGURATION_FALSE_POSITIVE_CHECKS = tuple(CORS_MISCONFIGURATION_SPEC.standard.false_positive_checks)
CORS_MISCONFIGURATION_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in CORS_MISCONFIGURATION_SPEC.standard.writeups
)

_SENSITIVE_CONTEXTS = {"payment", "identity", "customer_data", "administration", "partner_portal", "authentication", "account", "private"}


def analyze_cors_misconfiguration_signal(
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
    acao = str(headers.get("access-control-allow-origin") or "").strip()
    acac = str(headers.get("access-control-allow-credentials") or "").strip().lower()
    runtime = observations(details, "cors_observations", "cors_runtime_observations", "cross_origin_observations")
    if not acao and not runtime and truth(details.get("cors_header_observed")) is not True:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    if acao or truth(details.get("cors_header_observed")) is True:
        description = acao[:180] if acao else "stored CORS policy"
        add_unique(support, {
            "type": "cors_header", "source": "stored_http_headers", "source_group": "cors_response_policy", "weight": 20,
            "text": f"Stored response headers include a CORS policy ({description}).",
        })

    context_sensitive = bool(
        str(business_context or "general").lower() in _SENSITIVE_CONTEXTS
        or truth(details.get("sensitive_context")) is True
        or truth(details.get("authenticated_response")) is True
        or truth(details.get("user_specific_response")) is True
    )
    if context_sensitive:
        add_unique(support, {
            "type": "sensitive_context", "source": "endpoint_business_context", "source_group": "cors_sensitive_response_context", "weight": 18,
            "text": "Stored endpoint context marks the response as authenticated, user-specific or security-sensitive.",
        })

    if truth(details.get("trusted_origin_only")) is True:
        add_unique(contradict, {
            "type": "trusted_origin_only", "source": "stored_cors_policy", "source_group": "cors_origin_control", "weight": -42,
            "text": "Stored policy evidence indicates only explicitly trusted origins are allowed.",
        })
    if acac in {"false", "0", "no"} or truth(details.get("credentials_disabled")) is True:
        add_unique(contradict, {
            "type": "credentials_disabled", "source": "stored_cors_policy", "source_group": "cors_credential_control", "weight": -26,
            "text": "Stored CORS evidence indicates credentialed cross-origin requests are disabled for the relevant response.",
        })

    for index, obs in enumerate(runtime[:50]):
        controlled_origin = truth(scalar(obs, ("controlled_origin", "controlled_test_origin", "origin_is_test_controlled"))) is True
        unintended = truth(scalar(obs, ("origin_untrusted_by_policy", "unintended_origin", "origin_outside_allowlist"))) is True
        group = f"cors_observation:{index}"
        if truth(scalar(obs, ("cross_origin_read_blocked", "browser_read_blocked", "cors_read_blocked"))) is True:
            add_unique(contradict, {
                "type": "cross_origin_read_blocked", "source": "stored_controlled_cors_observation", "source_group": group, "weight": -44,
                "text": "Stored controlled browser observation shows the unintended-origin read is blocked.",
            })
        if not (controlled_origin and unintended):
            continue
        if truth(scalar(obs, ("untrusted_origin_allowed", "acao_allows_test_origin", "origin_reflected_and_accepted"))) is True:
            add_unique(support, {
                "type": "untrusted_origin_allowed", "source": "stored_controlled_cors_observation", "source_group": group, "weight": 52,
                "text": "Stored controlled-origin evidence shows an origin outside the intended trust policy is accepted by CORS.",
            })
        credentialed = truth(scalar(obs, ("credentials_included", "credentialed_request"))) is True
        readable = truth(scalar(obs, ("cross_origin_response_readable", "browser_read_succeeded", "credentialed_cross_origin_read"))) is True
        sensitive = truth(scalar(obs, ("sensitive_response", "user_specific_response", "authenticated_response"))) is True
        if credentialed and readable and sensitive:
            add_unique(support, {
                "type": "credentialed_cross_origin_read", "source": "stored_controlled_cors_observation", "source_group": group, "weight": 62,
                "text": "Stored controlled browser evidence shows a credentialed, security-sensitive response is readable from an unintended controlled origin.",
            })

    observed = {item["type"] for item in support}
    if "credentialed_cross_origin_read" in observed:
        variant = "credentialed_sensitive_cross_origin_read"
    elif "untrusted_origin_allowed" in observed:
        variant = "untrusted_origin_allowed"
    elif acao == "*":
        variant = "wildcard_policy_surface"
    elif acao:
        variant = "cors_origin_policy_surface"
    else:
        variant = "cors_behavior_surface"

    return finalize_result(
        analyzer=CorsMisconfigurationFamilyAnalyzer(),
        family="cors_misconfiguration",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=CORS_MISCONFIGURATION_TAXONOMY,
        methodology=CORS_MISCONFIGURATION_METHOD,
        false_positive_checks=CORS_MISCONFIGURATION_FALSE_POSITIVE_CHECKS,
        writeup_patterns=CORS_MISCONFIGURATION_WRITEUP_PATTERNS,
        direct_types={"untrusted_origin_allowed", "credentialed_cross_origin_read"},
        rule_ids=("family-cors-policy-surface", "family-cors-sensitive-context", "family-cors-controlled-origin"),
        summary="CORS hypothesis based on stored response policy, independent sensitive-response context and controlled-origin behavior when available.",
        base=20,
        extra_meta={
            "family_rule_version": CORS_MISCONFIGURATION_FAMILY_ANALYZER_RULE_VERSION,
            "acao": acao[:180],
            "credentials_header_present": bool(acac),
            "runtime_observation_count": len(runtime),
            "cross_origin_request_performed": False,
            "credentialed_request_performed": False,
            "browser_script_executed": False,
        },
    )


class CorsMisconfigurationFamilyAnalyzer(FamilyAnalyzer):
    family = "cors_misconfiguration"
    analyzer_version = CORS_MISCONFIGURATION_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_cors_misconfiguration_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

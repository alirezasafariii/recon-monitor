from __future__ import annotations

"""Dedicated WebSocket Authorization analyzer.

Static WebSocket construction, channel names and subscription operations are
surface only. Direct evidence requires already-stored controlled observations
using explicitly authorized test identities and test-owned channels/resources.
This analyzer never opens a socket or subscribes to a channel.
"""

from typing import Any, Iterable, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth


WEBSOCKET_AUTHORIZATION_FAMILY_ANALYZER_VERSION = "1.0.0"
WEBSOCKET_AUTHORIZATION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

WEBSOCKET_AUTHORIZATION_TAXONOMY = {
    "owasp": ["Broken Access Control", "WebSocket Security"],
    "wstg": ["WSTG-CLNT-10"],
    "cwe": ["CWE-862"],
    "related_cwe": ["CWE-639", "CWE-863", "CWE-285"],
}

WEBSOCKET_AUTHORIZATION_METHOD = (
    {
        "id": "WS-AUTHZ-01-channel-surface",
        "basis": ["WSTG-CLNT-10", "CWE-862"],
        "principle": "Identify channel/topic/resource identifiers and WebSocket subscribe/send semantics without treating client-visible names as an authorization flaw.",
    },
    {
        "id": "WS-AUTHZ-02-channel-policy",
        "basis": ["WSTG-CLNT-10", "CWE-863"],
        "principle": "Model the expected identity/tenant/resource-to-channel relationship and authentication context before evaluating subscription behavior.",
    },
    {
        "id": "WS-AUTHZ-03-controlled-comparison",
        "basis": ["CWE-862", "CWE-639"],
        "principle": "Direct evidence requires an already-stored controlled comparison using authorized test identities and test-owned channels; unrelated user channels are excluded.",
    },
    {
        "id": "WS-AUTHZ-04-denial-controls",
        "basis": ["CWE-862"],
        "principle": "Observed channel authorization or denial of an unauthorized test subscription is contradiction evidence for the same operation.",
    },
)

WEBSOCKET_AUTHORIZATION_FALSE_POSITIVE_CHECKS = (
    "A WebSocket URL, room name, topic, channel ID or subscription message is discovery surface only.",
    "Authentication during the HTTP upgrade does not prove per-message or per-channel authorization is missing, and its absence from client code does not prove it is missing server-side.",
    "Public broadcast channels and intentionally shared topics are not authorization failures.",
    "A failed or closed WebSocket connection can result from protocol, origin, authentication or transport errors unrelated to authorization.",
    "Direct evidence is limited to explicitly authorized test identities and test-owned channels/resources; unrelated real-user subscriptions are outside this analyzer contract.",
    "The analyzer performs no live socket connection, subscription, message send, channel guessing or enumeration.",
)

WEBSOCKET_AUTHORIZATION_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-clnt-10-websockets",
        "source": "OWASP WSTG",
        "ref": "WSTG-CLNT-10 / Testing WebSockets",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
        "principle": "WebSocket security review includes authentication, authorization and message/channel handling rather than relying only on the initial handshake.",
        "signals": ["websocket_channel", "websocket_operation", "unauthorized_subscription_observed"],
    },
    {
        "id": "cwe-862-missing-authorization",
        "source": "MITRE CWE",
        "ref": "CWE-862 / Missing Authorization",
        "url": "https://cwe.mitre.org/data/definitions/862.html",
        "principle": "A security-relevant action must verify that the requester is authorized for the resource or operation.",
        "signals": ["channel_identifier", "channel_authorization_differential"],
    },
)


def _safe_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text[:120])
    return result


def analyze_websocket_authorization_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "",
    js_url: str = "",
    source_kind: str = "",
    sink_kind: str = "websocket",
    channel_identifiers: Iterable[str] = (),
    operation: str = "",
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    channels = _safe_names(channel_identifiers)
    for key in ("channel", "channel_id", "topic", "topic_id", "room", "room_id", "subscription", "subscription_id"):
        value = details.get(key)
        if value is not None and str(value).strip():
            text = str(value).strip()[:120]
            if text not in channels:
                channels.append(text)
    operation = str(operation or details.get("websocket_operation") or details.get("operation") or "").strip()[:120]
    socket_surface = bool(
        str(sink_kind or "").lower() == "websocket"
        or "websocket" in str(source_kind or "").lower()
        or "websocket" in semantic_text.lower()
        or truth(details.get("websocket_surface")) is True
    )
    runtime = observations(details, "websocket_authorization_observations", "websocket_runtime_observations", "subscription_observations")
    if not socket_surface and not channels and not operation and not runtime:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    structural_group = f"websocket_static_surface:{js_url or endpoint}"
    if channels:
        add_unique(support, {
            "type": "channel_identifier", "source": "websocket_intelligence", "source_group": structural_group, "weight": 20,
            "text": f"Client-visible WebSocket channel/topic/resource identifiers are present: {', '.join(channels[:6])}.",
        })
    elif socket_surface:
        add_unique(support, {
            "type": "websocket_channel", "source": "javascript_dataflow", "source_group": structural_group, "weight": 16,
            "text": "Client-side WebSocket construction or channel-oriented messaging surface is present.",
        })
    if operation:
        evidence_type = "subscription_operation" if any(token in operation.lower() for token in ("subscribe", "join", "listen", "room", "topic")) else "websocket_operation"
        add_unique(support, {
            "type": evidence_type, "source": "websocket_intelligence", "source_group": structural_group, "weight": 16,
            "text": f"Client-visible WebSocket operation semantics are present: {operation}.",
        })
    elif socket_surface:
        add_unique(support, {
            "type": "websocket_operation", "source": "javascript_dataflow", "source_group": structural_group, "weight": 12,
            "text": "Static client evidence shows WebSocket construction or messaging semantics.",
        })

    policy = details.get("channel_authorization_policy") or details.get("websocket_authorization_policy") or details.get("channel_ownership_policy")
    if isinstance(policy, Mapping) and truth(policy.get("documented")) is True:
        add_unique(support, {
            "type": "channel_policy_context", "source": "stored_security_policy", "source_group": "websocket_channel_policy", "weight": 16,
            "text": "Stored target policy documents an identity/tenant/resource authorization boundary for the relevant WebSocket channel or operation.",
        })

    for index, obs in enumerate(runtime[:50]):
        controlled = truth(scalar(obs, ("controlled_test_context", "authorized_test_context"))) is True
        test_owned = truth(scalar(obs, ("test_owned_channel", "test_owned_resource", "controlled_channel"))) is True
        group = f"websocket_authz_observation:{index}"
        if truth(scalar(obs, ("channel_authorization_observed", "channel_guard_enforced"))) is True:
            add_unique(contradict, {
                "type": "channel_authorization_observed", "source": "stored_websocket_observation", "source_group": group, "weight": -40,
                "text": "Stored controlled evidence shows channel/resource authorization enforcement for the relevant WebSocket operation.",
            })
        if truth(scalar(obs, ("unauthorized_subscription_denied", "out_of_scope_subscription_denied"))) is True:
            add_unique(contradict, {
                "type": "unauthorized_subscription_denied", "source": "stored_websocket_observation", "source_group": group, "weight": -44,
                "text": "Stored controlled comparison shows an out-of-scope test subscription is denied.",
            })
        if not (controlled and test_owned):
            continue
        if truth(scalar(obs, ("unauthorized_subscription_observed", "out_of_scope_subscription_succeeded"))) is True:
            add_unique(support, {
                "type": "unauthorized_subscription_observed", "source": "stored_controlled_websocket_comparison", "source_group": group, "weight": 60,
                "text": "A controlled test identity successfully subscribed to a test-owned channel outside its documented authorization scope.",
            })
        if truth(scalar(obs, ("channel_authorization_differential", "channel_role_differential"))) is True:
            add_unique(support, {
                "type": "channel_authorization_differential", "source": "stored_controlled_websocket_comparison", "source_group": group, "weight": 56,
                "text": "A like-for-like controlled WebSocket comparison shows a channel authorization differential inconsistent with the documented test boundary.",
            })

    observed = {item["type"] for item in support}
    if "unauthorized_subscription_observed" in observed:
        variant = "unauthorized_test_subscription"
    elif "channel_authorization_differential" in observed:
        variant = "channel_authorization_differential"
    elif "channel_policy_context" in observed:
        variant = "channel_boundary_with_policy_context"
    else:
        variant = "websocket_channel_surface"

    return finalize_result(
        analyzer=WebsocketAuthorizationFamilyAnalyzer(),
        family="websocket_authorization",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=WEBSOCKET_AUTHORIZATION_TAXONOMY,
        methodology=WEBSOCKET_AUTHORIZATION_METHOD,
        false_positive_checks=WEBSOCKET_AUTHORIZATION_FALSE_POSITIVE_CHECKS,
        writeup_patterns=WEBSOCKET_AUTHORIZATION_WRITEUP_PATTERNS,
        direct_types={"unauthorized_subscription_observed", "channel_authorization_differential"},
        rule_ids=("family-websocket-channel-surface", "family-websocket-channel-policy", "family-websocket-controlled-comparison"),
        summary="WebSocket authorization hypothesis based on client channel/operation structure plus stored channel-policy and controlled comparison evidence.",
        base=22,
        extra_meta={
            "family_rule_version": WEBSOCKET_AUTHORIZATION_FAMILY_ANALYZER_RULE_VERSION,
            "channel_identifiers": channels[:12],
            "runtime_observation_count": len(runtime),
            "socket_connection_performed": False,
            "subscription_performed": False,
            "channel_enumeration_performed": False,
        },
    )


class WebsocketAuthorizationFamilyAnalyzer(FamilyAnalyzer):
    family = "websocket_authorization"
    analyzer_version = WEBSOCKET_AUTHORIZATION_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_websocket_authorization_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

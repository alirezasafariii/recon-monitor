from __future__ import annotations

"""Dedicated postMessage trust analyzer.

The analyzer separates static Web Messaging surfaces from stored runtime evidence
that a message from an untrusted origin/source was accepted and reached a
security-sensitive sink or action. Standards and public examples guide reasoning
only; they never become target evidence and this module performs no active
message injection.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


POSTMESSAGE_FAMILY_ANALYZER_VERSION = "1.0.0"
POSTMESSAGE_FAMILY_ANALYZER_RULE_VERSION = "2026.08.11.1"

POSTMESSAGE_SOURCES = {
    "postmessage", "message", "message_event", "messageevent", "event_data",
    "message_data", "window_message", "cross_document_message",
}
DOM_SINKS = {"innerhtml", "outerhtml", "insertadjacenthtml", "eval", "function", "document_write"}
NAVIGATION_SINKS = {"navigation", "location", "window_location", "location_assignment", "open"}
NETWORK_SINKS = {"fetch", "xhr", "xmlhttprequest", "axios", "websocket", "sendbeacon"}
STATE_SINKS = {
    "localstorage", "sessionstorage", "cookie", "auth_state", "session_state",
    "privileged_action", "account_action", "payment_action", "state_change",
}
SAFE_SINKS = {"textcontent", "innertext", "console_log", "log", "noop", "display_text"}

POSTMESSAGE_TAXONOMY = {
    "owasp": ["Web Messaging / Cross Document Messaging"],
    "wstg": ["WSTG-CLNT-11"],
    "cwe": ["CWE-346"],
}

POSTMESSAGE_METHOD = (
    {
        "id": "POSTMSG-01-handler-surface",
        "basis": ["WSTG-CLNT-11"],
        "principle": "Identify message handlers and the exact message data consumed; the existence of addEventListener('message', ...) alone is only a client-side trust surface.",
    },
    {
        "id": "POSTMSG-02-origin-source-policy",
        "basis": ["WSTG-CLNT-11", "CWE-346"],
        "principle": "Model the expected sender origins and source-window relationship, then distinguish exact allow-list checks from absent, wildcard, substring or otherwise weak trust checks.",
    },
    {
        "id": "POSTMSG-03-message-schema",
        "basis": ["WSTG-CLNT-11"],
        "principle": "Treat event.data as untrusted input even when the origin is trusted; record schema/type validation separately from origin validation.",
    },
    {
        "id": "POSTMSG-04-sensitive-consumer",
        "basis": ["WSTG-CLNT-11"],
        "principle": "Classify whether accepted message data reaches a sensitive DOM, navigation, network, storage, authentication or state-changing consumer.",
    },
    {
        "id": "POSTMSG-05-runtime-trust-decision",
        "basis": ["WSTG-CLNT-11", "CWE-346"],
        "principle": "Direct condition evidence requires a stored observation that an explicitly untrusted sender was accepted and reached the identified sensitive consumer despite the intended trust boundary.",
    },
)

POSTMESSAGE_FALSE_POSITIVE_CHECKS = (
    "A message handler and sensitive-looking sink in the same JavaScript flow are one correlated static observation, not two independent proofs.",
    "The presence of postMessage or event.data does not establish that arbitrary origins are accepted.",
    "An exact scheme-host-port origin allow-list or a verified source-window check is evidence against an unsafe trust decision.",
    "A wildcard targetOrigin on the sending side is a separate disclosure concern and does not by itself prove the receiving handler trusts an untrusted sender.",
    "A trusted-origin message that reaches a sensitive sink does not establish postMessage Trust failure without an untrusted-origin acceptance observation.",
    "A DOM sink downstream of postMessage may additionally belong to DOM-XSS, but DOM execution is not inferred from Web Messaging trust failure alone.",
    "Schema/type validation reduces message-data risk but does not substitute for origin/source validation; each control is evaluated separately.",
)

POSTMESSAGE_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-clnt-11-web-messaging",
        "source": "OWASP WSTG",
        "ref": "WSTG-CLNT-11 / Testing Web Messaging",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging",
        "principle": "The receiver should validate message origin/source and treat message data as untrusted before sensitive use.",
        "signals": ["postmessage_source", "message_handler", "origin_validation_absent", "untrusted_message_accepted"],
    },
    {
        "id": "cwe-346-origin-validation",
        "source": "MITRE CWE",
        "ref": "CWE-346 / Origin Validation Error",
        "url": "https://cwe.mitre.org/data/definitions/346.html",
        "principle": "Improper verification of the source of incoming communication can allow data from an unauthorized subject to be accepted.",
        "signals": ["origin_validation_absent", "untrusted_message_accepted"],
    },
)


def _normalize(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("event.", "event_").replace("window.", "window_")
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "accepted", "reached", "allowed", "missing", "absent"}:
        return True
    if text in {"false", "0", "no", "rejected", "blocked", "denied", "present", "enforced"}:
        return False
    return None


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {_normalize(key): value for key, value in item.items()}
    for key in keys:
        value = normalized.get(_normalize(key))
        if value is not None and str(value).strip() != "":
            return value
    return None


def _list_value(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        decoded = _loads(value, [])
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "postmessage_runtime_observations", "web_message_observations", "message_runtime_observations",
        "postmessage_observations", "runtime_observations",
    ):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
        if isinstance(decoded, Mapping):
            return [dict(decoded)]
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    identity = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
        str(item.get("text") or ""),
    )
    if any(
        (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        ) == identity
        for existing in items
    ):
        return
    items.append(item)


def _source_class(source_kind: str, snippet: str, details: Mapping[str, Any]) -> str:
    explicit = _normalize(_scalar(details, ("source_kind", "message_source", "source")))
    source = explicit or _normalize(source_kind)
    text = _normalize(f"{source} {snippet}")
    if source in POSTMESSAGE_SOURCES or "postmessage" in text or "messageevent" in text or "event_data" in text:
        return "postmessage"
    return ""


def _sink_class(sink_kind: str, snippet: str, details: Mapping[str, Any]) -> tuple[str, str]:
    explicit = _normalize(_scalar(details, ("sink_kind", "message_sink", "sensitive_sink", "sink")))
    sink = explicit or _normalize(sink_kind)
    text = _normalize(snippet)
    if sink in SAFE_SINKS:
        return sink, "safe"
    if sink in DOM_SINKS:
        return sink, "dom"
    if sink in NAVIGATION_SINKS:
        return sink, "navigation"
    if sink in NETWORK_SINKS:
        return sink, "network"
    if sink in STATE_SINKS:
        return sink, "state"
    for candidate in DOM_SINKS:
        if candidate in text:
            return candidate, "dom"
    for candidate in NAVIGATION_SINKS:
        if candidate in text:
            return candidate, "navigation"
    for candidate in NETWORK_SINKS:
        if candidate in text:
            return candidate, "network"
    for candidate in STATE_SINKS:
        if candidate in text:
            return candidate, "state"
    explicit_sensitive = _bool(_scalar(details, ("sensitive_sink", "sensitive_action", "security_sensitive_consumer")))
    if explicit_sensitive is True and sink:
        return sink, "sensitive"
    return sink, "unknown"


def is_postmessage_source(source_kind: str) -> bool:
    return _normalize(source_kind) in POSTMESSAGE_SOURCES or _normalize(source_kind) == "postmessage"


def _structural_evidence(source: str, sink: str, sink_class: str, js_url: str) -> list[dict[str, Any]]:
    if source != "postmessage":
        return []
    support = [
        {
            "type": "postmessage_source",
            "source": "javascript_dataflow",
            "source_group": "postmessage_static_flow",
            "weight": 18,
            "text": f"Static client-side flow identifies postMessage/event.data as an input source in {js_url or 'JavaScript'}.",
        },
        {
            "type": "message_handler",
            "source": "javascript_dataflow",
            "source_group": "postmessage_static_flow",
            "weight": 16,
            "text": "The same static flow indicates a Web Messaging handler consumes message-controlled data.",
        },
    ]
    if sink and sink_class not in {"safe", "unknown"}:
        support.append({
            "type": "sensitive_sink",
            "source": "javascript_dataflow",
            "source_group": "postmessage_static_flow",
            "weight": 20,
            "text": f"The same static flow reaches a {sink_class} consumer ({sink}); static proximity does not prove an untrusted sender is accepted.",
        })
        support.append({
            "type": "dataflow_sink",
            "source": "javascript_dataflow",
            "source_group": "postmessage_static_flow",
            "weight": 12,
            "text": f"Message-controlled data is statically associated with sink {sink}.",
        })
    return support


def _origin_is_untrusted(observation: Mapping[str, Any]) -> bool | None:
    explicit = _bool(_scalar(observation, ("untrusted_origin", "origin_untrusted", "sender_untrusted")))
    if explicit is not None:
        return explicit
    origin = str(_scalar(observation, ("message_origin", "origin", "event_origin")) or "").strip().rstrip("/")
    trusted = [item.rstrip("/") for item in _list_value(_scalar(observation, ("trusted_origins", "allowed_origins", "origin_allowlist")))]
    if origin and trusted:
        return origin not in trusted
    return None


def _runtime_evidence(details: Mapping[str, Any], *, sink: str, sink_class: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    observations = _observations(details)
    if not observations and any(
        key in details
        for key in (
            "message_accepted", "untrusted_message_accepted", "origin_validation_absent",
            "origin_check_observed", "trusted_origin_only", "sensitive_sink_reached",
        )
    ):
        observations = [dict(details)]

    for observation in observations:
        obs_sink = _normalize(_scalar(observation, ("sink_kind", "message_sink", "sink")))
        if obs_sink and sink and obs_sink != sink:
            continue

        untrusted = _origin_is_untrusted(observation)
        accepted = _bool(_scalar(observation, ("message_accepted", "handler_accepted", "accepted")))
        explicit_untrusted_accept = _bool(_scalar(observation, ("untrusted_message_accepted",)))
        sensitive_reached = _bool(_scalar(observation, (
            "sensitive_sink_reached", "sensitive_action_reached", "consumer_reached", "message_effect_observed",
        )))
        origin_check = _bool(_scalar(observation, (
            "origin_check_observed", "origin_validation_present", "origin_validation_enforced",
        )))
        origin_absent = _bool(_scalar(observation, ("origin_validation_absent", "origin_check_absent")))
        source_check = _bool(_scalar(observation, ("source_window_check_observed", "source_check_observed")))
        trusted_only = _bool(_scalar(observation, ("trusted_origin_only", "untrusted_origin_rejected")))
        schema_rejected = _bool(_scalar(observation, ("message_schema_rejected", "invalid_message_rejected")))

        if origin_check is True or source_check is True:
            _add_unique(contradict, {
                "type": "origin_check_observed",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_origin_control",
                "weight": -28,
                "text": "Stored runtime/client observation records an origin or source-window trust check for the relevant message handler.",
            })
        if trusted_only is True or (untrusted is True and accepted is False):
            _add_unique(contradict, {
                "type": "trusted_origin_only",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_origin_control",
                "weight": -34,
                "text": "Stored observation records that the relevant handler rejected the untrusted sender or accepted trusted origins only.",
            })
        if schema_rejected is True:
            _add_unique(contradict, {
                "type": "message_schema_rejected",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_schema_control",
                "weight": -18,
                "text": "Stored observation records that the tested message shape was rejected by message-data validation.",
            })

        if origin_absent is True or origin_check is False:
            _add_unique(support, {
                "type": "origin_validation_absent",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_origin_runtime",
                "weight": 24,
                "text": "Stored observation records that effective origin validation was absent for the relevant message handler.",
            })

        if explicit_untrusted_accept is True:
            accepted = True
            untrusted = True

        if untrusted is True and accepted is True and sensitive_reached is True and origin_check is not True and source_check is not True and trusted_only is not True:
            _add_unique(support, {
                "type": "untrusted_message_accepted",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_vulnerability_condition",
                "weight": 42,
                "text": "Stored runtime evidence establishes that a message from an explicitly untrusted sender was accepted and reached the identified sensitive consumer.",
            })
            direct = True
        elif untrusted is True and accepted is True:
            _add_unique(support, {
                "type": "untrusted_message_reached_handler",
                "source": "stored_postmessage_runtime",
                "source_group": "postmessage_runtime",
                "weight": 22,
                "text": "Stored runtime evidence records that an untrusted sender reached and was accepted by the message handler, but no sensitive effect is established yet.",
            })

    return support, contradict, direct


def _variant(sink_class: str, support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "untrusted_message_accepted" in types:
        return "untrusted_sender_to_sensitive_consumer"
    if "untrusted_message_reached_handler" in types:
        return "untrusted_sender_accepted_no_sensitive_effect"
    if "origin_validation_absent" in types:
        return "origin_validation_absent"
    if "trusted_origin_only" in controls or "origin_check_observed" in controls:
        return "origin_control_observed"
    return f"static_message_to_{sink_class}" if sink_class not in {"unknown", "safe"} else "static_message_handler"


def analyze_postmessage_trust_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    js_url: str = "",
    endpoint: str = "",
    method: str = "GET",
    source_kind: str = "",
    sink_kind: str = "",
    snippet: str = "",
    confidence: int = 0,
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, method, business_context
    details = dict(details or {})
    source = _source_class(source_kind, snippet, details)
    sink, sink_class = _sink_class(sink_kind, snippet, details)
    if source != "postmessage":
        return None
    if sink_class == "safe":
        return None

    support = _structural_evidence(source, sink, sink_class, js_url or endpoint)
    runtime_support, contradict, direct = _runtime_evidence(details, sink=sink, sink_class=sink_class)
    for item in runtime_support:
        _add_unique(support, item)
    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    confirmation_missing = confirmation_gaps("postmessage_trust", observed)
    # Stricter than the generic catalog: absence of an origin check is a control
    # gap, not confirmation. Confirmation requires an untrusted sender accepted
    # through the handler and reaching a sensitive consumer in stored runtime evidence.
    if "untrusted_message_accepted" not in observed:
        confirmation_missing = [
            "untrusted_message_accepted: stored runtime observation of an explicitly untrusted sender accepted and reaching the sensitive consumer"
        ]

    metadata = PostMessageTrustFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": POSTMESSAGE_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in POSTMESSAGE_TAXONOMY.items()},
        "methodology": [dict(step) for step in POSTMESSAGE_METHOD],
        "false_positive_checks": list(POSTMESSAGE_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in POSTMESSAGE_WRITEUP_PATTERNS],
        "source_kind": source,
        "sink_kind": sink,
        "sink_class": sink_class,
        "static_handler_and_sink_are_one_evidence_root": True,
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": not confirmation_missing and direct,
        "knowledge_does_not_change_target_evidence": True,
        "active_message_injection_performed": False,
    })

    missing = list(FAMILY_REASONING["postmessage_trust"]["next_evidence"])
    if "origin_validation_absent" in observed:
        missing = [item for item in missing if "origin/source checks" not in item.lower()]
    if "untrusted_message_accepted" in observed:
        missing = []

    return {
        "family": "postmessage_trust",
        "variant": _variant(sink_class, support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-postmessage-handler-surface",
            "family-postmessage-origin-source-trust",
            "family-postmessage-message-schema",
            "family-postmessage-sensitive-consumer",
            "family-postmessage-runtime-decision",
        ],
        "summary": (
            "Stored runtime evidence establishes that an explicitly untrusted message sender was accepted and reached a sensitive client-side consumer."
            if "untrusted_message_accepted" in observed
            else "Web Messaging evidence identifies a postMessage trust hypothesis; effective origin/source validation and sensitive runtime effect remain decisive."
        ),
        "direct": direct,
        "family_analyzer": metadata,
    }


class PostMessageTrustFamilyAnalyzer(FamilyAnalyzer):
    family = "postmessage_trust"
    analyzer_version = POSTMESSAGE_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_postmessage_trust_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            js_url=str(kwargs.get("js_url") or ""),
            source_kind=str(kwargs.get("source_kind") or ""),
            sink_kind=str(kwargs.get("sink_kind") or ""),
            snippet=str(kwargs.get("snippet") or ""),
            confidence=parse_int(kwargs.get("confidence"), 0),
        )

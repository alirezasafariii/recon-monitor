from __future__ import annotations

"""Dedicated DOM-based XSS analyzer backed by the canonical family spec.

The analyzer separates static client-side source/sink proximity from stored
runtime evidence that a controlled, non-executing marker reaches a dangerous
DOM/execution context without an effective context-appropriate neutralization.
Standards and public write-up patterns guide reasoning only; they never become
target evidence and this module never performs active validation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


DOM_XSS_FAMILY_ANALYZER_VERSION = "1.1.0"
DOM_XSS_FAMILY_ANALYZER_RULE_VERSION = "2026.08.15.4"
DOM_XSS_SPEC = get_detection_spec("dom_xss")

DOM_SOURCE_MARKERS = {
    "location", "location_href", "location_search", "location_hash",
    "document_url", "document_documenturi", "document_referrer", "window_name",
    "urlsearchparams", "localstorage", "sessionstorage", "cookie", "input_value",
}
POSTMESSAGE_MARKERS = {"postmessage", "message_event", "event_data"}
HTML_SINKS = {
    "innerhtml", "outerhtml", "insertadjacenthtml", "document_write",
    "document_writeln", "v_html", "dangerouslysetinnerhtml",
}
EXECUTION_SINKS = {
    "eval", "function", "function_constructor", "settimeout_string",
    "setinterval_string", "script_text", "script_src_javascript",
}
SAFE_SINKS = {"textcontent", "innertext", "createTextNode", "create_text_node"}

# Compatibility exports; canonical standards/write-up definitions live in family_specs.
DOM_XSS_TAXONOMY = DOM_XSS_SPEC.taxonomy()
DOM_XSS_METHOD = tuple(step.as_dict() for step in DOM_XSS_SPEC.standard.methodology)
DOM_XSS_FALSE_POSITIVE_CHECKS = tuple(DOM_XSS_SPEC.standard.false_positive_checks)
DOM_XSS_WRITEUP_PATTERNS = tuple(
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
    for item in DOM_XSS_SPEC.standard.writeups
)


def _normalize(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("document.", "document_").replace("location.", "location_").replace("window.", "window_")
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "reached", "reachable", "unsafe", "executable", "blocked", "enforced"}:
        return True
    if text in {"false", "0", "no", "not_reached", "unreachable", "safe", "absent", "missing"}:
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


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "dom_runtime_observations", "dom_observations", "runtime_observations",
        "client_runtime_observations", "dom_flow_observations",
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
    explicit = _normalize(_scalar(details, ("source_kind", "dom_source", "source")))
    source = explicit or _normalize(source_kind)
    text = f"{source} {snippet}".lower()
    if source in POSTMESSAGE_MARKERS or "postmessage" in text or "messageevent" in text:
        return "postmessage"
    if source in DOM_SOURCE_MARKERS:
        return source
    for marker in DOM_SOURCE_MARKERS:
        if marker.replace("_", ".") in text or marker in _normalize(text):
            return marker
    user_controlled = _bool(_scalar(details, ("user_controlled_source", "source_user_controlled", "attacker_controlled_source")))
    return source if user_controlled is True and source else ""


def _sink_class(sink_kind: str, snippet: str, details: Mapping[str, Any]) -> tuple[str, str]:
    explicit = _normalize(_scalar(details, ("sink_kind", "dom_sink", "sink")))
    sink = explicit or _normalize(sink_kind)
    normalized_snippet = _normalize(snippet)
    if sink in {_normalize(value) for value in SAFE_SINKS}:
        return sink, "safe_text"
    if sink in HTML_SINKS:
        return sink, "html"
    if sink in EXECUTION_SINKS:
        return sink, "execution"
    for candidate in HTML_SINKS:
        if candidate in normalized_snippet:
            return candidate, "html"
    for candidate in EXECUTION_SINKS:
        if candidate in normalized_snippet:
            return candidate, "execution"
    if sink in {"navigation", "location_assignment", "window_location"}:
        return sink, "navigation"
    return sink, "unknown"


def is_dangerous_dom_sink(sink_kind: str) -> bool:
    sink = _normalize(sink_kind)
    return sink in HTML_SINKS or sink in EXECUTION_SINKS


def _structural_evidence(source: str, sink: str, sink_context: str, js_url: str, confidence: int) -> list[dict[str, Any]]:
    if not source or sink_context not in {"html", "execution"}:
        return []
    # Both sides deliberately share one source_group: they are facts from one static flow.
    return [
        {
            "type": "dataflow_source",
            "source": "javascript_dataflow",
            "source_group": "dom_static_flow",
            "weight": 18,
            "text": f"Static client-side flow identifies user-influenced source {source} in {js_url or 'JavaScript'}.",
        },
        {
            "type": "dataflow_sink",
            "source": "javascript_dataflow",
            "source_group": "dom_static_flow",
            "weight": 20,
            "text": f"The same static flow identifies dangerous {sink_context} sink {sink}; static proximity does not prove runtime reachability.",
        },
    ]


def _runtime_evidence(
    details: Mapping[str, Any],
    *,
    source: str,
    sink: str,
    sink_context: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False

    observations = _observations(details)
    if not observations and any(
        key in details
        for key in (
            "runtime_dom_sink_reached", "unsanitized_dom_flow", "sanitization_observed",
            "runtime_unreachable", "trusted_types_enforced", "safe_dom_api_observed",
        )
    ):
        observations = [dict(details)]

    for index, observation in enumerate(observations):
        obs_source = _normalize(_scalar(observation, ("source_kind", "source", "dom_source")))
        obs_sink = _normalize(_scalar(observation, ("sink_kind", "sink", "dom_sink")))
        if obs_source and source and obs_source != source:
            continue
        if obs_sink and sink and obs_sink != sink:
            continue

        runtime_reached = _bool(_scalar(observation, (
            "runtime_dom_sink_reached", "marker_reached_sink", "sink_reached", "runtime_reachable", "reachable",
        )))
        explicit_unreachable = _bool(_scalar(observation, ("runtime_unreachable",))) is True or runtime_reached is False
        sanitized = _bool(_scalar(observation, (
            "sanitization_observed", "sanitized", "contextual_encoding_observed", "neutralization_observed",
        )))
        trusted_types = _bool(_scalar(observation, ("trusted_types_enforced", "trusted_types_blocked")))
        safe_api = _bool(_scalar(observation, ("safe_dom_api_observed", "safe_sink_observed")))
        explicit_unsanitized = _bool(_scalar(observation, ("unsanitized_dom_flow", "sanitization_absent", "neutralization_absent")))
        executable_context = _bool(_scalar(observation, (
            "execution_context_reached", "executable_context", "script_capable_context", "unsafe_html_context",
        )))

        if explicit_unreachable:
            _add_unique(contradict, {
                "type": "runtime_unreachable",
                "source": "stored_dom_runtime",
                "source_group": "dom_runtime",
                "weight": -30,
                "text": "Stored runtime observation records that the identified source-to-sink path was not reachable.",
            })
            continue

        if sanitized is True or trusted_types is True or safe_api is True:
            reason = "context-appropriate sanitization/encoding"
            if trusted_types is True:
                reason = "Trusted Types enforcement"
            elif safe_api is True:
                reason = "a safe text-only DOM API"
            _add_unique(contradict, {
                "type": "sanitization_observed",
                "source": "stored_dom_runtime",
                "source_group": "dom_neutralization",
                "weight": -32,
                "text": f"Stored client-side observation records {reason} on the relevant flow.",
            })

        if runtime_reached is True:
            _add_unique(support, {
                "type": "runtime_dom_sink_reached",
                "source": "stored_dom_runtime",
                "source_group": "dom_runtime",
                "weight": 28,
                "text": "A controlled harmless marker was observed reaching the identified dangerous DOM/execution sink at runtime.",
            })

        context_is_dangerous = sink_context == "execution" or executable_context is True
        neutralization_absent = explicit_unsanitized is True or sanitized is False
        if runtime_reached is True and context_is_dangerous and neutralization_absent and trusted_types is not True and safe_api is not True:
            _add_unique(support, {
                "type": "unsanitized_dom_flow",
                "source": "stored_dom_runtime",
                "source_group": "dom_vulnerability_condition",
                "weight": 40,
                "text": "Stored runtime evidence establishes a user-influenced value reaching a dangerous executable DOM context with effective neutralization explicitly absent.",
            })
            direct = True

    return support, contradict, direct


def _variant(sink_context: str, support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "unsanitized_dom_flow" in types:
        return "runtime_unsanitized_dom_flow"
    if "runtime_dom_sink_reached" in types:
        return "runtime_reachable_dom_sink"
    if "sanitization_observed" in controls:
        return "neutralized_dom_flow"
    if "runtime_unreachable" in controls:
        return "unreachable_static_flow"
    return "static_executable_sink" if sink_context == "execution" else "static_html_sink"


def analyze_dom_xss_signal(
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
    details = dict(details or {})
    source = _source_class(source_kind, snippet, details)
    sink, sink_context = _sink_class(sink_kind, snippet, details)

    # postMessage and navigation are neighboring families unless independent
    # stored runtime evidence explicitly establishes a DOM-XSS vulnerability condition.
    explicit_dom_condition = _bool(details.get("unsanitized_dom_flow")) is True
    if source == "postmessage" and not explicit_dom_condition:
        return None
    if sink_context in {"safe_text", "navigation", "unknown"} and not explicit_dom_condition:
        return None

    support = _structural_evidence(source, sink, sink_context, js_url or endpoint, parse_int(confidence, 0))
    runtime_support, contradict, direct = _runtime_evidence(
        details,
        source=source,
        sink=sink,
        sink_context=sink_context,
    )
    for item in runtime_support:
        _add_unique(support, item)
    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    confirmation_missing = confirmation_gaps("dom_xss", observed)
    if "unsanitized_dom_flow" not in observed:
        confirmation_missing = [
            "unsanitized_dom_flow: runtime-reachable dangerous DOM/execution context with effective neutralization explicitly absent"
        ]

    metadata = DomXssFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": DOM_XSS_FAMILY_ANALYZER_RULE_VERSION,
        "family_spec_version": DOM_XSS_SPEC.version,
        "taxonomy": {key: list(value) for key, value in DOM_XSS_TAXONOMY.items()},
        "methodology": [dict(step) for step in DOM_XSS_METHOD],
        "false_positive_checks": list(DOM_XSS_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in DOM_XSS_WRITEUP_PATTERNS],
        "source_kind": source,
        "sink_kind": sink,
        "sink_context": sink_context,
        "static_source_and_sink_are_one_evidence_root": True,
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": not confirmation_missing and direct,
        "knowledge_does_not_change_target_evidence": True,
        "safe_runtime_marker_only": True,
    })

    missing = list(FAMILY_REASONING["dom_xss"]["next_evidence"])
    if "runtime_dom_sink_reached" in observed:
        missing = [item for item in missing if "runtime reachability" not in item.lower()]
    if "unsanitized_dom_flow" in observed:
        missing = []

    return {
        "family": "dom_xss",
        "variant": _variant(sink_context, support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-dom-xss-source-sink",
            "family-dom-xss-runtime-reachability",
            "family-dom-xss-neutralization",
            "family-dom-xss-execution-context",
        ],
        "summary": (
            "Stored client-side evidence establishes an unsanitized runtime flow into a dangerous executable DOM context."
            if "unsanitized_dom_flow" in observed
            else "Client-side source/sink evidence identifies a DOM-XSS hypothesis; runtime reachability, executable context and effective neutralization remain decisive."
        ),
        "direct": direct,
        "family_analyzer": metadata,
    }


class DomXssFamilyAnalyzer(FamilyAnalyzer):
    family = "dom_xss"
    analyzer_version = DOM_XSS_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_dom_xss_signal(
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

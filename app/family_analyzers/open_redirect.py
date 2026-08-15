from __future__ import annotations

"""Dedicated Open Redirect / navigation-injection analyzer.

The analyzer separates static user-controlled navigation surfaces from stored
runtime evidence that a user-influenced destination was accepted and navigated
to an external origin. CWE/WSTG/write-up material guides reasoning only; it
never becomes target evidence and this module performs no active navigation.
"""

import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


OPEN_REDIRECT_FAMILY_ANALYZER_VERSION = "1.0.0"
OPEN_REDIRECT_FAMILY_ANALYZER_RULE_VERSION = "2026.08.11.1"

REDIRECT_SOURCES = {
    "redirect_parameter", "destination_parameter", "url_parameter", "return_url",
    "returnurl", "redirect_url", "redirecturl", "redirect_uri", "redirecturi",
    "next", "url", "target", "destination", "continue", "callback", "location_hash",
    "location_search", "query_parameter", "dataflow_source", "source_sink",
}
NAVIGATION_SINKS = {
    "navigation", "location", "window_location", "document_location", "location_href",
    "location_assign", "location_replace", "window_open", "open", "redirect",
    "client_redirect", "dataflow_sink", "source_sink",
}

OPEN_REDIRECT_SPEC = get_detection_spec("open_redirect")

# Compatibility exports; canonical definitions live in family_specs.
OPEN_REDIRECT_TAXONOMY = OPEN_REDIRECT_SPEC.taxonomy()
OPEN_REDIRECT_METHOD = tuple(step.as_dict() for step in OPEN_REDIRECT_SPEC.standard.methodology)
OPEN_REDIRECT_FALSE_POSITIVE_CHECKS = tuple(OPEN_REDIRECT_SPEC.standard.false_positive_checks)
OPEN_REDIRECT_WRITEUP_PATTERNS = tuple(
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
    for item in OPEN_REDIRECT_SPEC.standard.writeups
)

def _normalize(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("window.", "window_").replace("document.", "document_").replace("location.", "location_")
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "accepted", "reached", "allowed", "present", "enforced", "external"}:
        return True
    if text in {"false", "0", "no", "rejected", "blocked", "denied", "missing", "absent", "internal"}:
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
        "redirect_runtime_observations", "navigation_runtime_observations", "open_redirect_observations",
        "client_redirect_observations", "runtime_observations",
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
    explicit = _normalize(_scalar(details, (
        "source_kind", "redirect_source", "redirect_parameter", "destination_parameter", "parameter",
    )))
    source = explicit or _normalize(source_kind)
    text = _normalize(f"{source} {snippet}")
    if source in REDIRECT_SOURCES:
        return source
    if any(token in text for token in ("return_url", "returnurl", "redirect_url", "redirecturi", "redirect_uri", "location_hash", "location_search")):
        return "redirect_parameter"
    return ""


def _sink_class(sink_kind: str, snippet: str, details: Mapping[str, Any]) -> str:
    explicit = _normalize(_scalar(details, ("sink_kind", "navigation_sink", "redirect_sink", "sink")))
    sink = explicit or _normalize(sink_kind)
    text = _normalize(snippet)
    if sink in NAVIGATION_SINKS:
        return sink
    for candidate in NAVIGATION_SINKS:
        if candidate not in {"open", "redirect"} and candidate in text:
            return candidate
    return ""


def is_navigation_sink(sink_kind: str) -> bool:
    return _normalize(sink_kind) in NAVIGATION_SINKS


def _origin_parts(value: str, *, default_scheme: str = "https") -> tuple[str, str, int | None] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.startswith("//"):
            parsed = urlsplit(f"{default_scheme}:{raw}")
        elif "://" in raw:
            parsed = urlsplit(raw)
        else:
            return None
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    scheme = (parsed.scheme or default_scheme).lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, host, port


def _base_origin(target: str, endpoint: str) -> tuple[str, str, int | None] | None:
    endpoint_parts = _origin_parts(endpoint)
    if endpoint_parts:
        return endpoint_parts
    target_text = str(target or "").strip()
    if not target_text:
        return None
    return _origin_parts(target_text if "://" in target_text else f"https://{target_text}")


def _destination_external(destination: str, *, target: str, endpoint: str, trusted_origins: list[str], trusted_hosts: list[str]) -> bool | None:
    raw = str(destination or "").strip()
    if not raw:
        return None
    if raw.startswith(("/", "./", "../")) and not raw.startswith("//"):
        return False
    parts = _origin_parts(raw)
    if not parts:
        return None
    scheme, host, port = parts

    for trusted in trusted_origins:
        trusted_parts = _origin_parts(trusted)
        if trusted_parts and trusted_parts == parts:
            return False
    normalized_hosts = {str(item).strip().lower().rstrip(".") for item in trusted_hosts if str(item).strip()}
    if host in normalized_hosts:
        return False

    base = _base_origin(target, endpoint)
    if base:
        base_scheme, base_host, base_port = base
        return (scheme, host, port) != (base_scheme, base_host, base_port)
    if normalized_hosts:
        return host not in normalized_hosts
    return None


def _structural_evidence(source: str, sink: str, js_url: str) -> list[dict[str, Any]]:
    if not source or not sink:
        return []
    return [
        {
            "type": "redirect_parameter",
            "source": "javascript_dataflow",
            "source_group": "open_redirect_static_flow",
            "weight": 18,
            "text": f"Static client-side flow identifies a user-influenced navigation destination ({source}) in {js_url or 'JavaScript'}.",
        },
        {
            "type": "dataflow_source",
            "source": "javascript_dataflow",
            "source_group": "open_redirect_static_flow",
            "weight": 12,
            "text": "The same static flow contains a user-influenced destination source.",
        },
        {
            "type": "navigation_context",
            "source": "javascript_dataflow",
            "source_group": "open_redirect_static_flow",
            "weight": 20,
            "text": f"The same static flow reaches a navigation primitive ({sink}); static proximity does not prove that an external destination is accepted.",
        },
        {
            "type": "dataflow_sink",
            "source": "javascript_dataflow",
            "source_group": "open_redirect_static_flow",
            "weight": 12,
            "text": f"User-influenced data is statically associated with navigation sink {sink}.",
        },
    ]


def _runtime_evidence(
    details: Mapping[str, Any],
    *,
    target: str,
    endpoint: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    observations = _observations(details)
    if not observations and any(
        key in details
        for key in (
            "redirect_observed", "navigation_observed", "external_destination_accepted",
            "navigation_validation_absent", "destination_allowlist_observed", "same_origin_navigation_enforced",
        )
    ):
        observations = [dict(details)]

    for observation in observations:
        trusted_origins = _list_value(_scalar(observation, ("trusted_origins", "allowed_origins", "destination_allowlist")))
        trusted_hosts = _list_value(_scalar(observation, ("trusted_hosts", "allowed_hosts", "host_allowlist")))
        requested = str(_scalar(observation, (
            "requested_destination", "input_destination", "redirect_target", "destination", "url", "return_url", "next",
        )) or "").strip()
        final_destination = str(_scalar(observation, (
            "final_destination", "redirected_to", "navigation_destination", "result_location", "location",
        )) or "").strip()

        user_controlled = _bool(_scalar(observation, (
            "user_controlled_destination", "destination_user_controlled", "input_controlled", "redirect_parameter_controlled",
        )))
        redirect_observed = _bool(_scalar(observation, (
            "redirect_observed", "navigation_observed", "redirect_followed", "navigation_occurred", "destination_accepted",
        )))
        explicit_external_accept = _bool(_scalar(observation, ("external_destination_accepted",)))
        validation_absent = _bool(_scalar(observation, (
            "navigation_validation_absent", "destination_validation_absent", "redirect_validation_absent",
        )))
        validation_present = _bool(_scalar(observation, (
            "navigation_validation_observed", "destination_validation_observed", "redirect_validation_observed",
        )))
        allowlist = _bool(_scalar(observation, (
            "destination_allowlist_observed", "allowlist_enforced", "redirect_allowlist_enforced",
        )))
        same_origin = _bool(_scalar(observation, (
            "same_origin_navigation_enforced", "same_origin_enforced", "external_destination_rejected",
        )))
        relative_only = _bool(_scalar(observation, (
            "relative_path_only_enforced", "relative_destination_only", "relative_only",
        )))
        unsafe_scheme_rejected = _bool(_scalar(observation, ("unsafe_scheme_rejected", "scheme_validation_enforced")))

        destination = final_destination or requested
        external = _destination_external(
            destination,
            target=target,
            endpoint=endpoint,
            trusted_origins=trusted_origins,
            trusted_hosts=trusted_hosts,
        )
        explicit_external = _bool(_scalar(observation, ("external_destination", "destination_external", "external_origin")))
        if explicit_external is not None:
            external = explicit_external

        if validation_present is True or allowlist is True:
            _add_unique(contradict, {
                "type": "destination_allowlist_observed",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_destination_control",
                "weight": -30,
                "text": "Stored observation records destination validation or an allow-list for the relevant navigation decision.",
            })
        if same_origin is True or relative_only is True or (external is False and redirect_observed is True):
            _add_unique(contradict, {
                "type": "same_origin_navigation_enforced",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_destination_control",
                "weight": -32,
                "text": "Stored observation records same-origin/relative-only navigation or an accepted destination that remained within the intended origin.",
            })
        if unsafe_scheme_rejected is True:
            _add_unique(contradict, {
                "type": "unsafe_scheme_rejected",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_scheme_control",
                "weight": -14,
                "text": "Stored observation records scheme validation rejecting an unsafe navigation scheme.",
            })

        if user_controlled is True:
            _add_unique(support, {
                "type": "user_controlled_destination",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_runtime_input",
                "weight": 18,
                "text": "Stored runtime evidence ties the tested navigation destination to a user-controlled input.",
            })
        if validation_absent is True or validation_present is False:
            _add_unique(support, {
                "type": "navigation_validation_absent",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_validation_runtime",
                "weight": 22,
                "text": "Stored observation records that effective destination validation was absent for the relevant navigation decision.",
            })

        if explicit_external_accept is True:
            user_controlled = True
            redirect_observed = True
            external = True

        controls_block = validation_present is True or allowlist is True or same_origin is True or relative_only is True
        if user_controlled is True and redirect_observed is True and external is True and not controls_block:
            _add_unique(support, {
                "type": "external_destination_accepted",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_vulnerability_condition",
                "weight": 42,
                "text": "Stored runtime evidence establishes that a user-controlled destination was accepted and navigation reached an external origin outside the intended trust boundary.",
            })
            direct = True
        elif redirect_observed is True and external is True:
            _add_unique(support, {
                "type": "external_navigation_observed",
                "source": "stored_redirect_runtime",
                "source_group": "open_redirect_runtime",
                "weight": 18,
                "text": "Stored runtime evidence records navigation to an external destination, but user control of that destination has not been established.",
            })

    return support, contradict, direct


def _variant(support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "external_destination_accepted" in types:
        return "user_controlled_external_destination"
    if "external_navigation_observed" in types:
        return "external_navigation_without_control_proof"
    if "navigation_validation_absent" in types:
        return "destination_validation_absent"
    if "destination_allowlist_observed" in controls or "same_origin_navigation_enforced" in controls:
        return "destination_control_observed"
    return "static_source_to_navigation_sink"


def analyze_open_redirect_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    js_url: str = "",
    endpoint: str = "",
    method: str = "GET",
    source_kind: str = "",
    sink_kind: str = "navigation",
    snippet: str = "",
    confidence: int = 0,
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, analysis_id, method, business_context, confidence
    details = dict(details or {})
    source = _source_class(source_kind, snippet, details)
    sink = _sink_class(sink_kind, snippet, details)
    if not source or not sink:
        return None

    support = _structural_evidence(source, sink, js_url or endpoint)
    runtime_support, contradict, direct = _runtime_evidence(details, target=target, endpoint=endpoint or js_url)
    for item in runtime_support:
        _add_unique(support, item)
    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    confirmation_missing = confirmation_gaps("open_redirect", observed)
    if "external_destination_accepted" not in observed:
        confirmation_missing = [
            "external_destination_accepted: stored runtime observation of a user-controlled destination accepted and navigating to an external origin"
        ]

    metadata = OpenRedirectFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": OPEN_REDIRECT_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in OPEN_REDIRECT_TAXONOMY.items()},
        "methodology": [dict(step) for step in OPEN_REDIRECT_METHOD],
        "false_positive_checks": list(OPEN_REDIRECT_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in OPEN_REDIRECT_WRITEUP_PATTERNS],
        "source_kind": source,
        "sink_kind": sink,
        "static_source_and_navigation_are_one_evidence_root": True,
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": not confirmation_missing and direct,
        "knowledge_does_not_change_target_evidence": True,
        "active_navigation_performed": False,
    })

    missing = list(FAMILY_REASONING["open_redirect"]["next_evidence"])
    if "navigation_validation_absent" in observed:
        missing = [item for item in missing if "allow-list" not in item.lower() and "same-origin" not in item.lower()]
    if "external_destination_accepted" in observed:
        missing = []

    return {
        "family": "open_redirect",
        "variant": _variant(support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-open-redirect-input-surface",
            "family-open-redirect-navigation-sink",
            "family-open-redirect-destination-policy",
            "family-open-redirect-runtime-destination",
            "family-open-redirect-false-positive-review",
        ],
        "summary": (
            "Stored runtime evidence establishes that a user-controlled destination was accepted and navigation reached an external origin."
            if "external_destination_accepted" in observed
            else "Navigation evidence identifies an Open Redirect hypothesis; user control, destination validation and an accepted external runtime destination remain decisive."
        ),
        "direct": direct,
        "family_analyzer": metadata,
    }


class OpenRedirectFamilyAnalyzer(FamilyAnalyzer):
    family = "open_redirect"
    analyzer_version = OPEN_REDIRECT_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_open_redirect_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            js_url=str(kwargs.get("js_url") or ""),
            source_kind=str(kwargs.get("source_kind") or ""),
            sink_kind=str(kwargs.get("sink_kind") or "navigation"),
            snippet=str(kwargs.get("snippet") or ""),
            confidence=parse_int(kwargs.get("confidence"), 0),
        )

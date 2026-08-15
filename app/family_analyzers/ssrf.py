from __future__ import annotations

"""Dedicated Server-Side Request Forgery (SSRF) analyzer.

The analyzer separates a user-controlled remote-destination surface from proof
that the application server performed an outbound request and from the stricter
question of whether the destination trust boundary was actually bypassed.
Standards and write-up lessons come from the canonical family specification and
never become target evidence. This module performs no active network validation.
"""

import ipaddress
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from core import Database
from family_reasoning import confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


SSRF_FAMILY_ANALYZER_VERSION = "1.1.0"
SSRF_FAMILY_ANALYZER_RULE_VERSION = "2026.08.15.3"
SSRF_SPEC = get_detection_spec("ssrf")

DESTINATION_FIELDS = {
    "url", "uri", "endpoint", "destination", "destination_url", "destinationurl",
    "callback", "callback_url", "callbackurl", "webhook", "webhook_url", "webhookurl",
    "fetch_url", "fetchurl", "import_url", "importurl", "image_url", "imageurl",
    "preview_url", "previewurl", "proxy_url", "proxyurl", "remote_url", "remoteurl",
    "resource_url", "resourceurl", "source_url", "sourceurl", "target_url", "targeturl",
}
SERVER_FEATURE_MARKERS = {
    "webhook", "callback", "fetch", "fetchurl", "fetch_url", "proxy", "proxyurl", "proxy_url",
    "import", "importurl", "import_url", "preview", "previewurl", "preview_url", "remote",
    "remoteurl", "remote_url", "imageurl", "image_url", "resourceurl", "resource_url",
    "downloadurl", "download_url", "server_fetch", "outbound_request", "http_client",
}

# Compatibility exports; canonical definitions live in family_specs.
SSRF_TAXONOMY = SSRF_SPEC.taxonomy()
SSRF_METHOD = tuple(step.as_dict() for step in SSRF_SPEC.standard.methodology)
SSRF_FALSE_POSITIVE_CHECKS = tuple(SSRF_SPEC.standard.false_positive_checks)
SSRF_WRITEUP_PATTERNS = tuple(
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
    for item in SSRF_SPEC.standard.writeups
)


def _normalize(value: Any) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "accepted", "reached", "allowed", "present", "enforced", "server", "backend"}:
        return True
    if text in {"false", "0", "no", "rejected", "blocked", "denied", "missing", "absent", "client", "browser"}:
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
        "ssrf_runtime_observations", "server_fetch_observations", "outbound_request_observations",
        "controlled_callback_observations", "remote_fetch_observations", "runtime_observations",
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


def _destination_fields(body_fields: Iterable[str], query_fields: Iterable[str], details: Mapping[str, Any]) -> list[str]:
    explicit = _list_value(_scalar(details, ("destination_fields", "url_fields", "remote_destination_fields")))
    values = [*explicit, *[str(item) for item in body_fields], *[str(item) for item in query_fields]]
    found: list[str] = []
    for value in values:
        normalized = _normalize(value)
        if normalized in DESTINATION_FIELDS or normalized.endswith("_url") or normalized.endswith("_uri"):
            if value not in found:
                found.append(value)
    return found


def _server_feature_markers(endpoint: str, semantic_text: str, details: Mapping[str, Any]) -> list[str]:
    explicit = _list_value(_scalar(details, ("server_feature_markers", "server_fetch_features", "remote_fetch_features")))
    text = _normalize(" ".join([endpoint, semantic_text, " ".join(explicit)]))
    found = [marker for marker in sorted(SERVER_FEATURE_MARKERS) if marker in text]
    if _bool(_scalar(details, ("server_fetch_semantic", "server_feature", "server_request_function"))) is True:
        found.append("explicit_server_fetch_semantic")
    return list(dict.fromkeys(found))


def _structural_evidence(destination_fields: list[str], feature_markers: list[str]) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    group = "ssrf_structural_surface"
    if destination_fields:
        _add_unique(support, {
            "type": "remote_destination",
            "source": "endpoint_schema",
            "source_group": group,
            "weight": 18,
            "text": f"Structured remote-destination field observed: {', '.join(destination_fields[:6])}.",
        })
        _add_unique(support, {
            "type": "url_parameter",
            "source": "endpoint_schema",
            "source_group": group,
            "weight": 12,
            "text": "The same endpoint contract exposes a URL/URI-like destination input.",
        })
    if feature_markers:
        _add_unique(support, {
            "type": "server_feature",
            "source": "semantic",
            "source_group": group,
            "weight": 14,
            "text": f"Server-oriented remote-fetch feature markers observed: {', '.join(feature_markers[:6])}.",
        })
        _add_unique(support, {
            "type": "server_fetch_semantic",
            "source": "semantic",
            "source_group": group,
            "weight": 10,
            "text": "The same structural surface has semantics consistent with webhook/import/preview/proxy/server-fetch behavior; execution location remains unproven.",
        })
    return support


def _execution_location(observation: Mapping[str, Any]) -> str:
    value = _normalize(_scalar(observation, (
        "execution_location", "request_actor", "request_executor", "performed_by", "network_actor", "fetch_actor",
    )))
    if value in {"server", "backend", "worker", "application_server", "service", "server_side"}:
        return "server"
    if value in {"browser", "client", "frontend", "javascript", "client_side"}:
        return "browser"
    server_side = _bool(_scalar(observation, ("server_side_fetch", "backend_fetch", "server_performed_request")))
    if server_side is True:
        return "server"
    if server_side is False:
        return "browser"
    return "unknown"


def _destination_classification(value: str) -> dict[str, Any]:
    raw = str(value or "").strip()
    result: dict[str, Any] = {
        "raw_present": bool(raw),
        "scheme": "",
        "host_kind": "unknown",
        "restricted_literal": False,
    }
    if not raw:
        return result
    try:
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    except ValueError:
        return result
    result["scheme"] = str(parsed.scheme or "").lower()
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return result
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        result["host_kind"] = "hostname"
        return result
    if address.is_loopback:
        kind = "loopback"
    elif address.is_link_local:
        kind = "link_local"
    elif address.is_private:
        kind = "private"
    elif address.is_multicast:
        kind = "multicast"
    elif address.is_reserved:
        kind = "reserved"
    elif not address.is_global:
        kind = "non_global"
    else:
        kind = "public_ip"
    result["host_kind"] = kind
    result["restricted_literal"] = kind != "public_ip"
    return result


def _runtime_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool, list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    promotion_direct = False
    confirmation_direct = False
    destination_context: list[dict[str, Any]] = []
    observations = _observations(details)
    if not observations and any(
        key in details
        for key in (
            "server_fetch_observed", "controlled_callback_observed", "server_side_fetch",
            "browser_side_fetch_observed", "destination_validation_observed", "server_fetch_not_observed",
            "destination_policy_bypass_observed", "restricted_destination_accepted",
        )
    ):
        observations = [dict(details)]

    for observation in observations:
        execution = _execution_location(observation)
        destination = str(_scalar(observation, (
            "requested_destination", "input_destination", "destination", "url", "uri", "remote_url", "callback_url",
        )) or "").strip()
        destination_context.append(_destination_classification(destination))

        user_controlled = _bool(_scalar(observation, (
            "user_controlled_destination", "destination_user_controlled", "input_controlled", "url_parameter_controlled",
        )))
        server_fetch = _bool(_scalar(observation, (
            "server_fetch_observed", "outbound_request_observed", "server_request_observed", "remote_fetch_observed",
        )))
        explicit_no_fetch = _bool(_scalar(observation, ("server_fetch_not_observed", "outbound_request_not_observed")))
        browser_fetch = _bool(_scalar(observation, ("browser_side_fetch_observed", "client_fetch_observed")))
        callback_observed = _bool(_scalar(observation, ("controlled_callback_observed", "callback_received", "oast_callback_observed")))
        callback_correlated = _bool(_scalar(observation, (
            "callback_token_match", "callback_correlated", "request_correlation_match", "controlled_destination_correlated",
        )))
        controlled_destination = _bool(_scalar(observation, (
            "controlled_destination", "destination_owned_by_tester", "callback_destination_controlled",
        )))
        validation_present = _bool(_scalar(observation, (
            "destination_validation_observed", "destination_allowlist_enforced", "host_allowlist_enforced",
            "scheme_validation_enforced", "private_network_blocked", "metadata_endpoint_blocked",
            "redirect_revalidation_observed", "egress_policy_enforced",
        )))
        validation_absent = _bool(_scalar(observation, (
            "destination_validation_absent", "destination_allowlist_absent", "host_validation_absent",
        )))
        policy_bypass = _bool(_scalar(observation, (
            "destination_policy_bypass_observed", "destination_restriction_bypassed", "allowlist_bypass_observed",
        )))
        restricted_accepted = _bool(_scalar(observation, (
            "restricted_destination_accepted", "blocked_destination_accepted", "private_destination_accepted",
        )))

        if execution == "browser" or browser_fetch is True:
            _add_unique(contradict, {
                "type": "browser_side_fetch_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_execution_location",
                "weight": -36,
                "text": "Stored runtime evidence attributes the relevant network request to the browser/client rather than the application server.",
            })
        if explicit_no_fetch is True or server_fetch is False:
            _add_unique(contradict, {
                "type": "server_fetch_not_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_execution_location",
                "weight": -30,
                "text": "Stored runtime evidence explicitly records that the application server did not perform the supplied remote request.",
            })
        if validation_present is True:
            _add_unique(contradict, {
                "type": "destination_validation_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_destination_control",
                "weight": -30,
                "text": "Stored evidence records enforcement of destination, scheme, private-network, redirect or egress restrictions for the relevant fetch path.",
            })
        if validation_absent is True:
            _add_unique(support, {
                "type": "destination_validation_absent",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 18,
                "text": "Stored evidence records that no effective destination restriction was observed on the relevant server-fetch path; this alone does not prove a boundary bypass.",
            })

        correlated_callback = (
            callback_observed is True
            and callback_correlated is True
            and controlled_destination is True
            and user_controlled is True
            and execution == "server"
            and validation_present is not True
        )
        direct_server_fetch = (
            server_fetch is True
            and user_controlled is True
            and execution == "server"
            and validation_present is not True
        )
        observation_promotion_direct = False

        if direct_server_fetch:
            _add_unique(support, {
                "type": "server_fetch_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 38,
                "text": "Stored target evidence ties a user-controlled destination to an outbound request performed by the application server.",
            })
            observation_promotion_direct = True
            promotion_direct = True
        elif server_fetch is True and execution == "server":
            _add_unique(support, {
                "type": "server_fetch_capability_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 18,
                "text": "Stored evidence shows server-side remote fetching, but user control of the relevant destination is not established.",
            })

        if correlated_callback:
            _add_unique(support, {
                "type": "controlled_callback_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 40,
                "text": "A tester-controlled callback was correlated to the supplied user-controlled destination and attributed to server-side execution, without probing internal or unrelated third-party systems.",
            })
            observation_promotion_direct = True
            promotion_direct = True

        if observation_promotion_direct and policy_bypass is True:
            _add_unique(support, {
                "type": "destination_policy_bypass_observed",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 46,
                "text": "Stored target evidence records that an intended destination restriction was bypassed on the same user-controlled server-fetch observation.",
            })
            confirmation_direct = True
        if observation_promotion_direct and restricted_accepted is True:
            _add_unique(support, {
                "type": "restricted_destination_accepted",
                "source": "stored_ssrf_runtime",
                "source_group": "ssrf_runtime_outbound",
                "weight": 48,
                "text": "Stored target evidence records that a destination expected to be restricted was accepted on the same server-fetch observation.",
            })
            confirmation_direct = True

    return support, contradict, promotion_direct, confirmation_direct, destination_context


def _variant(support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "restricted_destination_accepted" in types:
        return "restricted_destination_boundary_failure"
    if "destination_policy_bypass_observed" in types:
        return "destination_policy_bypass"
    if "controlled_callback_observed" in types:
        return "controlled_callback_server_fetch"
    if "server_fetch_observed" in types:
        return "user_controlled_server_fetch"
    if "browser_side_fetch_observed" in controls:
        return "browser_side_network_activity"
    if "destination_validation_observed" in controls:
        return "destination_controls_observed"
    return "remote_fetch_surface"


def _matched_writeups(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in SSRF_SPEC.standard.writeups:
        overlap = sorted(observed & set(item.signal_hints))
        if not overlap:
            continue
        matches.append({
            "id": item.id,
            "source": item.source,
            "ref": item.ref,
            "url": item.url,
            "relation": item.relation,
            "principle": item.lesson,
            "matched_signals": overlap,
            "non_evidentiary": True,
            "counts_as_target_evidence": False,
        })
    return matches


def analyze_ssrf_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str = "UNKNOWN",
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, method, business_context
    details = dict(details or {})
    destinations = _destination_fields(body_fields, query_fields, details)
    features = _server_feature_markers(endpoint, semantic_text, details)
    support = _structural_evidence(destinations, features)
    runtime_support, contradict, promotion_direct, confirmation_direct, destination_context = _runtime_evidence(details)
    for item in runtime_support:
        _add_unique(support, item)

    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    catalog_confirmation_missing = confirmation_gaps("ssrf", observed)
    blockers = {str(item.get("type") or "") for item in contradict}
    confirmation_ready = confirmation_direct and not blockers.intersection(
        {"browser_side_fetch_observed", "destination_validation_observed", "server_fetch_not_observed"}
    )
    matched_writeups = _matched_writeups(observed)

    metadata = SsrfFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": SSRF_FAMILY_ANALYZER_RULE_VERSION,
        "family_spec_version": SSRF_SPEC.version,
        "family_spec_strategy": SSRF_SPEC.strategy,
        "taxonomy": SSRF_SPEC.taxonomy(),
        "methodology": [step.as_dict() for step in SSRF_SPEC.standard.methodology],
        "false_positive_checks": list(SSRF_SPEC.standard.false_positive_checks),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": matched_writeups,
        "promotion_required": [sorted(group) for group in SSRF_SPEC.promotion_required],
        "promotion_ready_from_stored_target_evidence": promotion_direct,
        "confirmation_required": [sorted(group) for group in SSRF_SPEC.confirmation_required],
        "family_reasoning_confirmation_gaps": catalog_confirmation_missing,
        "confirmation_missing": catalog_confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "next_evidence": list(SSRF_SPEC.next_evidence),
        "validation_level": SSRF_SPEC.validation_level,
        "knowledge_sources_matched": len(matched_writeups),
        "destination_fields": list(destinations),
        "server_feature_markers": list(features),
        "destination_context": destination_context,
        "structural_destination_and_feature_are_one_evidence_root": True,
        "knowledge_does_not_change_target_evidence": True,
        "active_validation_performed": False,
        "internal_or_metadata_probing_performed": False,
        "arbitrary_third_party_requests_performed": False,
        "dns_resolution_performed": False,
    })

    missing = list(SSRF_SPEC.next_evidence)
    if promotion_direct:
        missing = [item for item in missing if "server, not the browser" not in item.lower()]
    if confirmation_ready:
        missing = []

    return {
        "family": "ssrf",
        "variant": _variant(support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-ssrf-destination-surface",
            "family-ssrf-execution-location",
            "family-ssrf-destination-policy",
            "family-ssrf-stored-outbound-observation",
            "family-ssrf-boundary-failure",
        ],
        "summary": (
            "Stored target evidence establishes a user-controlled server-side request path and a destination trust-boundary failure."
            if confirmation_ready
            else "Stored evidence establishes a user-controlled server-side outbound request, but a destination trust-boundary bypass is not yet confirmed."
            if promotion_direct
            else "A remote-destination/server-fetch surface is retained as an SSRF hypothesis; server-side execution and destination-boundary failure remain unproven."
        ),
        "direct": promotion_direct,
        "family_analyzer": metadata,
    }


class SsrfFamilyAnalyzer(FamilyAnalyzer):
    family = "ssrf"
    analyzer_version = SSRF_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_ssrf_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            body_fields=kwargs.get("body_fields") or (),
            query_fields=kwargs.get("query_fields") or (),
            semantic_text=str(kwargs.get("semantic_text") or ""),
        )


__all__ = [
    "SSRF_FAMILY_ANALYZER_VERSION",
    "SSRF_FAMILY_ANALYZER_RULE_VERSION",
    "SSRF_SPEC",
    "SSRF_TAXONOMY",
    "SSRF_METHOD",
    "SSRF_FALSE_POSITIVE_CHECKS",
    "SSRF_WRITEUP_PATTERNS",
    "SsrfFamilyAnalyzer",
    "analyze_ssrf_signal",
]

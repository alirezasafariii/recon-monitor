from __future__ import annotations

"""Dedicated Information Disclosure analyzer.

This analyzer is intentionally evidence-preserving and read-only. It separates
information-looking surface markers from stored target observations that show a
response exposed data outside its intended visibility policy. CWE/WSTG material
is reasoning context only; it never becomes target evidence. Raw sensitive
values are never copied into analyzer output.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database
from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import policy_ready


INFORMATION_DISCLOSURE_FAMILY_ANALYZER_VERSION = "1.0.0"
INFORMATION_DISCLOSURE_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

INFORMATION_DISCLOSURE_SPEC = get_detection_spec("information_disclosure")
INFORMATION_DISCLOSURE_TAXONOMY = INFORMATION_DISCLOSURE_SPEC.taxonomy()
INFORMATION_DISCLOSURE_METHOD = tuple(step.as_dict() for step in INFORMATION_DISCLOSURE_SPEC.standard.methodology)
INFORMATION_DISCLOSURE_FALSE_POSITIVE_CHECKS = tuple(INFORMATION_DISCLOSURE_SPEC.standard.false_positive_checks)
INFORMATION_DISCLOSURE_KNOWLEDGE_PATTERNS = tuple(
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
    for item in INFORMATION_DISCLOSURE_SPEC.standard.writeups
)

_SURFACE_PATTERNS: dict[str, tuple[str, ...]] = {
    "error_detail_marker": (
        "stacktrace", "stack_trace", "stack trace", "traceback", "exception", "debug", "panic", "fatal error",
    ),
    "internal_detail_marker": (
        "internal", "filesystem", "file path", "absolute path", "framework", "build", "environment", "x-powered-by", "server version",
    ),
    "credential_like_marker": (
        "api_key", "apikey", "api key", "secret", "token", "password", "credential", "private_key", "private key",
    ),
    "source_map_marker": ("sourcemappingurl", "sourceMappingURL", ".map"),
}

_SECRET_CATEGORIES = {
    "credential", "credentials", "secret", "token", "access_token", "refresh_token", "api_key", "apikey", "password", "private_key",
}
_SOURCE_MAP_CATEGORIES = {"source_map", "sourcemap", "source_mapping", "javascript_source_map"}
_ERROR_SENSITIVE_CATEGORIES = {
    "stack_trace", "traceback", "internal_path", "filesystem_path", "sql_fragment", "query_fragment",
    "environment", "configuration", "debug_state", "memory_address", "internal_service", "package_inventory",
}
_PRIVATE_VISIBILITY = {"private", "restricted", "internal", "confidential", "owner_only", "staff_only", "admin_only"}
_PUBLIC_VISIBILITY = {"public", "anonymous", "internet", "unauthenticated"}


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "present", "public", "anonymous", "unauthorized", "exposed", "enforced", "redacted"}:
        return True
    if text in {"false", "0", "no", "absent", "private", "authorized", "not_observed", "not exposed", "not_exposed"}:
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
    if isinstance(value, Mapping):
        return [str(key).strip() for key, enabled in value.items() if _bool(enabled) is not False and str(key).strip()]
    if isinstance(value, str) and value.strip():
        decoded = _loads(value, [])
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        return [part.strip() for part in value.split(",") if part.strip()]
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


def _surface_markers(semantic_text: str, details: Mapping[str, Any]) -> dict[str, list[str]]:
    text = f"{semantic_text} {json.dumps(details, sort_keys=True, default=str)}".lower()
    found: dict[str, list[str]] = {}
    for marker_type, patterns in _SURFACE_PATTERNS.items():
        matches = []
        for pattern in patterns:
            if pattern.lower() in text and pattern not in matches:
                matches.append(pattern)
        if matches:
            found[marker_type] = matches[:8]
    return found


def _structural_evidence(markers: Mapping[str, list[str]], details_present: bool) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    if not markers:
        return support
    group = "information_disclosure_structural_surface"
    marker_names = sorted({value for values in markers.values() for value in values})
    _add_unique(support, {
        "type": "sensitive_marker",
        "source": "semantic_surface",
        "source_group": group,
        "weight": 14,
        "text": f"Sensitive/debug/internal-looking response markers are present: {', '.join(marker_names[:6])}.",
    })
    for marker_type in sorted(markers):
        _add_unique(support, {
            "type": marker_type,
            "source": "semantic_surface",
            "source_group": group,
            "weight": 8,
            "text": f"The stored surface contains {marker_type.replace('_', ' ')} clues; this does not establish sensitive exposure by itself.",
        })
    if details_present:
        _add_unique(support, {
            "type": "stored_evidence",
            "source": "normalized_analysis",
            "source_group": group,
            "weight": 6,
            "text": "The marker is present in normalized stored analysis context; marker and storage provenance intentionally count as one evidence root.",
        })
    return support


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "information_disclosure_observations",
        "disclosure_observations",
        "response_exposure_observations",
        "sensitive_response_observations",
        "error_disclosure_observations",
        "response_visibility_observations",
    ):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
        if isinstance(decoded, Mapping):
            return [dict(decoded)]
    direct_keys = {
        "sensitive_data_observed", "private_field_observed", "publicly_reachable", "anonymous_context",
        "unauthorized_actor_observed", "intended_public", "expected_public", "redaction_enforced",
    }
    if any(key in details for key in direct_keys):
        return [dict(details)]
    return []


def _safe_names(observation: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    fields: list[str] = []
    categories: list[str] = []
    for key in ("private_fields", "sensitive_fields", "exposed_fields", "field_names"):
        for value in _list_value(observation.get(key)):
            normalized = _normalize(value)
            if normalized and normalized not in fields:
                fields.append(normalized)
    for key in ("sensitive_categories", "data_categories", "exposed_categories", "detail_categories", "information_categories"):
        for value in _list_value(observation.get(key)):
            normalized = _normalize(value)
            if normalized and normalized not in categories:
                categories.append(normalized)
    return fields[:12], categories[:12]


def _runtime_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    contexts: list[dict[str, Any]] = []

    for index, observation in enumerate(_observations(details), start=1):
        group = f"information_disclosure_runtime_{index}"
        fields, categories = _safe_names(observation)
        visibility = _normalize(_scalar(observation, ("visibility", "expected_visibility", "data_visibility", "field_visibility")))

        response_observed = _bool(_scalar(observation, (
            "response_observed", "body_observed", "field_observed", "stored_response_observed", "observation_recorded",
        )))
        if response_observed is None and (fields or categories):
            response_observed = True

        intended_public = _bool(_scalar(observation, (
            "intended_public", "expected_public", "documented_public", "public_by_design", "metadata_intended_public",
        )))
        intended_private = _bool(_scalar(observation, (
            "intended_private", "expected_private", "restricted", "confidential", "private_field", "non_public_policy",
        )))
        if visibility in _PRIVATE_VISIBILITY:
            intended_private = True
        elif visibility in _PUBLIC_VISIBILITY:
            intended_public = True

        publicly_reachable = _bool(_scalar(observation, (
            "publicly_reachable", "public_response", "anonymous_context", "unauthenticated_access", "internet_reachable",
        )))
        unauthorized_actor = _bool(_scalar(observation, (
            "unauthorized_actor_observed", "unauthorized_context", "current_actor_unauthorized", "visibility_boundary_crossed",
        )))
        current_actor_authorized = _bool(_scalar(observation, ("current_actor_authorized", "authorized_context", "intended_recipient")))
        if current_actor_authorized is False:
            unauthorized_actor = True

        sensitive_observed = _bool(_scalar(observation, (
            "sensitive_data_observed", "sensitive_information_observed", "private_data_observed", "restricted_data_observed",
        )))
        private_field_observed = _bool(_scalar(observation, ("private_field_observed", "non_public_field_observed")))
        redaction_enforced = _bool(_scalar(observation, (
            "redaction_enforced", "sensitive_values_redacted", "field_redaction_observed", "filtering_enforced",
        )))

        if intended_public is True and intended_private is not True and private_field_observed is not True:
            _add_unique(contradict, {
                "type": "intended_public_metadata",
                "source": "stored_visibility_policy",
                "source_group": group,
                "weight": -34,
                "text": "Stored policy context identifies the observed metadata as intentionally public for this response context.",
            })
        if redaction_enforced is True:
            _add_unique(contradict, {
                "type": "redaction_enforced",
                "source": "stored_response_behavior",
                "source_group": group,
                "weight": -36,
                "text": "Stored response behavior shows sensitive values are redacted or filtered at the relevant output boundary.",
            })
        if current_actor_authorized is True and publicly_reachable is not True and unauthorized_actor is not True:
            _add_unique(contradict, {
                "type": "authorized_visibility_observed",
                "source": "stored_visibility_policy",
                "source_group": group,
                "weight": -18,
                "text": "The stored observation is tied to an actor/context authorized to receive the field; no cross-visibility exposure is established.",
            })

        secret_only = bool(categories) and set(categories).issubset(_SECRET_CATEGORIES)
        source_map_only = bool(categories) and set(categories).issubset(_SOURCE_MAP_CATEGORIES)
        explicit_sensitive = sensitive_observed is True or private_field_observed is True or intended_private is True
        if categories and any(category not in _SECRET_CATEGORIES | _SOURCE_MAP_CATEGORIES for category in categories):
            explicit_sensitive = True

        crossed_boundary = publicly_reachable is True or unauthorized_actor is True
        policy_non_public = intended_private is True or intended_public is False or private_field_observed is True
        safe_direct = (
            response_observed is True
            and crossed_boundary
            and explicit_sensitive
            and policy_non_public
            and redaction_enforced is not True
            and not secret_only
            and not source_map_only
        )

        if safe_direct:
            detail = "stored sensitive response metadata"
            if categories:
                detail = "categories " + ", ".join(categories[:6])
            _add_unique(support, {
                "type": "sensitive_response_observed",
                "source": "stored_response_behavior",
                "source_group": group,
                "weight": 46,
                "text": f"{detail.capitalize()} were observed across a documented non-public visibility boundary; raw values are not retained by the analyzer.",
            })
            direct = True
            if private_field_observed is True or fields:
                safe_field_names = ", ".join(fields[:6]) if fields else "one or more explicitly private fields"
                _add_unique(support, {
                    "type": "private_field_publicly_observed",
                    "source": "stored_response_behavior",
                    "source_group": group,
                    "weight": 50,
                    "text": f"Stored response metadata shows {safe_field_names} outside its intended private visibility context; no field values are copied into evidence.",
                })
            if set(categories).intersection(_ERROR_SENSITIVE_CATEGORIES):
                _add_unique(support, {
                    "type": "error_detail_exposure_observed",
                    "source": "stored_response_behavior",
                    "source_group": group,
                    "weight": 24,
                    "text": "The disclosed category includes sensitive internal/error/debug detail, not merely an error status or stack-trace marker.",
                })

        contexts.append({
            "index": index,
            "response_observed": response_observed is True,
            "public_or_unauthorized_context": crossed_boundary,
            "intended_non_public": policy_non_public,
            "sensitive_classification_present": explicit_sensitive,
            "redaction_enforced": redaction_enforced is True,
            "field_names": fields,
            "categories": categories,
            "specialized_secret_family_preferred": secret_only,
            "specialized_source_map_family_preferred": source_map_only,
            "direct_disclosure_observed": safe_direct,
        })

    return support, contradict, direct, contexts


def _variant(support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    support_types = {str(item.get("type") or "") for item in support}
    contradiction_types = {str(item.get("type") or "") for item in contradict}
    if "private_field_publicly_observed" in support_types:
        return "private_field_public_exposure"
    if "error_detail_exposure_observed" in support_types:
        return "sensitive_error_detail_exposure"
    if "sensitive_response_observed" in support_types:
        return "sensitive_response_exposure"
    if "redaction_enforced" in contradiction_types:
        return "redaction_enforced"
    if "intended_public_metadata" in contradiction_types:
        return "intended_public_metadata"
    return "sensitive_metadata_surface"


def analyze_information_disclosure_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str = "UNKNOWN",
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    path_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, method, body_fields, query_fields, path_fields, business_context
    details = dict(details or {})
    markers = _surface_markers(semantic_text, details)
    support = _structural_evidence(markers, bool(details))
    runtime_support, contradict, direct, contexts = _runtime_evidence(details)
    for item in runtime_support:
        _add_unique(support, item)

    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    state = policy_ready("information_disclosure", support, contradict)
    confirmation_ready = state["confirmation_ready"]
    confirmation_missing = [] if confirmation_ready else list(confirmation_gaps("information_disclosure", observed))

    neighbor_hints: list[str] = []
    if "credential_like_marker" in markers or any(context["specialized_secret_family_preferred"] for context in contexts):
        neighbor_hints.append("secret_exposure")
    if "source_map_marker" in markers or any(context["specialized_source_map_family_preferred"] for context in contexts):
        neighbor_hints.append("source_map_exposure")
    if "graphql" in endpoint.lower():
        neighbor_hints.append("graphql_data_exposure")

    metadata = InformationDisclosureFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": INFORMATION_DISCLOSURE_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in INFORMATION_DISCLOSURE_TAXONOMY.items()},
        "methodology": [dict(step) for step in INFORMATION_DISCLOSURE_METHOD],
        "false_positive_checks": list(INFORMATION_DISCLOSURE_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "knowledge_patterns": [dict(item, non_evidentiary=True) for item in INFORMATION_DISCLOSURE_KNOWLEDGE_PATTERNS],
        "surface_markers": {key: list(value) for key, value in markers.items()},
        "observation_context": contexts,
        "neighbor_family_hints": list(dict.fromkeys(neighbor_hints)),
        "structural_marker_and_storage_are_one_evidence_root": True,
        "promotion_ready_from_stored_target_evidence": state["promotion_ready"],
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "knowledge_does_not_change_target_evidence": True,
        "minimal_evidence_only": True,
        "raw_sensitive_values_persisted_by_analyzer": False,
        "active_validation_performed": False,
        "active_request_performed": False,
        "private_data_retrieval_performed_by_analyzer": False,
        "secret_validation_performed": False,
        "payload_generated": False,
    })

    missing = list(FAMILY_REASONING["information_disclosure"]["next_evidence"])
    if confirmation_ready:
        missing = []

    return {
        "family": "information_disclosure",
        "variant": _variant(support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-info-surface",
            "family-info-visibility-policy",
            "family-info-minimal-observation",
            "family-info-error-debug-boundary",
            "family-info-policy-differential",
            "family-info-neighbor-separation",
        ],
        "summary": (
            "Stored target evidence shows sensitive/private response metadata crossing a documented non-public visibility boundary; raw sensitive values are intentionally omitted."
            if confirmation_ready
            else "Sensitive/debug/internal-looking metadata is retained as a hidden hypothesis until stored response behavior establishes a non-public visibility-boundary exposure."
        ),
        "direct": direct,
        "family_analyzer": metadata,
    }


class InformationDisclosureFamilyAnalyzer(FamilyAnalyzer):
    family = "information_disclosure"
    analyzer_version = INFORMATION_DISCLOSURE_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_information_disclosure_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            body_fields=kwargs.get("body_fields") or (),
            query_fields=kwargs.get("query_fields") or (),
            path_fields=kwargs.get("path_fields") or (),
            details=context.details,
            business_context=context.business_context,
            semantic_text=str(kwargs.get("semantic_text") or ""),
        )

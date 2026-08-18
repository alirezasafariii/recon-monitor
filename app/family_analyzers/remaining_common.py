from __future__ import annotations

"""Shared evidence utilities for dedicated family analyzers.

This module normalizes already-collected observations and evaluates the canonical
Family Reasoning contract.  It does not discover vulnerabilities by itself and
is never registered in the Family Analyzer router.  Every registered family
keeps its own detector, false-positive checks and direct-evidence rules while
phase-one taxonomy is normalized through the canonical OWASP family catalog.
"""

import json
import re
from functools import lru_cache
from typing import Any, Iterable, Mapping, Sequence

from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec
from owasp_family_catalog import CANONICAL_TAXONOMY


_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


@lru_cache(maxsize=200_000)
def _normalize_text(text: str) -> str:
    return _NORMALIZE_RE.sub("_", text.strip().lower()).strip("_")


def normalize(value: Any) -> str:
    return _normalize_text(str(value or ""))


def truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "observed", "accepted", "allowed", "present", "enforced", "reached", "confirmed", "success"}:
        return True
    if text in {"0", "false", "no", "rejected", "blocked", "denied", "missing", "absent", "not_observed", "failed"}:
        return False
    return None


def loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def list_value(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        decoded = loads(value, [])
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


@lru_cache(maxsize=8192)
def _normalized_lookup_keys(keys: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(normalize(key) for key in keys)


def scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {
        normalize(key): value
        for key, value in item.items()
    }

    raw_keys = tuple(str(key) for key in keys)
    for normalized_key in _normalized_lookup_keys(raw_keys):
        value = normalized.get(normalized_key)
        if value is not None and str(value).strip() != "":
            return value
    return None


def observations(details: Mapping[str, Any] | None, *keys: str) -> list[dict[str, Any]]:
    details = dict(details or {})
    result: list[dict[str, Any]] = []
    for key in keys:
        raw = details.get(key)
        decoded = loads(raw, raw)
        if isinstance(decoded, Mapping):
            result.append(dict(decoded))
        elif isinstance(decoded, list):
            result.extend(dict(item) for item in decoded if isinstance(item, Mapping))
    return result


def add_unique(items: list[dict[str, Any]], item: Mapping[str, Any]) -> None:
    candidate = dict(item)
    identity = (
        str(candidate.get("type") or ""),
        str(candidate.get("source_group") or candidate.get("source") or ""),
        str(candidate.get("text") or ""),
    )
    for existing in items:
        existing_identity = (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        )
        if existing_identity == identity:
            return
    items.append(candidate)


def header_map(details: Mapping[str, Any] | None) -> dict[str, str]:
    details = dict(details or {})
    result: dict[str, str] = {}
    for container_key in ("headers", "response_headers", "responseHeaders", "http_headers", "httpHeaders"):
        raw = details.get(container_key)
        decoded = loads(raw, raw)
        if isinstance(decoded, Mapping):
            for key, value in decoded.items():
                result[str(key).strip().lower()] = str(value).strip()
    for key, value in details.items():
        normalized = str(key).strip().lower().replace("_", "-")
        if normalized in {
            "access-control-allow-origin", "access-control-allow-credentials",
            "access-control-allow-methods", "access-control-allow-headers",
            "cache-control", "vary", "age", "x-cache", "cf-cache-status",
        }:
            result[normalized] = str(value).strip()
    return result


def policy_ready(
    family: str,
    support: Sequence[Mapping[str, Any]],
    contradict: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    policy = FAMILY_REASONING[family]
    types = {str(item.get("type") or "") for item in support}
    contradiction_types = {str(item.get("type") or "") for item in contradict}
    roots = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in support
    }
    groups_satisfied = all(bool(set(group) & types) for group in policy.get("promotion_required", ()))
    source_ok = len(roots) >= int(policy.get("min_independent_sources", 1))
    blockers = set(policy.get("blocking_contradictions", ())) & contradiction_types
    override = bool(set(policy.get("override_signals", ())) & types)
    blocked = bool(blockers) and not override
    confirmation_groups = policy.get("confirmation_required", ())
    confirmation_ready = all(bool(set(group) & types) for group in confirmation_groups) if confirmation_groups else False
    confirmation_ready = bool(confirmation_ready and not blocked)
    return {
        "promotion_ready": bool(groups_satisfied and source_ok and not blocked),
        "confirmation_ready": confirmation_ready,
        "independent_roots": len(roots),
        "blocking_contradictions": sorted(blockers),
        "observed_types": sorted(types),
    }


def finalize_result(
    *,
    analyzer: Any,
    family: str,
    variant: str,
    support: list[dict[str, Any]],
    contradict: list[dict[str, Any]],
    taxonomy: Mapping[str, Sequence[str]],
    methodology: Sequence[Mapping[str, Any]],
    false_positive_checks: Sequence[str],
    writeup_patterns: Sequence[Mapping[str, Any]],
    direct_types: Iterable[str],
    rule_ids: Sequence[str],
    summary: str,
    base: int,
    extra_meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    state = policy_ready(family, support, contradict)
    observed = set(state["observed_types"])
    direct = bool(observed & set(direct_types))
    meta = analyzer.metadata()
    effective_taxonomy = (
        get_detection_spec(family).taxonomy()
        if family in MIGRATED_FAMILIES
        else CANONICAL_TAXONOMY.get(family, taxonomy)
    )
    meta.update({
        "taxonomy": {key: list(values) for key, values in effective_taxonomy.items()},
        "methodology": [dict(step) for step in methodology],
        "false_positive_checks": list(false_positive_checks),
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in writeup_patterns],
        "promotion_ready_from_stored_target_evidence": state["promotion_ready"],
        "confirmation_ready_from_stored_target_evidence": state["confirmation_ready"],
        "confirmation_missing": [] if state["confirmation_ready"] else list(confirmation_gaps(family, observed)),
        "independent_evidence_roots": state["independent_roots"],
        "blocking_contradictions": state["blocking_contradictions"],
        "knowledge_does_not_change_target_evidence": True,
        "active_request_performed": False,
    })
    if extra_meta:
        meta.update(dict(extra_meta))
    missing = [] if state["confirmation_ready"] else list(FAMILY_REASONING[family]["next_evidence"])
    return {
        "family": family,
        "variant": variant,
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": list(dict.fromkeys(str(item) for item in rule_ids if str(item))),
        "summary": summary,
        "base": int(base),
        "direct": direct,
        "family_analyzer": meta,
    }

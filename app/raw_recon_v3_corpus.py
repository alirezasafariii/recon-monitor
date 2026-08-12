from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import (
    ROOT,
    load_raw_cases,
    prior_source_index,
    validate_raw_corpus,
)

RAW_V3_CORPUS_VALIDATOR_VERSION = "1.0.0"
V3_MIN_SOURCE_ROOTS = 24
V3_MIN_SOURCE_PROJECTS = 20
V3_MIN_POSITIVE_FAMILIES = 18
V3_PRIOR_CORPORA = (
    ROOT / "benchmarks" / "golden" / "analysis_golden_v3.jsonl",
    ROOT / "benchmarks" / "golden" / "analysis_golden_v4.jsonl",
    ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl",
    ROOT / "benchmarks" / "raw" / "analysis_raw_v2.jsonl",
)


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _details(case: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = case.get("raw") if isinstance(case.get("raw"), Mapping) else {}
    value = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
    return value


def _variant_groups(cases: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in cases:
        result[_norm(row.get("source_root"))].append(dict(row))
    return result


def validate_v3_corpus(
    cases: Iterable[Mapping[str, Any]],
    *,
    require_collection_floor: bool = True,
) -> dict[str, Any]:
    """Validate the third raw holdout without executing detector scoring.

    Analysis 6.15 preserves the collision/observability contract established after raw v1: a
    positive variant may never be raw-identical to its near-miss or secure
    negative. The positive must carry a target-observable delta in raw.details;
    labels or advisory prose remain outside the detector input.
    """
    rows = [dict(row) for row in cases]
    base = validate_raw_corpus(
        rows,
        require_collection_floor=False,
        enforce_prior_independence=False,
    )
    errors = list(base.get("errors") or [])
    prior = prior_source_index(V3_PRIOR_CORPORA)
    groups = _variant_groups(rows)
    projects = {_norm(row.get("source_project")) for row in rows if _norm(row.get("source_project"))}
    families = {
        _norm(row.get("family"))
        for row in rows
        if _norm(row.get("case_kind")) == "positive" and _norm(row.get("family"))
    }
    prior_roots: set[str] = set()
    prior_urls: set[str] = set()
    collision_roots: set[str] = set()
    missing_observable_delta: set[str] = set()

    for row in rows:
        root = _norm(row.get("source_root"))
        provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        url = _norm(provenance.get("url"))
        if root and root in prior["roots"]:
            prior_roots.add(root)
        if url and url in prior["urls"]:
            prior_urls.add(url)

    for root, group in sorted(groups.items()):
        if not root:
            continue
        by_kind = {_norm(row.get("case_kind")): row for row in group}
        positive = by_kind.get("positive")
        near_miss = by_kind.get("near_miss")
        secure_negative = by_kind.get("secure_negative")
        if not positive or not near_miss or not secure_negative:
            continue
        positive_raw = positive.get("raw") if isinstance(positive.get("raw"), Mapping) else {}
        positive_details = _details(positive)
        if not positive_details:
            missing_observable_delta.add(root)
        for control in (near_miss, secure_negative):
            control_raw = control.get("raw") if isinstance(control.get("raw"), Mapping) else {}
            if _canonical(positive_raw) == _canonical(control_raw):
                collision_roots.add(root)
            if _canonical(positive_details) == _canonical(_details(control)):
                missing_observable_delta.add(root)

    if prior_roots:
        errors.append(f"v3 prior source_root overlap detected: {sorted(prior_roots)}")
    if prior_urls:
        errors.append(f"v3 prior provenance URL overlap detected: {sorted(prior_urls)}")
    if collision_roots:
        errors.append(f"v3 positive/control raw collision detected: {sorted(collision_roots)}")
    if missing_observable_delta:
        errors.append(
            "v3 positive variants must contain a distinct target-observable raw.details delta: "
            + repr(sorted(missing_observable_delta))
        )

    if require_collection_floor:
        if len(groups) < V3_MIN_SOURCE_ROOTS:
            errors.append(f"v3 source roots below floor: {len(groups)}/{V3_MIN_SOURCE_ROOTS}")
        if len(projects) < V3_MIN_SOURCE_PROJECTS:
            errors.append(f"v3 source projects below floor: {len(projects)}/{V3_MIN_SOURCE_PROJECTS}")
        if len(families) < V3_MIN_POSITIVE_FAMILIES:
            errors.append(f"v3 positive families below floor: {len(families)}/{V3_MIN_POSITIVE_FAMILIES}")

    root_count = len([root for root in groups if root])
    observable_count = max(0, root_count - len(missing_observable_delta))
    return {
        **base,
        "validator_version": RAW_V3_CORPUS_VALIDATOR_VERSION,
        "passed": not errors,
        "errors": errors,
        "source_root_count": root_count,
        "source_project_count": len(projects),
        "positive_family_count": len(families),
        "prior_source_root_overlap_count": len(prior_roots),
        "prior_url_overlap_count": len(prior_urls),
        "positive_control_raw_collision_count": len(collision_roots),
        "positive_observable_delta_count": observable_count,
        "positive_observable_delta_rate": round(observable_count / root_count, 6) if root_count else 0.0,
        "v3_prior_corpus_count": len(V3_PRIOR_CORPORA),
    }


__all__ = [
    "RAW_V3_CORPUS_VALIDATOR_VERSION",
    "V3_MIN_POSITIVE_FAMILIES",
    "V3_MIN_SOURCE_PROJECTS",
    "V3_MIN_SOURCE_ROOTS",
    "V3_PRIOR_CORPORA",
    "load_raw_cases",
    "validate_v3_corpus",
]

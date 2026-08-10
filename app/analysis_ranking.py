from __future__ import annotations

from typing import Any, Iterable, Mapping

from family_reasoners import (
    FAMILY_REASONER_RULE_VERSION,
    FAMILY_REASONER_VERSION,
    condition_confidence,
    rank_with_family_reasoners,
    reason_family,
)

RANKING_ENGINE_VERSION = "2.0.0"
RANKING_RULE_VERSION = "2026.08.10.6.7"


def admission_confidence(assessment: Mapping[str, Any]) -> float:
    """Backward-compatible wrapper around the family-reasoner condition model."""
    return condition_confidence(assessment)


def family_compatibility(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return family-specific identity fit separately from vulnerability confidence.

    Analysis 6.7 no longer ranks every bug family with one generic coverage formula.
    Each family owns its analytical question, group weights, scoped source counting,
    controls, and confusion boundaries in ``family_reasoners.py``.
    """
    row = reason_family(family, support, contradict)
    total_group_weight = sum(float(item.get("weight") or 0.0) for item in row["group_results"])
    normalized_coverage = (
        float(row["weighted_group_coverage"]) / total_group_weight
        if total_group_weight > 0
        else 0.0
    )
    return {
        **row,
        # Compatibility aliases used by Benchmark 3.x and existing diagnostics.
        "coverage": round(normalized_coverage, 6),
        "ranking_engine_version": RANKING_ENGINE_VERSION,
        "ranking_rule_version": RANKING_RULE_VERSION,
        "family_reasoner_version": FAMILY_REASONER_VERSION,
        "family_reasoner_rule_version": FAMILY_REASONER_RULE_VERSION,
    }


def rank_families(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows = rank_with_family_reasoners(support, contradict)
    for row in rows:
        total_group_weight = sum(float(item.get("weight") or 0.0) for item in row["group_results"])
        row["coverage"] = round(
            float(row["weighted_group_coverage"]) / total_group_weight
            if total_group_weight > 0
            else 0.0,
            6,
        )
        row["ranking_engine_version"] = RANKING_ENGINE_VERSION
        row["ranking_rule_version"] = RANKING_RULE_VERSION
    return rows

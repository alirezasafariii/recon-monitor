from __future__ import annotations

from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission

RANKING_ENGINE_VERSION = "1.0.0"
RANKING_RULE_VERSION = "2026.08.10.6.5"


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def admission_confidence(assessment: Mapping[str, Any]) -> float:
    """Probability-like confidence that the vulnerability condition is established.

    This is deliberately separate from family fit. A family-specific security control can
    make the vulnerability condition unlikely while simultaneously making the family
    classification more certain.
    """
    if assessment.get("admitted"):
        return 0.96
    state = str(assessment.get("state") or "")
    if state == "shadow_contradicted":
        return 0.04
    satisfied = len(assessment.get("required_satisfied") or [])
    missing = len(assessment.get("required_missing") or [])
    coverage = satisfied / max(1, satisfied + missing)
    if state == "shadow_partial":
        return round(min(0.28, 0.06 + 0.24 * coverage), 6)
    return 0.04


def family_compatibility(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rank how well evidence belongs to a vulnerability family, not whether it is vulnerable.

    Blocking contradictions are intentionally *not* subtracted from family fit. They are
    evidence that the relevant security control was observed for this family, and therefore
    belong in condition confidence / admission, not in family identity scoring.
    """
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    assessment = assess_admission(family, support_items, contradict_items)
    policy = FAMILY_ADMISSION_POLICIES[family]
    required_count = max(1, len(policy.get("required", [])))
    satisfied_count = len(assessment.get("required_satisfied") or [])
    coverage = satisfied_count / required_count
    required_sources = max(1, int(policy.get("min_independent_sources", 1)))
    source_ratio = min(1.0, int(assessment.get("independent_sources") or 0) / required_sources)

    score = 0.68 * coverage + 0.14 * source_ratio
    if assessment.get("admitted"):
        score += 0.18
    score = _clamp(score)
    blocking = list(assessment.get("blocking_contradictions") or [])
    condition_confidence = admission_confidence(assessment)
    return {
        "family": family,
        "score": round(score, 6),
        "family_fit_score": round(score, 6),
        "coverage": round(coverage, 6),
        "source_ratio": round(source_ratio, 6),
        "condition_confidence": condition_confidence,
        "control_evidence": blocking,
        "assessment": assessment,
        "ranking_engine_version": RANKING_ENGINE_VERSION,
        "ranking_rule_version": RANKING_RULE_VERSION,
    }


def rank_families(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    rows = [family_compatibility(family, support_items, contradict_items) for family in FAMILY_ADMISSION_POLICIES]
    rows.sort(
        key=lambda item: (
            float(item["family_fit_score"]),
            bool(item["assessment"].get("admitted")),
            float(item["coverage"]),
            float(item["source_ratio"]),
            str(item["family"]),
        ),
        reverse=True,
    )
    return rows

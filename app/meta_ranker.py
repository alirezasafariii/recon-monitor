from __future__ import annotations

"""Explainable bug-proximity ranking for Recon Monitor.

The meta ranker combines already-existing target evidence with non-evidentiary
knowledge and historical context.  It deliberately produces two independent
numbers:

* ``bug_proximity_score``: how closely a surface resembles a vulnerability
  family and therefore how useful it may be to investigate;
* ``target_evidence_confidence``: how much family-specific evidence was actually
  observed on the target.

Knowledge retrieval, historical feedback, correlation, and LLM advice are never
allowed to increase ``target_evidence_confidence`` or satisfy admission gates.
"""

from collections import defaultdict
from typing import Any, Iterable, Mapping

META_RANKER_VERSION = "1.0.0"
META_RANKER_RULE_VERSION = "2026.08.10.1"

DEFAULT_WEIGHTS: dict[str, float] = {
    "target_evidence": 0.40,
    "profile_compatibility": 0.30,
    "writeup_similarity": 0.15,
    "historical_feedback": 0.07,
    "correlation": 0.05,
    "llm_advisory": 0.03,
}


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _normalize_token(value: Any) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _source_group(item: Mapping[str, Any]) -> str:
    return _normalize_token(item.get("source_group") or item.get("source") or item.get("type") or "unknown")


def _matched_types(ranking: Mapping[str, Any]) -> tuple[set[str], set[str], set[str]]:
    matched = ranking.get("matched", {}) if isinstance(ranking.get("matched"), Mapping) else {}
    strong = {_normalize_token(value) for value in matched.get("strong", [])}
    medium = {_normalize_token(value) for value in matched.get("medium", [])}
    weak = {_normalize_token(value) for value in matched.get("weak", [])}
    return strong, medium, weak


def target_evidence_confidence(
    ranking: Mapping[str, Any],
    support: Iterable[Mapping[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Score only target-originating family-specific evidence.

    No writeup, taxonomy, historical result, correlation prior, or LLM output is
    accepted by this function.  This makes the evidence/proximity boundary easy
    to audit and regression test.
    """

    strong, medium, weak = _matched_types(ranking)
    matched_types = strong | medium | weak
    groups: set[str] = set()
    matched_support = 0
    for item in support:
        item_type = _normalize_token(item.get("type"))
        if item_type in matched_types:
            groups.add(_source_group(item))
            matched_support += 1

    contradictions = [str(value) for value in ranking.get("contradictions", []) if str(value).strip()]
    raw = (
        len(strong) * 26
        + len(medium) * 13
        + len(weak) * 5
        + min(18, len(groups) * 6)
        - len(contradictions) * 18
    )
    if not matched_types:
        score = 0
    else:
        score = _clamp(raw, 0, 96)

    return score, {
        "matched_strong": sorted(strong),
        "matched_medium": sorted(medium),
        "matched_weak": sorted(weak),
        "matched_support_items": matched_support,
        "independent_target_source_groups": len(groups),
        "contradictions": contradictions,
        "source": "target_observations_only",
    }


def _writeup_scores(retrieved_writeups: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    scores: dict[str, int] = defaultdict(int)
    for doc in retrieved_writeups:
        family = str(doc.get("family") or "").strip()
        if not family:
            continue
        scores[family] = max(scores[family], _clamp(float(doc.get("retrieval_score") or 0)))
    return dict(scores)


def _optional_score(mapping: Mapping[str, Any] | None, family: str) -> int | None:
    if not mapping or family not in mapping:
        return None
    try:
        return _clamp(float(mapping[family]))
    except (TypeError, ValueError):
        return None


def _weighted_score(components: Mapping[str, int | None]) -> int:
    numerator = 0.0
    denominator = 0.0
    for name, value in components.items():
        if value is None:
            continue
        weight = float(DEFAULT_WEIGHTS.get(name, 0.0))
        if weight <= 0:
            continue
        numerator += float(value) * weight
        denominator += weight
    return _clamp(numerator / denominator if denominator else 0.0)


def _proximity_band(score: int) -> str:
    if score >= 85:
        return "very_high"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "trace"


def _hunt_priority(proximity: int, evidence: int) -> str:
    if proximity >= 80 and evidence >= 45:
        return "HIGH"
    if proximity >= 60 or evidence >= 55:
        return "MEDIUM"
    if proximity >= 35:
        return "LOW"
    return "NOISE"


def _admission_gaps(admission_by_family: Mapping[str, Any] | None, family: str) -> list[str]:
    if not admission_by_family:
        return []
    raw = admission_by_family.get(family)
    if not isinstance(raw, Mapping):
        return []
    gaps: list[str] = []
    for group in raw.get("required_missing", []):
        if isinstance(group, (list, tuple, set)):
            values = [str(value) for value in group if str(value).strip()]
            if values:
                gaps.append("one_of:" + "|".join(values))
        elif str(group).strip():
            gaps.append(str(group))
    for value in raw.get("blocking_contradictions", []):
        if str(value).strip():
            gaps.append("blocking_contradiction:" + str(value))
    return gaps


def rank_bug_proximity(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None,
    family_rankings: Iterable[Mapping[str, Any]],
    retrieved_writeups: Iterable[Mapping[str, Any]],
    *,
    historical_scores: Mapping[str, Any] | None = None,
    correlation_scores: Mapping[str, Any] | None = None,
    llm_advisory_scores: Mapping[str, Any] | None = None,
    admission_by_family: Mapping[str, Any] | None = None,
    limit: int = 3,
) -> dict[str, Any]:
    """Combine evidence and advisory channels into an explainable Top-N ranking.

    ``llm_advisory_scores`` is intentionally optional and only carries 3% of the
    configured weight.  Missing optional components are excluded rather than
    replaced with artificial neutral scores.
    """

    support_items = [dict(item) for item in support]
    _ = [dict(item) for item in (contradict or [])]  # kept explicit for API symmetry/auditability
    rankings_by_family = {
        str(item.get("family")): dict(item)
        for item in family_rankings
        if str(item.get("family") or "").strip()
    }
    writeup_scores = _writeup_scores(retrieved_writeups)

    families = set(rankings_by_family) | set(writeup_scores)
    if historical_scores:
        families |= {str(value) for value in historical_scores}
    if correlation_scores:
        families |= {str(value) for value in correlation_scores}
    if llm_advisory_scores:
        families |= {str(value) for value in llm_advisory_scores}

    results: list[dict[str, Any]] = []
    for family in sorted(families):
        ranking = rankings_by_family.get(
            family,
            {
                "family": family,
                "label": family.replace("_", " ").title(),
                "score": 0,
                "matched": {"strong": [], "medium": [], "weak": [], "text": []},
                "contradictions": [],
                "taxonomy": {},
                "tags": [],
            },
        )
        evidence_score, evidence_explanation = target_evidence_confidence(ranking, support_items)
        profile_score = _clamp(float(ranking.get("score") or 0))
        writeup_score = writeup_scores.get(family)
        historical_score = _optional_score(historical_scores, family)
        correlation_score = _optional_score(correlation_scores, family)
        llm_score = _optional_score(llm_advisory_scores, family)

        components: dict[str, int | None] = {
            "target_evidence": evidence_score,
            "profile_compatibility": profile_score,
            "writeup_similarity": writeup_score,
            "historical_feedback": historical_score,
            "correlation": correlation_score,
            "llm_advisory": llm_score,
        }
        proximity = _weighted_score(components)

        contradiction_count = len(evidence_explanation["contradictions"])
        if contradiction_count:
            proximity = _clamp(proximity - min(30, contradiction_count * 12))

        # Guardrails: knowledge or advisory channels can make a family worth
        # looking at, but they cannot manufacture high confidence in the absence
        # of family-specific target evidence.
        strong_count = len(evidence_explanation["matched_strong"])
        if evidence_score == 0:
            proximity = min(proximity, 35)
        elif evidence_score < 25:
            proximity = min(proximity, 55)
        elif strong_count == 0 and evidence_score < 50:
            proximity = min(proximity, 69)

        available = [name for name, value in components.items() if value is not None]
        unavailable = [name for name, value in components.items() if value is None]
        why: list[str] = []
        if evidence_explanation["matched_strong"]:
            why.append("strong target signals: " + ", ".join(evidence_explanation["matched_strong"][:6]))
        if evidence_explanation["matched_medium"]:
            why.append("supporting target signals: " + ", ".join(evidence_explanation["matched_medium"][:6]))
        if evidence_explanation["matched_weak"]:
            why.append("weak target signals: " + ", ".join(evidence_explanation["matched_weak"][:6]))
        if writeup_score is not None:
            why.append(f"writeup similarity: {writeup_score}/100 (non-evidentiary)")
        if historical_score is not None:
            why.append(f"historical analyst prior: {historical_score}/100 (non-evidentiary)")
        if correlation_score is not None:
            why.append(f"related-surface correlation: {correlation_score}/100 (non-evidentiary)")
        if llm_score is not None:
            why.append(f"LLM advisory: {llm_score}/100 (non-evidentiary)")

        results.append(
            {
                "family": family,
                "label": str(ranking.get("label") or family),
                "bug_proximity_score": proximity,
                "target_evidence_confidence": evidence_score,
                "proximity_band": _proximity_band(proximity),
                "hunt_priority": _hunt_priority(proximity, evidence_score),
                "components": components,
                "available_components": available,
                "unavailable_components": unavailable,
                "evidence_explanation": evidence_explanation,
                "evidence_gaps": _admission_gaps(admission_by_family, family),
                "why": why,
                "taxonomy": ranking.get("taxonomy", {}),
                "tags": list(ranking.get("tags", [])),
                "status": "proximity_only_not_confirmed",
            }
        )

    results.sort(
        key=lambda item: (
            int(item["bug_proximity_score"]),
            int(item["target_evidence_confidence"]),
        ),
        reverse=True,
    )
    top = results[: max(1, int(limit))]
    primary = top[0] if top else None
    return {
        "engine_version": META_RANKER_VERSION,
        "rule_version": META_RANKER_RULE_VERSION,
        "weights": dict(DEFAULT_WEIGHTS),
        "primary": primary,
        "alternatives": top[1:],
        "rankings": top,
        "safety": {
            "bug_proximity_is_not_vulnerability_confidence": True,
            "target_evidence_confidence_uses_target_observations_only": True,
            "knowledge_cannot_satisfy_admission": True,
            "llm_is_advisory_only": True,
        },
    }

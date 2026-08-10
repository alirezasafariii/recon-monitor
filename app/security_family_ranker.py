from __future__ import annotations

from typing import Any, Iterable, Mapping

from family_reasoners import FAMILY_REASONER_PROFILES, reason_family

SECURITY_FAMILY_RANKER_VERSION = "1.0.0"
SECURITY_FAMILY_RANKER_RULE_VERSION = "2026.08.10.6.7"


def _score_0_96(value: float) -> int:
    return max(0, min(96, int(round(float(value) * 96))))


def production_family_rankings(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
    labels: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    label_map = dict(labels or {})
    rows: list[dict[str, Any]] = []

    for family in FAMILY_REASONER_PROFILES:
        reasoned = reason_family(family, support_items, contradict_items)
        score = _score_0_96(reasoned["family_fit_score"])
        if score <= 0:
            continue
        rows.append({
            "family": family,
            "label": label_map.get(family, family),
            "score": score,
            "reason": {
                "primary_question": reasoned["primary_question"],
                "group_results": reasoned["group_results"],
                "identity_group_hits": reasoned["identity_group_hits"],
                "condition_hits": reasoned["condition_hits"],
                "condition_confidence": reasoned["condition_confidence"],
                "matched_contradict": reasoned["control_evidence"],
                "confounder_evidence": reasoned["confounder_evidence"],
                "confounder_penalty": reasoned["confounder_penalty"],
                "scoped_independent_sources": reasoned["scoped_independent_sources"],
                "unscoped_evidence_count": reasoned["unscoped_evidence_count"],
                "family_fit_score": reasoned["family_fit_score"],
                "contradictions_affect_family_fit": False,
                "family_reasoner_version": reasoned["family_reasoner_version"],
                "family_reasoner_rule_version": reasoned["family_reasoner_rule_version"],
                "security_family_ranker_version": SECURITY_FAMILY_RANKER_VERSION,
                "security_family_ranker_rule_version": SECURITY_FAMILY_RANKER_RULE_VERSION,
            },
        })

    rows.sort(
        key=lambda item: (
            int(item["score"]),
            float(item["reason"]["condition_confidence"]),
            len(item["reason"]["condition_hits"]),
            int(item["reason"]["identity_group_hits"]),
            str(item["family"]),
        ),
        reverse=True,
    )
    return rows

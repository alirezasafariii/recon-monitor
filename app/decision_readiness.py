from __future__ import annotations

"""Advisory decision-readiness scoring for Analysis findings.

Bug proximity answers "is this worth investigating?". Decision readiness answers
"how close is the currently stored target evidence to the canonical confirmation
contract?". The two must remain separate: a structurally interesting surface may
have high proximity while still lacking decisive vulnerability evidence.

This module is side-effect free. It cannot create evidence, satisfy admission,
or satisfy confirmation. Family Reasoning remains the authoritative contract.
"""

import re
from typing import Any, Iterable, Mapping

from family_reasoning import FAMILY_REASONING

DECISION_READINESS_VERSION = "1.0.0"
DECISION_READINESS_RULE_VERSION = "2026.08.13.1"


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _types(items: Iterable[Mapping[str, Any]] | None) -> set[str]:
    return {
        _token(item.get("type"))
        for item in (items or [])
        if isinstance(item, Mapping) and _token(item.get("type"))
    }


def _groups(raw: Any) -> list[set[str]]:
    result: list[set[str]] = []
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return result
    for group in raw:
        if isinstance(group, (list, tuple, set, frozenset)):
            values = {_token(value) for value in group if _token(value)}
        else:
            token = _token(group)
            values = {token} if token else set()
        if values:
            result.append(values)
    return result


def _recognized_contradictions(values: Iterable[Any] | None) -> set[str]:
    return {_token(value) for value in (values or []) if _token(value)}


def decision_readiness(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
    *,
    target_evidence_confidence: int = 0,
    recognized_contradictions: Iterable[Any] | None = None,
    reasoning: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return an advisory score tied to canonical confirmation requirements.

    Rules are intentionally fail-closed:
    - structural/promotional evidence without any confirmation-group match is
      capped below normal decision thresholds;
    - partial confirmation-group coverage is capped;
    - any recognized security-control contradiction sharply reduces readiness;
    - the output never changes the underlying evidence or hard gates.
    """

    family = str(family or "").strip()
    contracts = reasoning if isinstance(reasoning, Mapping) else FAMILY_REASONING
    contract = contracts.get(family, {}) if isinstance(contracts, Mapping) else {}
    support_types = _types(support)
    contradict_types = _types(contradict)

    required_groups = _groups(contract.get("confirmation_required", ())) if isinstance(contract, Mapping) else []
    blocking = {
        _token(value)
        for value in contract.get("blocking_contradictions", ())
        if _token(value)
    } if isinstance(contract, Mapping) and isinstance(
        contract.get("blocking_contradictions", ()), (list, tuple, set, frozenset)
    ) else set()

    satisfied_groups: list[list[str]] = []
    missing_groups: list[list[str]] = []
    matched_decisive: set[str] = set()
    for group in required_groups:
        matched = group & support_types
        if matched:
            matched_decisive.update(matched)
            satisfied_groups.append(sorted(group))
        else:
            missing_groups.append(sorted(group))

    if required_groups:
        coverage = len(satisfied_groups) / len(required_groups)
    else:
        coverage = 0.0

    canonical_blocking = blocking & contradict_types
    recognized = _recognized_contradictions(recognized_contradictions)
    observed_controls = canonical_blocking | recognized

    evidence = _clamp(float(target_evidence_confidence))
    base = (0.55 * evidence) + (45.0 * coverage)

    if not required_groups:
        score = min(_clamp(base), 25)
    elif coverage <= 0.0:
        score = min(_clamp(base), 30)
    elif coverage < 1.0:
        score = min(_clamp(base), 55)
    else:
        score = _clamp(base)

    # A stored contradiction/control means the mechanism is not currently
    # decision-ready even if the vulnerable-path signal is also present. Keep it
    # visible for investigation, but fail closed for decision readiness.
    if observed_controls:
        score = min(_clamp(score - min(60, len(observed_controls) * 35)), 25)

    if evidence == 0:
        score = min(score, 20)

    if observed_controls:
        band = "blocked_by_control"
    elif required_groups and coverage >= 1.0 and score >= 70:
        band = "decision_ready_advisory"
    elif matched_decisive:
        band = "decisive_evidence_incomplete"
    elif support_types:
        band = "investigation_only"
    else:
        band = "no_target_evidence"

    return {
        "engine_version": DECISION_READINESS_VERSION,
        "rule_version": DECISION_READINESS_RULE_VERSION,
        "family": family,
        "score": int(score),
        "band": band,
        "target_evidence_confidence": evidence,
        "confirmation_group_count": len(required_groups),
        "confirmation_groups_satisfied": len(satisfied_groups),
        "confirmation_coverage": round(coverage, 6),
        "matched_decisive_signals": sorted(matched_decisive),
        "missing_confirmation_groups": missing_groups,
        "blocking_contradictions": sorted(observed_controls),
        "advisory_only": True,
        "may_satisfy_admission": False,
        "may_satisfy_confirmation": False,
        "may_create_target_evidence": False,
    }

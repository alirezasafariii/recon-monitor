from __future__ import annotations

"""Diagnostic next-evidence planning for Analysis Brain hypotheses.

The planner consumes Evidence Coverage plus the canonical Family Reasoning
contract and answers one question: what is the safest *next evidence step* for a
current hypothesis? It never executes validation, creates evidence, satisfies
Admission, or promotes a Candidate.

Evidence Coverage is family-level diagnostic context. Planner decisions remain
hypothesis-local: evidence observed on one hypothesis can never satisfy the gap
of another hypothesis in the same family. Evidence records are filtered through
the same family-scope quarantine used by canonical Admission.
"""

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import atomic_write_text, json_dumps, utc_now
from evidence_coverage import INCOMPLETE_COLLECTION_STATUSES
from family_evidence_scope import scope_family_evidence
from family_reasoning import (
    FAMILY_REASONING,
    FAMILY_REASONING_RULE_VERSION,
    FAMILY_REASONING_VERSION,
)

EVIDENCE_COMPLETION_PLANNER_VERSION = "1.0.0"
EVIDENCE_COMPLETION_PLANNER_RULE_VERSION = "2026.08.16.4"

GAP_TYPES = {
    "passive_collection_gap",
    "passive_observation_missing",
    "behavioral_validation_needed",
    "controlled_validation_needed",
    "contradictory_evidence_present",
    "independent_source_needed",
    "analyst_review_needed",
    "no_further_safe_action",
}

ACTION_BY_GAP = {
    "passive_collection_gap": "repeat_passive_collection",
    "passive_observation_missing": "review_passive_evidence",
    "behavioral_validation_needed": "prepare_passive_live_validation",
    "controlled_validation_needed": "prepare_controlled_validation",
    "contradictory_evidence_present": "review_contradictory_evidence",
    "independent_source_needed": "seek_independent_evidence_source",
    "analyst_review_needed": "manual_evidence_review",
    "no_further_safe_action": "no_action",
}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _typed_evidence(value: Any) -> list[dict[str, Any]]:
    raw = _loads(value, [])
    if not isinstance(raw, list):
        return []
    return [
        dict(item)
        for item in raw
        if isinstance(item, Mapping) and str(item.get("type") or "").strip()
    ]


def _scoped_evidence(
    family: str,
    value: Any,
    *,
    channel: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scope = scope_family_evidence(
        family,
        _typed_evidence(value),
        annotate_unscoped=False,
        channel=channel,
    )
    accepted = [
        dict(item)
        for item in scope.get("accepted", [])
        if isinstance(item, Mapping) and str(item.get("type") or "").strip()
    ]
    diagnostics = {
        "version": str(scope.get("version") or ""),
        "rule_version": str(scope.get("rule_version") or ""),
        "accepted_count": int(scope.get("accepted_count") or 0),
        "rejected_cross_family_count": int(scope.get("rejected_count") or 0),
    }
    return accepted, diagnostics


def _evidence_types(items: Iterable[Mapping[str, Any]]) -> set[str]:
    return {
        str(item.get("type") or "").strip()
        for item in items
        if str(item.get("type") or "").strip()
    }


def _source_groups(items: Iterable[Mapping[str, Any]]) -> set[str]:
    result: set[str] = set()
    for item in items:
        signal = str(item.get("type") or "").strip()
        if not signal:
            continue
        source_group = str(
            item.get("source_group") or item.get("source") or signal
        ).strip()
        if source_group:
            result.add(source_group)
    return result


def _coverage_signal_index(family_coverage: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Index family coverage rows only for collection metadata, not evidence state."""
    result: dict[str, dict[str, Any]] = {}
    for key in ("promotion_required", "confirmation_required"):
        for raw_group in family_coverage.get(key, []):
            if not isinstance(raw_group, Mapping):
                continue
            for raw_signal in raw_group.get("signals", []):
                if not isinstance(raw_signal, Mapping):
                    continue
                signal = str(raw_signal.get("signal") or "").strip()
                if signal:
                    result.setdefault(signal, dict(raw_signal))
    for key in ("blocking_contradictions", "override_signals"):
        for raw_signal in family_coverage.get(key, []):
            if not isinstance(raw_signal, Mapping):
                continue
            signal = str(raw_signal.get("signal") or "").strip()
            if signal:
                result.setdefault(signal, dict(raw_signal))
    return result


def _hypothesis_signal_status(
    signal: str,
    *,
    support_types: set[str],
    contradict_types: set[str],
    coverage_metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if signal in support_types or signal in contradict_types:
        channel = (
            "both"
            if signal in support_types and signal in contradict_types
            else "support"
            if signal in support_types
            else "contradict"
        )
        return {
            "signal": signal,
            "status": "observed",
            "observation_channel": channel,
            "collection_dimensions": list(
                (coverage_metadata or {}).get("collection_dimensions", [])
            ),
            "collection_status": dict(
                (coverage_metadata or {}).get("collection_status", {})
            ),
            "reason": "Typed, family-compatible target evidence for this signal exists on this hypothesis.",
        }

    metadata = dict(coverage_metadata or {})
    dimensions = [
        str(value)
        for value in metadata.get("collection_dimensions", [])
        if str(value).strip()
    ]
    collection_status = {
        str(key): str(value or "unknown").strip().lower()
        for key, value in dict(metadata.get("collection_status") or {}).items()
    }

    if not dimensions:
        return {
            "signal": signal,
            "status": "unknown",
            "observation_channel": "none",
            "collection_dimensions": [],
            "collection_status": {},
            "reason": (
                "This hypothesis lacks direct family-compatible evidence and current "
                "Evidence Coverage cannot justify an absence statement for this "
                "behavioral or unmapped signal."
            ),
        }

    states = [collection_status.get(dimension, "unknown") for dimension in dimensions]
    if any(state in INCOMPLETE_COLLECTION_STATUSES for state in states):
        status = "not_collected"
        reason = (
            "This hypothesis lacks the signal and at least one relevant passive "
            "collection dimension was incomplete."
        )
    elif any(state == "unknown" for state in states):
        status = "unknown"
        reason = (
            "This hypothesis lacks the signal and collection completeness is unknown "
            "for at least one relevant passive dimension."
        )
    elif states and all(state == "complete" for state in states):
        status = "not_observed"
        reason = (
            "This hypothesis lacks the signal while all mapped passive collection "
            "dimensions were complete."
        )
    else:
        status = "unknown"
        reason = "Hypothesis-local coverage could not be determined conservatively."

    return {
        "signal": signal,
        "status": status,
        "observation_channel": "none",
        "collection_dimensions": dimensions,
        "collection_status": collection_status,
        "reason": reason,
    }


def _project_groups(
    groups: Iterable[Iterable[str]],
    *,
    support_types: set[str],
    contradict_types: set[str],
    signal_index: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for index, group in enumerate(groups):
        signals = [
            _hypothesis_signal_status(
                str(signal),
                support_types=support_types,
                contradict_types=contradict_types,
                coverage_metadata=signal_index.get(str(signal)),
            )
            for signal in sorted({str(value) for value in group if str(value).strip()})
        ]
        support_observed = [
            item["signal"]
            for item in signals
            if item["status"] == "observed"
            and item.get("observation_channel") in {"support", "both"}
        ]
        statuses = {str(item.get("status") or "unknown") for item in signals}
        if support_observed:
            status = "observed"
            reason = "This hypothesis satisfies the canonical OR-group with typed support."
        elif "not_collected" in statuses:
            status = "not_collected"
            reason = "At least one alternative was not fully collected for this hypothesis."
        elif "unknown" in statuses:
            status = "unknown"
            reason = "At least one alternative requires evidence that cannot be assessed passively."
        elif signals and statuses == {"not_observed"}:
            status = "not_observed"
            reason = "No alternative was observed for this hypothesis in complete passive inputs."
        else:
            status = "unknown"
            reason = "Canonical evidence-group coverage is unknown for this hypothesis."
        projected.append(
            {
                "group_index": index,
                "status": status,
                "signals": signals,
                "support_observed": support_observed,
                "reason": reason,
            }
        )
    return projected


def _group_gaps(groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in groups:
        group = dict(raw)
        status = str(group.get("status") or "unknown")
        if status == "observed":
            continue
        result.append(
            {
                "group_index": int(group.get("group_index") or 0),
                "status": status,
                "alternatives": [
                    {
                        "signal": str(signal.get("signal") or ""),
                        "status": str(signal.get("status") or "unknown"),
                        "collection_dimensions": [
                            str(value)
                            for value in signal.get("collection_dimensions", [])
                            if str(value).strip()
                        ],
                        "collection_status": dict(signal.get("collection_status") or {}),
                        "reason": str(signal.get("reason") or ""),
                    }
                    for signal in group.get("signals", [])
                    if isinstance(signal, Mapping)
                ],
                "reason": str(group.get("reason") or ""),
            }
        )
    return result


def _missing_dimensions(gaps: Iterable[Mapping[str, Any]]) -> list[str]:
    dimensions: set[str] = set()
    for gap in gaps:
        for signal in gap.get("alternatives", []):
            if not isinstance(signal, Mapping):
                continue
            if str(signal.get("status") or "") != "not_collected":
                continue
            for dimension in signal.get("collection_dimensions", []):
                if str(dimension).strip():
                    dimensions.add(str(dimension))
    return sorted(dimensions)


def _gap_type(
    *,
    hypothesis_state: str,
    validation_level: str,
    gaps: Iterable[Mapping[str, Any]],
    blocking_signals: Iterable[str],
    independent_source_gap: int,
) -> str:
    if hypothesis_state == "shadow_contradicted" or list(blocking_signals):
        return "contradictory_evidence_present"

    statuses = {str(gap.get("status") or "unknown") for gap in gaps}
    if "not_collected" in statuses:
        return "passive_collection_gap"
    if "unknown" in statuses:
        if validation_level == "controlled":
            return "controlled_validation_needed"
        if validation_level == "passive_live":
            return "behavioral_validation_needed"
        return "analyst_review_needed"
    if "not_observed" in statuses:
        return "passive_observation_missing"
    if independent_source_gap > 0:
        return "independent_source_needed"
    return "no_further_safe_action"


def _case_requirements(contract: Mapping[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for raw in contract.get("case_requirements", ()):
        if not isinstance(raw, Mapping):
            continue
        result.append(
            {
                "key": str(raw.get("key") or ""),
                "label": str(raw.get("label") or ""),
                "why": str(raw.get("why") or ""),
            }
        )
    return result


def _plan_for_hypothesis(
    row: Mapping[str, Any],
    *,
    evidence_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    family = str(row.get("bug_family") or "").strip()
    state = str(row.get("state") or "shadow_signal").strip()
    contract = FAMILY_REASONING.get(family, {})
    family_coverage_raw = evidence_coverage.get("families", {}).get(family, {})
    family_coverage = (
        dict(family_coverage_raw) if isinstance(family_coverage_raw, Mapping) else {}
    )
    admission = _loads(row.get("admission_json"), {})
    admitted = bool(admission.get("admitted")) or state == "admitted"

    support_items, support_scope = _scoped_evidence(
        family,
        row.get("supporting_evidence_json"),
        channel="evidence_completion_planner_support",
    )
    contradict_items, contradict_scope = _scoped_evidence(
        family,
        row.get("contradicting_evidence_json"),
        channel="evidence_completion_planner_contradict",
    )
    support_types = _evidence_types(support_items)
    contradict_types = _evidence_types(contradict_items)
    source_groups = _source_groups(support_items)
    signal_index = _coverage_signal_index(family_coverage)

    phase = "confirmation" if admitted else "promotion"
    canonical_groups = (
        contract.get("confirmation_required", ())
        if admitted
        else contract.get("promotion_required", ())
    )
    projected_groups = _project_groups(
        canonical_groups,
        support_types=support_types,
        contradict_types=contradict_types,
        signal_index=signal_index,
    )
    gaps = _group_gaps(projected_groups)

    blocking_observed = sorted(
        set(str(value) for value in contract.get("blocking_contradictions", ()))
        & contradict_types
    )
    override_observed = sorted(
        set(str(value) for value in contract.get("override_signals", ()))
        & support_types
    )
    effective_blocking = [] if override_observed else blocking_observed

    minimum_sources = int(contract.get("min_independent_sources", 1) or 1)
    independent_source_gap = max(0, minimum_sources - len(source_groups))
    validation_level = str(
        contract.get("validation_level")
        or family_coverage.get("validation_level")
        or admission.get("validation_level")
        or "offline"
    )
    gap_type = _gap_type(
        hypothesis_state=state,
        validation_level=validation_level,
        gaps=gaps,
        blocking_signals=effective_blocking,
        independent_source_gap=independent_source_gap,
    )

    active_action_required = gap_type == "controlled_validation_needed"
    live_target_interaction_required = gap_type in {
        "controlled_validation_needed",
        "behavioral_validation_needed",
    }
    authorization_required = live_target_interaction_required

    return {
        "hypothesis_id": str(row.get("hypothesis_id") or ""),
        "family": family,
        "family_label": str(contract.get("label") or family),
        "category": str(contract.get("category") or "unknown"),
        "state": state,
        "summary": str(row.get("summary") or ""),
        "asset": str(row.get("asset") or ""),
        "endpoint": str(row.get("endpoint") or ""),
        "planning_phase": phase,
        "gap_type": gap_type,
        "recommended_action": ACTION_BY_GAP[gap_type],
        "validation_level": validation_level,
        "missing_evidence_groups": gaps,
        "missing_collection_dimensions": _missing_dimensions(gaps),
        "independent_sources": len(source_groups),
        "min_independent_sources": minimum_sources,
        "independent_source_gap": independent_source_gap,
        "source_groups": sorted(source_groups),
        "stored_missing_evidence": [
            str(value)
            for value in _loads(row.get("missing_evidence_json"), [])
            if str(value).strip()
        ],
        "blocking_contradictions": blocking_observed,
        "override_signals_observed": override_observed,
        "evidence_scope": {
            "support": support_scope,
            "contradict": contradict_scope,
        },
        "next_evidence": [
            str(value) for value in contract.get("next_evidence", ()) if str(value).strip()
        ],
        "case_requirements": _case_requirements(contract),
        "active_action_required": active_action_required,
        "live_target_interaction_required": live_target_interaction_required,
        "authorization_required": authorization_required,
        "safe_to_execute_automatically": False,
        "executor_enabled": False,
        "execution_payload": None,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
    }


def snapshot_evidence_completion_plan(
    ctx: Any,
    *,
    analysis_id: str,
    evidence_coverage: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Build one non-executing evidence-completion plan per current hypothesis."""

    coverage = dict(evidence_coverage or {})
    rows = ctx.db.all(
        "SELECT hypothesis_id,bug_family,state,summary,asset,endpoint,"
        "supporting_evidence_json,contradicting_evidence_json,"
        "missing_evidence_json,admission_json "
        "FROM analysis_hypotheses WHERE analysis_id=? AND target=? "
        "ORDER BY bug_family,hypothesis_id",
        (analysis_id, ctx.policy.name),
    )
    plans = [
        _plan_for_hypothesis(dict(row), evidence_coverage=coverage)
        for row in rows
    ]
    counts = Counter(str(plan.get("gap_type") or "analyst_review_needed") for plan in plans)

    result: dict[str, Any] = {
        "version": EVIDENCE_COMPLETION_PLANNER_VERSION,
        "rule_version": EVIDENCE_COMPLETION_PLANNER_RULE_VERSION,
        "generated_at": utc_now(),
        "run_id": str(ctx.run_id),
        "analysis_id": str(analysis_id),
        "target": str(ctx.policy.name),
        "family_reasoning_version": FAMILY_REASONING_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "evidence_coverage_version": str(coverage.get("version") or "unknown"),
        "plan_count": len(plans),
        "gap_type_counts": {gap: int(counts.get(gap, 0)) for gap in sorted(GAP_TYPES)},
        "plans": plans,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "executes_validation": False,
        "numeric_score": None,
        "safety_semantics": (
            "Plans are advisory evidence-acquisition guidance only. No target request, "
            "callback, credential use, role switch, object mutation, payload, or validation "
            "step is executed by this module. Live or controlled work remains behind the "
            "existing authorization gates and human review."
        ),
        "isolation_semantics": (
            "Each plan is computed from family-compatible evidence stored on that hypothesis. "
            "Family-level Evidence Coverage contributes collection metadata only; evidence "
            "from sibling hypotheses or explicitly cross-family records cannot satisfy this "
            "hypothesis."
        ),
    }

    if persist:
        output = Path(ctx.run_dir) / "evidence-completion-plan.json"
        result["output"] = str(output)
        atomic_write_text(output, json_dumps(result, pretty=True) + "\n")
    return result

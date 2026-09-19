from __future__ import annotations

"""Raw-native quality diagnostics for vulnerability Analysis.

This module measures the behavior of the hypothesis-first raw Analysis path.
It is deliberately diagnostic only: no metric here can admit, promote, rank, or
confirm a vulnerability.  Historical Alert feedback remains available in the
legacy quality snapshot, while these metrics describe what the current raw
Analysis engine actually did.
"""

from collections import Counter, defaultdict
from typing import Any, Mapping

from core import json_dumps, utc_now

RAW_ANALYSIS_QUALITY_VERSION = "1.2.1"
RAW_ANALYSIS_QUALITY_RULE_VERSION = "2026.09.19.3"


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        import json

        decoded = json.loads(value or "")
    except (TypeError, ValueError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _average(total: int, denominator: int) -> float:
    return round(total / denominator, 3) if denominator else 0.0


def _context_only_support(items: list[dict[str, Any]]) -> bool:
    for item in items:
        evidence_type = str(item.get("type") or "")
        evidence_role = str(item.get("target_evidence_role") or "")
        source_group = str(item.get("source_group") or "")
        if (
            evidence_type.startswith("context_only:")
            or evidence_role == "context_only"
            or source_group == "raw_context_only"
        ):
            return True
    return False


def _budget_metrics(
    raw_routing: Mapping[str, Any] | None,
    *,
    analysis_budget: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    routing = raw_routing if isinstance(raw_routing, Mapping) else {}
    raw_budget = routing.get("analyzer_budget", {})
    budget = raw_budget if isinstance(raw_budget, Mapping) else {}
    aggregate = (
        analysis_budget
        if isinstance(analysis_budget, Mapping)
        else budget
    )
    attempted = max(0, int(budget.get("attempted") or 0))
    executed = max(0, int(budget.get("executed") or 0))
    skipped = max(0, int(budget.get("skipped") or 0))
    analysis_attempted = max(0, int(aggregate.get("attempted") or 0))
    analysis_executed = max(0, int(aggregate.get("executed") or 0))
    analysis_skipped = max(0, int(aggregate.get("skipped") or 0))
    limit = max(0, int(budget.get("limit") or aggregate.get("limit") or 0))
    analyzer_execution_coverage = (
        round(executed / attempted, 4) if attempted else None
    )
    return {
        "version": str(budget.get("version") or ""),
        "scope": str(budget.get("scope") or routing.get("scope") or "analysis"),
        "target": str(budget.get("target") or routing.get("target") or ""),
        "limit": limit,
        "limit_scope": str(budget.get("limit_scope") or "analysis"),
        "attempted": attempted,
        "executed": executed,
        "skipped": skipped,
        "analysis_attempted": analysis_attempted,
        "analysis_executed": analysis_executed,
        "analysis_skipped": analysis_skipped,
        "exhausted": bool(budget.get("exhausted")),
        # Operational budget utilization is not collection/input completeness.
        "analyzer_execution_coverage": analyzer_execution_coverage,
        "execution_coverage": analyzer_execution_coverage,
        "remaining_capacity": (
            max(0, limit - analysis_executed)
            if limit
            and str(budget.get("limit_scope") or "analysis") == "analysis"
            else max(0, limit - executed)
            if limit
            else None
        ),
        "families": dict(budget.get("families") or {})
        if isinstance(budget.get("families"), Mapping)
        else {},
    }


def raw_quality_snapshot(
    db: Any,
    analysis_id: str,
    target: str | None = None,
    *,
    raw_routing: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return diagnostics for raw hypotheses created by one Analysis run.

    Only rows whose source reference starts with ``raw-`` are included.  The
    result describes engine behavior, evidence coverage, and scale-guard use;
    it intentionally does not estimate real-world precision or recall.
    """

    routing = raw_routing if isinstance(raw_routing, Mapping) else {}
    aggregate_budget_raw = routing.get("analyzer_budget", {})
    aggregate_budget = (
        aggregate_budget_raw
        if isinstance(aggregate_budget_raw, Mapping)
        else {}
    )
    routing_scope = "analysis_total"
    if target:
        by_target = routing.get("by_target", {})
        if isinstance(by_target, Mapping):
            target_routing = by_target.get(target)
            if isinstance(target_routing, Mapping):
                routing = target_routing
                routing_scope = "target"
    elif str(routing.get("scope") or "") == "analysis":
        routing_scope = "analysis_total"

    budget = _budget_metrics(
        routing,
        analysis_budget=aggregate_budget,
    )
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)

    try:
        rows = db.all(
            "SELECT state,bug_family,source_ref,supporting_evidence_json,"
            "contradicting_evidence_json,missing_evidence_json,"
            "decisive_signals_json,admission_json,seen_count "
            "FROM analysis_hypotheses WHERE analysis_id=? "
            "AND source_ref LIKE 'raw-%'"
            f"{target_clause} ORDER BY bug_family,hypothesis_id",
            tuple(params),
        )
    except Exception as exc:
        return {
            "version": RAW_ANALYSIS_QUALITY_VERSION,
            "rule_version": RAW_ANALYSIS_QUALITY_RULE_VERSION,
            "status": "degraded",
            "error_type": type(exc).__name__,
            "hypotheses": 0,
            "states": {},
            "families": {},
            "budget": budget,
            "diagnostic_only": True,
        }

    states: Counter[str] = Counter()
    family_metrics: dict[str, Counter[str]] = defaultdict(Counter)
    raw_roots: set[str] = set()
    admitted = promoted = contradicted = context_only = context_only_promoted = 0
    support_total = contradiction_total = missing_total = decisive_total = source_total = 0
    with_decisive = with_missing = with_contradiction = 0

    for raw_row in rows:
        row = dict(raw_row)
        state = str(row.get("state") or "unknown")
        family = str(row.get("bug_family") or "unknown")
        source_ref = str(row.get("source_ref") or "")
        support = [
            dict(item)
            for item in _loads(row.get("supporting_evidence_json"), [])
            if isinstance(item, Mapping)
        ]
        contradictions = [
            dict(item)
            for item in _loads(row.get("contradicting_evidence_json"), [])
            if isinstance(item, Mapping)
        ]
        missing = [str(item) for item in _loads(row.get("missing_evidence_json"), []) if str(item)]
        decisive = [str(item) for item in _loads(row.get("decisive_signals_json"), []) if str(item)]
        admission = _loads(row.get("admission_json"), {})
        if not isinstance(admission, Mapping):
            admission = {}

        is_admitted = bool(admission.get("admitted"))
        is_promoted = state == "promoted"
        blocking = admission.get("blocking_contradictions", [])
        has_blocking = bool(blocking) if isinstance(blocking, list) else False
        is_contradicted = state == "shadow_contradicted" or has_blocking
        is_context_only = _context_only_support(support)
        independent_sources = max(0, int(admission.get("independent_sources") or 0))

        states[state] += 1
        raw_roots.add(source_ref)
        metrics = family_metrics[family]
        metrics["hypotheses"] += 1
        metrics[state] += 1
        metrics["support_items"] += len(support)
        metrics["contradiction_items"] += len(contradictions)
        metrics["missing_items"] += len(missing)
        metrics["decisive_signals"] += len(decisive)
        metrics["independent_sources"] += independent_sources
        metrics["seen_count"] += max(1, int(row.get("seen_count") or 1))

        if is_admitted:
            admitted += 1
            metrics["admitted"] += 1
        if is_promoted:
            promoted += 1
            metrics["promoted"] += 1
        if is_contradicted:
            contradicted += 1
            metrics["contradicted"] += 1
        if is_context_only:
            context_only += 1
            metrics["context_only"] += 1
            if is_promoted:
                context_only_promoted += 1
                metrics["context_only_promoted"] += 1

        support_total += len(support)
        contradiction_total += len(contradictions)
        missing_total += len(missing)
        decisive_total += len(decisive)
        source_total += independent_sources
        with_decisive += int(bool(decisive))
        with_missing += int(bool(missing))
        with_contradiction += int(bool(contradictions))

    total = len(rows)
    family_output: dict[str, Any] = {}
    for family, counts in sorted(family_metrics.items()):
        hypotheses = int(counts["hypotheses"])
        family_output[family] = {
            "hypotheses": hypotheses,
            "admitted": int(counts["admitted"]),
            "promoted": int(counts["promoted"]),
            "contradicted": int(counts["contradicted"]),
            "context_only": int(counts["context_only"]),
            "context_only_promoted": int(counts["context_only_promoted"]),
            "admission_rate": _rate(int(counts["admitted"]), hypotheses),
            "promotion_rate": _rate(int(counts["promoted"]), hypotheses),
            "average_support_items": _average(int(counts["support_items"]), hypotheses),
            "average_contradiction_items": _average(int(counts["contradiction_items"]), hypotheses),
            "average_missing_items": _average(int(counts["missing_items"]), hypotheses),
            "average_decisive_signals": _average(int(counts["decisive_signals"]), hypotheses),
            "average_independent_sources": _average(int(counts["independent_sources"]), hypotheses),
            "observation_merges": max(0, int(counts["seen_count"]) - hypotheses),
            "states": {
                key: int(value)
                for key, value in sorted(counts.items())
                if key
                not in {
                    "hypotheses",
                    "admitted",
                    "promoted",
                    "contradicted",
                    "context_only",
                    "context_only_promoted",
                    "support_items",
                    "contradiction_items",
                    "missing_items",
                    "decisive_signals",
                    "independent_sources",
                    "seen_count",
                }
                and value
            },
        }

    guardrail_ok = context_only_promoted == 0
    if not guardrail_ok:
        status = "guardrail_violation"
    elif budget["exhausted"]:
        status = "budget_exhausted"
    elif total:
        status = "observed"
    else:
        status = "empty"

    raw_selection = routing.get("surface_selection", {})
    selection = (
        raw_selection
        if isinstance(raw_selection, Mapping)
        else {}
    )
    input_coverage = selection.get("input_ingestion_coverage")
    surface_coverage = selection.get("surface_selection_coverage")
    result = {
        "version": RAW_ANALYSIS_QUALITY_VERSION,
        "rule_version": RAW_ANALYSIS_QUALITY_RULE_VERSION,
        "status": status,
        "hypotheses": total,
        "raw_observation_roots": len(raw_roots),
        "states": dict(sorted(states.items())),
        "admitted": admitted,
        "promoted": promoted,
        "contradicted": contradicted,
        "context_only_hypotheses": context_only,
        "context_only_promoted": context_only_promoted,
        "guardrails": {
            "context_only_never_promoted": guardrail_ok,
        },
        "rates": {
            "admission": _rate(admitted, total),
            "promotion": _rate(promoted, total),
            "promotion_of_admitted": _rate(promoted, admitted),
            "contradiction": _rate(contradicted, total),
            "context_only": _rate(context_only, total),
        },
        "evidence_coverage": {
            "average_support_items": _average(support_total, total),
            "average_contradiction_items": _average(contradiction_total, total),
            "average_missing_items": _average(missing_total, total),
            "average_decisive_signals": _average(decisive_total, total),
            "average_independent_sources": _average(source_total, total),
            "with_decisive_signal": with_decisive,
            "with_missing_evidence": with_missing,
            "with_contradicting_evidence": with_contradiction,
        },
        "families": family_output,
        "family_count": len(family_output),
        "budget": budget,
        "routing": {
            "version": str(routing.get("version") or ""),
            "rule_version": str(routing.get("rule_version") or ""),
            "scope": routing_scope,
            "target": target or "",
            "surface_limit": int(routing.get("surface_limit") or 0),
            "surface_limit_scope": str(
                routing.get("surface_limit_scope") or "analysis"
            ),
            "active_requests": int(routing.get("active_requests") or 0),
            "eligible_input_records": int(
                selection.get("eligible_input_records") or 0
            ),
            "loaded_input_records": int(
                selection.get("loaded_input_records") or 0
            ),
            "input_coverage": (
                float(input_coverage)
                if input_coverage is not None
                else None
            ),
            "candidate_surfaces": int(
                selection.get("candidate_surfaces") or 0
            ),
            "selected_surfaces": int(
                selection.get("selected_surfaces") or 0
            ),
            "dropped_surfaces": int(
                selection.get("dropped_surfaces") or 0
            ),
            "surface_selection_coverage": (
                float(surface_coverage)
                if surface_coverage is not None
                else None
            ),
            "cap_reached": bool(selection.get("cap_reached")),
            "by_source": dict(selection.get("by_source") or {})
            if isinstance(selection.get("by_source"), Mapping)
            else {},
        },
        "diagnostic_only": True,
        "accuracy_claim": "none",
    }
    return result


def persist_raw_quality_snapshot(
    db: Any,
    analysis_id: str,
    target: str | None,
    metrics: Mapping[str, Any],
) -> None:
    """Persist a diagnostic snapshot without changing Analysis decisions."""

    db.execute(
        "INSERT INTO analysis_quality_snapshots(analysis_id,target,metrics_json,created_at) VALUES(?,?,?,?)",
        (analysis_id, target or "*", json_dumps(dict(metrics)), utc_now()),
    )

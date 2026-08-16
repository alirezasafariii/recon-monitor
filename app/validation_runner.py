from __future__ import annotations

"""Dry-run execution contracts for future validation work.

This module is intentionally non-executing. It consumes Evidence Completion
Planner output plus Validation Eligibility decisions, re-checks the canonical
eligibility gate at dry-run time, and emits reviewable contracts only for items
that remain eligible.

A contract is not a request recipe and is not execution permission. This module
never opens a socket, constructs an HTTP request, reserves/consumes budget,
loads credentials, switches identity, mutates a target, satisfies Admission, or
promotes a Candidate.
"""

from collections import Counter
import hashlib
from pathlib import Path
from typing import Any, Mapping

from core import atomic_write_text, json_dumps, utc_now
from validation_eligibility import snapshot_validation_eligibility

VALIDATION_RUNNER_VERSION = "0.1.0"
VALIDATION_RUNNER_RULE_VERSION = "2026.08.16.1"

RUNNER_STATUSES = {
    "dry_run_ready",
    "skipped_not_eligible",
    "blocked_recheck",
    "stale_eligibility",
    "invalid_contract",
}

DRY_RUN_LEVELS = {"passive_live", "controlled"}


def _safe_surface(plan: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = str(plan.get("endpoint") or "").strip()
    asset = str(plan.get("asset") or "").strip()
    raw = endpoint or asset
    kind = "endpoint" if endpoint else ("asset" if asset else "missing")

    # Never copy query strings or fragments into the dry-run contract. They can
    # contain session material, tokens, redirect destinations, or other values
    # that should not be propagated merely to describe a future validation step.
    display = raw
    if kind == "endpoint":
        positions = [pos for marker in ("?", "#") if (pos := raw.find(marker)) >= 0]
        if positions:
            display = raw[: min(positions)]

    return {
        "kind": kind,
        "present": bool(raw),
        "display": display,
        "query_and_fragment_redacted": bool(raw and display != raw),
    }


def _index_by_hypothesis(items: Any) -> tuple[dict[str, dict[str, Any]], set[str]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    if not isinstance(items, list):
        return indexed, duplicates
    for item in items:
        if not isinstance(item, Mapping):
            continue
        hypothesis_id = str(item.get("hypothesis_id") or "").strip()
        if not hypothesis_id:
            continue
        if hypothesis_id in indexed:
            duplicates.add(hypothesis_id)
            continue
        indexed[hypothesis_id] = dict(item)
    return indexed, duplicates


def _gate_projection(decision: Mapping[str, Any]) -> dict[str, Any]:
    scope = dict(decision.get("scope") or {})
    authorization = dict(decision.get("authorization") or {})
    context = dict(decision.get("context") or {})
    budget = dict(decision.get("budget") or {})
    return {
        "status": str(decision.get("status") or "ineligible"),
        "blocking_reasons": [str(value) for value in decision.get("blocking_reasons", [])],
        "scope": {
            "surface_present": bool(scope.get("surface_present")),
            "effective_in_scope": bool(scope.get("effective_in_scope")),
        },
        "authorization": {
            "required": bool(authorization.get("required")),
            "active_allowed": bool(authorization.get("active_allowed")),
            "missing_gates": [str(value) for value in authorization.get("missing_gates", [])],
        },
        "context": {
            "required_keys": [str(value) for value in context.get("required_keys", [])],
            "missing_keys": [str(value) for value in context.get("missing_keys", [])],
            "values_redacted": True,
        },
        "budget": {
            "required": bool(budget.get("required")),
            "blocked": bool(budget.get("blocked")),
            "blocking_reasons": [str(value) for value in budget.get("blocking_reasons", [])],
            "remaining": {
                str(key): int(value)
                for key, value in dict(budget.get("remaining") or {}).items()
            },
            "consumes_budget": False,
        },
    }


def _contract_id(
    ctx: Any,
    planner: Mapping[str, Any],
    plan: Mapping[str, Any],
    recheck: Mapping[str, Any],
) -> str:
    material = {
        "run_id": str(ctx.run_id),
        "analysis_id": str(planner.get("analysis_id") or ""),
        "target": str(ctx.policy.name),
        "hypothesis_id": str(plan.get("hypothesis_id") or ""),
        "family": str(plan.get("family") or ""),
        "validation_level": str(plan.get("validation_level") or ""),
        "planning_phase": str(plan.get("planning_phase") or ""),
        "surface": _safe_surface(plan),
        "eligibility_rule_version": str(recheck.get("rule_version") or ""),
        "runner_rule_version": VALIDATION_RUNNER_RULE_VERSION,
    }
    digest = hashlib.sha256(json_dumps(material).encode("utf-8")).hexdigest()
    return f"VDR-{digest[:24]}"


def _dry_run_contract(
    ctx: Any,
    planner: Mapping[str, Any],
    plan: Mapping[str, Any],
    fresh_decision: Mapping[str, Any],
    recheck: Mapping[str, Any],
) -> dict[str, Any]:
    level = str(plan.get("validation_level") or "")
    operation_class = (
        "passive_live_observation_review"
        if level == "passive_live"
        else "controlled_validation_review"
    )
    return {
        "contract_id": _contract_id(ctx, planner, plan, recheck),
        "contract_version": VALIDATION_RUNNER_VERSION,
        "mode": "dry_run_only",
        "run_id": str(ctx.run_id),
        "analysis_id": str(planner.get("analysis_id") or ""),
        "target": str(ctx.policy.name),
        "hypothesis_id": str(plan.get("hypothesis_id") or ""),
        "family": str(plan.get("family") or ""),
        "planning_phase": str(plan.get("planning_phase") or "promotion"),
        "validation_level": level,
        "recommended_action": str(plan.get("recommended_action") or ""),
        "operation_class": operation_class,
        "surface": _safe_surface(plan),
        "preconditions": _gate_projection(fresh_decision),
        "human_approval_required": True,
        "future_execution_requires_fresh_gate_check": True,
        "future_execution_requires_separate_executor": True,
        "runner_consideration_only": True,
        "request_recipe": None,
        "network_request": None,
        "payload": None,
        "credentials": None,
        "identity_switch": None,
        "transport": None,
        "budget_reservation": None,
        "network_requests_planned": 0,
        "network_requests_executed": 0,
        "budget_consumed": False,
        "side_effects_allowed": False,
        "execution_enabled": False,
        "automatic_execution_allowed": False,
        "safe_to_execute_automatically": False,
        "executes_validation": False,
        "dry_run": True,
    }


def snapshot_validation_runner_dry_run(
    ctx: Any,
    *,
    evidence_completion_plan: Mapping[str, Any] | None = None,
    validation_eligibility: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Emit non-executing contracts for items that remain eligible after re-check."""

    planner = dict(evidence_completion_plan or {})
    eligibility = dict(validation_eligibility or {})

    # Re-evaluate the canonical gate instead of trusting a potentially stale
    # eligibility snapshot. Persist=False ensures this review does not overwrite
    # the Gate's own diagnostic artifact.
    recheck = snapshot_validation_eligibility(
        ctx,
        evidence_completion_plan=planner,
        persist=False,
    )

    plans, duplicate_plans = _index_by_hypothesis(planner.get("plans", []))
    input_decisions, duplicate_input = _index_by_hypothesis(eligibility.get("decisions", []))
    fresh_decisions, duplicate_fresh = _index_by_hypothesis(recheck.get("decisions", []))

    items: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []

    # Preserve Gate ordering so reviewer output remains deterministic.
    raw_input = eligibility.get("decisions", [])
    if not isinstance(raw_input, list):
        raw_input = []

    for raw in raw_input:
        if not isinstance(raw, Mapping):
            continue
        input_decision = dict(raw)
        hypothesis_id = str(input_decision.get("hypothesis_id") or "").strip()
        input_status = str(input_decision.get("status") or "ineligible")
        row: dict[str, Any] = {
            "hypothesis_id": hypothesis_id,
            "family": str(input_decision.get("family") or ""),
            "validation_level": str(input_decision.get("validation_level") or ""),
            "input_eligibility_status": input_status,
            "current_eligibility_status": "unknown",
            "status": "invalid_contract",
            "blocking_reasons": [],
            "contract_id": None,
            "executes_validation": False,
            "network_requests_executed": 0,
            "budget_consumed": False,
        }

        if not hypothesis_id:
            row["blocking_reasons"].append("missing_hypothesis_id")
            items.append(row)
            continue
        if hypothesis_id in duplicate_plans or hypothesis_id in duplicate_input or hypothesis_id in duplicate_fresh:
            row["blocking_reasons"].append("duplicate_hypothesis_id")
            items.append(row)
            continue

        plan = plans.get(hypothesis_id)
        fresh = fresh_decisions.get(hypothesis_id)
        if plan is None:
            row["blocking_reasons"].append("planner_item_missing")
            items.append(row)
            continue
        if fresh is None:
            row["status"] = "blocked_recheck"
            row["blocking_reasons"].append("fresh_eligibility_decision_missing")
            items.append(row)
            continue

        fresh_status = str(fresh.get("status") or "ineligible")
        row["current_eligibility_status"] = fresh_status

        if input_status != "eligible":
            row["status"] = "skipped_not_eligible"
            row["blocking_reasons"].append(f"input_gate:{input_status}")
            items.append(row)
            continue

        plan_family = str(plan.get("family") or "")
        plan_level = str(plan.get("validation_level") or "")
        if (
            str(input_decision.get("family") or "") != plan_family
            or str(input_decision.get("validation_level") or "") != plan_level
        ):
            row["status"] = "stale_eligibility"
            row["blocking_reasons"].append("planner_and_input_gate_contract_mismatch")
            items.append(row)
            continue

        if fresh_status != "eligible":
            row["status"] = "blocked_recheck"
            row["blocking_reasons"].extend(
                [f"fresh_gate:{fresh_status}"]
                + [str(value) for value in fresh.get("blocking_reasons", [])]
            )
            items.append(row)
            continue

        if (
            str(fresh.get("family") or "") != plan_family
            or str(fresh.get("validation_level") or "") != plan_level
        ):
            row["status"] = "stale_eligibility"
            row["blocking_reasons"].append("planner_and_fresh_gate_contract_mismatch")
            items.append(row)
            continue

        if plan_level not in DRY_RUN_LEVELS:
            row["status"] = "invalid_contract"
            row["blocking_reasons"].append("unsupported_dry_run_validation_level")
            items.append(row)
            continue
        if not bool(plan.get("live_target_interaction_required")):
            row["status"] = "invalid_contract"
            row["blocking_reasons"].append("live_target_interaction_not_requested")
            items.append(row)
            continue

        contract = _dry_run_contract(ctx, planner, plan, fresh, recheck)
        contracts.append(contract)
        row["status"] = "dry_run_ready"
        row["contract_id"] = contract["contract_id"]
        items.append(row)

    counts = Counter(str(item.get("status") or "invalid_contract") for item in items)
    result: dict[str, Any] = {
        "version": VALIDATION_RUNNER_VERSION,
        "rule_version": VALIDATION_RUNNER_RULE_VERSION,
        "generated_at": utc_now(),
        "run_id": str(ctx.run_id),
        "analysis_id": str(planner.get("analysis_id") or ""),
        "target": str(ctx.policy.name),
        "planner_version": str(planner.get("version") or "unknown"),
        "input_eligibility_version": str(eligibility.get("version") or "unknown"),
        "input_eligibility_rule_version": str(eligibility.get("rule_version") or "unknown"),
        "recheck_eligibility_version": str(recheck.get("version") or "unknown"),
        "recheck_eligibility_rule_version": str(recheck.get("rule_version") or "unknown"),
        "item_count": len(items),
        "contract_count": len(contracts),
        "status_counts": {
            status: int(counts.get(status, 0))
            for status in sorted(RUNNER_STATUSES)
        },
        "items": items,
        "contracts": contracts,
        "mode": "dry_run_only",
        "human_approval_required": True,
        "execution_enabled": False,
        "automatic_execution_allowed": False,
        "safe_to_execute_automatically": False,
        "executes_validation": False,
        "network_requests_planned": 0,
        "network_requests_executed": 0,
        "budget_reserved": False,
        "budget_consumed": False,
        "loads_credentials": False,
        "switches_identity": False,
        "mutates_target": False,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "numeric_score": None,
        "safety_semantics": (
            "Dry-run contracts are review artifacts only. A ready contract does not authorize "
            "or perform validation and intentionally contains no request recipe, payload, "
            "credential material, transport object, identity switch, or budget reservation."
        ),
    }

    if persist:
        output = Path(ctx.run_dir) / "validation-runner-dry-run.json"
        atomic_write_text(output, json_dumps(result, pretty=True) + "\n")
        result["output"] = str(output)

    return result

from __future__ import annotations

"""Fail-closed eligibility decisions for future evidence validation.

This module sits after Evidence Completion Planner and answers a narrower
question: if a plan asks for live or controlled evidence collection, are the
existing Recon Monitor safety preconditions currently satisfied?

It never executes a request, builds a payload, loads credentials, satisfies
Admission, or promotes a Candidate.  An ``eligible`` decision only means a
future Runner may consider the plan after its own safety review.
"""

from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from core import atomic_write_text, json_dumps, utc_now

VALIDATION_ELIGIBILITY_VERSION = "1.0.0"
VALIDATION_ELIGIBILITY_RULE_VERSION = "2026.08.16.1"

ELIGIBILITY_STATUSES = {
    "eligible",
    "ineligible",
    "manual_only",
    "authorization_missing",
    "context_missing",
    "outside_scope",
    "budget_blocked",
}

LIVE_GAP_TYPES = {
    "behavioral_validation_needed",
    "controlled_validation_needed",
}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(str(value).strip())


def _configured_context_keys(ctx: Any) -> set[str]:
    raw = getattr(ctx.policy, "active", {}).get("validation_context", {})
    if not isinstance(raw, Mapping):
        return set()
    return {
        str(key).strip()
        for key, value in raw.items()
        if str(key).strip() and _truthy(value)
    }


def _surface_scope(ctx: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = str(plan.get("endpoint") or "").strip()
    asset = str(plan.get("asset") or "").strip()

    endpoint_in_scope: bool | None = None
    asset_in_scope: bool | None = None

    if endpoint:
        endpoint_in_scope = bool(ctx.policy.url_in_scope(endpoint))
    if asset:
        if asset.lower().startswith(("http://", "https://")):
            asset_in_scope = bool(ctx.policy.url_in_scope(asset))
        else:
            asset_in_scope = bool(ctx.policy.host_in_scope(asset))

    if endpoint:
        effective_in_scope = endpoint_in_scope is True
    elif asset:
        effective_in_scope = asset_in_scope is True
    else:
        effective_in_scope = False

    return {
        "surface_present": bool(endpoint or asset),
        "endpoint_present": bool(endpoint),
        "asset_present": bool(asset),
        "endpoint_in_scope": endpoint_in_scope,
        "asset_in_scope": asset_in_scope,
        "effective_in_scope": effective_in_scope,
        "scope_policy": "explicit endpoint wins; otherwise asset scope is used",
    }


def _authorization_state(ctx: Any, required: bool) -> dict[str, Any]:
    config_authorized = bool(getattr(ctx.config, "authorized", False))
    active_globally_enabled = bool(
        getattr(ctx.config, "active_globally_enabled", False)
    )
    cli_allow_active = bool(getattr(ctx, "allow_active", False))
    target_active_confirmation = bool(getattr(ctx.policy, "active_confirmed", False))

    active_allowed = False
    try:
        active_allowed = bool(ctx.policy.active_allowed(ctx.config, cli_allow_active))
    except Exception:
        active_allowed = (
            config_authorized
            and active_globally_enabled
            and cli_allow_active
            and target_active_confirmation
        )

    missing: list[str] = []
    if required:
        if not config_authorized:
            missing.append("I_HAVE_AUTHORIZATION")
        if not active_globally_enabled:
            missing.append("ENABLE_ACTIVE_MODULES")
        if not cli_allow_active:
            missing.append("cli_allow_active")
        if not target_active_confirmation:
            missing.append("target_active_confirmation")

    return {
        "required": required,
        "config_authorized": config_authorized,
        "active_globally_enabled": active_globally_enabled,
        "cli_allow_active": cli_allow_active,
        "target_active_confirmation": target_active_confirmation,
        "active_allowed": active_allowed if required else False,
        "missing_gates": missing,
    }


def _context_state(
    ctx: Any,
    plan: Mapping[str, Any],
    scope: Mapping[str, Any],
) -> dict[str, Any]:
    required_keys = sorted(
        {
            str(item.get("key") or "").strip()
            for item in plan.get("case_requirements", [])
            if isinstance(item, Mapping) and str(item.get("key") or "").strip()
        }
    )
    configured_keys = _configured_context_keys(ctx)
    inferred_keys: set[str] = set()

    if scope.get("surface_present") and scope.get("effective_in_scope"):
        inferred_keys.add("endpoint")
    if plan.get("source_groups") or int(plan.get("independent_sources") or 0) > 0:
        inferred_keys.add("evidence")

    available_keys = configured_keys | inferred_keys
    missing_keys = sorted(set(required_keys) - available_keys)

    return {
        "required_keys": required_keys,
        "configured_keys": sorted(configured_keys),
        "inferred_keys": sorted(inferred_keys),
        "available_keys": sorted(available_keys),
        "missing_keys": missing_keys,
        "values_redacted": True,
        "configuration_source": "policy.active.validation_context",
    }


def _budget_snapshot(ctx: Any) -> dict[str, dict[str, int]]:
    budget = getattr(ctx, "budget", None)
    if budget is not None and hasattr(budget, "snapshot"):
        try:
            snapshot = budget.snapshot()
            if isinstance(snapshot, Mapping):
                return {
                    str(metric): {
                        "used": int(dict(values).get("used") or 0),
                        "limit": int(dict(values).get("limit") or 0),
                    }
                    for metric, values in snapshot.items()
                    if isinstance(values, Mapping)
                }
        except Exception:
            pass

    db = getattr(ctx, "db", None)
    if db is None:
        return {}
    try:
        rows = db.all(
            "SELECT metric,used,limit_value FROM run_budgets "
            "WHERE run_id=? AND target=? ORDER BY metric",
            (str(ctx.run_id), str(ctx.policy.name)),
        )
    except Exception:
        return {}
    return {
        str(row["metric"]): {
            "used": int(row["used"]),
            "limit": int(row["limit_value"]),
        }
        for row in rows
    }


def _budget_state(ctx: Any, required: bool) -> dict[str, Any]:
    required_metrics = ["http_requests"] if required else []
    snapshot = _budget_snapshot(ctx)
    blockers: list[str] = []

    runtime_ok = True
    if required:
        budget = getattr(ctx, "budget", None)
        if budget is not None and hasattr(budget, "check_runtime"):
            try:
                budget.check_runtime()
            except Exception as exc:
                runtime_ok = False
                blockers.append(f"runtime:{type(exc).__name__}")

        for metric in required_metrics:
            row = snapshot.get(metric)
            if row is None:
                blockers.append(f"{metric}:unavailable")
                continue
            limit_value = int(row.get("limit") or 0)
            used = int(row.get("used") or 0)
            if limit_value <= 0:
                blockers.append(f"{metric}:unavailable")
            elif used >= limit_value:
                blockers.append(f"{metric}:exhausted")

    remaining = {
        metric: max(0, int(values.get("limit") or 0) - int(values.get("used") or 0))
        for metric, values in snapshot.items()
    }
    return {
        "required": required,
        "required_metrics": required_metrics,
        "snapshot": snapshot,
        "remaining": remaining,
        "runtime_ok": runtime_ok,
        "blocked": bool(blockers),
        "blocking_reasons": blockers,
        "consumes_budget": False,
    }


def _decision(ctx: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    gap_type = str(plan.get("gap_type") or "no_further_safe_action")
    validation_level = str(plan.get("validation_level") or "offline")
    live_required = bool(plan.get("live_target_interaction_required")) or gap_type in LIVE_GAP_TYPES

    scope = _surface_scope(ctx, plan)
    authorization = _authorization_state(ctx, live_required)
    context = _context_state(ctx, plan, scope)
    budget = _budget_state(ctx, live_required)

    blocking_reasons: list[str] = []

    if validation_level == "manual_only":
        status = "manual_only"
        blocking_reasons.append("canonical_validation_level_manual_only")
    elif not live_required:
        status = "ineligible"
        blocking_reasons.append("plan_does_not_request_live_validation")
    elif not scope["surface_present"]:
        status = "context_missing"
        blocking_reasons.append("validation_surface_missing")
    elif not scope["effective_in_scope"]:
        status = "outside_scope"
        blocking_reasons.append("validation_surface_outside_target_policy")
    elif not authorization["active_allowed"]:
        status = "authorization_missing"
        blocking_reasons.extend(
            f"authorization:{gate}" for gate in authorization["missing_gates"]
        )
    elif context["missing_keys"]:
        status = "context_missing"
        blocking_reasons.extend(
            f"context:{key}" for key in context["missing_keys"]
        )
    elif budget["blocked"]:
        status = "budget_blocked"
        blocking_reasons.extend(
            f"budget:{reason}" for reason in budget["blocking_reasons"]
        )
    else:
        status = "eligible"

    return {
        "hypothesis_id": str(plan.get("hypothesis_id") or ""),
        "family": str(plan.get("family") or ""),
        "planning_phase": str(plan.get("planning_phase") or "promotion"),
        "gap_type": gap_type,
        "validation_level": validation_level,
        "recommended_action": str(plan.get("recommended_action") or ""),
        "status": status,
        "eligible_for_runner_consideration": status == "eligible",
        "blocking_reasons": blocking_reasons,
        "scope": scope,
        "authorization": authorization,
        "context": context,
        "budget": budget,
        "automatic_execution_allowed": False,
        "safe_to_execute_automatically": False,
        "executor_enabled": False,
        "execution_payload": None,
        "executes_validation": False,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
    }


def snapshot_validation_eligibility(
    ctx: Any,
    *,
    evidence_completion_plan: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Classify whether each Planner item is eligible for future Runner review."""

    planner = dict(evidence_completion_plan or {})
    decisions = [
        _decision(ctx, dict(plan))
        for plan in planner.get("plans", [])
        if isinstance(plan, Mapping)
    ]
    counts = Counter(str(item.get("status") or "ineligible") for item in decisions)

    result: dict[str, Any] = {
        "version": VALIDATION_ELIGIBILITY_VERSION,
        "rule_version": VALIDATION_ELIGIBILITY_RULE_VERSION,
        "generated_at": utc_now(),
        "run_id": str(ctx.run_id),
        "analysis_id": str(planner.get("analysis_id") or ""),
        "target": str(ctx.policy.name),
        "planner_version": str(planner.get("version") or "unknown"),
        "decision_count": len(decisions),
        "status_counts": {
            status: int(counts.get(status, 0))
            for status in sorted(ELIGIBILITY_STATUSES)
        },
        "decisions": decisions,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "executes_validation": False,
        "automatic_execution_allowed": False,
        "numeric_score": None,
        "safety_semantics": (
            "Eligibility is a fail-closed advisory gate for a future Runner. Eligible does "
            "not authorize execution: this module creates no request, payload, callback, "
            "credential operation, role switch, object mutation, or target-side action."
        ),
        "context_semantics": (
            "Sensitive validation-context values are never serialized. Only requirement "
            "keys and presence/absence are recorded. Explicit context may be declared under "
            "policy.active.validation_context; endpoint/evidence presence may be inferred "
            "from the hypothesis plan."
        ),
    }

    if persist:
        output = Path(ctx.run_dir) / "validation-eligibility.json"
        result["output"] = str(output)
        atomic_write_text(output, json_dumps(result, pretty=True) + "\n")
    return result

from __future__ import annotations

"""Safety-aware next-evidence planner for incomplete vulnerability hypotheses.

The planner converts missing-evidence gaps into bounded next-step guidance. It
never performs live requests, never creates supporting evidence by itself, and
never changes admission. Controlled recommendations can now point to the
offline controlled-evidence executor, which compares explicitly authorized,
test-owned stored captures without credential storage or network execution.
"""

import json
from collections import Counter
from typing import Any, Iterable, Mapping

from core import Database
from family_reasoning import validation_level_for_family


EVIDENCE_PLANNER_VERSION = "1.2.0"
EVIDENCE_PLANNER_RULE_VERSION = "2026.08.14.3"
MAX_HYPOTHESES = 500
MAX_STEPS_PER_HYPOTHESIS = 3


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _family_validation_level(family: str) -> str:
    try:
        return validation_level_for_family(str(family or ""))
    except Exception:
        return "offline"


def _step_for_gap(gap: str, family: str, validation_level: str) -> dict[str, Any]:
    del family
    lower = str(gap or "").lower()
    if any(token in lower for token in (
        "another explicitly authorized", "another authorized", "ownership",
        "tenant boundary", "role boundary", "lower-privileged", "controlled test",
        "test identity", "test object",
    )):
        return {
            "kind": "controlled_comparison",
            "level": "controlled",
            "automatic": False,
            "requires_explicit_test_identity_or_resource": True,
            "execution_contract": "explicit_authorized_stored_capture_pair",
            "executor": "controlled_evidence_executor",
            "live_request_execution": False,
            "credentials_stored": False,
            "imported_or_test_capture_required": True,
            "purpose": gap,
        }
    if any(token in lower for token in (
        "runtime", "browser", "execution", "concurrent", "race", "side effect",
        "state transition", "workflow invariant", "filesystem",
        "server performs the request",
    )):
        return {
            "kind": "manual_validation",
            "level": "manual_only",
            "automatic": False,
            "requires_analyst_control": True,
            "controlled_capture_comparison_available_after_safe_manual_capture": True,
            "purpose": gap,
        }
    if any(token in lower for token in (
        "header", "cors", "redirect", "location", "cache", "anonymous",
        "authentication", "status", "response", "reachability", "public",
    )):
        level = "passive_live" if validation_level == "passive_live" else "offline"
        return {
            "kind": "bounded_passive_observation" if level == "passive_live" else "offline_review",
            "level": level,
            "automatic": False,
            "safe_methods": ["HEAD", "GET", "OPTIONS"] if level == "passive_live" else [],
            "redirects_followed": False,
            "credentials_used": False,
            "purpose": gap,
        }
    return {
        "kind": "offline_review",
        "level": "offline",
        "automatic": False,
        "purpose": gap,
    }


def plan_result_evidence(family: str, missing: Iterable[Any]) -> dict[str, Any]:
    """Build a compact plan that can be embedded in one analyzer result.

    The plan is explanatory metadata only. It does not execute, create evidence,
    or alter the analyzer's support/contradiction/admission fields.
    """

    validation_level = _family_validation_level(family)
    gaps = [str(value) for value in missing if str(value).strip()]
    steps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for gap in gaps:
        step = _step_for_gap(gap, family, validation_level)
        identity = (str(step.get("kind") or ""), str(step.get("purpose") or ""))
        if identity in seen:
            continue
        seen.add(identity)
        steps.append(step)
        if len(steps) >= MAX_STEPS_PER_HYPOTHESIS:
            break
    if not steps:
        steps = [{
            "kind": "offline_review",
            "level": "offline",
            "automatic": False,
            "purpose": "Review supporting and contradicting stored target evidence before any active validation.",
        }]
    rank = {"offline": 0, "passive_live": 1, "controlled": 2, "manual_only": 3}
    highest = max(
        (str(step.get("level") or "offline") for step in steps),
        key=lambda value: rank.get(value, 0),
        default="offline",
    )
    return {
        "version": EVIDENCE_PLANNER_VERSION,
        "rule_version": EVIDENCE_PLANNER_RULE_VERSION,
        "family": str(family or ""),
        "family_validation_level": validation_level,
        "minimum_next_step_level": highest,
        "steps": steps,
        "diagnostic_only": True,
        "network_requests": False,
        "creates_target_evidence": False,
        "changes_admission": False,
        "controlled_executor_available": any(
            str(step.get("executor") or "") == "controlled_evidence_executor"
            for step in steps
        ),
    }


def plan_hypothesis_evidence(
    db: Database,
    analysis_id: str,
    *,
    target: str | None = None,
) -> dict[str, Any]:
    params: list[Any] = [analysis_id]
    target_sql = ""
    if target:
        target_sql = " AND target=?"
        params.append(target)
    try:
        rows = [
            dict(row)
            for row in db.all(
                "SELECT hypothesis_id,target,endpoint,bug_family,state,missing_evidence_json,admission_json "
                "FROM analysis_hypotheses WHERE analysis_id=? AND state<>'promoted'"
                + target_sql
                + " ORDER BY hypothesis_id LIMIT ?",
                (*params, MAX_HYPOTHESES),
            )
        ]
    except Exception as exc:
        return {
            "version": EVIDENCE_PLANNER_VERSION,
            "rule_version": EVIDENCE_PLANNER_RULE_VERSION,
            "status": "degraded",
            "error_type": type(exc).__name__,
            "planned_hypotheses": 0,
            "plans": [],
            "diagnostic_only": True,
        }

    plans: list[dict[str, Any]] = []
    counts = Counter()
    for row in rows:
        family = str(row.get("bug_family") or "")
        missing = [
            str(value)
            for value in _loads(row.get("missing_evidence_json"), [])
            if str(value).strip()
        ]
        admission = _loads(row.get("admission_json"), {})
        if not isinstance(admission, Mapping):
            admission = {}
        compact = plan_result_evidence(family, missing)
        for step in compact["steps"]:
            counts[str(step.get("kind") or "unknown")] += 1
        plans.append({
            "hypothesis_id": str(row.get("hypothesis_id") or ""),
            "target": str(row.get("target") or ""),
            "endpoint": str(row.get("endpoint") or ""),
            "family": family,
            "state": str(row.get("state") or ""),
            "family_validation_level": compact["family_validation_level"],
            "minimum_next_step_level": compact["minimum_next_step_level"],
            "controlled_executor_available": compact["controlled_executor_available"],
            "admitted": bool(admission.get("admitted")),
            "steps": compact["steps"],
        })

    return {
        "version": EVIDENCE_PLANNER_VERSION,
        "rule_version": EVIDENCE_PLANNER_RULE_VERSION,
        "status": "ready",
        "considered_hypotheses": len(rows),
        "planned_hypotheses": len(plans),
        "plan_kind_counts": dict(counts),
        "plans": plans,
        "safety": {
            "network_requests": False,
            "creates_target_evidence": False,
            "changes_admission": False,
            "controlled_steps_require_explicit_test_identity_or_resource": True,
            "controlled_executor_uses_stored_capture_pairs_only": True,
            "controlled_executor_stores_no_credentials": True,
            "manual_only_steps_never_auto_execute": True,
            "passive_live_execution_remains_scope_and_approval_gated": True,
        },
    }


__all__ = [
    "EVIDENCE_PLANNER_VERSION",
    "EVIDENCE_PLANNER_RULE_VERSION",
    "plan_result_evidence",
    "plan_hypothesis_evidence",
]

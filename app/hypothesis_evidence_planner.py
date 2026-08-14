from __future__ import annotations

"""Safety-aware next-evidence planner for incomplete vulnerability hypotheses.

The planner converts missing-evidence gaps into bounded next-step guidance.  It
never performs requests, never creates supporting evidence, and never changes
admission.  Automatic execution remains restricted to the existing Safe
Validation engine and its scope/approval rules.
"""

import json
from collections import Counter
from typing import Any, Mapping

from core import Database
from family_reasoning import validation_level_for_family

EVIDENCE_PLANNER_VERSION = "1.0.0"
EVIDENCE_PLANNER_RULE_VERSION = "2026.08.14.1"
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


def _step_for_gap(gap: str, family: str, validation_level: str) -> dict[str, Any]:
    lower = str(gap or "").lower()
    if any(token in lower for token in ("another explicitly authorized", "another authorized", "ownership", "tenant boundary", "role boundary", "lower-privileged", "controlled test", "test identity", "test object")):
        return {
            "kind": "controlled_comparison",
            "level": "controlled",
            "automatic": False,
            "requires_explicit_test_identity_or_resource": True,
            "purpose": gap,
        }
    if any(token in lower for token in ("runtime", "browser", "execution", "concurrent", "race", "side effect", "state transition", "workflow invariant", "filesystem", "server performs the request")):
        return {
            "kind": "manual_validation",
            "level": "manual_only",
            "automatic": False,
            "requires_analyst_control": True,
            "purpose": gap,
        }
    if any(token in lower for token in ("header", "cors", "redirect", "location", "cache", "anonymous", "authentication", "status", "response", "reachability", "public")):
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
        try:
            validation_level = validation_level_for_family(family)
        except Exception:
            validation_level = "offline"
        missing = [
            str(value)
            for value in _loads(row.get("missing_evidence_json"), [])
            if str(value).strip()
        ]
        admission = _loads(row.get("admission_json"), {})
        if not isinstance(admission, Mapping):
            admission = {}
        steps: list[dict[str, Any]] = []
        seen_kinds: set[tuple[str, str]] = set()
        for gap in missing:
            step = _step_for_gap(gap, family, validation_level)
            key = (str(step.get("kind") or ""), str(step.get("purpose") or ""))
            if key in seen_kinds:
                continue
            seen_kinds.add(key)
            steps.append(step)
            if len(steps) >= MAX_STEPS_PER_HYPOTHESIS:
                break
        if not steps:
            steps = [
                {
                    "kind": "offline_review",
                    "level": "offline",
                    "automatic": False,
                    "purpose": "Review supporting and contradicting stored target evidence before any active validation.",
                }
            ]
        highest = "offline"
        rank = {"offline": 0, "passive_live": 1, "controlled": 2, "manual_only": 3}
        for step in steps:
            level = str(step.get("level") or "offline")
            if rank.get(level, 0) > rank.get(highest, 0):
                highest = level
            counts[str(step.get("kind") or "unknown")] += 1
        plans.append(
            {
                "hypothesis_id": str(row.get("hypothesis_id") or ""),
                "target": str(row.get("target") or ""),
                "endpoint": str(row.get("endpoint") or ""),
                "family": family,
                "state": str(row.get("state") or ""),
                "family_validation_level": validation_level,
                "minimum_next_step_level": highest,
                "admitted": bool(admission.get("admitted")),
                "steps": steps,
            }
        )

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
            "manual_only_steps_never_auto_execute": True,
            "passive_live_execution_remains_scope_and_approval_gated": True,
        },
    }


__all__ = [
    "EVIDENCE_PLANNER_VERSION",
    "EVIDENCE_PLANNER_RULE_VERSION",
    "plan_hypothesis_evidence",
]

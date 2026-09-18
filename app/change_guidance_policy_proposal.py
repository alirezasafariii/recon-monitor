from __future__ import annotations

"""Versioned, audited policy-change proposals derived from P11 review packets.

This module creates non-executable proposal records only. It intentionally has
no apply function and never mutates Meta Ranker weights, calibration/drift
thresholds, Queue score, Investigation Workflow ordering, evidence, Admission,
or validation behavior.
"""

import hashlib
from typing import Any, Mapping, Sequence

from change_guidance_calibration import _MIN_FEEDBACK_PER_SIGNAL
from change_guidance_drift import (
    DEFAULT_WINDOW_DAYS,
    MIN_FEEDBACK_PER_WINDOW,
    MIN_SLICE_FEEDBACK,
)
from change_guidance_review_packet import change_guidance_review_packets
from core import Database, ReconError, json_dumps, safe_json_loads, utc_now
from meta_ranker import DEFAULT_WEIGHTS, META_RANKER_RULE_VERSION, META_RANKER_VERSION


CHANGE_GUIDANCE_POLICY_PROPOSAL_VERSION = "1.0.0"
CHANGE_GUIDANCE_POLICY_PROPOSAL_RULE_VERSION = "2026.09.18.1"
CHANGE_GUIDANCE_POLICY_PROPOSAL_SCHEMA_VERSION = 1

_ALLOWED_STATES = {
    "draft",
    "under_review",
    "accepted_for_separate_implementation",
    "rejected",
    "superseded",
}
_TERMINAL_STATES = {
    "accepted_for_separate_implementation",
    "rejected",
    "superseded",
}

_POLICY_SURFACES = {
    "meta_ranker.derived_change_weight",
    "change_guidance.calibration_sample_gate",
    "change_guidance.drift_window_and_sample_gate",
}


def ensure_change_guidance_policy_proposal_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS change_guidance_policy_proposals (
          proposal_version_id TEXT PRIMARY KEY,
          proposal_key TEXT NOT NULL,
          proposal_version INTEGER NOT NULL,
          source_packet_id TEXT NOT NULL,
          target TEXT NOT NULL DEFAULT '',
          signal_type TEXT NOT NULL,
          proposal_direction TEXT NOT NULL,
          policy_surface TEXT NOT NULL,
          state TEXT NOT NULL,
          before_json TEXT NOT NULL,
          after_json TEXT NOT NULL,
          diff_json TEXT NOT NULL,
          rationale TEXT NOT NULL,
          rollback_plan TEXT NOT NULL,
          test_requirements_json TEXT NOT NULL,
          source_packet_json TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          created_by TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          decision_by TEXT NOT NULL DEFAULT '',
          decision_at TEXT NOT NULL DEFAULT '',
          decision_note TEXT NOT NULL DEFAULT '',
          UNIQUE(proposal_key, proposal_version)
        )
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_change_guidance_policy_proposals_target "
        "ON change_guidance_policy_proposals(target,updated_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_change_guidance_policy_proposals_packet "
        "ON change_guidance_policy_proposals(source_packet_id,policy_surface,proposal_version)"
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('change_guidance_policy_proposal_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(CHANGE_GUIDANCE_POLICY_PROPOSAL_SCHEMA_VERSION),),
    )


def supported_policy_surfaces() -> list[str]:
    return sorted(_POLICY_SURFACES)


def current_policy_snapshot(policy_surface: str) -> dict[str, Any]:
    surface = str(policy_surface or "").strip()
    if surface == "meta_ranker.derived_change_weight":
        return {
            "policy_surface": surface,
            "meta_ranker_version": META_RANKER_VERSION,
            "meta_ranker_rule_version": META_RANKER_RULE_VERSION,
            "derived_change_weight": float(DEFAULT_WEIGHTS["derived_change"]),
        }
    if surface == "change_guidance.calibration_sample_gate":
        return {
            "policy_surface": surface,
            "minimum_feedback_per_signal": int(_MIN_FEEDBACK_PER_SIGNAL),
        }
    if surface == "change_guidance.drift_window_and_sample_gate":
        return {
            "policy_surface": surface,
            "window_days": int(DEFAULT_WINDOW_DAYS),
            "minimum_feedback_per_window": int(MIN_FEEDBACK_PER_WINDOW),
            "minimum_feedback_per_slice": int(MIN_SLICE_FEEDBACK),
        }
    raise ReconError(f"Unsupported policy surface: {surface}")


def _clean_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconError(f"{label} must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _bounded_int(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ReconError(f"{label} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ReconError(f"{label} must be between {minimum} and {maximum}")
    return parsed


def _bounded_float(value: Any, *, label: str, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ReconError(f"{label} must be numeric") from exc
    if parsed < minimum or parsed > maximum:
        raise ReconError(f"{label} must be between {minimum} and {maximum}")
    return round(parsed, 6)


def _validate_after(policy_surface: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    after = _clean_mapping(raw, label="Candidate after state")
    surface = str(policy_surface or "").strip()
    if surface == "meta_ranker.derived_change_weight":
        allowed = {"derived_change_weight"}
        if set(after) != allowed:
            raise ReconError(
                "Derived-change weight proposal must contain only derived_change_weight"
            )
        return {
            "derived_change_weight": _bounded_float(
                after["derived_change_weight"],
                label="derived_change_weight",
                minimum=0.0,
                maximum=0.50,
            )
        }
    if surface == "change_guidance.calibration_sample_gate":
        allowed = {"minimum_feedback_per_signal"}
        if set(after) != allowed:
            raise ReconError(
                "Calibration sample-gate proposal must contain only minimum_feedback_per_signal"
            )
        return {
            "minimum_feedback_per_signal": _bounded_int(
                after["minimum_feedback_per_signal"],
                label="minimum_feedback_per_signal",
                minimum=3,
                maximum=100,
            )
        }
    if surface == "change_guidance.drift_window_and_sample_gate":
        allowed = {
            "window_days",
            "minimum_feedback_per_window",
            "minimum_feedback_per_slice",
        }
        if set(after) != allowed:
            raise ReconError(
                "Drift proposal must contain window_days, minimum_feedback_per_window, "
                "and minimum_feedback_per_slice"
            )
        return {
            "window_days": _bounded_int(
                after["window_days"],
                label="window_days",
                minimum=7,
                maximum=180,
            ),
            "minimum_feedback_per_window": _bounded_int(
                after["minimum_feedback_per_window"],
                label="minimum_feedback_per_window",
                minimum=3,
                maximum=100,
            ),
            "minimum_feedback_per_slice": _bounded_int(
                after["minimum_feedback_per_slice"],
                label="minimum_feedback_per_slice",
                minimum=2,
                maximum=50,
            ),
        }
    raise ReconError(f"Unsupported policy surface: {surface}")


def _policy_values(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in snapshot.items()
        if str(key) not in {
            "policy_surface",
            "meta_ranker_version",
            "meta_ranker_rule_version",
        }
    }


def _diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[dict[str, Any]]:
    before_values = _policy_values(before)
    keys = sorted(set(before_values) | set(after))
    rows: list[dict[str, Any]] = []
    for key in keys:
        old = before_values.get(key)
        new = after.get(key)
        if old == new:
            continue
        rows.append({"field": key, "before": old, "after": new})
    return rows


def _clean_text(value: Any, *, label: str, maximum: int = 4000) -> str:
    text = str(value or "").strip()
    if not text:
        raise ReconError(f"{label} is required")
    return text[:maximum]


def _clean_tests(values: Sequence[Any]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if text not in cleaned:
            cleaned.append(text[:1000])
        if len(cleaned) >= 20:
            break
    if not cleaned:
        raise ReconError("At least one test requirement is required")
    return cleaned


def _proposal_key(source_packet_id: str, policy_surface: str) -> str:
    digest = hashlib.sha256(
        f"{source_packet_id}|{policy_surface}".encode("utf-8", "replace")
    ).hexdigest()[:16]
    return "CGPP-" + digest


def _content_hash(
    *,
    source_packet_id: str,
    policy_surface: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    rationale: str,
    rollback_plan: str,
    test_requirements: Sequence[str],
) -> str:
    return hashlib.sha256(
        json_dumps(
            {
                "source_packet_id": source_packet_id,
                "policy_surface": policy_surface,
                "before": dict(before),
                "after": dict(after),
                "rationale": rationale,
                "rollback_plan": rollback_plan,
                "test_requirements": list(test_requirements),
            }
        ).encode("utf-8", "replace")
    ).hexdigest()


def _decode_row(row: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    for field, default in (
        ("before_json", {}),
        ("after_json", {}),
        ("diff_json", []),
        ("test_requirements_json", []),
        ("source_packet_json", {}),
    ):
        item[field.removesuffix("_json")] = safe_json_loads(
            item.get(field),
            default,
            expected_type=type(default),
        )
    item["proposal_version"] = int(item.get("proposal_version") or 0)
    item["production_applied"] = False
    item["apply_available"] = False
    item["safety"] = {
        "proposal_only": True,
        "production_change_applied": False,
        "apply_endpoint_exists": False,
        "requires_separate_code_or_config_change": True,
        "network_requests": False,
    }
    return item


def list_policy_change_proposals(
    db: Database,
    *,
    target: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_change_guidance_policy_proposal_schema(db)
    bounded = max(1, min(int(limit or 100), 500))
    if target:
        rows = db.all(
            "SELECT * FROM change_guidance_policy_proposals "
            "WHERE target=? ORDER BY updated_at DESC,proposal_key,proposal_version DESC LIMIT ?",
            (str(target), bounded),
        )
    else:
        rows = db.all(
            "SELECT * FROM change_guidance_policy_proposals "
            "ORDER BY updated_at DESC,proposal_key,proposal_version DESC LIMIT ?",
            (bounded,),
        )
    return [_decode_row(row) for row in rows]


def create_policy_change_proposal(
    db: Database,
    *,
    source_packet_id: str,
    target: str,
    policy_surface: str,
    after: Mapping[str, Any],
    rationale: str,
    rollback_plan: str,
    test_requirements: Sequence[Any],
    actor: str = "analyst",
    review_packet_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_change_guidance_policy_proposal_schema(db)
    packet_id = str(source_packet_id or "").strip()
    surface = str(policy_surface or "").strip()
    if surface not in _POLICY_SURFACES:
        raise ReconError(f"Unsupported policy surface: {surface}")

    packet_report = (
        dict(review_packet_report)
        if isinstance(review_packet_report, Mapping)
        else change_guidance_review_packets(db, target=str(target or ""))
    )
    packet = next(
        (
            dict(row)
            for row in packet_report.get("packets", [])
            if isinstance(row, Mapping)
            and str(row.get("proposal_id") or "") == packet_id
        ),
        None,
    )
    if packet is None:
        raise ReconError("Source P11 review packet was not found for this target")
    if str(packet.get("review_status") or "") != "ready_for_manual_review":
        raise ReconError("Source P11 packet is not ready for manual review")

    before = current_policy_snapshot(surface)
    candidate_after = _validate_after(surface, after)
    diff = _diff(before, candidate_after)
    if not diff:
        raise ReconError("Candidate policy state does not differ from the current snapshot")

    clean_rationale = _clean_text(rationale, label="Rationale")
    clean_rollback = _clean_text(rollback_plan, label="Rollback plan")
    tests = _clean_tests(test_requirements)
    proposal_key = _proposal_key(packet_id, surface)
    digest = _content_hash(
        source_packet_id=packet_id,
        policy_surface=surface,
        before=before,
        after=candidate_after,
        rationale=clean_rationale,
        rollback_plan=clean_rollback,
        test_requirements=tests,
    )

    latest = db.one(
        "SELECT * FROM change_guidance_policy_proposals "
        "WHERE proposal_key=? ORDER BY proposal_version DESC LIMIT 1",
        (proposal_key,),
    )
    if latest is not None:
        latest_item = _decode_row(latest)
        if str(latest_item.get("content_hash") or "") == digest:
            return latest_item
        latest_state = str(latest_item.get("state") or "")
        if latest_state == "accepted_for_separate_implementation":
            raise ReconError(
                "Accepted proposal cannot be amended in-place; create the separate implementation change first"
            )
        next_version = int(latest_item["proposal_version"]) + 1
        if latest_state != "superseded":
            db.execute(
                "UPDATE change_guidance_policy_proposals "
                "SET state='superseded',updated_at=? WHERE proposal_version_id=?",
                (utc_now(), str(latest_item["proposal_version_id"])),
            )
    else:
        next_version = 1

    version_id = f"{proposal_key}-v{next_version:03d}"
    now = utc_now()
    db.execute(
        "INSERT INTO change_guidance_policy_proposals("
        "proposal_version_id,proposal_key,proposal_version,source_packet_id,target,"
        "signal_type,proposal_direction,policy_surface,state,before_json,after_json,"
        "diff_json,rationale,rollback_plan,test_requirements_json,source_packet_json,"
        "content_hash,created_by,created_at,updated_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            version_id,
            proposal_key,
            next_version,
            packet_id,
            str(target or ""),
            str(packet.get("signal_type") or ""),
            str(packet.get("proposal_direction") or ""),
            surface,
            "draft",
            json_dumps(before),
            json_dumps(candidate_after),
            json_dumps(diff),
            clean_rationale,
            clean_rollback,
            json_dumps(tests),
            json_dumps(packet),
            digest,
            str(actor or "analyst")[:200],
            now,
            now,
        ),
    )
    db.audit(
        "change_guidance_policy_proposal_created",
        actor=str(actor or "analyst")[:200],
        target=str(target or ""),
        entity_type="change_guidance_policy_proposal",
        entity_value=version_id,
        details={
            "proposal_key": proposal_key,
            "proposal_version": next_version,
            "source_packet_id": packet_id,
            "policy_surface": surface,
            "state": "draft",
            "production_change_applied": False,
        },
    )
    row = db.one(
        "SELECT * FROM change_guidance_policy_proposals WHERE proposal_version_id=?",
        (version_id,),
    )
    if row is None:
        raise ReconError("Policy proposal persistence failed")
    return _decode_row(row)


def submit_policy_change_proposal(
    db: Database,
    proposal_version_id: str,
    *,
    actor: str = "analyst",
) -> dict[str, Any]:
    ensure_change_guidance_policy_proposal_schema(db)
    proposal_id = str(proposal_version_id or "").strip()
    row = db.one(
        "SELECT * FROM change_guidance_policy_proposals WHERE proposal_version_id=?",
        (proposal_id,),
    )
    if row is None:
        raise ReconError("Policy proposal not found")
    current = str(row["state"] or "")
    if current == "under_review":
        return _decode_row(row)
    if current != "draft":
        raise ReconError(f"Only draft proposals can be submitted; current state is {current}")
    now = utc_now()
    db.execute(
        "UPDATE change_guidance_policy_proposals "
        "SET state='under_review',updated_at=? WHERE proposal_version_id=?",
        (now, proposal_id),
    )
    db.audit(
        "change_guidance_policy_proposal_submitted",
        actor=str(actor or "analyst")[:200],
        target=str(row["target"] or ""),
        entity_type="change_guidance_policy_proposal",
        entity_value=proposal_id,
        details={
            "state": "under_review",
            "production_change_applied": False,
        },
    )
    updated = db.one(
        "SELECT * FROM change_guidance_policy_proposals WHERE proposal_version_id=?",
        (proposal_id,),
    )
    return _decode_row(updated) if updated is not None else {}


def decide_policy_change_proposal(
    db: Database,
    proposal_version_id: str,
    *,
    decision: str,
    note: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    ensure_change_guidance_policy_proposal_schema(db)
    proposal_id = str(proposal_version_id or "").strip()
    decision_value = str(decision or "").strip().lower()
    if decision_value not in {"accept", "reject"}:
        raise ReconError("Proposal decision must be accept or reject")
    row = db.one(
        "SELECT * FROM change_guidance_policy_proposals WHERE proposal_version_id=?",
        (proposal_id,),
    )
    if row is None:
        raise ReconError("Policy proposal not found")
    current = str(row["state"] or "")
    if current not in {"under_review"}:
        raise ReconError(
            f"Only under-review proposals can receive a decision; current state is {current}"
        )
    decision_note = _clean_text(note, label="Decision note", maximum=2000)
    new_state = (
        "accepted_for_separate_implementation"
        if decision_value == "accept"
        else "rejected"
    )
    now = utc_now()
    db.execute(
        "UPDATE change_guidance_policy_proposals "
        "SET state=?,decision_by=?,decision_at=?,decision_note=?,updated_at=? "
        "WHERE proposal_version_id=?",
        (
            new_state,
            str(actor or "analyst")[:200],
            now,
            decision_note,
            now,
            proposal_id,
        ),
    )
    db.audit(
        "change_guidance_policy_proposal_decided",
        actor=str(actor or "analyst")[:200],
        target=str(row["target"] or ""),
        entity_type="change_guidance_policy_proposal",
        entity_value=proposal_id,
        details={
            "decision": decision_value,
            "state": new_state,
            "production_change_applied": False,
            "requires_separate_code_or_config_change": True,
        },
    )
    updated = db.one(
        "SELECT * FROM change_guidance_policy_proposals WHERE proposal_version_id=?",
        (proposal_id,),
    )
    return _decode_row(updated) if updated is not None else {}


__all__ = [
    "CHANGE_GUIDANCE_POLICY_PROPOSAL_VERSION",
    "CHANGE_GUIDANCE_POLICY_PROPOSAL_RULE_VERSION",
    "CHANGE_GUIDANCE_POLICY_PROPOSAL_SCHEMA_VERSION",
    "ensure_change_guidance_policy_proposal_schema",
    "supported_policy_surfaces",
    "current_policy_snapshot",
    "list_policy_change_proposals",
    "create_policy_change_proposal",
    "submit_policy_change_proposal",
    "decide_policy_change_proposal",
]

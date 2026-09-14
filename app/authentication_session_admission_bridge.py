from __future__ import annotations

"""Fail-closed offline bridge for reviewed authentication/session lifecycle evidence.

The bridge performs no network I/O. It consumes only evidence previously reviewed
by ``authentication_session_differential`` and may create a Potential Finding only
when the existing authentication/session hypothesis satisfies Canonical Admission.
"""

import json
from typing import Any, Mapping

from core import Database, ReconError, utc_now
from hypothesis_admission import record_hypothesis


AUTH_SESSION_ADMISSION_BRIDGE_VERSION = "1.0.0"
AUTH_SESSION_ADMISSION_BRIDGE_SCHEMA_VERSION = 1
_DIRECT_SIGNALS = {
    "session_reuse_after_logout",
    "token_not_rotated",
    "authentication_state_violation",
}
_STRUCTURAL_SURFACE_TYPES = {"authentication_surface"}
_STRUCTURAL_OPERATION_TYPES = {"client_operation", "state_change", "auth_boundary"}
_BLOCKING_TYPES = {
    "session_rotation_observed",
    "recovery_verification_enforced",
    "expired_session_rejected",
}


def ensure_auth_session_admission_bridge_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS authentication_session_admission_bridge_runs (
          lifecycle_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          evidence_id TEXT NOT NULL,
          signal_type TEXT NOT NULL,
          admission_state TEXT NOT NULL DEFAULT '',
          admitted INTEGER NOT NULL DEFAULT 0,
          candidate_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('authentication_session_admission_bridge_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(AUTH_SESSION_ADMISSION_BRIDGE_SCHEMA_VERSION),),
    )


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _review_context(
    db: Database, lifecycle_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run = db.one(
        "SELECT * FROM authentication_session_differential_runs WHERE lifecycle_id=?",
        (lifecycle_id,),
    )
    if not run:
        raise ReconError("Authentication lifecycle review was not found")
    review = dict(run)
    if str(review.get("status") or "") != "reviewed":
        raise ReconError("Authentication lifecycle review is not in reviewed state")

    evidence_row = db.one(
        "SELECT * FROM evidence_records WHERE evidence_id=?",
        (str(review.get("evidence_id") or ""),),
    )
    if not evidence_row:
        raise ReconError("Authentication lifecycle review evidence was not found")
    evidence = dict(evidence_row)
    if str(evidence.get("integrity_hash") or "") != str(review.get("artifact_hash") or ""):
        raise ReconError("Authentication lifecycle review integrity mismatch")

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(review.get("hypothesis_id") or ""),),
    )
    if not hypothesis_row:
        raise ReconError("Authentication lifecycle review hypothesis was not found")
    hypothesis = dict(hypothesis_row)

    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "source_run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        if str(review.get(key) or "") != value:
            raise ReconError(f"Authentication lifecycle review {key} mismatch")
    return review, evidence, hypothesis


def _eligibility(
    review: Mapping[str, Any],
    evidence: Mapping[str, Any],
    hypothesis: Mapping[str, Any],
) -> tuple[bool, str]:
    if str(hypothesis.get("bug_family") or "") != "authentication_session":
        return False, "hypothesis_family_mismatch"
    signal_type = str(review.get("signal_type") or "")
    if signal_type not in _DIRECT_SIGNALS:
        return False, "review_does_not_record_supported_direct_signal"
    if str(review.get("polarity") or "") != "support":
        return False, "review_is_not_support"
    if str(evidence.get("evidence_type") or "") != "controlled_auth_session_lifecycle_failure":
        return False, "review_evidence_type_mismatch"
    if str(evidence.get("polarity") or "") != "support":
        return False, "review_evidence_is_not_support"
    if str(evidence.get("source_kind") or "") != "analyst_verified_controlled_session":
        return False, "review_source_kind_mismatch"
    if str(evidence.get("directness") or "") != "direct":
        return False, "review_is_not_direct"

    support = [
        dict(item)
        for item in _loads(hypothesis.get("supporting_evidence_json"), [])
        if isinstance(item, Mapping)
    ]
    contradict = [
        dict(item)
        for item in _loads(hypothesis.get("contradicting_evidence_json"), [])
        if isinstance(item, Mapping)
    ]
    support_types = {str(item.get("type") or "") for item in support}
    contradiction_types = {str(item.get("type") or "") for item in contradict}
    if not (support_types & _STRUCTURAL_SURFACE_TYPES):
        return False, "missing_authentication_surface_context"
    if not (support_types & _STRUCTURAL_OPERATION_TYPES):
        return False, "missing_authentication_operation_context"
    if contradiction_types & _BLOCKING_TYPES:
        return False, "blocking_authentication_contradiction_present"
    return True, "eligible"


def apply_authentication_session_admission(
    db: Database,
    *,
    lifecycle_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one reviewed lifecycle artifact exactly once through Canonical Admission."""

    lifecycle_id = str(lifecycle_id or "").strip()
    if not lifecycle_id.startswith("ASL-"):
        raise ReconError("A valid authentication lifecycle_id is required")
    ensure_auth_session_admission_bridge_schema(db)

    previous = db.one(
        "SELECT * FROM authentication_session_admission_bridge_runs WHERE lifecycle_id=?",
        (lifecycle_id,),
    )
    if previous:
        return {
            "version": AUTH_SESSION_ADMISSION_BRIDGE_VERSION,
            "status": "already_applied",
            "lifecycle_id": lifecycle_id,
            "analysis_id": str(previous["analysis_id"]),
            "hypothesis_id": str(previous["hypothesis_id"]),
            "target": str(previous["target"]),
            "signal_type": str(previous["signal_type"]),
            "admission_state": str(previous["admission_state"] or ""),
            "admitted": bool(previous["admitted"]),
            "candidate_id": str(previous["candidate_id"] or ""),
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }

    review, evidence, hypothesis = _review_context(db, lifecycle_id)
    eligible, reason = _eligibility(review, evidence, hypothesis)
    if not eligible:
        return {
            "version": AUTH_SESSION_ADMISSION_BRIDGE_VERSION,
            "status": "not_eligible",
            "reason": reason,
            "lifecycle_id": lifecycle_id,
            "analysis_id": str(hypothesis.get("analysis_id") or ""),
            "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
            "target": str(hypothesis.get("target") or ""),
            "signal_type": str(review.get("signal_type") or ""),
            "admitted": False,
            "candidate_id": "",
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }

    support = [
        dict(item)
        for item in _loads(hypothesis.get("supporting_evidence_json"), [])
        if isinstance(item, Mapping)
    ]
    contradict = [
        dict(item)
        for item in _loads(hypothesis.get("contradicting_evidence_json"), [])
        if isinstance(item, Mapping)
    ]
    signal_type = str(review["signal_type"])
    support.append(
        {
            "type": signal_type,
            "source": "analyst_verified_controlled_session",
            "source_group": f"controlled_auth_session:{lifecycle_id}",
            "weight": 40 if signal_type != "token_not_rotated" else 34,
            "text": "Analyst-reviewed redacted metadata from a controlled test session records a direct authentication/session lifecycle boundary failure.",
            "lifecycle_id": lifecycle_id,
            "transition_type": str(review.get("transition_type") or ""),
            "evidence_id": str(evidence.get("evidence_id") or ""),
            "real_user_data_used": False,
            "raw_secret_material_stored": False,
        }
    )
    missing = [
        str(item)
        for item in _loads(hypothesis.get("missing_evidence_json"), [])
        if str(item).strip()
    ]
    rules = list(
        dict.fromkeys(
            [
                *[
                    str(item)
                    for item in _loads(hypothesis.get("rule_ids_json"), [])
                    if str(item).strip()
                ],
                "controlled-auth-session-admission-v1",
            ]
        )
    )

    with db.transaction():
        updated = record_hypothesis(
            db,
            analysis_id=str(hypothesis.get("analysis_id") or ""),
            source_run_id=str(hypothesis.get("source_run_id") or ""),
            target=str(hypothesis.get("target") or ""),
            alert_id=hypothesis.get("alert_id"),
            asset=str(hypothesis.get("asset") or ""),
            endpoint=str(hypothesis.get("endpoint") or ""),
            source_ref=str(hypothesis.get("source_ref") or f"authentication-session:{lifecycle_id}"),
            family="authentication_session",
            variant=str(hypothesis.get("bug_variant") or "auth_lifecycle"),
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rules,
            summary=str(hypothesis.get("summary") or "Potential authentication/session lifecycle weakness."),
        )
        admitted = bool(updated.get("assessment", {}).get("admitted"))
        admission_state = str(updated.get("assessment", {}).get("state") or "")
        candidate_id = ""

        if admitted:
            refreshed_row = db.one(
                "SELECT promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
                (str(updated["hypothesis_id"]),),
            )
            candidate_id = str(refreshed_row["promoted_candidate_id"] or "") if refreshed_row else ""
            if not candidate_id:
                import bug_candidates_family21 as candidate_bridge

                candidate_bridge._promote_static_family_result(
                    db,
                    analysis_id=str(hypothesis.get("analysis_id") or ""),
                    run_id=str(hypothesis.get("source_run_id") or ""),
                    target=str(hypothesis.get("target") or ""),
                    endpoint=str(hypothesis.get("endpoint") or ""),
                    source_ref=str(hypothesis.get("source_ref") or f"authentication-session:{lifecycle_id}"),
                    family="authentication_session",
                    dedicated={
                        "family": "authentication_session",
                        "variant": str(hypothesis.get("bug_variant") or "auth_lifecycle"),
                        "support": updated["support"],
                        "contradict": updated["contradict"],
                        "missing": updated["missing"],
                        "rule_ids": updated["rule_ids"],
                        "summary": "Potential Authentication or Session Weakness supported by analyst-reviewed controlled lifecycle evidence.",
                        "direct": True,
                    },
                    confidence=90,
                )
                refreshed_row = db.one(
                    "SELECT promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
                    (str(updated["hypothesis_id"]),),
                )
                candidate_id = str(refreshed_row["promoted_candidate_id"] or "") if refreshed_row else ""

        if candidate_id:
            db.execute(
                "INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    candidate_id,
                    str(evidence.get("evidence_id") or ""),
                    "support",
                    90,
                    f"controlled_auth_session:{signal_type}",
                    utc_now(),
                ),
            )

        status = "promoted" if candidate_id else "admitted" if admitted else "not_admitted"
        db.execute(
            """INSERT INTO authentication_session_admission_bridge_runs(
            lifecycle_id,analysis_id,hypothesis_id,source_run_id,target,evidence_id,signal_type,
            admission_state,admitted,candidate_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                lifecycle_id,
                str(hypothesis.get("analysis_id") or ""),
                str(updated["hypothesis_id"]),
                str(hypothesis.get("source_run_id") or ""),
                str(hypothesis.get("target") or ""),
                str(evidence.get("evidence_id") or ""),
                signal_type,
                admission_state,
                int(admitted),
                candidate_id,
                status,
                utc_now(),
            ),
        )
        db.audit(
            "authentication_session_controlled_lifecycle_admission_applied",
            actor=actor,
            target=str(hypothesis.get("target") or ""),
            entity_type="analysis_hypothesis",
            entity_value=str(updated["hypothesis_id"]),
            details={
                "lifecycle_id": lifecycle_id,
                "signal_type": signal_type,
                "evidence_id": str(evidence.get("evidence_id") or ""),
                "admitted": admitted,
                "admission_state": admission_state,
                "candidate_id": candidate_id,
                "network_requests_executed": 0,
                "raw_secret_material_stored": False,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": AUTH_SESSION_ADMISSION_BRIDGE_VERSION,
        "status": status,
        "lifecycle_id": lifecycle_id,
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "hypothesis_id": str(updated["hypothesis_id"]),
        "target": str(hypothesis.get("target") or ""),
        "signal_type": signal_type,
        "evidence_id": str(evidence.get("evidence_id") or ""),
        "admission_state": admission_state,
        "admitted": admitted,
        "candidate_id": candidate_id,
        "network_requests_executed": 0,
        "real_user_data_used": False,
        "raw_secret_material_stored": False,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }

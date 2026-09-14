from __future__ import annotations

"""Authentication/session configuration for the generic reviewed-evidence framework."""

from typing import Any

from core import Database
from reviewed_evidence_admission import ReviewedAdmissionConfig, apply_reviewed_evidence_admission


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


_CONFIG = ReviewedAdmissionConfig(
    version=AUTH_SESSION_ADMISSION_BRIDGE_VERSION,
    family="authentication_session",
    id_name="lifecycle_id",
    id_prefix="ASL-",
    review_table="authentication_session_differential_runs",
    review_id_column="lifecycle_id",
    bridge_table="authentication_session_admission_bridge_runs",
    bridge_id_column="lifecycle_id",
    evidence_type="controlled_auth_session_lifecycle_failure",
    source_kind="analyst_verified_controlled_session",
    direct_signals=frozenset(_DIRECT_SIGNALS),
    structural_groups=(
        frozenset(_STRUCTURAL_SURFACE_TYPES),
        frozenset(_STRUCTURAL_OPERATION_TYPES),
    ),
    blocking_types=frozenset(_BLOCKING_TYPES),
    support_source="analyst_verified_controlled_session",
    support_group_prefix="controlled_auth_session",
    support_text="Analyst-reviewed redacted metadata from a controlled test session records a direct authentication/session lifecycle boundary failure.",
    support_weights={
        "session_reuse_after_logout": 40,
        "token_not_rotated": 34,
        "authentication_state_violation": 40,
    },
    rule_id="controlled-auth-session-admission-v1",
    source_ref_prefix="authentication-session",
    default_variant="auth_lifecycle",
    default_summary="Potential authentication/session lifecycle weakness.",
    candidate_summary="Potential Authentication or Session Weakness supported by analyst-reviewed controlled lifecycle evidence.",
    confidence=90,
    relation_template="controlled_auth_session:{signal}",
    audit_event="authentication_session_controlled_lifecycle_admission_applied",
    review_metadata_fields=("transition_type",),
    support_flags={"real_user_data_used": False, "raw_secret_material_stored": False},
    result_flags={"real_user_data_used": False, "raw_secret_material_stored": False},
)

_REASON_COMPAT = {
    "missing_structural_context_group_1": "missing_authentication_surface_context",
    "missing_structural_context_group_2": "missing_authentication_operation_context",
    "blocking_contradiction_present": "blocking_authentication_contradiction_present",
}


def apply_authentication_session_admission(
    db: Database,
    *,
    lifecycle_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    result = apply_reviewed_evidence_admission(
        db,
        config=_CONFIG,
        review_id=lifecycle_id,
        ensure_schema=ensure_auth_session_admission_bridge_schema,
        actor=actor,
    )
    if result.get("status") == "not_eligible":
        reason = str(result.get("reason") or "")
        result["reason"] = _REASON_COMPAT.get(reason, reason)
    return result

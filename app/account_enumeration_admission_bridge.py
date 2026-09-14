from __future__ import annotations

"""Account Enumeration configuration for the generic reviewed-evidence framework."""

from typing import Any

from core import Database
from reviewed_evidence_admission import ReviewedAdmissionConfig, apply_reviewed_evidence_admission


ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_VERSION = "1.0.0"
ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_SCHEMA_VERSION = 1
_BLOCKING_TYPES = {"uniform_identity_response", "uniform_identity_timing", "rate_limit_confounded"}
_STRUCTURAL_INPUT_TYPES = {"identity_lookup"}
_STRUCTURAL_OPERATION_TYPES = {"authentication_surface", "client_operation"}


def ensure_account_enumeration_bridge_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS account_enumeration_admission_bridge_runs (
          comparison_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          evidence_id TEXT NOT NULL,
          admission_state TEXT NOT NULL DEFAULT '',
          admitted INTEGER NOT NULL DEFAULT 0,
          candidate_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('account_enumeration_admission_bridge_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_SCHEMA_VERSION),),
    )


_CONFIG = ReviewedAdmissionConfig(
    version=ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_VERSION,
    family="account_enumeration",
    id_name="comparison_id",
    id_prefix="CID-",
    review_table="controlled_identity_differential_runs",
    review_id_column="comparison_id",
    bridge_table="account_enumeration_admission_bridge_runs",
    bridge_id_column="comparison_id",
    evidence_type="controlled_identity_response_difference",
    source_kind="analyst_verified_controlled_identity",
    direct_signals=frozenset({"identity_response_differential"}),
    structural_groups=(
        frozenset(_STRUCTURAL_INPUT_TYPES),
        frozenset(_STRUCTURAL_OPERATION_TYPES),
    ),
    blocking_types=frozenset(_BLOCKING_TYPES),
    support_source="analyst_verified_controlled_identity",
    support_group_prefix="controlled_identity",
    support_text="Analyst-reviewed redacted comparison of two controlled test identities records a material response-profile differential.",
    support_weights={"identity_response_differential": 38},
    rule_id="controlled-identity-account-enumeration-admission-v1",
    source_ref_prefix="controlled-identity",
    default_variant="identity_response_difference",
    default_summary="Potential account-enumeration response differential.",
    candidate_summary="Potential Account Enumeration supported by an analyst-reviewed controlled-identity response differential.",
    confidence=88,
    relation_template="controlled_identity_response_differential",
    audit_event="account_enumeration_controlled_identity_admission_applied",
    fixed_signal="identity_response_differential",
    require_review_support=False,
    bridge_has_signal_type=False,
    support_flags={"real_user_data_used": False, "identity_values_stored": False},
    result_flags={"real_user_data_used": False, "identity_values_stored": False},
)

_REASON_COMPAT = {
    "review_evidence_type_mismatch": "review_does_not_record_material_response_difference",
    "review_evidence_is_not_support": "review_is_not_direct_support",
    "missing_structural_context_group_1": "missing_identity_lookup_context",
    "missing_structural_context_group_2": "missing_identity_operation_context",
    "blocking_contradiction_present": "blocking_identity_contradiction_present",
}


def apply_account_enumeration_admission(
    db: Database,
    *,
    comparison_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    result = apply_reviewed_evidence_admission(
        db,
        config=_CONFIG,
        review_id=comparison_id,
        ensure_schema=ensure_account_enumeration_bridge_schema,
        actor=actor,
    )
    if result.get("status") == "not_eligible":
        reason = str(result.get("reason") or "")
        result["reason"] = _REASON_COMPAT.get(reason, reason)
    return result

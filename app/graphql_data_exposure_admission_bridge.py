from __future__ import annotations

"""GraphQL configuration for the generic reviewed-evidence admission framework."""

from typing import Any

from core import Database
from reviewed_evidence_admission import ReviewedAdmissionConfig, apply_reviewed_evidence_admission


GRAPHQL_DATA_ADMISSION_BRIDGE_VERSION = "1.0.0"
GRAPHQL_DATA_ADMISSION_BRIDGE_SCHEMA_VERSION = 1
_DIRECT_SIGNALS = {"sensitive_graphql_response_observed", "field_authorization_differential"}
_STRUCTURAL_FIELD_TYPES = {"sensitive_fields"}
_STRUCTURAL_OPERATION_TYPES = {"client_operation"}
_POLICY_TYPES = {"field_policy_context"}
_BLOCKING_TYPES = {"field_authorization_observed", "sensitive_fields_not_returned"}


def ensure_graphql_data_admission_bridge_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS graphql_data_exposure_admission_bridge_runs (
          comparison_id TEXT PRIMARY KEY,
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
        "INSERT INTO schema_meta(key,value) VALUES('graphql_data_exposure_admission_bridge_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(GRAPHQL_DATA_ADMISSION_BRIDGE_SCHEMA_VERSION),),
    )


_CONFIG = ReviewedAdmissionConfig(
    version=GRAPHQL_DATA_ADMISSION_BRIDGE_VERSION,
    family="graphql_data_exposure",
    id_name="comparison_id",
    id_prefix="GQLD-",
    review_table="graphql_data_exposure_differential_runs",
    review_id_column="comparison_id",
    bridge_table="graphql_data_exposure_admission_bridge_runs",
    bridge_id_column="comparison_id",
    evidence_type="controlled_graphql_field_policy_violation",
    source_kind="analyst_verified_controlled_graphql",
    direct_signals=frozenset(_DIRECT_SIGNALS),
    structural_groups=(
        frozenset(_STRUCTURAL_FIELD_TYPES),
        frozenset(_STRUCTURAL_OPERATION_TYPES),
        frozenset(_POLICY_TYPES),
    ),
    blocking_types=frozenset(_BLOCKING_TYPES),
    support_source="analyst_verified_controlled_graphql",
    support_group_prefix="controlled_graphql",
    support_text="Analyst-reviewed value-redacted GraphQL response-shape metadata records a direct field-level policy violation in a controlled role context.",
    support_weights={
        "sensitive_graphql_response_observed": 56,
        "field_authorization_differential": 54,
    },
    rule_id="controlled-graphql-field-policy-admission-v1",
    source_ref_prefix="graphql-data",
    default_variant="sensitive_fields_with_policy_context",
    default_summary="Potential GraphQL excessive data exposure.",
    candidate_summary="Potential GraphQL Excessive Data Exposure supported by analyst-reviewed controlled field-policy evidence.",
    confidence=90,
    relation_template="controlled_graphql:{signal}",
    audit_event="graphql_data_exposure_controlled_field_policy_admission_applied",
    review_metadata_fields=("comparison_mode",),
    support_flags={"real_user_data_used": False, "raw_field_values_stored": False},
    result_flags={"real_user_data_used": False, "raw_field_values_stored": False},
)

_REASON_COMPAT = {
    "missing_structural_context_group_1": "missing_sensitive_field_context",
    "missing_structural_context_group_2": "missing_graphql_operation_context",
    "missing_structural_context_group_3": "missing_documented_field_policy_context",
    "blocking_contradiction_present": "blocking_graphql_field_control_present",
}


def apply_graphql_data_exposure_admission(
    db: Database,
    *,
    comparison_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    result = apply_reviewed_evidence_admission(
        db,
        config=_CONFIG,
        review_id=comparison_id,
        ensure_schema=ensure_graphql_data_admission_bridge_schema,
        actor=actor,
    )
    if result.get("status") == "not_eligible":
        reason = str(result.get("reason") or "")
        result["reason"] = _REASON_COMPAT.get(reason, reason)
    return result

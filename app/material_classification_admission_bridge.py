from __future__ import annotations

"""Admission configuration for analyst-reviewed redacted material classification.

This module performs no collection, provider validation, or network I/O. It only
configures the generic reviewed-evidence admission framework to consume immutable
review records previously written by ``material_classification_review``.
"""

from typing import Any

from core import Database
from reviewed_evidence_admission import ReviewedAdmissionConfig, apply_reviewed_evidence_admission


MATERIAL_CLASSIFICATION_ADMISSION_VERSION = "1.0.0"
MATERIAL_CLASSIFICATION_ADMISSION_SCHEMA_VERSION = 1
_DIRECT_SIGNALS = {"credential_material_confirmed"}
_STRUCTURAL_PATTERN_TYPES = {"secret_pattern"}
_STRUCTURAL_CONTEXT_TYPES = {"context"}
_BLOCKING_TYPES = {"placeholder", "intended_public_client_identifier"}


def ensure_material_classification_admission_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS material_classification_admission_bridge_runs (
          review_id TEXT PRIMARY KEY,
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
        "INSERT INTO schema_meta(key,value) VALUES('material_classification_admission_bridge_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(MATERIAL_CLASSIFICATION_ADMISSION_SCHEMA_VERSION),),
    )


_CONFIG = ReviewedAdmissionConfig(
    version=MATERIAL_CLASSIFICATION_ADMISSION_VERSION,
    family="secret_exposure",
    id_name="review_id",
    id_prefix="MCR-",
    review_table="material_classification_review_runs",
    review_id_column="review_id",
    bridge_table="material_classification_admission_bridge_runs",
    bridge_id_column="review_id",
    evidence_type="reviewed_redacted_material_structure",
    source_kind="analyst_verified_redacted_classification",
    direct_signals=frozenset(_DIRECT_SIGNALS),
    structural_groups=(
        frozenset(_STRUCTURAL_PATTERN_TYPES),
        frozenset(_STRUCTURAL_CONTEXT_TYPES),
    ),
    blocking_types=frozenset(_BLOCKING_TYPES),
    support_source="analyst_verified_redacted_classification",
    support_group_prefix="reviewed_material",
    support_text=(
        "Analyst-reviewed redacted metadata confirms structurally complete credential material "
        "in client-delivered context; no reusable value is retained or validated online."
    ),
    support_weights={"credential_material_confirmed": 52},
    rule_id="reviewed-material-classification-admission-v1",
    source_ref_prefix="material-review",
    default_variant="credential_material_confirmed",
    default_summary="Potential client-delivered credential material exposure.",
    candidate_summary=(
        "Potential Secret Exposure supported by analyst-reviewed redacted structural evidence; "
        "credential validity was not tested."
    ),
    confidence=90,
    relation_template="reviewed_material:{signal}",
    audit_event="material_classification_admission_applied",
    review_metadata_fields=("material_class",),
    support_flags={
        "raw_value_stored": False,
        "provider_validation_performed": False,
        "network_request_performed": False,
    },
    result_flags={
        "raw_value_stored": False,
        "provider_validation_performed": False,
    },
)

_REASON_COMPAT = {
    "missing_structural_context_group_1": "missing_secret_pattern_context",
    "missing_structural_context_group_2": "missing_client_delivery_context",
    "blocking_contradiction_present": "blocking_material_contradiction_present",
}


def apply_material_classification_admission(
    db: Database,
    *,
    review_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one immutable redacted material review through Canonical Admission."""

    result = apply_reviewed_evidence_admission(
        db,
        config=_CONFIG,
        review_id=review_id,
        ensure_schema=ensure_material_classification_admission_schema,
        actor=actor,
    )
    if result.get("status") == "not_eligible":
        reason = str(result.get("reason") or "")
        result["reason"] = _REASON_COMPAT.get(reason, reason)
    return result

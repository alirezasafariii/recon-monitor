from __future__ import annotations

"""Fail-closed offline bridge for reviewed GraphQL field-policy evidence.

The bridge performs no network I/O. It consumes only evidence previously reviewed
by ``graphql_data_exposure_differential`` and may create a Potential Finding only
when the existing GraphQL data-exposure hypothesis satisfies Canonical Admission.
"""

import json
from typing import Any, Mapping

from core import Database, ReconError, utc_now
from hypothesis_admission import record_hypothesis


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


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _review_context(
    db: Database, comparison_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run = db.one(
        "SELECT * FROM graphql_data_exposure_differential_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if not run:
        raise ReconError("GraphQL field-policy review was not found")
    review = dict(run)
    if str(review.get("status") or "") != "reviewed":
        raise ReconError("GraphQL field-policy review is not in reviewed state")

    evidence_row = db.one(
        "SELECT * FROM evidence_records WHERE evidence_id=?",
        (str(review.get("evidence_id") or ""),),
    )
    if not evidence_row:
        raise ReconError("GraphQL field-policy review evidence was not found")
    evidence = dict(evidence_row)
    if str(evidence.get("integrity_hash") or "") != str(review.get("artifact_hash") or ""):
        raise ReconError("GraphQL field-policy review integrity mismatch")

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(review.get("hypothesis_id") or ""),),
    )
    if not hypothesis_row:
        raise ReconError("GraphQL field-policy review hypothesis was not found")
    hypothesis = dict(hypothesis_row)

    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "source_run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        if str(review.get(key) or "") != value:
            raise ReconError(f"GraphQL field-policy review {key} mismatch")
    return review, evidence, hypothesis


def _eligibility(
    review: Mapping[str, Any],
    evidence: Mapping[str, Any],
    hypothesis: Mapping[str, Any],
) -> tuple[bool, str]:
    if str(hypothesis.get("bug_family") or "") != "graphql_data_exposure":
        return False, "hypothesis_family_mismatch"
    signal_type = str(review.get("signal_type") or "")
    if signal_type not in _DIRECT_SIGNALS:
        return False, "review_does_not_record_supported_direct_signal"
    if str(review.get("polarity") or "") != "support":
        return False, "review_is_not_support"
    if str(evidence.get("evidence_type") or "") != "controlled_graphql_field_policy_violation":
        return False, "review_evidence_type_mismatch"
    if str(evidence.get("polarity") or "") != "support":
        return False, "review_evidence_is_not_support"
    if str(evidence.get("source_kind") or "") != "analyst_verified_controlled_graphql":
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
    if not (support_types & _STRUCTURAL_FIELD_TYPES):
        return False, "missing_sensitive_field_context"
    if not (support_types & _STRUCTURAL_OPERATION_TYPES):
        return False, "missing_graphql_operation_context"
    if not (support_types & _POLICY_TYPES):
        return False, "missing_documented_field_policy_context"
    if contradiction_types & _BLOCKING_TYPES:
        return False, "blocking_graphql_field_control_present"
    return True, "eligible"


def apply_graphql_data_exposure_admission(
    db: Database,
    *,
    comparison_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one reviewed GraphQL field-policy artifact exactly once through Admission."""

    comparison_id = str(comparison_id or "").strip()
    if not comparison_id.startswith("GQLD-"):
        raise ReconError("A valid GraphQL field-policy comparison_id is required")
    ensure_graphql_data_admission_bridge_schema(db)

    previous = db.one(
        "SELECT * FROM graphql_data_exposure_admission_bridge_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if previous:
        return {
            "version": GRAPHQL_DATA_ADMISSION_BRIDGE_VERSION,
            "status": "already_applied",
            "comparison_id": comparison_id,
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

    review, evidence, hypothesis = _review_context(db, comparison_id)
    eligible, reason = _eligibility(review, evidence, hypothesis)
    if not eligible:
        return {
            "version": GRAPHQL_DATA_ADMISSION_BRIDGE_VERSION,
            "status": "not_eligible",
            "reason": reason,
            "comparison_id": comparison_id,
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
            "source": "analyst_verified_controlled_graphql",
            "source_group": f"controlled_graphql:{comparison_id}",
            "weight": 56 if signal_type == "sensitive_graphql_response_observed" else 54,
            "text": "Analyst-reviewed value-redacted GraphQL response-shape metadata records a direct field-level policy violation in a controlled role context.",
            "comparison_id": comparison_id,
            "comparison_mode": str(review.get("comparison_mode") or ""),
            "evidence_id": str(evidence.get("evidence_id") or ""),
            "real_user_data_used": False,
            "raw_field_values_stored": False,
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
                "controlled-graphql-field-policy-admission-v1",
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
            source_ref=str(hypothesis.get("source_ref") or f"graphql-data:{comparison_id}"),
            family="graphql_data_exposure",
            variant=str(hypothesis.get("bug_variant") or "sensitive_fields_with_policy_context"),
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rules,
            summary=str(hypothesis.get("summary") or "Potential GraphQL excessive data exposure."),
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
                    source_ref=str(hypothesis.get("source_ref") or f"graphql-data:{comparison_id}"),
                    family="graphql_data_exposure",
                    dedicated={
                        "family": "graphql_data_exposure",
                        "variant": str(hypothesis.get("bug_variant") or "sensitive_fields_with_policy_context"),
                        "support": updated["support"],
                        "contradict": updated["contradict"],
                        "missing": updated["missing"],
                        "rule_ids": updated["rule_ids"],
                        "summary": "Potential GraphQL Excessive Data Exposure supported by analyst-reviewed controlled field-policy evidence.",
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
                    f"controlled_graphql:{signal_type}",
                    utc_now(),
                ),
            )

        status = "promoted" if candidate_id else "admitted" if admitted else "not_admitted"
        db.execute(
            """INSERT INTO graphql_data_exposure_admission_bridge_runs(
            comparison_id,analysis_id,hypothesis_id,source_run_id,target,evidence_id,signal_type,
            admission_state,admitted,candidate_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                comparison_id,
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
            "graphql_data_exposure_controlled_field_policy_admission_applied",
            actor=actor,
            target=str(hypothesis.get("target") or ""),
            entity_type="analysis_hypothesis",
            entity_value=str(updated["hypothesis_id"]),
            details={
                "comparison_id": comparison_id,
                "signal_type": signal_type,
                "evidence_id": str(evidence.get("evidence_id") or ""),
                "admitted": admitted,
                "admission_state": admission_state,
                "candidate_id": candidate_id,
                "network_requests_executed": 0,
                "raw_field_values_stored": False,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": GRAPHQL_DATA_ADMISSION_BRIDGE_VERSION,
        "status": status,
        "comparison_id": comparison_id,
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
        "raw_field_values_stored": False,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }

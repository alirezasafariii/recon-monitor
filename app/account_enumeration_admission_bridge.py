from __future__ import annotations

"""Offline bridge from reviewed controlled-identity evidence to canonical admission.

The bridge performs no network I/O. It consumes only evidence already reviewed by
``controlled_identity_differential`` and may create a Potential Finding only when
the existing Account Enumeration hypothesis satisfies canonical Admission after
the reviewed differential is added.
"""

import json
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, utc_now
from hypothesis_admission import record_hypothesis


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


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _review_context(db: Database, comparison_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run = db.one(
        "SELECT * FROM controlled_identity_differential_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if not run:
        raise ReconError("Controlled identity review was not found")
    review = dict(run)
    if str(review.get("status") or "") != "reviewed":
        raise ReconError("Controlled identity review is not in reviewed state")

    evidence_row = db.one(
        "SELECT * FROM evidence_records WHERE evidence_id=?",
        (str(review.get("evidence_id") or ""),),
    )
    if not evidence_row:
        raise ReconError("Controlled identity review evidence was not found")
    evidence = dict(evidence_row)
    if str(evidence.get("integrity_hash") or "") != str(review.get("artifact_hash") or ""):
        raise ReconError("Controlled identity review integrity mismatch")

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(review.get("hypothesis_id") or ""),),
    )
    if not hypothesis_row:
        raise ReconError("Controlled identity review hypothesis was not found")
    hypothesis = dict(hypothesis_row)

    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "source_run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        review_key = "source_run_id" if key == "source_run_id" else key
        if str(review.get(review_key) or "") != value:
            raise ReconError(f"Controlled identity review {review_key} mismatch")
    return review, evidence, hypothesis


def _eligibility(evidence: Mapping[str, Any], hypothesis: Mapping[str, Any]) -> tuple[bool, str]:
    if str(hypothesis.get("bug_family") or "") != "account_enumeration":
        return False, "hypothesis_family_mismatch"
    if str(evidence.get("evidence_type") or "") != "controlled_identity_response_difference":
        return False, "review_does_not_record_material_response_difference"
    if str(evidence.get("polarity") or "") != "support":
        return False, "review_is_not_direct_support"
    if str(evidence.get("source_kind") or "") != "analyst_verified_controlled_identity":
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
    if not (support_types & _STRUCTURAL_INPUT_TYPES):
        return False, "missing_identity_lookup_context"
    if not (support_types & _STRUCTURAL_OPERATION_TYPES):
        return False, "missing_identity_operation_context"
    if contradiction_types & _BLOCKING_TYPES:
        return False, "blocking_identity_contradiction_present"
    return True, "eligible"


def apply_account_enumeration_admission(
    db: Database,
    *,
    comparison_id: str,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one reviewed controlled-identity comparison exactly once.

    The function never performs live validation and never reports a confirmed
    vulnerability. Its strongest outcome is a Potential Finding created through
    the repository's existing canonical Admission and Candidate machinery.
    """

    comparison_id = str(comparison_id or "").strip()
    if not comparison_id.startswith("CID-"):
        raise ReconError("A valid controlled identity comparison_id is required")
    ensure_account_enumeration_bridge_schema(db)

    previous = db.one(
        "SELECT * FROM account_enumeration_admission_bridge_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if previous:
        return {
            "version": ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_VERSION,
            "status": "already_applied",
            "comparison_id": comparison_id,
            "analysis_id": str(previous["analysis_id"]),
            "hypothesis_id": str(previous["hypothesis_id"]),
            "target": str(previous["target"]),
            "admission_state": str(previous["admission_state"] or ""),
            "admitted": bool(previous["admitted"]),
            "candidate_id": str(previous["candidate_id"] or ""),
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }

    review, evidence, hypothesis = _review_context(db, comparison_id)
    eligible, reason = _eligibility(evidence, hypothesis)
    if not eligible:
        return {
            "version": ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_VERSION,
            "status": "not_eligible",
            "reason": reason,
            "comparison_id": comparison_id,
            "analysis_id": str(hypothesis.get("analysis_id") or ""),
            "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
            "target": str(hypothesis.get("target") or ""),
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
    support.append(
        {
            "type": "identity_response_differential",
            "source": "analyst_verified_controlled_identity",
            "source_group": f"controlled_identity:{comparison_id}",
            "weight": 38,
            "text": "Analyst-reviewed redacted comparison of two controlled test identities records a material response-profile differential.",
            "comparison_id": comparison_id,
            "evidence_id": str(evidence.get("evidence_id") or ""),
            "real_user_data_used": False,
            "identity_values_stored": False,
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
                "controlled-identity-account-enumeration-admission-v1",
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
            source_ref=str(hypothesis.get("source_ref") or f"controlled-identity:{comparison_id}"),
            family="account_enumeration",
            variant=str(hypothesis.get("bug_variant") or "identity_response_difference"),
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rules,
            summary=str(hypothesis.get("summary") or "Potential account-enumeration response differential."),
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
                    source_ref=str(hypothesis.get("source_ref") or f"controlled-identity:{comparison_id}"),
                    family="account_enumeration",
                    dedicated={
                        "family": "account_enumeration",
                        "variant": str(hypothesis.get("bug_variant") or "identity_response_difference"),
                        "support": updated["support"],
                        "contradict": updated["contradict"],
                        "missing": updated["missing"],
                        "rule_ids": updated["rule_ids"],
                        "summary": "Potential Account Enumeration supported by an analyst-reviewed controlled-identity response differential.",
                        "direct": True,
                    },
                    confidence=88,
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
                    88,
                    "controlled_identity_response_differential",
                    utc_now(),
                ),
            )

        status = "promoted" if candidate_id else "admitted" if admitted else "not_admitted"
        db.execute(
            """INSERT INTO account_enumeration_admission_bridge_runs(
            comparison_id,analysis_id,hypothesis_id,source_run_id,target,evidence_id,
            admission_state,admitted,candidate_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                comparison_id,
                str(hypothesis.get("analysis_id") or ""),
                str(updated["hypothesis_id"]),
                str(hypothesis.get("source_run_id") or ""),
                str(hypothesis.get("target") or ""),
                str(evidence.get("evidence_id") or ""),
                admission_state,
                int(admitted),
                candidate_id,
                status,
                utc_now(),
            ),
        )
        db.audit(
            "account_enumeration_controlled_identity_admission_applied",
            actor=actor,
            target=str(hypothesis.get("target") or ""),
            entity_type="analysis_hypothesis",
            entity_value=str(updated["hypothesis_id"]),
            details={
                "comparison_id": comparison_id,
                "evidence_id": str(evidence.get("evidence_id") or ""),
                "admitted": admitted,
                "admission_state": admission_state,
                "candidate_id": candidate_id,
                "network_requests_executed": 0,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": ACCOUNT_ENUMERATION_ADMISSION_BRIDGE_VERSION,
        "status": status,
        "comparison_id": comparison_id,
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "hypothesis_id": str(updated["hypothesis_id"]),
        "target": str(hypothesis.get("target") or ""),
        "evidence_id": str(evidence.get("evidence_id") or ""),
        "admission_state": admission_state,
        "admitted": admitted,
        "candidate_id": candidate_id,
        "network_requests_executed": 0,
        "real_user_data_used": False,
        "identity_values_stored": False,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }

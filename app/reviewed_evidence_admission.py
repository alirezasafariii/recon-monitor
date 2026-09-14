from __future__ import annotations

"""Generic fail-closed bridge from reviewed evidence to Canonical Admission.

This module does not collect evidence and performs no network I/O. Family-specific
reviewers remain responsible for producing immutable evidence records. The generic
bridge verifies review/evidence/hypothesis identity, applies structural and blocker
gates, enriches the existing hypothesis with one already-reviewed direct signal,
and delegates Potential Finding creation to the repository's existing Candidate
machinery.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from core import Database, ReconError, utc_now
from hypothesis_admission import record_hypothesis


REVIEWED_EVIDENCE_ADMISSION_VERSION = "1.0.0"
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class ReviewedAdmissionConfig:
    version: str
    family: str
    id_name: str
    id_prefix: str
    review_table: str
    review_id_column: str
    bridge_table: str
    bridge_id_column: str
    evidence_type: str
    source_kind: str
    direct_signals: frozenset[str]
    structural_groups: tuple[frozenset[str], ...]
    blocking_types: frozenset[str]
    support_source: str
    support_group_prefix: str
    support_text: str
    support_weights: Mapping[str, int]
    rule_id: str
    source_ref_prefix: str
    default_variant: str
    default_summary: str
    candidate_summary: str
    confidence: int
    relation_template: str
    audit_event: str
    fixed_signal: str = ""
    review_signal_column: str = "signal_type"
    review_polarity_column: str = "polarity"
    require_review_support: bool = True
    bridge_has_signal_type: bool = True
    review_metadata_fields: tuple[str, ...] = ()
    support_flags: Mapping[str, Any] = field(default_factory=dict)
    result_flags: Mapping[str, Any] = field(default_factory=dict)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _validated_identifier(value: str) -> str:
    text = str(value or "")
    if not _IDENT_RE.fullmatch(text):
        raise ReconError("Reviewed evidence admission configuration contains an invalid SQL identifier")
    return text


def _review_context(
    db: Database,
    config: ReviewedAdmissionConfig,
    review_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    review_table = _validated_identifier(config.review_table)
    review_id_column = _validated_identifier(config.review_id_column)
    run = db.one(
        f"SELECT * FROM {review_table} WHERE {review_id_column}=?",
        (review_id,),
    )
    if not run:
        raise ReconError("Reviewed evidence record was not found")
    review = dict(run)
    if str(review.get("status") or "") != "reviewed":
        raise ReconError("Reviewed evidence record is not in reviewed state")

    evidence_row = db.one(
        "SELECT * FROM evidence_records WHERE evidence_id=?",
        (str(review.get("evidence_id") or ""),),
    )
    if not evidence_row:
        raise ReconError("Reviewed evidence payload was not found")
    evidence = dict(evidence_row)
    if str(evidence.get("integrity_hash") or "") != str(review.get("artifact_hash") or ""):
        raise ReconError("Reviewed evidence integrity mismatch")

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(review.get("hypothesis_id") or ""),),
    )
    if not hypothesis_row:
        raise ReconError("Reviewed evidence hypothesis was not found")
    hypothesis = dict(hypothesis_row)

    for key in ("analysis_id", "source_run_id", "target"):
        expected = str(hypothesis.get(key) or "")
        if str(review.get(key) or "") != expected:
            raise ReconError(f"Reviewed evidence {key} mismatch")
    return review, evidence, hypothesis


def _signal(config: ReviewedAdmissionConfig, review: Mapping[str, Any]) -> str:
    return str(config.fixed_signal or review.get(config.review_signal_column) or "")


def _eligibility(
    config: ReviewedAdmissionConfig,
    review: Mapping[str, Any],
    evidence: Mapping[str, Any],
    hypothesis: Mapping[str, Any],
) -> tuple[bool, str, str]:
    if str(hypothesis.get("bug_family") or "") != config.family:
        return False, "hypothesis_family_mismatch", ""

    signal_type = _signal(config, review)
    if signal_type not in config.direct_signals:
        return False, "review_does_not_record_supported_direct_signal", signal_type
    if (
        config.require_review_support
        and config.review_polarity_column in review
        and str(review.get(config.review_polarity_column) or "") != "support"
    ):
        return False, "review_is_not_support", signal_type
    if str(evidence.get("evidence_type") or "") != config.evidence_type:
        return False, "review_evidence_type_mismatch", signal_type
    if str(evidence.get("polarity") or "") != "support":
        return False, "review_evidence_is_not_support", signal_type
    if str(evidence.get("source_kind") or "") != config.source_kind:
        return False, "review_source_kind_mismatch", signal_type
    if str(evidence.get("directness") or "") != "direct":
        return False, "review_is_not_direct", signal_type

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
    for index, group in enumerate(config.structural_groups, start=1):
        if not (support_types & set(group)):
            return False, f"missing_structural_context_group_{index}", signal_type
    if contradiction_types & set(config.blocking_types):
        return False, "blocking_contradiction_present", signal_type
    return True, "eligible", signal_type


def _previous_result(
    config: ReviewedAdmissionConfig,
    review_id: str,
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    signal_type = str(previous.get("signal_type") or config.fixed_signal or "")
    result = {
        "version": config.version,
        "framework_version": REVIEWED_EVIDENCE_ADMISSION_VERSION,
        "status": "already_applied",
        config.id_name: review_id,
        "analysis_id": str(previous.get("analysis_id") or ""),
        "hypothesis_id": str(previous.get("hypothesis_id") or ""),
        "target": str(previous.get("target") or ""),
        "signal_type": signal_type,
        "admission_state": str(previous.get("admission_state") or ""),
        "admitted": bool(previous.get("admitted")),
        "candidate_id": str(previous.get("candidate_id") or ""),
        "network_requests_executed": 0,
        "vulnerability_confirmed": False,
    }
    result.update(dict(config.result_flags))
    return result


def apply_reviewed_evidence_admission(
    db: Database,
    *,
    config: ReviewedAdmissionConfig,
    review_id: str,
    ensure_schema: Any,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one immutable reviewed-evidence record exactly once."""

    review_id = str(review_id or "").strip()
    if not review_id.startswith(config.id_prefix):
        raise ReconError(f"A valid {config.id_name} is required")
    ensure_schema(db)

    bridge_table = _validated_identifier(config.bridge_table)
    bridge_id_column = _validated_identifier(config.bridge_id_column)
    previous = db.one(
        f"SELECT * FROM {bridge_table} WHERE {bridge_id_column}=?",
        (review_id,),
    )
    if previous:
        return _previous_result(config, review_id, dict(previous))

    review, evidence, hypothesis = _review_context(db, config, review_id)
    eligible, reason, signal_type = _eligibility(config, review, evidence, hypothesis)
    if not eligible:
        result = {
            "version": config.version,
            "framework_version": REVIEWED_EVIDENCE_ADMISSION_VERSION,
            "status": "not_eligible",
            "reason": reason,
            config.id_name: review_id,
            "analysis_id": str(hypothesis.get("analysis_id") or ""),
            "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
            "target": str(hypothesis.get("target") or ""),
            "signal_type": signal_type,
            "admitted": False,
            "candidate_id": "",
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }
        result.update(dict(config.result_flags))
        return result

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
    direct = {
        "type": signal_type,
        "source": config.support_source,
        "source_group": f"{config.support_group_prefix}:{review_id}",
        "weight": int(config.support_weights.get(signal_type, 40)),
        "text": config.support_text,
        config.id_name: review_id,
        "evidence_id": str(evidence.get("evidence_id") or ""),
    }
    for field_name in config.review_metadata_fields:
        direct[field_name] = review.get(field_name)
    direct.update(dict(config.support_flags))
    support.append(direct)

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
                config.rule_id,
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
            source_ref=str(hypothesis.get("source_ref") or f"{config.source_ref_prefix}:{review_id}"),
            family=config.family,
            variant=str(hypothesis.get("bug_variant") or config.default_variant),
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rules,
            summary=str(hypothesis.get("summary") or config.default_summary),
        )
        admitted = bool(updated.get("assessment", {}).get("admitted"))
        admission_state = str(updated.get("assessment", {}).get("state") or "")
        candidate_id = ""

        if admitted:
            refreshed = db.one(
                "SELECT promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
                (str(updated["hypothesis_id"]),),
            )
            candidate_id = str(refreshed["promoted_candidate_id"] or "") if refreshed else ""
            if not candidate_id:
                import bug_candidates_family21 as candidate_bridge

                candidate_bridge._promote_static_family_result(
                    db,
                    analysis_id=str(hypothesis.get("analysis_id") or ""),
                    run_id=str(hypothesis.get("source_run_id") or ""),
                    target=str(hypothesis.get("target") or ""),
                    endpoint=str(hypothesis.get("endpoint") or ""),
                    source_ref=str(hypothesis.get("source_ref") or f"{config.source_ref_prefix}:{review_id}"),
                    family=config.family,
                    dedicated={
                        "family": config.family,
                        "variant": str(hypothesis.get("bug_variant") or config.default_variant),
                        "support": updated["support"],
                        "contradict": updated["contradict"],
                        "missing": updated["missing"],
                        "rule_ids": updated["rule_ids"],
                        "summary": config.candidate_summary,
                        "direct": True,
                    },
                    confidence=int(config.confidence),
                )
                refreshed = db.one(
                    "SELECT promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
                    (str(updated["hypothesis_id"]),),
                )
                candidate_id = str(refreshed["promoted_candidate_id"] or "") if refreshed else ""

        if candidate_id:
            db.execute(
                "INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    candidate_id,
                    str(evidence.get("evidence_id") or ""),
                    "support",
                    int(config.confidence),
                    config.relation_template.format(signal=signal_type),
                    utc_now(),
                ),
            )

        status = "promoted" if candidate_id else "admitted" if admitted else "not_admitted"
        columns = [
            bridge_id_column,
            "analysis_id",
            "hypothesis_id",
            "source_run_id",
            "target",
            "evidence_id",
        ]
        values: list[Any] = [
            review_id,
            str(hypothesis.get("analysis_id") or ""),
            str(updated["hypothesis_id"]),
            str(hypothesis.get("source_run_id") or ""),
            str(hypothesis.get("target") or ""),
            str(evidence.get("evidence_id") or ""),
        ]
        if config.bridge_has_signal_type:
            columns.append("signal_type")
            values.append(signal_type)
        columns.extend(["admission_state", "admitted", "candidate_id", "status", "applied_at"])
        values.extend([admission_state, int(admitted), candidate_id, status, utc_now()])
        placeholders = ",".join("?" for _ in columns)
        db.execute(
            f"INSERT INTO {bridge_table}({','.join(columns)}) VALUES({placeholders})",
            tuple(values),
        )

        audit_details = {
            config.id_name: review_id,
            "signal_type": signal_type,
            "evidence_id": str(evidence.get("evidence_id") or ""),
            "admitted": admitted,
            "admission_state": admission_state,
            "candidate_id": candidate_id,
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }
        audit_details.update(dict(config.result_flags))
        db.audit(
            config.audit_event,
            actor=actor,
            target=str(hypothesis.get("target") or ""),
            entity_type="analysis_hypothesis",
            entity_value=str(updated["hypothesis_id"]),
            details=audit_details,
        )

    result = {
        "version": config.version,
        "framework_version": REVIEWED_EVIDENCE_ADMISSION_VERSION,
        "status": status,
        config.id_name: review_id,
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "hypothesis_id": str(updated["hypothesis_id"]),
        "target": str(hypothesis.get("target") or ""),
        "signal_type": signal_type,
        "evidence_id": str(evidence.get("evidence_id") or ""),
        "admission_state": admission_state,
        "admitted": admitted,
        "candidate_id": candidate_id,
        "network_requests_executed": 0,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }
    result.update(dict(config.result_flags))
    return result

from __future__ import annotations

"""Offline adapter for analyst-verified Differential Evidence v2 artifacts."""

import json
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now
from differential_evidence import (
    DIFFERENTIAL_EVIDENCE_VERSION,
    load_differential_artifact,
    validate_open_redirect_artifact,
)


DIFFERENTIAL_EVIDENCE_ADAPTER_VERSION = "1.0.0"
DIFFERENTIAL_EVIDENCE_ADAPTER_RULE_VERSION = "2026.09.14.1"
DIFFERENTIAL_EVIDENCE_ADAPTER_SCHEMA_VERSION = 1


def ensure_differential_evidence_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS differential_evidence_adapter_runs (
          differential_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          family TEXT NOT NULL,
          artifact_hash TEXT NOT NULL,
          evidence_id TEXT NOT NULL DEFAULT '',
          admission_state TEXT NOT NULL DEFAULT '',
          admitted INTEGER NOT NULL DEFAULT 0,
          candidate_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('differential_evidence_adapter_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(DIFFERENTIAL_EVIDENCE_ADAPTER_SCHEMA_VERSION),),
    )


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    identity = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
    )
    if any(
        (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
        ) == identity
        for existing in items
    ):
        return
    items.append(item)


def _persist_evidence_record(
    db: Database,
    *,
    normalized: Mapping[str, Any],
    artifact_name: str,
) -> str:
    differential_id = str(normalized["differential_id"])
    analysis_id = str(normalized["analysis_id"])
    target = str(normalized["target"])
    root = sha256_text(
        "|".join(["differential-evidence-v2", differential_id, "open_redirect", target])
    )
    integrity = str(normalized["artifact_hash"])
    evidence_id = "EVD-" + sha256_text(root + "|" + integrity)[:16].upper()
    observed_at = str(normalized["observed_at"])
    summary = (
        "Analyst-verified Open Redirect differential evidence records an expected-vs-observed "
        "controlled destination acceptance without following or connecting to that destination."
    )
    db.execute(
        """INSERT OR IGNORE INTO evidence_records(
        evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,
        parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,
        raw_reference,integrity_hash,first_seen,last_seen,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            evidence_id,
            analysis_id,
            str(normalized["run_id"]),
            target,
            "external_destination_accepted",
            "support",
            "analyst_verified_differential",
            "differential_evidence_v2",
            str(artifact_name)[:240],
            "differential_evidence_adapter",
            DIFFERENTIAL_EVIDENCE_ADAPTER_VERSION,
            f"differential_evidence:{differential_id}",
            root,
            90,
            95,
            "direct",
            summary,
            f"differential_evidence:{differential_id}",
            integrity,
            observed_at,
            observed_at,
            utc_now(),
        ),
    )
    stored = db.one(
        "SELECT evidence_id,integrity_hash FROM evidence_records "
        "WHERE analysis_id=? AND root_fingerprint=? AND polarity='support'",
        (analysis_id, root),
    )
    if not stored or str(stored["integrity_hash"] or "") != integrity:
        raise ReconError("Differential evidence root collision or mutable evidence detected")
    return str(stored["evidence_id"] or evidence_id)


def adapt_differential_evidence(
    db: Database,
    *,
    artifact_path: str | Path,
    actor: str = "analyst",
    max_age_seconds: int = 24 * 60 * 60,
) -> dict[str, Any]:
    """Validate and apply one differential artifact exactly once, without network I/O."""

    ensure_differential_evidence_schema(db)
    raw = load_differential_artifact(artifact_path)
    normalized = validate_open_redirect_artifact(raw, max_age_seconds=max_age_seconds)
    differential_id = str(normalized["differential_id"])
    artifact_hash = str(normalized["artifact_hash"])

    previous = db.one(
        "SELECT * FROM differential_evidence_adapter_runs WHERE differential_id=?",
        (differential_id,),
    )
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously adapted Differential Evidence has changed; refusing mutable evidence")
        return {
            "version": DIFFERENTIAL_EVIDENCE_ADAPTER_VERSION,
            "differential_evidence_version": DIFFERENTIAL_EVIDENCE_VERSION,
            "status": "already_applied",
            "differential_id": differential_id,
            "analysis_id": str(previous["analysis_id"]),
            "hypothesis_id": str(previous["hypothesis_id"]),
            "family": str(previous["family"]),
            "target": str(previous["target"]),
            "admission_state": str(previous["admission_state"] or ""),
            "admitted": bool(previous["admitted"]),
            "candidate_id": str(previous["candidate_id"] or ""),
            "network_requests_executed_by_adapter": 0,
            "vulnerability_confirmed": False,
        }

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(normalized["hypothesis_id"]),),
    )
    if not hypothesis_row:
        raise ReconError("Differential Evidence hypothesis was not found")
    hypothesis = dict(hypothesis_row)
    identity = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
        "family": str(hypothesis.get("bug_family") or ""),
    }
    for key, expected in identity.items():
        artifact_key = "run_id" if key == "run_id" else key
        if str(normalized.get(artifact_key) or "") != expected:
            raise ReconError(f"Differential Evidence {artifact_key} mismatch")
    if identity["family"] != "open_redirect":
        raise ReconError("Differential Evidence v2 currently promotes Open Redirect only")

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
    source_group = f"differential_evidence:{differential_id}"
    _append_unique(
        support,
        {
            "type": "user_controlled_destination",
            "source": "analyst_verified_differential",
            "source_group": source_group,
            "weight": 22,
            "text": "Analyst-reviewed differential evidence ties the tested redirect destination to the controlled input parameter.",
            "differential_id": differential_id,
            "raw_body_stored": False,
        },
    )
    _append_unique(
        support,
        {
            "type": "external_destination_accepted",
            "source": "analyst_verified_differential",
            "source_group": source_group,
            "weight": 52,
            "text": "Analyst-reviewed expected-vs-observed evidence records acceptance of the reserved controlled external destination without following it.",
            "differential_id": differential_id,
            "raw_body_stored": False,
        },
    )

    existing_missing = [
        str(value)
        for value in _loads(hypothesis.get("missing_evidence_json"), [])
        if str(value)
    ]
    missing = [
        value
        for value in existing_missing
        if "external_destination_accepted" not in value
        and "external" not in value.lower()
    ]
    rules = list(
        dict.fromkeys(
            [
                *[
                    str(value)
                    for value in _loads(hypothesis.get("rule_ids_json"), [])
                    if str(value)
                ],
                "differential-evidence-v2-open-redirect",
            ]
        )
    )

    with db.transaction():
        evidence_id = _persist_evidence_record(
            db,
            normalized=normalized,
            artifact_name=Path(artifact_path).name,
        )
        import bug_candidates_family21 as candidate_bridge

        candidate_bridge._promote_static_family_result(
            db,
            analysis_id=identity["analysis_id"],
            run_id=identity["run_id"],
            target=identity["target"],
            endpoint=str(hypothesis.get("endpoint") or ""),
            source_ref=str(hypothesis.get("source_ref") or f"differential:{differential_id}"),
            family="open_redirect",
            dedicated={
                "family": "open_redirect",
                "variant": str(hypothesis.get("bug_variant") or "controlled_external_destination"),
                "support": support,
                "contradict": contradict,
                "missing": missing,
                "rule_ids": rules,
                "summary": "Potential Open Redirect supported by analyst-verified differential evidence for a reserved controlled destination.",
                "direct": True,
            },
            confidence=90,
        )

        updated_row = db.one(
            "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
            (str(normalized["hypothesis_id"]),),
        )
        updated = dict(updated_row) if updated_row else hypothesis
        admission = _loads(updated.get("admission_json"), {})
        admitted = bool(admission.get("admitted"))
        admission_state = str(admission.get("state") or updated.get("state") or "")
        candidate_id = str(updated.get("promoted_candidate_id") or "")

        if candidate_id:
            db.execute(
                "INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    candidate_id,
                    evidence_id,
                    "support",
                    90,
                    "analyst_verified_differential_v2",
                    utc_now(),
                ),
            )

        db.execute(
            """INSERT INTO differential_evidence_adapter_runs(
            differential_id,analysis_id,hypothesis_id,source_run_id,target,family,artifact_hash,evidence_id,
            admission_state,admitted,candidate_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                differential_id,
                identity["analysis_id"],
                str(normalized["hypothesis_id"]),
                identity["run_id"],
                identity["target"],
                "open_redirect",
                artifact_hash,
                evidence_id,
                admission_state,
                int(admitted),
                candidate_id,
                "applied",
                utc_now(),
            ),
        )
        db.audit(
            "differential_evidence_v2_adapted",
            actor=actor,
            target=identity["target"],
            entity_type="analysis_hypothesis",
            entity_value=str(normalized["hypothesis_id"]),
            details={
                "differential_id": differential_id,
                "family": "open_redirect",
                "evidence_id": evidence_id,
                "admitted": admitted,
                "candidate_id": candidate_id,
                "network_requests_executed_by_adapter": 0,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": DIFFERENTIAL_EVIDENCE_ADAPTER_VERSION,
        "rule_version": DIFFERENTIAL_EVIDENCE_ADAPTER_RULE_VERSION,
        "differential_evidence_version": DIFFERENTIAL_EVIDENCE_VERSION,
        "status": "applied",
        "differential_id": differential_id,
        "analysis_id": identity["analysis_id"],
        "hypothesis_id": str(normalized["hypothesis_id"]),
        "family": "open_redirect",
        "target": identity["target"],
        "evidence_id": evidence_id,
        "admission_state": admission_state,
        "admitted": admitted,
        "candidate_id": candidate_id,
        "network_requests_executed_by_adapter": 0,
        "raw_bodies_stored": False,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }

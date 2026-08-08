from __future__ import annotations

import json
import uuid
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, parse_int, sha256_text, utc_now

AUDIT_VERSION = "1.0.0"


def _loads(value: Any, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _row(row: Any) -> dict[str, Any]:
    return dict(row) if row is not None else {}


def _rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _document(value: Any) -> dict[str, Any]:
    data = dict(value) if isinstance(value, Mapping) else {"value": value}
    payload = json_dumps(data)
    return {"sha256": sha256_text(payload), "data": data}


def _source_snapshot(db: Database, candidate: Mapping[str, Any], evidence_id: str, signal: Mapping[str, Any]) -> dict[str, Any]:
    """Capture the exact stored records available when evidence is linked.

    The snapshot intentionally stores structured observations and provenance, not
    hidden chain-of-thought. It is an audit artifact: conclusion -> evidence ->
    stored source record -> run/tool/parser metadata.
    """
    candidate_id = str(candidate.get("candidate_id") or "")
    analysis_id = str(candidate.get("analysis_id") or "")
    target = str(candidate.get("target") or "")
    endpoint = str(candidate.get("endpoint") or "")
    source_ref = str(candidate.get("source_ref") or "")
    alert_id = candidate.get("alert_id")

    documents: dict[str, Any] = {}
    evidence_row = db.one("SELECT * FROM evidence_records WHERE evidence_id=?", (evidence_id,))
    if evidence_row:
        documents["evidence_record"] = _document(_row(evidence_row))
    if alert_id is not None:
        alert = db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if alert:
            documents["alert"] = _document(_row(alert))
        result = db.one("SELECT * FROM analysis_results WHERE analysis_id=? AND alert_id=?", (analysis_id, alert_id))
        if result:
            documents["analysis_result"] = _document(_row(result))
    if endpoint:
        endpoint_row = db.one(
            "SELECT * FROM endpoint_intelligence WHERE target=? AND endpoint=? ORDER BY last_seen DESC LIMIT 1",
            (target, endpoint),
        )
        if endpoint_row:
            documents["endpoint_intelligence"] = _document(_row(endpoint_row))
        boundary = db.one(
            "SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? AND endpoint=? ORDER BY confidence DESC LIMIT 1",
            (analysis_id, endpoint),
        )
        if boundary:
            documents["authentication_boundary_diff"] = _document(_row(boundary))
        shape = db.one(
            "SELECT * FROM response_shape_diffs WHERE analysis_id=? AND endpoint=? ORDER BY confidence DESC LIMIT 1",
            (analysis_id, endpoint),
        )
        if shape:
            documents["response_shape_diff"] = _document(_row(shape))
        protocol = db.all(
            "SELECT * FROM protocol_findings WHERE analysis_id=? AND entity=? ORDER BY confidence DESC LIMIT 25",
            (analysis_id, endpoint),
        )
        if protocol:
            documents["protocol_findings"] = _document({"rows": _rows(protocol)})
        relations = db.all(
            "SELECT * FROM identity_relations WHERE analysis_id=? AND (source_value=? OR destination_value=?) ORDER BY confidence DESC LIMIT 50",
            (analysis_id, endpoint, endpoint),
        )
        if relations:
            documents["identity_relations"] = _document({"rows": _rows(relations)})

    artifact_candidates = {
        str(signal.get("artifact") or ""),
        str(signal.get("raw_reference") or ""),
        source_ref,
    }
    artifact_candidates = {value for value in artifact_candidates if value}
    js_urls = [value for value in artifact_candidates if ".js" in value.lower() and value.startswith(("http://", "https://"))]
    if js_urls:
        placeholders = ",".join("?" for _ in js_urls)
        js_rows = db.all(
            f"SELECT * FROM js_files WHERE target=? AND url IN ({placeholders}) ORDER BY last_seen DESC LIMIT 20",
            (target, *js_urls),
        )
        if js_rows:
            documents["javascript"] = _document({"rows": _rows(js_rows)})

    snapshot = {
        "audit_version": AUDIT_VERSION,
        "candidate": {
            "candidate_id": candidate_id,
            "candidate_fingerprint": str(candidate.get("candidate_fingerprint") or ""),
            "analysis_id": analysis_id,
            "source_run_id": str(candidate.get("source_run_id") or ""),
            "target": target,
            "endpoint": endpoint,
            "source_ref": source_ref,
            "alert_id": alert_id,
        },
        "evidence_id": evidence_id,
        "signal": dict(signal),
        "documents": documents,
        "captured_at": utc_now(),
    }
    snapshot["snapshot_hash"] = sha256_text(json_dumps(snapshot))
    return snapshot


def capture_evidence_snapshot(db: Database, candidate: Mapping[str, Any], evidence_id: str, signal: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = _source_snapshot(db, candidate, evidence_id, signal)
    db.execute(
        "INSERT OR REPLACE INTO candidate_evidence_snapshots(candidate_id,evidence_id,snapshot_hash,snapshot_json,created_at) VALUES(?,?,?,?,?)",
        (candidate["candidate_id"], evidence_id, snapshot["snapshot_hash"], json_dumps(snapshot), utc_now()),
    )
    return snapshot


def record_excluded_signal(
    db: Database,
    candidate: Mapping[str, Any],
    signal: Mapping[str, Any],
    polarity: str,
    root_fingerprint: str,
    reason_code: str,
    reason: str,
) -> None:
    payload = dict(signal)
    payload.pop("_selection_score", None)
    exclusion_id = str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"recon-monitor:excluded-evidence:{candidate['candidate_id']}:{polarity}:{root_fingerprint}:{reason_code}:{sha256_text(json_dumps(payload))}",
    ))
    db.execute(
        """INSERT OR REPLACE INTO candidate_evidence_exclusions(
        exclusion_id,candidate_id,analysis_id,root_fingerprint,polarity,reason_code,reason,signal_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (exclusion_id, candidate["candidate_id"], candidate["analysis_id"], root_fingerprint, polarity, reason_code, reason, json_dumps(payload), utc_now()),
    )


def _current_audit_snapshot(db: Database, candidate_id: str, reasoning: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _row(db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))
    evidence = _rows(db.all(
        """SELECT e.*,l.polarity AS link_polarity,l.weight,l.relation,s.snapshot_hash,s.snapshot_json
        FROM candidate_evidence_links l
        JOIN evidence_records e ON e.evidence_id=l.evidence_id
        LEFT JOIN candidate_evidence_snapshots s ON s.candidate_id=l.candidate_id AND s.evidence_id=l.evidence_id
        WHERE l.candidate_id=? ORDER BY l.polarity DESC,e.trust_score DESC,e.evidence_id""",
        (candidate_id,),
    ))
    exclusions = _rows(db.all(
        "SELECT * FROM candidate_evidence_exclusions WHERE candidate_id=? ORDER BY polarity,reason_code,exclusion_id",
        (candidate_id,),
    ))
    rankings = _rows(db.all("SELECT * FROM family_rankings WHERE candidate_id=? ORDER BY rank", (candidate_id,)))
    compact_evidence = []
    for row in evidence:
        compact_evidence.append({
            "evidence_id": row.get("evidence_id"),
            "polarity": row.get("link_polarity") or row.get("polarity"),
            "root_fingerprint": row.get("root_fingerprint"),
            "integrity_hash": row.get("integrity_hash"),
            "snapshot_hash": row.get("snapshot_hash"),
            "snapshot": _loads(row.get("snapshot_json"), {}),
        })
    snapshot = {
        "audit_version": AUDIT_VERSION,
        "candidate": {key: candidate.get(key) for key in (
            "candidate_id", "candidate_fingerprint", "analysis_id", "source_run_id", "target", "endpoint", "source_ref",
            "bug_family", "bug_variant", "title", "summary", "candidate_state", "calibrated_likelihood", "evidence_strength",
            "exploitability_confidence", "evidence_coverage", "observation_quality", "impact_potential", "investigation_value",
            "precondition_state", "reachability_state", "rule_version", "analyst_decision",
        )},
        "evidence": compact_evidence,
        "excluded": [{
            "exclusion_id": row.get("exclusion_id"), "root_fingerprint": row.get("root_fingerprint"), "polarity": row.get("polarity"),
            "reason_code": row.get("reason_code"), "reason": row.get("reason"), "signal": _loads(row.get("signal_json"), {}),
        } for row in exclusions],
        "family_rankings": rankings,
        "reasoning": dict(reasoning),
        "created_at": utc_now(),
    }
    snapshot["analysis_snapshot_hash"] = sha256_text(json_dumps(snapshot))
    return snapshot


def record_analysis_version(db: Database, candidate_id: str, reasoning: Mapping[str, Any], engine_version: str, rule_version: str) -> dict[str, Any]:
    snapshot = _current_audit_snapshot(db, candidate_id, reasoning)
    existing = db.one(
        "SELECT version FROM candidate_analysis_versions WHERE candidate_id=? AND analysis_snapshot_hash=?",
        (candidate_id, snapshot["analysis_snapshot_hash"]),
    )
    if existing:
        return {"version": int(existing["version"]), **snapshot, "reused": True}
    version_row = db.one("SELECT COALESCE(MAX(version),0)+1 AS version FROM candidate_analysis_versions WHERE candidate_id=?", (candidate_id,))
    version = int(version_row["version"] if version_row else 1)
    candidate = snapshot["candidate"]
    db.execute(
        """INSERT INTO candidate_analysis_versions(
        candidate_id,version,analysis_id,candidate_fingerprint,engine_version,rule_version,analysis_snapshot_hash,snapshot_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (candidate_id, version, candidate.get("analysis_id") or "", candidate.get("candidate_fingerprint") or "", engine_version, rule_version,
         snapshot["analysis_snapshot_hash"], json_dumps(snapshot), utc_now()),
    )
    return {"version": version, **snapshot, "reused": False}


def build_evidence_dossier(db: Database, candidate_id: str) -> dict[str, Any]:
    candidate = _row(db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))
    if not candidate:
        raise ValueError(f"Candidate not found: {candidate_id}")
    evidence = _rows(db.all(
        """SELECT e.*,l.polarity AS link_polarity,l.weight,l.relation,s.snapshot_hash,s.snapshot_json
        FROM candidate_evidence_links l
        JOIN evidence_records e ON e.evidence_id=l.evidence_id
        LEFT JOIN candidate_evidence_snapshots s ON s.candidate_id=l.candidate_id AND s.evidence_id=l.evidence_id
        WHERE l.candidate_id=? ORDER BY CASE l.polarity WHEN 'support' THEN 0 ELSE 1 END,e.trust_score DESC,e.evidence_id""",
        (candidate_id,),
    ))
    exclusions = _rows(db.all(
        "SELECT * FROM candidate_evidence_exclusions WHERE candidate_id=? ORDER BY polarity,reason_code,created_at",
        (candidate_id,),
    ))
    rankings = _rows(db.all("SELECT * FROM family_rankings WHERE candidate_id=? ORDER BY rank", (candidate_id,)))
    trace_row = db.one("SELECT * FROM candidate_reasoning_traces WHERE candidate_id=?", (candidate_id,))
    reasoning = _loads(trace_row["trace_json"], {}) if trace_row else _loads(candidate.get("reasoning_trace_json"), {})
    analysis = _row(db.one("SELECT * FROM analysis_runs WHERE id=?", (candidate.get("analysis_id"),)))

    verified = 0
    snapshot_rows = []
    groups: dict[str, list[str]] = defaultdict(list)
    for row in evidence:
        snapshot = _loads(row.get("snapshot_json"), {})
        stored_hash = str(row.get("snapshot_hash") or "")
        recalculated = ""
        if snapshot:
            unhashed = dict(snapshot)
            embedded = str(unhashed.pop("snapshot_hash", ""))
            recalculated = sha256_text(json_dumps(unhashed))
            if stored_hash and embedded == stored_hash and recalculated == stored_hash:
                verified += 1
        row["snapshot"] = snapshot
        row["snapshot_verified"] = bool(snapshot and stored_hash and recalculated == stored_hash)
        group = str(row.get("source_group") or row.get("source_kind") or "unknown")
        groups[group].append(str(row.get("evidence_id") or ""))
        snapshot_rows.append(row)

    current_versions = _rows(db.all("SELECT * FROM candidate_analysis_versions WHERE candidate_id=? ORDER BY version", (candidate_id,)))
    fingerprint = str(candidate.get("candidate_fingerprint") or "")
    history = _rows(db.all(
        """SELECT c.candidate_id,c.analysis_id,c.source_run_id,c.calibrated_likelihood,c.evidence_strength,c.evidence_coverage,
        c.observation_quality,c.candidate_state,c.updated_at,a.finished_at
        FROM bug_candidates c LEFT JOIN analysis_runs a ON a.id=c.analysis_id
        WHERE c.candidate_fingerprint=? ORDER BY COALESCE(a.finished_at,c.updated_at),c.updated_at""",
        (fingerprint,),
    )) if fingerprint else []

    timeline: list[dict[str, Any]] = []
    for row in snapshot_rows:
        timeline.append({
            "at": str(row.get("first_seen") or row.get("created_at") or ""),
            "kind": "evidence",
            "title": str(row.get("summary") or row.get("evidence_type") or "Evidence observed"),
            "evidence_id": row.get("evidence_id"),
            "source": str(row.get("source_kind") or ""),
        })
    for row in history:
        timeline.append({
            "at": str(row.get("finished_at") or row.get("updated_at") or ""),
            "kind": "analysis",
            "title": f"Analysis {row.get('calibrated_likelihood',0)}% · {row.get('candidate_state','')}",
            "analysis_id": row.get("analysis_id"),
            "source_run_id": row.get("source_run_id"),
        })
    timeline.sort(key=lambda item: (str(item.get("at") or ""), str(item.get("kind") or "")))

    support = [row for row in snapshot_rows if (row.get("link_polarity") or row.get("polarity")) == "support"]
    contradict = [row for row in snapshot_rows if (row.get("link_polarity") or row.get("polarity")) == "contradict"]
    preconditions = reasoning.get("preconditions", {}) if isinstance(reasoning, Mapping) else {}
    calibration = reasoning.get("calibration", {}) if isinstance(reasoning, Mapping) else {}
    lineage = reasoning.get("evidence_lineage", {}) if isinstance(reasoning, Mapping) else {}
    analysis_quality = round((parse_int(candidate.get("observation_quality"), 0) + parse_int(candidate.get("evidence_coverage"), 0)) / 2)
    confidence_breakdown = {
        "calibrated_likelihood": parse_int(candidate.get("calibrated_likelihood"), parse_int(candidate.get("likelihood_score"), 0)),
        "evidence_strength": parse_int(candidate.get("evidence_strength"), 0),
        "observation_quality": parse_int(candidate.get("observation_quality"), 0),
        "evidence_coverage": parse_int(candidate.get("evidence_coverage"), 0),
        "analysis_quality": analysis_quality,
        "exploitability_confidence": parse_int(candidate.get("exploitability_confidence"), 0),
        "independent_evidence_groups": len(groups),
        "supporting_evidence": len(support),
        "contradicting_evidence": len(contradict),
        "suppressed_correlated_signals": len(exclusions),
        "calibration": calibration,
        "preconditions": preconditions,
        "lineage": lineage,
    }
    return {
        "audit_version": AUDIT_VERSION,
        "candidate": candidate,
        "analysis": analysis,
        "supporting": support,
        "contradicting": contradict,
        "excluded": [{**row, "signal": _loads(row.get("signal_json"), {})} for row in exclusions],
        "groups": dict(groups),
        "family_rankings": rankings,
        "reasoning": reasoning,
        "confidence": confidence_breakdown,
        "timeline": timeline,
        "history": history,
        "versions": [{**row, "snapshot": _loads(row.get("snapshot_json"), {})} for row in current_versions],
        "integrity": {
            "snapshots": len(snapshot_rows),
            "verified": verified,
            "status": "verified" if snapshot_rows and verified == len(snapshot_rows) else "partial" if verified else "unavailable",
        },
    }

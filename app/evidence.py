from __future__ import annotations

import io
import json
import re
import zipfile
import hashlib
from typing import Any

from core import APP_VERSION, Database, json_dumps, safe_json_loads, utc_now


def _rows(db: Database, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in db.all(sql, params)]


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")[:100] or "evidence"



def _attach_v6_records(db: Database, payload: dict[str, Any], target: str) -> None:
    """Attach case-scoped Recon Monitor 6 intelligence without leaking unrelated targets."""
    case_ids = [str(row.get("case_id") or "") for row in payload.get("security_cases", []) if row.get("case_id")]
    validation_run_ids = [str(row.get("run_id") or "") for row in payload.get("validation_runs", []) if row.get("run_id")]
    story_ids = [str(row.get("story_id") or "") for row in payload.get("security_stories", []) if row.get("story_id")]
    if case_ids:
        placeholders = ",".join("?" for _ in case_ids)
        payload["revalidation_policies"] = _rows(db, f"SELECT * FROM revalidation_policies WHERE case_id IN ({placeholders})", tuple(case_ids))
        payload["review_rankings"] = _rows(db, f"SELECT * FROM review_rankings WHERE case_id IN ({placeholders})", tuple(case_ids))
        payload["burp_roundtrip_packages"] = _rows(db, f"SELECT * FROM burp_roundtrip_packages WHERE case_id IN ({placeholders})", tuple(case_ids))
        package_ids = [str(row.get("package_id") or "") for row in payload["burp_roundtrip_packages"] if row.get("package_id")]
        if package_ids:
            package_placeholders = ",".join("?" for _ in package_ids)
            payload["burp_roundtrip_results"] = _rows(db, f"SELECT * FROM burp_roundtrip_results WHERE package_id IN ({package_placeholders})", tuple(package_ids))
        else:
            payload["burp_roundtrip_results"] = []
        payload["report_quality_snapshots"] = _rows(db, f"SELECT * FROM report_quality_snapshots WHERE case_id IN ({placeholders})", tuple(case_ids))
    else:
        payload["revalidation_policies"] = []
        payload["review_rankings"] = []
        payload["burp_roundtrip_packages"] = []
        payload["burp_roundtrip_results"] = []
        payload["report_quality_snapshots"] = []
    if validation_run_ids:
        placeholders = ",".join("?" for _ in validation_run_ids)
        payload["validation_intelligence"] = _rows(db, f"SELECT * FROM validation_intelligence WHERE validation_run_id IN ({placeholders})", tuple(validation_run_ids))
    else:
        payload["validation_intelligence"] = []
    if story_ids:
        placeholders = ",".join("?" for _ in story_ids)
        payload["story_correlation_links"] = _rows(db, f"SELECT * FROM story_correlation_links WHERE story_id IN ({placeholders})", tuple(story_ids))
    else:
        payload["story_correlation_links"] = []
    payload["data_quality_snapshots"] = _rows(db, "SELECT * FROM data_quality_snapshots WHERE target=? ORDER BY created_at DESC LIMIT 50", (target,))
    payload["schedule_jobs"] = _rows(db, "SELECT * FROM schedule_jobs WHERE target=?", (target,))
    payload["notification_events"] = _rows(db, "SELECT * FROM notification_events WHERE target=? ORDER BY created_at DESC LIMIT 200", (target,))
    event_ids = [str(row.get("event_id") or "") for row in payload["notification_events"] if row.get("event_id")]
    if event_ids:
        placeholders = ",".join("?" for _ in event_ids)
        payload["notification_deliveries"] = _rows(db, f"SELECT * FROM notification_deliveries WHERE event_id IN ({placeholders})", tuple(event_ids))
    else:
        payload["notification_deliveries"] = []
    payload["target_template_applications"] = _rows(db, "SELECT * FROM target_template_applications WHERE target=? ORDER BY created_at DESC LIMIT 50", (target,))

def build_evidence_export(
    db: Database,
    *,
    target: str = "",
    entity_type: str = "",
    entity_value: str = "",
    alert_id: int = 0,
) -> tuple[str, bytes]:
    alert: dict[str, Any] | None = None
    if alert_id:
        row = db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if row:
            alert = dict(row)
            target = str(alert.get("target") or target)
            entity_type = "alert"
            entity_value = str(alert_id)
    if not target:
        raise ValueError("Target is required for evidence export")

    needle = str(alert.get("item") if alert else entity_value or "")
    like = f"%{needle}%"
    payload: dict[str, Any] = {
        "schema": 2,
        "generated_at": utc_now(),
        "recon_monitor_version": APP_VERSION,
        "target": target,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "alert": alert,
    }

    payload["alerts"] = _rows(
        db,
        "SELECT * FROM alerts WHERE target=? AND (id=? OR item LIKE ? OR title LIKE ?) ORDER BY risk_score DESC,last_seen DESC LIMIT 200",
        (target, alert_id, like, like),
    )
    alert_ids = [int(row["id"]) for row in payload["alerts"]]
    if alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)
        payload["alert_history"] = _rows(
            db,
            f"SELECT * FROM alert_history WHERE alert_id IN ({placeholders}) ORDER BY created_at",
            tuple(alert_ids),
        )
    else:
        payload["alert_history"] = []

    payload["assets"] = _rows(db, "SELECT * FROM assets WHERE target=? AND host LIKE ? LIMIT 500", (target, like))
    payload["dns_records"] = _rows(db, "SELECT * FROM dns_records WHERE target=? AND (host LIKE ? OR value LIKE ?) LIMIT 1000", (target, like, like))
    payload["urls"] = _rows(db, "SELECT * FROM urls WHERE target=? AND url LIKE ? LIMIT 1000", (target, like))
    payload["javascript_files"] = _rows(db, "SELECT * FROM js_files WHERE target=? AND url LIKE ? LIMIT 200", (target, like))
    payload["javascript_indicators"] = _rows(
        db,
        "SELECT * FROM js_indicators WHERE target=? AND (js_url LIKE ? OR value LIKE ?) LIMIT 2000",
        (target, like, like),
    )
    alert_details: dict[str, Any] = safe_json_loads(alert.get("details_json") if alert else None, {}, expected_type=dict)
    payload["javascript_diffs"] = _rows(
        db,
        "SELECT id,run_id,target,js_url,old_raw_hash,new_raw_hash,old_semantic_hash,new_semantic_hash,summary_json,diff_text,diff_path,created_at FROM js_diffs WHERE target=? AND (js_url LIKE ? OR CAST(id AS TEXT)=?) ORDER BY created_at DESC LIMIT 100",
        (target, like, str(alert_details.get("diff_id", ""))),
    )
    payload["endpoints"] = _rows(
        db,
        "SELECT * FROM endpoint_intelligence WHERE target=? AND endpoint LIKE ? ORDER BY confidence DESC LIMIT 1000",
        (target, like),
    )
    payload["fingerprints"] = _rows(
        db,
        "SELECT * FROM fingerprints WHERE target=? AND url LIKE ? LIMIT 500",
        (target, like),
    )
    payload["technologies"] = _rows(
        db,
        "SELECT * FROM technology_observations WHERE target=? AND (url LIKE ? OR technology LIKE ?) ORDER BY confidence DESC LIMIT 500",
        (target, like, like),
    )
    payload["asset_edges"] = _rows(
        db,
        "SELECT * FROM asset_edges WHERE target=? AND (source_value LIKE ? OR destination_value LIKE ?) LIMIT 2000",
        (target, like, like),
    )
    payload["notes"] = _rows(
        db,
        "SELECT * FROM investigation_notes WHERE target=? AND (entity_value LIKE ? OR note LIKE ?) ORDER BY created_at DESC LIMIT 500",
        (target, like, like),
    )
    payload["tags"] = _rows(
        db,
        "SELECT * FROM entity_tags WHERE target=? AND entity_value LIKE ? ORDER BY tag LIMIT 500",
        (target, like),
    )

    payload["analysis_results"] = _rows(
        db,
        "SELECT r.* FROM analysis_results r WHERE r.target=? AND (r.alert_id=? OR r.hypothesis LIKE ? OR r.endpoint_schema_json LIKE ?) ORDER BY r.created_at DESC LIMIT 200",
        (target, alert_id, like, like),
    )
    analysis_ids = sorted({str(row.get("analysis_id") or "") for row in payload["analysis_results"] if row.get("analysis_id")})
    if analysis_ids:
        placeholders = ",".join("?" for _ in analysis_ids)
        payload["analysis_runs"] = _rows(db, f"SELECT * FROM analysis_runs WHERE id IN ({placeholders})", tuple(analysis_ids))
        payload["analysis_clusters"] = _rows(db, f"SELECT * FROM analysis_clusters WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["endpoint_schemas"] = _rows(db, f"SELECT * FROM endpoint_schemas WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["javascript_dataflows"] = _rows(db, f"SELECT * FROM js_dataflows WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["source_map_intelligence"] = _rows(db, f"SELECT * FROM source_map_intelligence WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["secret_intelligence"] = _rows(db, f"SELECT * FROM secret_intelligence WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["graphql_intelligence"] = _rows(db, f"SELECT * FROM graphql_intelligence WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["api_relationships"] = _rows(db, f"SELECT * FROM api_relationships WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["deployment_signatures"] = _rows(db, f"SELECT * FROM deployment_signatures WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["bug_candidates"] = _rows(db, f"SELECT * FROM bug_candidates WHERE analysis_id IN ({placeholders}) AND (alert_id=? OR target=? OR endpoint LIKE ? OR source_ref LIKE ?)", (*analysis_ids, alert_id, target, like, like))
        payload["authentication_boundaries"] = _rows(db, f"SELECT * FROM authentication_boundaries WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["response_shape_fingerprints"] = _rows(db, f"SELECT * FROM response_shape_fingerprints WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["semantic_js_units"] = _rows(db, f"SELECT * FROM semantic_js_units WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["feature_flags"] = _rows(db, f"SELECT * FROM feature_flags WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["endpoint_contracts"] = _rows(db, f"SELECT * FROM endpoint_contracts WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["parameter_relationships"] = _rows(db, f"SELECT * FROM parameter_relationships WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["candidate_bundles"] = _rows(db, f"SELECT * FROM candidate_bundles WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["candidate_feedback"] = _rows(db, f"SELECT * FROM candidate_feedback WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["candidate_evaluations"] = _rows(db, f"SELECT * FROM candidate_evaluations WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["behavioral_observations"] = _rows(db, f"SELECT * FROM behavioral_observations WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["authentication_boundary_diffs"] = _rows(db, f"SELECT * FROM authentication_boundary_diffs WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["response_shape_diffs"] = _rows(db, f"SELECT * FROM response_shape_diffs WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["protocol_findings"] = _rows(db, f"SELECT * FROM protocol_findings WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["identity_entities"] = _rows(db, f"SELECT * FROM identity_entities WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["identity_relations"] = _rows(db, f"SELECT * FROM identity_relations WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["evidence_records"] = _rows(db, f"SELECT * FROM evidence_records WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["candidate_evidence_links"] = _rows(db, f"SELECT l.* FROM candidate_evidence_links l JOIN bug_candidates c ON c.candidate_id=l.candidate_id WHERE c.analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["family_rankings"] = _rows(db, f"SELECT * FROM family_rankings WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["candidate_reasoning_traces"] = _rows(db, f"SELECT * FROM candidate_reasoning_traces WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["shadow_rule_results"] = _rows(db, f"SELECT * FROM shadow_rule_results WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["reasoning_evaluations"] = _rows(db, f"SELECT * FROM reasoning_evaluations WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["reasoning_regression_gates"] = _rows(db, f"SELECT * FROM reasoning_regression_gates WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["engine_quality_snapshots"] = _rows(db, f"SELECT * FROM engine_quality_snapshots WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["security_cases"] = _rows(db, f"SELECT * FROM security_cases WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        case_ids = [str(row["case_id"]) for row in payload["security_cases"]]
        if case_ids:
            case_placeholders = ",".join("?" for _ in case_ids)
            payload["security_case_members"] = _rows(db, f"SELECT * FROM security_case_members WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["security_case_events"] = _rows(db, f"SELECT * FROM security_case_events WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_packages"] = _rows(db, f"SELECT * FROM validation_packages WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["report_drafts"] = _rows(db, f"SELECT * FROM report_drafts WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_plans"] = _rows(db, f"SELECT * FROM validation_plans WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_runs"] = _rows(db, f"SELECT * FROM validation_runs WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            run_ids = [str(row["run_id"]) for row in payload["validation_runs"]]
            if run_ids:
                run_placeholders = ",".join("?" for _ in run_ids)
                payload["validation_observations"] = _rows(db, f"SELECT * FROM validation_observations WHERE run_id IN ({run_placeholders})", tuple(run_ids))
                payload["validation_feedback"] = _rows(db, f"SELECT * FROM validation_feedback WHERE run_id IN ({run_placeholders})", tuple(run_ids))
            else:
                payload["validation_observations"] = []; payload["validation_feedback"] = []
            payload["imported_http_evidence"] = _rows(db, f"SELECT * FROM imported_http_evidence WHERE case_id IN ({case_placeholders})", tuple(case_ids))
        else:
            payload["security_case_members"] = []; payload["security_case_events"] = []; payload["validation_packages"] = []; payload["report_drafts"] = []
            payload["validation_plans"] = []; payload["validation_runs"] = []; payload["validation_observations"] = []; payload["validation_feedback"] = []; payload["imported_http_evidence"] = []
        payload["security_stories"] = _rows(db, f"SELECT * FROM security_stories WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["incremental_checkpoints"] = _rows(db, f"SELECT * FROM incremental_checkpoints WHERE analysis_id IN ({placeholders})", tuple(analysis_ids))
        payload["target_learning_profiles"] = _rows(db, "SELECT * FROM target_learning_profiles WHERE target=?", (target,))
        payload["scope_snapshots"] = _rows(db, "SELECT * FROM scope_snapshots WHERE target=? ORDER BY created_at DESC LIMIT 20", (target,))
    else:
        for key in ("analysis_runs","analysis_clusters","endpoint_schemas","javascript_dataflows","source_map_intelligence","secret_intelligence","graphql_intelligence","api_relationships","deployment_signatures","bug_candidates","authentication_boundaries","response_shape_fingerprints","semantic_js_units","feature_flags","endpoint_contracts","parameter_relationships","candidate_bundles","candidate_feedback","candidate_evaluations","behavioral_observations","authentication_boundary_diffs","response_shape_diffs","protocol_findings","identity_entities","identity_relations","evidence_records","candidate_evidence_links","family_rankings","candidate_reasoning_traces","shadow_rule_results","reasoning_evaluations","reasoning_regression_gates","engine_quality_snapshots","security_cases","security_case_members","security_case_events","validation_packages","report_drafts","validation_plans","validation_runs","validation_observations","validation_feedback","imported_http_evidence","security_stories","incremental_checkpoints","target_learning_profiles","scope_snapshots"):
            payload[key] = []
        # Validation records may exist for a case even when the exported alert
        # has no analysis_results row (for example after an analyst-only import).
        payload["security_cases"] = _rows(db, "SELECT * FROM security_cases WHERE target=? ORDER BY updated_at DESC LIMIT 200", (target,))
        case_ids = [str(row["case_id"]) for row in payload["security_cases"]]
        if case_ids:
            case_placeholders = ",".join("?" for _ in case_ids)
            payload["security_case_members"] = _rows(db, f"SELECT * FROM security_case_members WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["security_case_events"] = _rows(db, f"SELECT * FROM security_case_events WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_packages"] = _rows(db, f"SELECT * FROM validation_packages WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["report_drafts"] = _rows(db, f"SELECT * FROM report_drafts WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_plans"] = _rows(db, f"SELECT * FROM validation_plans WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            payload["validation_runs"] = _rows(db, f"SELECT * FROM validation_runs WHERE case_id IN ({case_placeholders})", tuple(case_ids))
            run_ids = [str(row["run_id"]) for row in payload["validation_runs"]]
            if run_ids:
                run_placeholders = ",".join("?" for _ in run_ids)
                payload["validation_observations"] = _rows(db, f"SELECT * FROM validation_observations WHERE run_id IN ({run_placeholders})", tuple(run_ids))
                payload["validation_feedback"] = _rows(db, f"SELECT * FROM validation_feedback WHERE run_id IN ({run_placeholders})", tuple(run_ids))
            payload["imported_http_evidence"] = _rows(db, f"SELECT * FROM imported_http_evidence WHERE case_id IN ({case_placeholders})", tuple(case_ids))

    _attach_v6_records(db, payload, target)
    files: dict[str, bytes] = {}
    files["evidence.json"] = (json_dumps(payload, pretty=True) + "\n").encode("utf-8")
    summary = [
        "# Recon Monitor evidence package",
        "",
        f"- Generated: {payload['generated_at']}",
        f"- Target: {target}",
        f"- Entity: {entity_type} {entity_value}",
        f"- Alert ID: {alert_id or 'n/a'}",
        "",
        "## Included records",
    ]
    for key, value in payload.items():
        if isinstance(value, list):
            summary.append(f"- {key}: {len(value)}")
    summary.extend([
        "",
        "This package contains monitoring evidence and metadata. It does not assert that a vulnerability exists.",
    ])
    files["README.md"] = ("\n".join(summary) + "\n").encode("utf-8")
    for diff in payload["javascript_diffs"]:
        if diff.get("diff_text"):
            files[f"js-diffs/{int(diff['id']):06d}-{_safe(str(diff['js_url']))}.diff"] = str(diff["diff_text"]).encode("utf-8")
    manifest = {
        "schema": 2,
        "generated_at": utc_now(),
        "target": target,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "run_version": APP_VERSION,
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in sorted(files.items())},
    }
    manifest_bytes = (json_dumps(manifest, pretty=True) + "\n").encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    db.execute(
        "INSERT INTO evidence_manifests(target,entity_type,entity_value,manifest_sha256,manifest_json,created_at) VALUES(?,?,?,?,?,?)",
        (target, entity_type or "entity", entity_value or str(alert_id), manifest_hash, json_dumps(manifest), utc_now()),
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("MANIFEST.json", manifest_bytes)
        archive.writestr("MANIFEST.sha256", manifest_hash + "  MANIFEST.json\n")
    filename = f"recon-evidence-{_safe(target)}-{_safe(entity_type or 'entity')}-{_safe(entity_value or str(alert_id))}.zip"
    return filename, buffer.getvalue()

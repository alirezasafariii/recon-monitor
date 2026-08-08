from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import platform
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Iterable

from core import (
    APP_VERSION,
    AppPaths,
    Config,
    Database,
    Logger,
    PolicySet,
    ReconError,
    TelegramNotifier,
    atomic_write_bytes,
    atomic_write_text,
    json_dumps,
    parse_bool,
    parse_int,
    safe_json_loads,
    sha256_bytes,
    sha256_text,
    utc_now,
)

PLATFORM_V6_VERSION = "6.0.4"
UTC = dt.timezone.utc

VALID_REVALIDATION_TRIGGERS = {
    "after_deployment",
    "interval",
    "response_shape_change",
    "authentication_boundary_change",
    "evidence_change",
    "manual",
}
NOTIFICATION_MODES = {"immediate", "digest", "system_warning", "silent"}
RETENTION_CATEGORIES = {
    "raw_http_artifacts",
    "javascript_snapshots",
    "temporary_exports",
    "logs",
    "backups",
    "confirmed_evidence",
    "case_evidence",
}

TARGET_TEMPLATES: dict[str, dict[str, Any]] = {
    "passive-only": {
        "label": "Passive only",
        "description": "Historical and passive discovery with all active modules disabled.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 1, "crawl_depth": 1, "max_urls": 5000, "max_http_requests": 4000, "max_runtime_minutes": 90},
        "analysis": {"profile": "quiet", "validation_default": "offline"},
    },
    "standard-web": {
        "label": "Standard web application",
        "description": "Balanced web recon with JavaScript and endpoint intelligence.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 3, "crawl_depth": 2, "max_urls": 10000, "max_http_requests": 10000, "max_runtime_minutes": 120},
        "analysis": {"profile": "balanced", "validation_default": "offline"},
    },
    "javascript-spa": {
        "label": "JavaScript-heavy SPA",
        "description": "Higher JavaScript and source-map coverage for modern SPAs.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": True, "ports": False, "nuclei": False},
        "limits": {"request_rate": 2, "crawl_depth": 3, "max_urls": 20000, "max_js_files": 800, "max_http_requests": 18000, "max_runtime_minutes": 180},
        "analysis": {"profile": "balanced", "focus": ["javascript", "source_maps", "dom", "postmessage"]},
    },
    "api-heavy": {
        "label": "API-heavy target",
        "description": "Endpoint contract, response-shape and authorization-context focused profile.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 2, "crawl_depth": 2, "max_urls": 25000, "max_http_requests": 20000, "max_runtime_minutes": 180},
        "analysis": {"profile": "balanced", "focus": ["rest", "response_shapes", "authorization", "identity_graph"]},
    },
    "graphql": {
        "label": "GraphQL application",
        "description": "Low-noise GraphQL discovery and stored-operation analysis; no automatic mutations.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 2, "crawl_depth": 2, "max_urls": 15000, "max_http_requests": 10000, "max_runtime_minutes": 150},
        "analysis": {"profile": "balanced", "focus": ["graphql", "authorization"], "graphql_mutations": False},
    },
    "large-enterprise": {
        "label": "Large enterprise scope",
        "description": "Incremental, budgeted monitoring for broad scopes.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 3, "dns_rate": 150, "crawl_depth": 2, "max_urls": 75000, "max_http_requests": 50000, "max_runtime_minutes": 360, "max_new_assets": 20000},
        "analysis": {"profile": "quiet", "incremental": True},
    },
    "low-noise": {
        "label": "Low-noise monitoring",
        "description": "Conservative collection and quiet analysis profile.",
        "modules": {"subdomains": True, "dns": True, "urls": True, "javascript": True, "endpoint_validation": False, "fingerprint": True, "screenshots": False, "ports": False, "nuclei": False},
        "limits": {"request_rate": 1, "crawl_depth": 1, "max_urls": 6000, "max_http_requests": 5000, "max_runtime_minutes": 120},
        "analysis": {"profile": "quiet", "minimum_investigation_value": 65},
    },
}


def _loads(value: Any, default: Any) -> Any:
    return safe_json_loads(value, default, expected_type=type(default))


def _parse_ts(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _age_days(value: Any) -> float:
    parsed = _parse_ts(value)
    if not parsed:
        return 9999.0
    return max(0.0, (dt.datetime.now(UTC) - parsed).total_seconds() / 86400)


def _latest_run(db: Database, target: str | None = None) -> str:
    if target:
        row = db.one(
            "SELECT r.id FROM runs r JOIN run_targets t ON t.run_id=r.id WHERE r.status='success' AND t.target=? ORDER BY r.finished_at DESC LIMIT 1",
            (target,),
        )
    else:
        row = db.one("SELECT id FROM runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
    return str(row["id"]) if row else ""


def _latest_analysis(db: Database, target: str | None = None) -> str:
    if target:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' AND target IN (?, '*') ORDER BY finished_at DESC LIMIT 1", (target,))
    else:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
    return str(row["id"]) if row else ""


def _case_candidate(db: Database, case_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case:
        raise ReconError(f"Security case not found: {case_id}")
    member = db.one(
        "SELECT member_id FROM security_case_members WHERE case_id=? AND member_type='candidate' ORDER BY created_at LIMIT 1",
        (case_id,),
    )
    candidate = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (str(member["member_id"]),)) if member else None
    return dict(case), dict(candidate) if candidate else {}


# ---------------------------------------------------------------------------
# Validation intelligence and revalidation
# ---------------------------------------------------------------------------

def validation_intelligence(db: Database, validation_run_id: str, *, persist: bool = True) -> dict[str, Any]:
    run = db.one("SELECT * FROM validation_runs WHERE run_id=?", (validation_run_id,))
    if not run:
        raise ReconError(f"Validation run not found: {validation_run_id}")
    run_d = dict(run)
    observations = [dict(row) for row in db.all("SELECT * FROM validation_observations WHERE run_id=? ORDER BY sequence", (validation_run_id,))]
    case, candidate = _case_candidate(db, str(run["case_id"]))
    plan = db.one("SELECT * FROM validation_plans WHERE plan_id=?", (str(run["plan_id"]),))
    plan_json = _loads(plan["plan_json"], {}) if plan else {}
    summary = _loads(run["summary_json"], {})

    successful = [row for row in observations if row.get("status_code") is not None]
    methods = {str(row.get("method") or "").upper() for row in successful}
    same_scope = all(str(row.get("url") or "").startswith(("http://", "https://")) for row in successful)
    stopped = str(run["status"]) in {"stopped_for_safety", "failed"} or str(run["result"]) in {"stopped_for_safety", "blocked_by_scope"}
    reliability = 35
    reliability += min(25, len(successful) * 9)
    reliability += 15 if str(run["status"]) == "completed" else 0
    reliability += 10 if not stopped else -20
    reliability += 8 if len(methods) <= 2 else 2
    reliability += 7 if same_scope else -25
    reliability = max(0, min(100, reliability))

    contexts = set()
    shape_hashes = []
    statuses = []
    for row in observations:
        obs = _loads(row.get("observation_json"), {})
        context = str(obs.get("context") or obs.get("authentication_context") or "anonymous")
        contexts.add(context)
        if obs.get("shape_hash"):
            shape_hashes.append(str(obs["shape_hash"]))
        if row.get("status_code") is not None:
            statuses.append(int(row["status_code"]))
    expected_contexts = {"anonymous"}
    family = str(candidate.get("bug_family") or case.get("primary_family") or "")
    if family in {"broken_object_authorization", "broken_function_authorization", "authentication_session", "graphql_authorization", "websocket_authorization"}:
        expected_contexts.add("authenticated_test_identity")
    if family in {"broken_object_authorization", "broken_function_authorization"}:
        expected_contexts.add("second_authorized_test_identity")
    context_coverage = round(100 * len(contexts & expected_contexts) / max(1, len(expected_contexts)))

    identity_confidence = 100 if plan_json.get("test_identity_ids") else (70 if "authenticated_test_identity" in contexts else 35)
    scope_confidence = 100 if same_scope and not str(run["result"]) == "blocked_by_scope" else 0
    comparability = 40
    if len(statuses) >= 2:
        comparability += 20
    if len(set(shape_hashes)) >= 1:
        comparability += 20
    if summary.get("comparison") or summary.get("baseline"):
        comparability += 15
    if stopped:
        comparability -= 20
    comparability = max(0, min(100, comparability))
    freshness = max(0, min(100, round(100 - _age_days(run["finished_at"] or run["started_at"]) * 4)))

    previous = db.one(
        "SELECT run_id,result,summary_json,finished_at FROM validation_runs WHERE case_id=? AND run_id<>? AND status='completed' ORDER BY finished_at DESC LIMIT 1",
        (str(run["case_id"]), validation_run_id),
    )
    baseline_delta: dict[str, Any] = {"previous_validation_run": str(previous["run_id"]) if previous else "", "historical_protection_observations": 0}
    if previous:
        prev_summary = _loads(previous["summary_json"], {})
        baseline_delta.update(
            {
                "previous_result": str(previous["result"]),
                "result_changed": str(previous["result"]) != str(run["result"]),
                "previous_finished_at": previous["finished_at"],
                "summary_changed": sha256_text(json_dumps(prev_summary)) != sha256_text(json_dumps(summary)),
            }
        )
    endpoint = str(candidate.get("endpoint") or "")
    if endpoint:
        baseline_delta["historical_protection_observations"] = parse_int(
            (db.one("SELECT COUNT(*) count FROM authentication_boundaries WHERE endpoint=? AND lower(boundary) LIKE '%protected%'", (endpoint,)) or {"count": 0})["count"],
            0,
        )
        latest_shape = db.one("SELECT shape_hash,created_at FROM response_shape_fingerprints WHERE endpoint=? ORDER BY created_at DESC LIMIT 1", (endpoint,))
        if latest_shape:
            baseline_delta["latest_stored_shape_hash"] = str(latest_shape["shape_hash"])
            baseline_delta["latest_stored_shape_at"] = latest_shape["created_at"]

    limitations: list[str] = []
    if context_coverage < 100:
        limitations.append("Not all expected authorization contexts were observed.")
    if identity_confidence < 80:
        limitations.append("Test-identity provenance is incomplete or absent.")
    if comparability < 70:
        limitations.append("Response comparability is limited by missing baselines or shape metadata.")
    if len(successful) < 2:
        limitations.append("Only one or no successful live observation is available.")
    if stopped:
        limitations.append("The run stopped or was blocked by a safety condition.")

    overall = round(
        reliability * 0.28
        + context_coverage * 0.22
        + comparability * 0.18
        + identity_confidence * 0.12
        + scope_confidence * 0.12
        + freshness * 0.08
    )
    payload = {
        "version": PLATFORM_V6_VERSION,
        "validation_run_id": validation_run_id,
        "case_id": str(run["case_id"]),
        "target": str(run["target"]),
        "result": str(run["result"]),
        "overall_confidence": max(0, min(100, overall)),
        "test_reliability": reliability,
        "context_coverage": context_coverage,
        "response_comparability": comparability,
        "identity_confidence": identity_confidence,
        "scope_confidence": scope_confidence,
        "freshness": freshness,
        "observed_contexts": sorted(contexts),
        "expected_contexts": sorted(expected_contexts),
        "baseline_delta": baseline_delta,
        "limitations": limitations,
        "generated_at": utc_now(),
    }
    if persist:
        db.execute(
            "INSERT INTO validation_intelligence(validation_run_id,case_id,overall_confidence,test_reliability,context_coverage,response_comparability,identity_confidence,scope_confidence,freshness,baseline_delta_json,limitations_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(validation_run_id) DO UPDATE SET overall_confidence=excluded.overall_confidence,test_reliability=excluded.test_reliability,context_coverage=excluded.context_coverage,response_comparability=excluded.response_comparability,identity_confidence=excluded.identity_confidence,scope_confidence=excluded.scope_confidence,freshness=excluded.freshness,baseline_delta_json=excluded.baseline_delta_json,limitations_json=excluded.limitations_json,created_at=excluded.created_at",
            (
                validation_run_id,
                str(run["case_id"]),
                payload["overall_confidence"],
                reliability,
                context_coverage,
                comparability,
                identity_confidence,
                scope_confidence,
                freshness,
                json_dumps(baseline_delta),
                json_dumps(limitations),
                payload["generated_at"],
            ),
        )
        policy = db.one("SELECT trigger,interval_days FROM revalidation_policies WHERE case_id=? AND enabled=1", (str(run["case_id"]),))
        if policy:
            next_due = None
            if str(policy["trigger"]) == "interval":
                next_due_dt = dt.datetime.now(UTC) + dt.timedelta(days=parse_int(policy["interval_days"], 7, 1, 365))
                next_due = next_due_dt.isoformat().replace("+00:00", "Z")
            db.execute("UPDATE revalidation_policies SET last_run_at=?,next_due_at=?,updated_at=? WHERE case_id=?", (str(run["finished_at"] or run["started_at"] or utc_now()), next_due, utc_now(), str(run["case_id"])))
        db.audit("validation_intelligence_updated", entity_type="validation_run", entity_value=validation_run_id, target=str(run["target"]), details={"overall_confidence": payload["overall_confidence"]})
    return payload


def set_revalidation_policy(
    db: Database,
    case_id: str,
    trigger: str,
    *,
    interval_days: int = 7,
    enabled: bool = True,
    actor: str = "system",
) -> dict[str, Any]:
    trigger = trigger.strip().lower()
    if trigger not in VALID_REVALIDATION_TRIGGERS:
        raise ReconError(f"Invalid revalidation trigger: {trigger}")
    _case_candidate(db, case_id)
    interval_days = parse_int(interval_days, 7, 1, 365)
    now = dt.datetime.now(UTC)
    next_due = now + dt.timedelta(days=interval_days) if trigger == "interval" and enabled else None
    db.execute(
        "INSERT INTO revalidation_policies(case_id,trigger,interval_days,enabled,last_run_at,next_due_at,created_by,created_at,updated_at) VALUES(?,?,?,?,NULL,?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET trigger=excluded.trigger,interval_days=excluded.interval_days,enabled=excluded.enabled,next_due_at=excluded.next_due_at,created_by=excluded.created_by,updated_at=excluded.updated_at",
        (case_id, trigger, interval_days, 1 if enabled else 0, next_due.isoformat().replace("+00:00", "Z") if next_due else None, actor, utc_now(), utc_now()),
    )
    db.audit("revalidation_policy_updated", actor=actor, entity_type="security_case", entity_value=case_id, details={"trigger": trigger, "interval_days": interval_days, "enabled": enabled})
    return dict(db.one("SELECT * FROM revalidation_policies WHERE case_id=?", (case_id,)))


def due_revalidations(db: Database, *, limit: int = 100) -> list[dict[str, Any]]:
    """Return policies whose configured trigger has actually changed since the last run."""
    rows = [dict(row) for row in db.all(
        "SELECT p.*,c.target,c.title,c.state,c.validation_state,c.analysis_id FROM revalidation_policies p JOIN security_cases c ON c.case_id=p.case_id WHERE p.enabled=1 AND c.state NOT IN ('rejected','reported','closed') ORDER BY COALESCE(p.next_due_at,p.updated_at) LIMIT ?",
        (parse_int(limit, 100, 1, 1000),),
    )]
    now = dt.datetime.now(UTC)
    due: list[dict[str, Any]] = []
    source_map = {
        "after_deployment": ("deployment_signatures", "created_at"),
        "response_shape_change": ("response_shape_diffs", "created_at"),
        "authentication_boundary_change": ("authentication_boundary_diffs", "created_at"),
        "evidence_change": ("evidence_records", "created_at"),
    }
    for row in rows:
        trigger = str(row.get("trigger") or "manual")
        reason = ""
        if trigger == "manual":
            continue
        if trigger == "interval":
            next_due = _parse_ts(row.get("next_due_at"))
            if next_due and next_due <= now:
                reason = "interval elapsed"
        elif trigger in source_map:
            table, timestamp_col = source_map[trigger]
            latest = db.one(f"SELECT MAX({timestamp_col}) latest FROM {table} WHERE analysis_id=?", (str(row.get("analysis_id") or ""),))
            latest_ts = _parse_ts(latest["latest"] if latest else None)
            last_run = _parse_ts(row.get("last_run_at"))
            if latest_ts and (not last_run or latest_ts > last_run):
                reason = f"{trigger.replace('_', ' ')} observed at {latest_ts.isoformat()}"
        if reason:
            row["due_reason"] = reason
            due.append(row)
    return due[:parse_int(limit, 100, 1, 1000)]


def process_due_revalidations(paths: AppPaths, config: Config, db: Database, *, limit: int = 50, execute_offline: bool = True, actor: str = "scheduler") -> dict[str, Any]:
    """Prepare and optionally execute only offline revalidation plans.

    This function never elevates a case to passive-live validation and never
    sends a network request. Live revalidation always remains candidate-specific
    and requires the existing explicit approval gates.
    """
    from safe_validation import create_validation_plan, execute_validation_plan
    due = due_revalidations(db, limit=limit)
    prepared: list[dict[str, Any]] = []
    for item in due:
        case_id = str(item["case_id"])
        plan = create_validation_plan(paths, db, case_id, requested_level="offline", actor=actor)
        result: dict[str, Any] = {"case_id": case_id, "plan_id": plan["plan_id"], "trigger": item["trigger"], "due_reason": item.get("due_reason", "")}
        if execute_offline:
            run = execute_validation_plan(paths, config, db, str(plan["plan_id"]), allow_live=False, actor=actor)
            result.update({"validation_run_id": run["run_id"], "result": run["result"], "network_requests": run.get("network_requests", 0)})
        prepared.append(result)
    db.audit("due_revalidations_processed", actor=actor, entity_type="revalidation", entity_value="offline", details={"due": len(due), "processed": len(prepared), "execute_offline": execute_offline})
    return {"due": len(due), "processed": len(prepared), "execute_offline": execute_offline, "items": prepared}


# ---------------------------------------------------------------------------
# Data quality and blind-spot engine
# ---------------------------------------------------------------------------

def data_quality_snapshot(db: Database, run_id: str | None = None, target: str | None = None, *, persist: bool = True) -> dict[str, Any]:
    run_id = run_id or _latest_run(db, target)
    if not run_id:
        raise ReconError("No completed recon run is available")
    targets = [str(row["target"]) for row in db.all("SELECT target FROM run_targets WHERE run_id=? ORDER BY target", (run_id,))]
    if target:
        targets = [item for item in targets if item == target]
    stages = [dict(row) for row in db.all("SELECT target,stage,status,metrics_json,error FROM stage_runs WHERE run_id=?", (run_id,))]
    stage_map = {(str(row["target"]), str(row["stage"])): row for row in stages}
    expected_stages = ["subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "report"]

    target_results: dict[str, Any] = {}
    all_blind_spots: list[dict[str, str]] = []
    for item in targets or [target or "*"]:
        statuses = {stage: str(stage_map.get((item, stage), {}).get("status") or "missing") for stage in expected_stages}
        stage_success = sum(1 for status in statuses.values() if status in {"success", "skipped"})
        tool_success = round(100 * stage_success / len(expected_stages))
        assets = parse_int((db.one("SELECT COUNT(*) count FROM assets WHERE target=? AND last_run_id=?", (item, run_id)) or {"count": 0})["count"], 0)
        resolved = parse_int((db.one("SELECT COUNT(*) count FROM assets WHERE target=? AND last_run_id=? AND resolved=1", (item, run_id)) or {"count": 0})["count"], 0)
        urls = parse_int((db.one("SELECT COUNT(*) count FROM urls WHERE target=? AND last_run_id=?", (item, run_id)) or {"count": 0})["count"], 0)
        js_files = parse_int((db.one("SELECT COUNT(*) count FROM js_files WHERE target=? AND last_run_id=?", (item, run_id)) or {"count": 0})["count"], 0)
        js_indicators = parse_int((db.one("SELECT COUNT(*) count FROM js_indicators WHERE target=? AND last_run_id=?", (item, run_id)) or {"count": 0})["count"], 0)
        fingerprints = parse_int((db.one("SELECT COUNT(*) count FROM fingerprints WHERE target=? AND last_run_id=?", (item, run_id)) or {"count": 0})["count"], 0)
        analysis_id = _latest_analysis(db, item)
        endpoints = parse_int((db.one("SELECT COUNT(*) count FROM endpoint_contracts WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0
        response_shapes = parse_int((db.one("SELECT COUNT(*) count FROM response_shape_fingerprints WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0
        auth_contexts = parse_int((db.one("SELECT COUNT(DISTINCT context) count FROM behavioral_observations WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0
        comparisons = parse_int((db.one("SELECT COUNT(*) count FROM authentication_boundary_diffs WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0
        evidence = parse_int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0
        parser_types = parse_int((db.one("SELECT COUNT(DISTINCT parser_name) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0) if analysis_id else 0

        dns_coverage = round(100 * resolved / max(1, assets)) if assets else 0
        http_coverage = round(100 * fingerprints / max(1, resolved)) if resolved else 0
        js_coverage = min(100, round(100 * js_files / max(1, fingerprints))) if fingerprints else 0
        endpoint_coverage = min(100, round(100 * endpoints / max(1, urls))) if urls else 0
        shape_coverage = min(100, round(100 * response_shapes / max(1, endpoints))) if endpoints else 0
        auth_coverage = min(100, auth_contexts * 25)
        behavioral_coverage = min(100, comparisons * 10)
        parser_coverage = min(100, parser_types * 12)
        metrics = {
            "tool_stage_success": tool_success,
            "dns_coverage": dns_coverage,
            "http_coverage": http_coverage,
            "javascript_coverage": js_coverage,
            "endpoint_contract_coverage": endpoint_coverage,
            "response_shape_coverage": shape_coverage,
            "authentication_context_coverage": auth_coverage,
            "behavioral_comparison_coverage": behavioral_coverage,
            "parser_coverage": parser_coverage,
            "counts": {"assets": assets, "resolved": resolved, "urls": urls, "javascript_files": js_files, "javascript_indicators": js_indicators, "fingerprints": fingerprints, "endpoint_contracts": endpoints, "response_shapes": response_shapes, "authentication_contexts": auth_contexts, "behavioral_diffs": comparisons, "evidence_records": evidence},
            "stage_status": statuses,
        }
        score = round(
            tool_success * 0.18
            + dns_coverage * 0.11
            + http_coverage * 0.14
            + js_coverage * 0.10
            + endpoint_coverage * 0.13
            + shape_coverage * 0.12
            + auth_coverage * 0.12
            + behavioral_coverage * 0.06
            + parser_coverage * 0.04
        )
        blind_spots: list[dict[str, str]] = []
        if auth_contexts == 0:
            blind_spots.append({"severity": "high", "code": "no_authenticated_context", "message": "No authenticated behavioral context is stored."})
        elif auth_contexts < 2:
            blind_spots.append({"severity": "medium", "code": "single_auth_context", "message": "Only one authentication context is available; role and ownership comparisons remain weak."})
        if js_files == 0 and statuses.get("javascript") == "success":
            blind_spots.append({"severity": "medium", "code": "no_javascript_artifacts", "message": "The JavaScript stage completed but no JavaScript artifact was retained."})
        if endpoints and response_shapes == 0:
            blind_spots.append({"severity": "high", "code": "no_response_shapes", "message": "Endpoint contracts exist but no response-shape observations are available."})
        if statuses.get("fingerprint") not in {"success", "skipped"}:
            blind_spots.append({"severity": "high", "code": "fingerprint_stage_incomplete", "message": "HTTP fingerprint collection did not complete successfully."})
        missing = [stage for stage, status in statuses.items() if status not in {"success", "skipped"}]
        if missing:
            blind_spots.append({"severity": "high", "code": "incomplete_stages", "message": "Incomplete stages: " + ", ".join(missing)})
        if evidence == 0 and analysis_id:
            blind_spots.append({"severity": "medium", "code": "no_reasoning_evidence", "message": "Analysis exists but no unified evidence record is available."})
        target_results[item] = {"score": max(0, min(100, score)), "metrics": metrics, "blind_spots": blind_spots}
        all_blind_spots.extend({"target": item, **spot} for spot in blind_spots)

    overall = round(sum(result["score"] for result in target_results.values()) / max(1, len(target_results)))
    payload = {"version": PLATFORM_V6_VERSION, "run_id": run_id, "target": target or "*", "score": overall, "targets": target_results, "blind_spots": all_blind_spots, "generated_at": utc_now()}
    if persist:
        db.execute(
            "INSERT INTO data_quality_snapshots(run_id,target,score,metrics_json,blind_spots_json,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,target) DO UPDATE SET score=excluded.score,metrics_json=excluded.metrics_json,blind_spots_json=excluded.blind_spots_json,created_at=excluded.created_at",
            (run_id, target or "*", overall, json_dumps(target_results), json_dumps(all_blind_spots), payload["generated_at"]),
        )
        db.audit("data_quality_snapshot_created", entity_type="run", entity_value=run_id, target=target or "", details={"score": overall, "blind_spots": len(all_blind_spots)})
    return payload


# ---------------------------------------------------------------------------
# Cost-aware review queue
# ---------------------------------------------------------------------------

def review_value_for_case(db: Database, case_id: str, *, persist: bool = True) -> dict[str, Any]:
    case, candidate = _case_candidate(db, case_id)
    likelihood = parse_int(candidate.get("calibrated_likelihood"), parse_int(candidate.get("likelihood_score"), 0), 0, 100)
    impact = parse_int(candidate.get("impact_score"), parse_int(candidate.get("priority_score"), parse_int(case.get("priority_score"), 0)), 0, 100)
    coverage = parse_int(candidate.get("evidence_coverage"), 0, 0, 100)
    exploitability = parse_int(candidate.get("exploitability_confidence"), 0, 0, 100)
    novelty = parse_int(candidate.get("novelty_score"), 50, 0, 100)
    unknowns = _loads(candidate.get("unknowns_json"), [])
    family = str(candidate.get("bug_family") or case.get("primary_family") or "unknown")
    family_row = db.one("SELECT sample_count,observed_rate FROM family_calibration WHERE target IN (?, '*') AND bug_family=? ORDER BY CASE WHEN target=? THEN 0 ELSE 1 END,updated_at DESC LIMIT 1", (str(case["target"]), family, str(case["target"])))
    historical_precision = round(float(family_row["observed_rate"]) * 100) if family_row else 50

    validation_level = ""
    plan = db.one("SELECT level,plan_json FROM validation_plans WHERE case_id=? ORDER BY created_at DESC LIMIT 1", (case_id,))
    if plan:
        validation_level = str(plan["level"])
    effort = 20
    required_contexts: list[str] = []
    if family in {"broken_object_authorization", "broken_function_authorization"}:
        effort += 45
        required_contexts.extend(["two authorized test identities", "registered test objects"])
    elif family in {"graphql_authorization", "websocket_authorization"}:
        effort += 30
        required_contexts.append("authorized protocol context")
    elif family in {"race_condition", "business_logic", "file_upload", "ssrf", "path_traversal"}:
        effort += 55
        required_contexts.append("manual or staging validation")
    elif family in {"information_disclosure", "open_redirect", "cors", "sensitive_caching", "source_maps", "secrets"}:
        effort += 5
    if validation_level in {"controlled", "manual_only"}:
        effort += 20
    if len(unknowns) >= 4:
        effort += 10
    effort = max(5, min(100, effort))
    effort_band = "quick" if effort <= 30 else "moderate" if effort <= 60 else "deep"

    information_gain = round((100 - coverage) * 0.55 + len(unknowns) * 6 + (15 if case.get("validation_state") in {"not_started", "inconclusive"} else 0))
    information_gain = max(0, min(100, information_gain))
    security_value = likelihood * 0.22 + impact * 0.34 + exploitability * 0.15 + novelty * 0.10 + historical_precision * 0.19
    review_value = round(security_value * (0.55 + information_gain / 220) * 100 / max(35, effort))
    review_value = max(0, min(100, review_value))
    explanation = {
        "formula": "security_value × expected_information_gain ÷ analyst_effort",
        "likelihood": likelihood,
        "impact": impact,
        "exploitability": exploitability,
        "novelty": novelty,
        "historical_family_precision": historical_precision,
        "evidence_coverage": coverage,
        "unknown_count": len(unknowns),
    }
    payload = {"case_id": case_id, "review_value": review_value, "analyst_effort": effort, "effort_band": effort_band, "expected_information_gain": information_gain, "required_contexts": required_contexts, "explanation": explanation, "updated_at": utc_now()}
    if persist:
        db.execute(
            "INSERT INTO review_rankings(case_id,review_value,analyst_effort,information_gain,required_contexts_json,explanation_json,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET review_value=excluded.review_value,analyst_effort=excluded.analyst_effort,information_gain=excluded.information_gain,required_contexts_json=excluded.required_contexts_json,explanation_json=excluded.explanation_json,updated_at=excluded.updated_at",
            (case_id, review_value, effort, information_gain, json_dumps(required_contexts), json_dumps(explanation), payload["updated_at"]),
        )
        db.execute("UPDATE security_cases SET review_value=?,analyst_effort=?,information_gain=?,updated_at=? WHERE case_id=?", (review_value, effort, information_gain, payload["updated_at"], case_id))
    return payload


def rank_review_queue(db: Database, *, target: str | None = None, limit: int = 100, refresh: bool = False) -> list[dict[str, Any]]:
    where = "WHERE state NOT IN ('rejected','reported','closed')"
    params: list[Any] = []
    if target:
        where += " AND target=?"
        params.append(target)
    rows = [dict(row) for row in db.all(f"SELECT * FROM security_cases {where} ORDER BY COALESCE(review_value,0) DESC,priority_score DESC,updated_at DESC LIMIT ?", (*params, parse_int(limit, 100, 1, 1000)))]
    if refresh:
        for row in rows:
            review_value_for_case(db, str(row["case_id"]), persist=True)
        rows = [dict(row) for row in db.all(f"SELECT * FROM security_cases {where} ORDER BY COALESCE(review_value,0) DESC,priority_score DESC,updated_at DESC LIMIT ?", (*params, parse_int(limit, 100, 1, 1000)))]
    return rows


# ---------------------------------------------------------------------------
# Burp round-trip packages and report quality
# ---------------------------------------------------------------------------

def build_burp_roundtrip_package(paths: AppPaths, db: Database, case_id: str, *, actor: str = "system") -> dict[str, Any]:
    case, candidate = _case_candidate(db, case_id)
    package_id = "burp-" + uuid.uuid4().hex[:14]
    endpoint = str(candidate.get("endpoint") or "")
    method_match = re.match(r"^([A-Z]+)\s+", endpoint)
    method = method_match.group(1) if method_match else "GET"
    url = endpoint.split(" ", 1)[1] if method_match and " " in endpoint else endpoint
    # v7 enriches the redacted handoff with investigation context only.
    # It never exports credentials, cookies, raw request/response bodies, or exploit payloads.
    try:
        from workspace_v7 import evidence_gap_for_case, authentication_contexts
        evidence_gap = evidence_gap_for_case(db, case_id, persist=False)
        auth_context = authentication_contexts(db, target=str(case["target"]), analysis_id=str(case.get("analysis_id") or ""), persist=False)
    except Exception:
        evidence_gap = {"coverage": 0, "next_actions": [], "requirements": []}
        auth_context = {"contexts": []}
    package = {
        "format": "recon-monitor-burp-roundtrip-v2",
        "package_id": package_id,
        "case_id": case_id,
        "target": str(case["target"]),
        "title": str(case["title"]),
        "primary_family": str(case["primary_family"]),
        "request_context": {"method": method, "url_or_endpoint": url, "headers": {}, "body": None, "query_values_removed": True},
        "candidate_reasoning": _loads(candidate.get("reasoning_trace_json"), {}),
        "known_parameters": _loads(candidate.get("parameters_json"), []),
        "expected_relationship": _loads(candidate.get("quality_explanation_json"), {}).get("ownership_model", "unknown"),
        "missing_evidence": _loads(candidate.get("unknowns_json"), []),
        "evidence_gap": {"coverage": evidence_gap.get("coverage", 0), "requirements": evidence_gap.get("requirements", []), "next_actions": evidence_gap.get("next_actions", [])},
        "authorized_context_labels": [str(item.get("label") or item.get("context_label") or item.get("context") or "") for item in (auth_context if isinstance(auth_context, list) else auth_context.get("contexts", [])) if str(item.get("label") or item.get("context_label") or item.get("context") or "")][:20],
        "safe_stop_conditions": ["Do not access third-party objects", "Do not execute state-changing actions", "Stop on unexpected sensitive data", "Keep all requests within authorized scope"],
        "return_schema": {"observed_behavior": "string", "expected_behavior": "string", "decision": "confirmed_by_analyst|rejected|needs_more_evidence", "reason_code": "string", "request_metadata": "redacted object", "response_metadata": "redacted object"},
        "created_by": actor,
        "created_at": utc_now(),
    }
    export_dir = paths.reports / "burp-roundtrip"
    export_dir.mkdir(parents=True, exist_ok=True)
    export_path = export_dir / f"{package_id}.json"
    atomic_write_text(export_path, json_dumps(package, pretty=True) + "\n", 0o600)
    digest = sha256_bytes(export_path.read_bytes())
    db.execute("INSERT INTO burp_roundtrip_packages(package_id,case_id,target,export_path,sha256,package_json,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?, 'exported',?,?,?)", (package_id, case_id, str(case["target"]), str(export_path), digest, json_dumps(package), actor, package["created_at"], package["created_at"]))
    db.audit("burp_roundtrip_exported", actor=actor, target=str(case["target"]), entity_type="security_case", entity_value=case_id, details={"package_id": package_id, "sha256": digest})
    return {**package, "path": str(export_path), "sha256": digest}


def import_burp_roundtrip_result(db: Database, package_id: str, result: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    package = db.one("SELECT * FROM burp_roundtrip_packages WHERE package_id=?", (package_id,))
    if not package:
        raise ReconError(f"Burp round-trip package not found: {package_id}")
    allowed_decisions = {"confirmed_by_analyst", "rejected", "needs_more_evidence", "useful"}
    decision = str(result.get("decision") or "needs_more_evidence")
    if decision not in allowed_decisions:
        raise ReconError("Invalid round-trip decision")
    safe_result = {
        "observed_behavior": str(result.get("observed_behavior") or "")[:4000],
        "expected_behavior": str(result.get("expected_behavior") or "")[:4000],
        "decision": decision,
        "reason_code": str(result.get("reason_code") or "insufficient_evidence")[:120],
        "request_metadata": _redact_mapping(result.get("request_metadata") if isinstance(result.get("request_metadata"), dict) else {}),
        "response_metadata": _redact_mapping(result.get("response_metadata") if isinstance(result.get("response_metadata"), dict) else {}),
        "raw_body_stored": False,
        "imported_by": actor,
        "imported_at": utc_now(),
    }
    result_id = "burpr-" + uuid.uuid4().hex[:14]
    db.execute("INSERT INTO burp_roundtrip_results(result_id,package_id,case_id,result_json,decision,reason_code,imported_by,created_at) VALUES(?,?,?,?,?,?,?,?)", (result_id, package_id, str(package["case_id"]), json_dumps(safe_result), decision, safe_result["reason_code"], actor, safe_result["imported_at"]))
    db.execute("UPDATE burp_roundtrip_packages SET status='returned',updated_at=? WHERE package_id=?", (safe_result["imported_at"], package_id))
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (str(package["case_id"]), "burp_roundtrip_returned", actor, json_dumps({"result_id": result_id, "decision": decision, "reason_code": safe_result["reason_code"]}), safe_result["imported_at"]))
    db.audit("burp_roundtrip_imported", actor=actor, target=str(package["target"]), entity_type="security_case", entity_value=str(package["case_id"]), details={"result_id": result_id, "decision": decision})
    try:
        from workspace_v7 import case_autopilot
        case_autopilot(db, str(package["case_id"]), actor=actor, persist=True)
    except Exception:
        pass
    return {"result_id": result_id, "package_id": package_id, "case_id": str(package["case_id"]), **safe_result}


def _redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    sensitive = re.compile(r"authorization|cookie|token|secret|password|session|api[-_]?key|email|phone|account", re.I)
    for key, item in value.items():
        key_s = str(key)[:120]
        if sensitive.search(key_s):
            redacted[key_s] = "<redacted>"
        elif isinstance(item, dict):
            redacted[key_s] = _redact_mapping(item)
        elif isinstance(item, list):
            redacted[key_s] = ["<redacted>" if isinstance(v, (dict, list)) else str(v)[:300] for v in item[:100]]
        else:
            text = str(item)
            redacted[key_s] = text[:1000]
    return redacted


def report_quality(db: Database, draft_id: str | None = None, case_id: str | None = None, *, persist: bool = True) -> dict[str, Any]:
    row = None
    if draft_id:
        row = db.one("SELECT * FROM report_drafts WHERE draft_id=?", (draft_id,))
    elif case_id:
        row = db.one("SELECT * FROM report_drafts WHERE case_id=? ORDER BY updated_at DESC LIMIT 1", (case_id,))
    if not row:
        raise ReconError("Report draft not found")
    body = _loads(row["body_json"], {})
    checks: list[dict[str, Any]] = []
    dimensions = [
        ("affected_asset", ["affected_asset", "asset", "target"], 12),
        ("observed_behavior", ["observed_behavior", "observation", "summary"], 18),
        ("expected_behavior", ["expected_behavior", "expected"], 14),
        ("impact", ["impact", "security_impact"], 16),
        ("evidence", ["evidence", "supporting_evidence"], 18),
        ("reproduction", ["reproduction", "reproduction_notes", "steps"], 12),
        ("scope_confirmation", ["scope_confirmation", "scope"], 6),
        ("redaction", ["redaction", "redacted"], 4),
    ]
    score = 0
    missing = []
    for label, keys, weight in dimensions:
        value = next((body.get(key) for key in keys if body.get(key)), None)
        present = bool(value and str(value).strip() not in {"", "missing", "unknown", "[]", "{}"})
        if present:
            score += weight
        else:
            missing.append(label.replace("_", " "))
        checks.append({"dimension": label, "present": present, "weight": weight})
    case = db.one("SELECT scope_status,state,validation_state FROM security_cases WHERE case_id=?", (str(row["case_id"]),))
    if case and str(case["scope_status"]) not in {"in_scope", "confirmed", "authorized"}:
        score = max(0, score - 8)
        missing.append("confirmed scope status")
    payload = {"draft_id": str(row["draft_id"]), "case_id": str(row["case_id"]), "quality_score": max(0, min(100, score)), "checks": checks, "missing": sorted(set(missing)), "ready_for_submission": score >= 85 and not missing, "generated_at": utc_now()}
    if persist:
        db.execute("INSERT INTO report_quality_snapshots(draft_id,case_id,quality_score,checks_json,missing_json,created_at) VALUES(?,?,?,?,?,?)", (str(row["draft_id"]), str(row["case_id"]), payload["quality_score"], json_dumps(checks), json_dumps(payload["missing"]), payload["generated_at"]))
        db.execute("UPDATE report_drafts SET readiness_score=?,updated_at=? WHERE draft_id=?", (payload["quality_score"], payload["generated_at"], str(row["draft_id"])))
    return payload


# ---------------------------------------------------------------------------
# Story correlation v2
# ---------------------------------------------------------------------------

def correlate_security_stories(db: Database, analysis_id: str | None = None, *, persist: bool = True) -> dict[str, Any]:
    analysis_id = analysis_id or _latest_analysis(db)
    if not analysis_id:
        return {"analysis_id": "", "stories": 0, "links": 0}
    candidates = [dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY target,updated_at", (analysis_id,))]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in candidates:
        endpoint = str(candidate.get("endpoint") or "")
        clean = endpoint.split(" ", 1)[-1]
        try:
            path = urllib.parse.urlsplit(clean).path or clean
        except ValueError:
            path = clean
        segments = [seg for seg in path.split("/") if seg]
        prefix = "/" + "/".join(segments[:2]) if segments else str(candidate.get("bug_family") or "unknown")
        deployment = db.one("SELECT signature FROM deployment_signatures WHERE analysis_id=? AND target=? ORDER BY created_at DESC LIMIT 1", (analysis_id, str(candidate.get("target") or "")))
        deployment_key = str(deployment["signature"])[:12] if deployment else "none"
        key = (str(candidate.get("target") or "*"), f"{prefix}|{deployment_key}")
        groups.setdefault(key, []).append(candidate)
    stories = 0
    links = 0
    now = utc_now()
    for (target, correlation_key), rows in groups.items():
        if not rows:
            continue
        story_key = sha256_text(f"v2|{analysis_id}|{target}|{correlation_key}")
        story_id = "story-" + story_key[:16]
        families = sorted({str(row.get("bug_family") or "unknown") for row in rows})
        endpoints = sorted({str(row.get("endpoint") or "") for row in rows if row.get("endpoint")})
        priority = max(parse_int(row.get("investigation_value"), parse_int(row.get("priority_score"), 0)) for row in rows)
        timeline = [{"at": row.get("updated_at"), "type": "candidate", "candidate_id": row.get("candidate_id"), "family": row.get("bug_family"), "endpoint": row.get("endpoint")} for row in rows[:100]]
        metadata = {"correlation_version": "2", "correlation_key": correlation_key, "families": families, "endpoints": endpoints, "candidate_count": len(rows), "dimensions": ["deployment_window", "endpoint_prefix", "object_model", "authentication_boundary"]}
        title = f"{target}: correlated security change"
        summary = f"{len(rows)} candidate(s) across {len(families)} family/families share an endpoint/deployment context."
        if persist:
            db.execute(
                "INSERT INTO security_stories(story_id,story_key,analysis_id,target,title,summary,priority_score,status,timeline_json,correlation_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'open',?,?,?,?) ON CONFLICT(target,story_key) DO UPDATE SET title=excluded.title,summary=excluded.summary,priority_score=excluded.priority_score,timeline_json=excluded.timeline_json,correlation_json=excluded.correlation_json,updated_at=excluded.updated_at",
                (story_id, story_key, analysis_id, target, title, summary, priority, json_dumps(timeline), json_dumps(metadata), now, now),
            )
            db.execute("DELETE FROM story_correlation_links WHERE story_id=?", (story_id,))
            for row in rows:
                db.execute("INSERT OR IGNORE INTO story_correlation_links(story_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?, 'candidate', ?, 'correlated', ?, ?)", (story_id, str(row["candidate_id"]), json_dumps({"family": row.get("bug_family"), "endpoint": row.get("endpoint")}), now))
                links += 1
        stories += 1
    if persist:
        db.audit("security_story_correlation_v2", entity_type="analysis", entity_value=analysis_id, details={"stories": stories, "links": links})
    return {"analysis_id": analysis_id, "stories": stories, "links": links, "generated_at": now}


# ---------------------------------------------------------------------------
# Scheduler and smart notifications
# ---------------------------------------------------------------------------

def _cadence_seconds(cadence: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([mhd])\s*", cadence.lower())
    if not match:
        raise ReconError("Cadence must look like 30m, 3h, or 1d")
    value = int(match.group(1))
    multiplier = {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    return max(3600, min(31 * 86400, value * multiplier))


def generate_schedule_job(paths: AppPaths, db: Database, target: str, *, apply: bool = False, actor: str = "system") -> dict[str, Any]:
    policy = db.one("SELECT * FROM schedule_policies WHERE target=?", (target,))
    if not policy:
        raise ReconError(f"Schedule policy not found for target: {target}")
    interval = _cadence_seconds(str(policy["cadence"]))
    label = "com.reconmonitor.target." + re.sub(r"[^A-Za-z0-9_.-]+", "-", target)[:80]
    generated_dir = paths.state / "launchagents"
    generated_dir.mkdir(parents=True, exist_ok=True)
    generated = generated_dir / f"{label}.plist"
    payload = {
        "Label": label,
        "ProgramArguments": [sys.executable, str(paths.app / "recon_monitor.py"), "suite", "scheduled-run", "--target", target],
        "WorkingDirectory": str(paths.root),
        "StartInterval": interval,
        "RunAtLoad": False,
        "StandardOutPath": str(paths.logs / f"schedule-{target}.log"),
        "StandardErrorPath": str(paths.logs / f"schedule-{target}.log"),
        "ProcessType": "Background",
        "Nice": 5,
    }
    atomic_write_bytes(generated, plistlib.dumps(payload), 0o600)
    applied_path = ""
    status = "generated"
    error = ""
    if apply:
        if sys.platform != "darwin":
            raise ReconError("Applying LaunchAgent schedules is supported only on macOS")
        destination = Path.home() / "Library" / "LaunchAgents" / generated.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(generated, destination)
        os.chmod(destination, 0o600)
        applied_path = str(destination)
        result = subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(destination)], capture_output=True, text=True, check=False)
        if result.returncode not in {0, 37}:
            status = "apply_failed"
            error = (result.stderr or result.stdout).strip()[:1000]
        else:
            status = "enabled"
    now = utc_now()
    db.execute("INSERT INTO schedule_jobs(target,label,generated_path,applied_path,status,last_error,last_synced_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(target) DO UPDATE SET label=excluded.label,generated_path=excluded.generated_path,applied_path=excluded.applied_path,status=excluded.status,last_error=excluded.last_error,last_synced_at=excluded.last_synced_at,updated_at=excluded.updated_at", (target, label, str(generated), applied_path, status, error, now, now, now))
    db.audit("schedule_job_synced", actor=actor, target=target, entity_type="schedule", entity_value=label, details={"apply": apply, "status": status, "interval_seconds": interval})
    return {"target": target, "label": label, "generated_path": str(generated), "applied_path": applied_path, "status": status, "error": error, "interval_seconds": interval}



def _inside_quiet_hours(spec: str, now: dt.datetime | None = None) -> bool:
    spec = str(spec or "").strip()
    if not spec:
        return False
    match = re.fullmatch(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", spec)
    if not match:
        raise ReconError("Quiet hours must look like 22:00-07:00")
    start = int(match.group(1)) * 60 + int(match.group(2))
    end = int(match.group(3)) * 60 + int(match.group(4))
    if not (0 <= start < 1440 and 0 <= end < 1440):
        raise ReconError("Quiet-hour values are out of range")
    local = now or dt.datetime.now().astimezone()
    minute = local.hour * 60 + local.minute
    return start <= minute < end if start < end else minute >= start or minute < end


def run_scheduled_workflow(paths: AppPaths, config: Config, db: Database, target: str, *, dry_run: bool = False, actor: str = "scheduler") -> dict[str, Any]:
    policy = db.one("SELECT * FROM schedule_policies WHERE target=? AND enabled=1", (target,))
    if not policy:
        raise ReconError(f"Enabled schedule policy not found for target: {target}")
    quiet = _inside_quiet_hours(str(policy["quiet_hours"] or ""))
    plan = {
        "target": target,
        "cadence": str(policy["cadence"]),
        "max_runtime_minutes": parse_int(policy["max_runtime_minutes"], 120),
        "request_budget": parse_int(policy["request_budget"], 10000),
        "quiet_hours": str(policy["quiet_hours"] or ""),
        "inside_quiet_hours": quiet,
        "commands": ["authorized recon run", "platform intelligence sync", "offline due revalidation", "immediate notification delivery"],
    }
    if dry_run or quiet:
        return {**plan, "dry_run": dry_run, "status": "skipped_quiet_hours" if quiet else "planned"}
    started = utc_now()
    command = [str(paths.root / "recon-monitor.sh"), "run", "--target", target, "--no-progress"]
    completed = subprocess.run(command, cwd=paths.root, capture_output=True, text=True, timeout=parse_int(policy["max_runtime_minutes"], 120, 1, 1440) * 60, check=False)
    if completed.returncode != 0:
        queue_notification(db, {"event_type": "run_failure", "title": f"Scheduled run failed for {target}", "score": 95, "error": (completed.stderr or completed.stdout)[-1000:]}, target=target, actor=actor)
    sync = platform_v6_sync(paths, db)
    revalidation = process_due_revalidations(paths, config, db, limit=50, execute_offline=True, actor=actor)
    notifications = deliver_notifications(paths, config, db, mode="immediate", limit=50, dry_run=False)
    now = utc_now()
    db.execute("UPDATE schedule_policies SET last_run_at=?,updated_at=? WHERE target=?", (now, now, target))
    db.audit("scheduled_workflow_completed", actor=actor, target=target, entity_type="schedule", entity_value=target, details={"returncode": completed.returncode, "started_at": started, "revalidations": revalidation["processed"], "notifications": notifications["delivered"]})
    return {**plan, "status": "success" if completed.returncode == 0 else "failed", "returncode": completed.returncode, "stdout_tail": completed.stdout[-2000:], "stderr_tail": completed.stderr[-2000:], "sync": sync, "revalidation": revalidation, "notifications": notifications}

def classify_notification(event: dict[str, Any]) -> tuple[str, int, str]:
    event_type = str(event.get("event_type") or event.get("category") or "general")
    score = parse_int(event.get("score"), parse_int(event.get("risk_score"), 0), 0, 100)
    text = " ".join(str(event.get(key) or "") for key in ("title", "summary", "message", "event_type")).lower()
    if any(term in text for term in ("database integrity", "scope violation", "run failure", "backup failure")):
        return "system_warning", max(score, 90), "operational safety event"
    if any(term in text for term in ("authentication boundary", "sensitive response", "validated candidate", "critical asset")) or score >= 85:
        return "immediate", max(score, 85), "high-signal security event"
    if any(term in text for term in ("known noise", "duplicate", "expected behavior")):
        return "silent", score, "known low-value or duplicate event"
    return "digest", score, "normal security intelligence event"


def queue_notification(db: Database, event: dict[str, Any], *, target: str = "*", actor: str = "system") -> dict[str, Any]:
    mode, score, reason = classify_notification(event)
    event_type = str(event.get("event_type") or event.get("category") or "general")
    policy = db.one("SELECT * FROM notification_policies WHERE target IN (?, '*') AND event_type=? AND enabled=1 ORDER BY CASE WHEN target=? THEN 0 ELSE 1 END LIMIT 1", (target, event_type, target))
    if policy:
        mode = str(policy["mode"])
        if score < parse_int(policy["minimum_score"], 0):
            mode = "silent"
            reason = "below notification policy threshold"
    canonical = {k: event.get(k) for k in sorted(event) if k not in {"timestamp", "created_at", "updated_at"}}
    fingerprint = sha256_text(f"{target}|{event_type}|{json_dumps(canonical)}")
    cutoff = (dt.datetime.now(UTC) - dt.timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    existing = db.one("SELECT event_id,status,occurrences FROM notification_events WHERE fingerprint=? AND created_at>=? ORDER BY created_at DESC LIMIT 1", (fingerprint, cutoff))
    if existing:
        db.execute("UPDATE notification_events SET occurrences=occurrences+1,last_seen_at=? WHERE event_id=?", (utc_now(), str(existing["event_id"])))
        return {"event_id": str(existing["event_id"]), "deduplicated": True, "mode": mode, "score": score}
    event_id = "notify-" + uuid.uuid4().hex[:14]
    now = utc_now()
    db.execute("INSERT INTO notification_events(event_id,target,event_type,mode,score,fingerprint,payload_json,status,occurrences,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,'queued',1,?,?)", (event_id, target, event_type, mode, score, fingerprint, json_dumps({**event, "classification_reason": reason}), now, now))
    db.audit("notification_queued", actor=actor, target=target, entity_type="notification", entity_value=event_id, details={"mode": mode, "score": score, "event_type": event_type})
    return {"event_id": event_id, "deduplicated": False, "mode": mode, "score": score, "reason": reason}


def deliver_notifications(paths: AppPaths, config: Config, db: Database, *, mode: str = "immediate", limit: int = 50, dry_run: bool = False) -> dict[str, Any]:
    if mode not in {"immediate", "digest", "system_warning"}:
        raise ReconError("Delivery mode must be immediate, digest, or system_warning")
    rows = [dict(row) for row in db.all("SELECT * FROM notification_events WHERE status='queued' AND mode=? ORDER BY score DESC,created_at LIMIT ?", (mode, parse_int(limit, 50, 1, 500)))]
    if not rows:
        return {"mode": mode, "queued": 0, "delivered": 0, "dry_run": dry_run}
    lines = [f"Recon Monitor {APP_VERSION} — {mode.replace('_', ' ').title()}"]
    for row in rows:
        payload = _loads(row["payload_json"], {})
        lines.append(f"• [{row['score']}] {payload.get('title') or payload.get('message') or row['event_type']} ({row['target']})")
    message = "\n".join(lines)[:15000]
    delivered = 0
    error = ""
    if not dry_run:
        logger = Logger(paths, verbose=False)
        notifier = TelegramNotifier(config, logger)
        try:
            if notifier.send(message):
                delivered = len(rows)
        except Exception as exc:  # keep queue on delivery failure
            error = str(exc)
    if dry_run:
        delivered = 0
    elif delivered:
        now = utc_now()
        for row in rows:
            db.execute("UPDATE notification_events SET status='delivered',delivered_at=? WHERE event_id=?", (now, str(row["event_id"])))
            db.execute("INSERT INTO notification_deliveries(event_id,channel,status,error,created_at) VALUES(?, 'telegram', 'delivered', '', ?)", (str(row["event_id"]), now))
    return {"mode": mode, "queued": len(rows), "delivered": delivered, "dry_run": dry_run, "message": message if dry_run else "", "error": error}


# ---------------------------------------------------------------------------
# Security posture, retention, performance diagnostics, templates
# ---------------------------------------------------------------------------

def security_posture(paths: AppPaths, config: Config, db: Database, *, persist: bool = True, apply_safe_permissions: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def add(name: str, ok: bool, detail: str, severity: str = "medium") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "severity": severity})

    auth = config.bool("DASHBOARD_AUTH_ENABLED", False)
    add("dashboard_authentication", auth, "Enabled" if auth else "Disabled; local-only use is safer but authentication is recommended.", "high")
    add("session_csrf", True, "Session-mode forms use same-origin and CSRF validation.")
    add("localhost_default", True, "Dashboard and API reject remote binding unless explicitly permitted.")
    add("keychain_support", True, "macOS Keychain references are supported for configured secrets.")
    expired_tokens = parse_int((db.one("SELECT COUNT(*) count FROM api_tokens WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at<=?", (utc_now(),)) or {"count": 0})["count"], 0)
    unscoped_tokens = parse_int((db.one("SELECT COUNT(*) count FROM api_tokens WHERE revoked_at IS NULL AND COALESCE(scopes_json,'[]') IN ('[]','')") or {"count": 0})["count"], 0)
    add("api_token_expiration", expired_tokens == 0, f"Expired active tokens: {expired_tokens}", "high")
    add("api_token_scopes", unscoped_tokens == 0, f"Unscoped active tokens: {unscoped_tokens}")
    chain = verify_audit_chain(db)
    add("audit_integrity_chain", bool(chain["ok"]), f"Verified {chain['verified']} chained audit event(s).", "high")
    sensitive_paths = [paths.config, paths.db, paths.audit_log]
    insecure: list[str] = []
    for path in sensitive_paths:
        if not path.exists():
            continue
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            insecure.append(f"{path}:{oct(mode)}")
            if apply_safe_permissions:
                os.chmod(path, 0o600)
    add("sensitive_file_permissions", not insecure, "Secure" if not insecure else "Overly broad: " + ", ".join(insecure), "high")
    score = round(100 * sum(1 for item in checks if item["ok"]) / max(1, len(checks)))
    payload = {"version": PLATFORM_V6_VERSION, "score": score, "checks": checks, "generated_at": utc_now(), "permissions_applied": apply_safe_permissions}
    if persist:
        db.execute("INSERT INTO security_posture_snapshots(score,checks_json,created_at) VALUES(?,?,?)", (score, json_dumps(checks), payload["generated_at"]))
        db.audit("security_posture_checked", entity_type="platform", entity_value="security", details={"score": score, "permissions_applied": apply_safe_permissions})
    return payload


def verify_audit_chain(db: Database) -> dict[str, Any]:
    rows = db.all("SELECT audit_id,previous_hash,event_hash,event_json FROM audit_integrity ORDER BY audit_id")
    previous = ""
    verified = 0
    for row in rows:
        event_json = str(row["event_json"])
        expected = sha256_text(previous + "|" + event_json)
        if str(row["previous_hash"] or "") != previous or str(row["event_hash"] or "") != expected:
            return {"ok": False, "verified": verified, "failed_audit_id": row["audit_id"]}
        previous = expected
        verified += 1
    return {"ok": True, "verified": verified, "head_hash": previous}


def set_retention_policy(db: Database, category: str, days: int, *, enabled: bool = True, keep_count: int = 0, actor: str = "system") -> dict[str, Any]:
    if category not in RETENTION_CATEGORIES:
        raise ReconError(f"Invalid retention category: {category}")
    if category in {"confirmed_evidence", "case_evidence"}:
        days = 0
        enabled = False
    now = utc_now()
    db.execute("INSERT INTO retention_policies(category,retention_days,keep_count,enabled,protected,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(category) DO UPDATE SET retention_days=excluded.retention_days,keep_count=excluded.keep_count,enabled=excluded.enabled,protected=excluded.protected,updated_at=excluded.updated_at", (category, parse_int(days, 90, 0, 3650), parse_int(keep_count, 0, 0, 1000), 1 if enabled else 0, 1 if category in {"confirmed_evidence", "case_evidence"} else 0, now, now))
    db.audit("retention_policy_updated", actor=actor, entity_type="retention", entity_value=category, details={"days": days, "keep_count": keep_count, "enabled": enabled})
    return dict(db.one("SELECT * FROM retention_policies WHERE category=?", (category,)))


def seed_retention_policies(db: Database) -> int:
    defaults = {
        "raw_http_artifacts": (90, 0, True),
        "javascript_snapshots": (180, 0, True),
        "temporary_exports": (30, 0, True),
        "logs": (45, 0, True),
        "backups": (0, 10, True),
        "confirmed_evidence": (0, 0, False),
        "case_evidence": (0, 0, False),
    }
    count = 0
    for category, (days, keep, enabled) in defaults.items():
        if not db.one("SELECT 1 FROM retention_policies WHERE category=?", (category,)):
            set_retention_policy(db, category, days, enabled=enabled, keep_count=keep)
            count += 1
    return count


def retention_preview(paths: AppPaths, db: Database, *, persist: bool = True) -> dict[str, Any]:
    seed_retention_policies(db)
    policies = {str(row["category"]): dict(row) for row in db.all("SELECT * FROM retention_policies")}
    candidates: list[dict[str, Any]] = []
    protected_paths: set[str] = set()
    for row in db.all("SELECT package_json FROM validation_packages UNION ALL SELECT body_json FROM report_drafts"):
        text = str(row[0] or "")
        for match in re.findall(r"(?:/[^\"']+)", text):
            protected_paths.add(match)

    def add_files(base: Path, category: str, days: int) -> None:
        if not base.exists() or days <= 0:
            return
        cutoff = time.time() - days * 86400
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_mtime >= cutoff:
                continue
            protected = str(path) in protected_paths or "confirmed" in path.name.lower()
            candidates.append({"category": category, "path": str(path), "size": stat.st_size, "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, UTC).isoformat().replace("+00:00", "Z"), "protected": protected})

    add_files(paths.state / "objects", "raw_http_artifacts", parse_int(policies.get("raw_http_artifacts", {}).get("retention_days"), 90))
    add_files(paths.blobs, "javascript_snapshots", parse_int(policies.get("javascript_snapshots", {}).get("retention_days"), 180))
    add_files(paths.reports, "temporary_exports", parse_int(policies.get("temporary_exports", {}).get("retention_days"), 30))
    add_files(paths.logs, "logs", parse_int(policies.get("logs", {}).get("retention_days"), 45))
    backup_keep = parse_int(policies.get("backups", {}).get("keep_count"), 10)
    backups = sorted([path for path in paths.backups.glob("*") if path.is_file()], key=lambda p: p.stat().st_mtime, reverse=True)
    for path in backups[backup_keep:]:
        stat = path.stat()
        candidates.append({"category": "backups", "path": str(path), "size": stat.st_size, "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, UTC).isoformat().replace("+00:00", "Z"), "protected": False})
    deletable = [item for item in candidates if not item["protected"]]
    payload = {"preview_id": "retention-" + uuid.uuid4().hex[:14], "files": len(deletable), "bytes": sum(item["size"] for item in deletable), "protected_files": len(candidates) - len(deletable), "candidates": candidates[:5000], "generated_at": utc_now()}
    if persist:
        db.execute("INSERT INTO retention_previews(preview_id,files_count,bytes_count,protected_count,preview_json,created_at) VALUES(?,?,?,?,?,?)", (payload["preview_id"], payload["files"], payload["bytes"], payload["protected_files"], json_dumps(payload), payload["generated_at"]))
    return payload


def apply_retention(paths: AppPaths, db: Database, preview_id: str, *, actor: str = "system", confirmation: str = "") -> dict[str, Any]:
    required = f"DELETE_RETENTION_PREVIEW_{preview_id}"
    if confirmation != required:
        raise ReconError(f"Exact confirmation required: {required}")
    row = db.one("SELECT preview_json FROM retention_previews WHERE preview_id=?", (preview_id,))
    if not row:
        raise ReconError("Retention preview not found")
    preview = _loads(row["preview_json"], {})
    deleted = 0
    freed = 0
    errors = []
    for item in preview.get("candidates", []):
        if item.get("protected"):
            continue
        path = Path(str(item.get("path") or ""))
        try:
            resolved = path.resolve()
            if not str(resolved).startswith(str(paths.root.resolve())):
                raise ReconError("candidate path leaves project root")
            size = path.stat().st_size if path.exists() else 0
            path.unlink(missing_ok=True)
            deleted += 1
            freed += size
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
    execution_id = "retention-run-" + uuid.uuid4().hex[:12]
    db.execute("INSERT INTO retention_executions(execution_id,preview_id,deleted_count,freed_bytes,errors_json,executed_by,created_at) VALUES(?,?,?,?,?,?,?)", (execution_id, preview_id, deleted, freed, json_dumps(errors), actor, utc_now()))
    db.audit("retention_applied", actor=actor, entity_type="retention", entity_value=execution_id, details={"preview_id": preview_id, "deleted": deleted, "freed_bytes": freed, "errors": len(errors)})
    return {"execution_id": execution_id, "preview_id": preview_id, "deleted": deleted, "freed_bytes": freed, "errors": errors}


def performance_diagnostics(paths: AppPaths, db: Database, *, limit: int = 50) -> dict[str, Any]:
    slow = [dict(row) for row in db.all("SELECT * FROM performance_samples WHERE duration_ms>=100 ORDER BY duration_ms DESC,created_at DESC LIMIT ?", (parse_int(limit, 50, 1, 500),))]
    recent = [dict(row) for row in db.all("SELECT * FROM performance_samples ORDER BY created_at DESC LIMIT ?", (parse_int(limit, 50, 1, 500),))]
    tables = []
    for row in db.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        name = str(row["name"])
        try:
            count = parse_int((db.one(f'SELECT COUNT(*) count FROM "{name}"') or {"count": 0})["count"], 0)
        except sqlite3.Error:
            count = 0
        tables.append({"table": name, "rows": count})
    tables.sort(key=lambda item: item["rows"], reverse=True)
    db_bytes = paths.db.stat().st_size if paths.db.exists() else 0
    wal = Path(str(paths.db) + "-wal")
    wal_bytes = wal.stat().st_size if wal.exists() else 0
    cache_hits = parse_int((db.one("SELECT COUNT(*) count FROM performance_samples WHERE cache_hit=1") or {"count": 0})["count"], 0)
    sample_count = parse_int((db.one("SELECT COUNT(*) count FROM performance_samples") or {"count": 0})["count"], 0)
    return {"version": PLATFORM_V6_VERSION, "database_bytes": db_bytes, "wal_bytes": wal_bytes, "sample_count": sample_count, "cache_hit_rate": round(cache_hits / max(1, sample_count), 3), "slow_samples": slow, "recent_samples": recent, "largest_tables": tables[:25], "generated_at": utc_now()}


def record_performance_sample(db: Database, category: str, name: str, duration_ms: float, *, details: dict[str, Any] | None = None, cache_hit: bool = False) -> None:
    db.execute("INSERT INTO performance_samples(category,name,duration_ms,cache_hit,details_json,created_at) VALUES(?,?,?,?,?,?)", (category, name[:240], round(float(duration_ms), 3), 1 if cache_hit else 0, json_dumps(details or {}), utc_now()))


def list_target_templates() -> list[dict[str, Any]]:
    return [{"template_id": template_id, **value} for template_id, value in TARGET_TEMPLATES.items()]


def apply_target_template(paths: AppPaths, target_name: str, template_id: str, *, actor: str = "system", dry_run: bool = True) -> dict[str, Any]:
    if template_id not in TARGET_TEMPLATES:
        raise ReconError(f"Unknown target template: {template_id}")
    if not paths.policy.exists():
        raise ReconError("Target policy file does not exist")
    document = json.loads(paths.policy.read_text(encoding="utf-8"))
    targets = document.get("targets", [])
    matched = None
    for target in targets:
        roots = [str(value) for value in target.get("roots", [])]
        if str(target.get("name") or "") == target_name or target_name in roots:
            matched = target
            break
    if matched is None:
        raise ReconError(f"Target not found in policy: {target_name}")
    template = TARGET_TEMPLATES[template_id]
    before = json.loads(json.dumps(matched))
    matched["modules"] = {**dict(matched.get("modules", {})), **dict(template.get("modules", {}))}
    matched["limits"] = {**dict(matched.get("limits", {})), **dict(template.get("limits", {}))}
    matched["analysis"] = {**dict(matched.get("analysis", {})), **dict(template.get("analysis", {}))}
    matched.setdefault("tags", [])
    tag = f"template:{template_id}"
    if tag not in matched["tags"]:
        matched["tags"].append(tag)
    result = {"target": target_name, "template_id": template_id, "dry_run": dry_run, "before": before, "after": matched}
    if not dry_run:
        atomic_write_text(paths.policy, json_dumps(document, pretty=True) + "\n", 0o600)
        db = Database(paths.db)
        try:
            db.execute("INSERT INTO target_template_applications(application_id,target,template_id,template_json,applied_by,created_at) VALUES(?,?,?,?,?,?)", ("tmpl-" + uuid.uuid4().hex[:14], target_name, template_id, json_dumps(template), actor, utc_now()))
            db.audit("target_template_applied", actor=actor, target=target_name, entity_type="target_template", entity_value=template_id)
        finally:
            db.close()
    return result


def platform_v6_sync(paths: AppPaths, db: Database, *, run_id: str | None = None, analysis_id: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    run_id = run_id or _latest_run(db)
    analysis_id = analysis_id or _latest_analysis(db)
    data_quality = data_quality_snapshot(db, run_id, persist=True) if run_id else {}
    story = correlate_security_stories(db, analysis_id, persist=True) if analysis_id else {}
    cases = [str(row["case_id"]) for row in db.all("SELECT case_id FROM security_cases WHERE state NOT IN ('rejected','reported','closed') ORDER BY updated_at DESC LIMIT 1000")]
    rankings = 0
    for case_id in cases:
        review_value_for_case(db, case_id, persist=True)
        rankings += 1
    validations = [str(row["run_id"]) for row in db.all("SELECT run_id FROM validation_runs WHERE status='completed' ORDER BY finished_at DESC LIMIT 500")]
    validation_updates = 0
    for validation_run_id in validations:
        validation_intelligence(db, validation_run_id, persist=True)
        validation_updates += 1
    seed_retention_policies(db)
    notifications = {"queued": 0, "silent": 0}
    for blind_spot in list(data_quality.get("blind_spots") or []):
        if str(blind_spot.get("severity")) == "high":
            queued = queue_notification(db, {"event_type": "data_quality_blind_spot", "title": blind_spot.get("message"), "score": 90, "run_id": run_id}, target=str(data_quality.get("target") or "*"))
            notifications["queued" if queued.get("mode") != "silent" else "silent"] += 1
    high_value = db.all("SELECT case_id,target,title,review_value FROM security_cases WHERE state NOT IN ('rejected','reported','closed') AND review_value>=85 ORDER BY review_value DESC LIMIT 50")
    for item in high_value:
        queued = queue_notification(db, {"event_type": "high_value_case", "title": str(item["title"]), "score": parse_int(item["review_value"], 85), "case_id": str(item["case_id"])}, target=str(item["target"]))
        notifications["queued" if queued.get("mode") != "silent" else "silent"] += 1
    elapsed = (time.perf_counter() - started) * 1000
    record_performance_sample(db, "platform", "platform_v6_sync", elapsed, details={"rankings": rankings, "validations": validation_updates})
    payload = {"version": PLATFORM_V6_VERSION, "run_id": run_id, "analysis_id": analysis_id, "data_quality": data_quality, "story_correlation": story, "review_rankings": rankings, "validation_intelligence": validation_updates, "notifications": notifications, "duration_ms": round(elapsed, 2), "generated_at": utc_now()}
    db.audit("platform_v6_synced", entity_type="platform", entity_value="6.0", details={"run_id": run_id, "analysis_id": analysis_id, "duration_ms": payload["duration_ms"]})
    return payload

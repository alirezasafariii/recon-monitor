from __future__ import annotations

import json
import math
import os
import platform
import re
import shutil
import sqlite3
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Iterable

from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, ReconError, json_dumps, safe_json_loads, sha256_text, utc_now

WORKSPACE_V7_VERSION = APP_VERSION

BUG_FAMILY_REQUIREMENTS: dict[str, list[dict[str, str]]] = {
    "broken_object_authorization": [
        {"key": "authenticated_context", "label": "Authenticated test identity", "why": "The endpoint must be observed in an authorized authenticated context."},
        {"key": "second_identity", "label": "Second authorized test identity", "why": "Ownership boundaries cannot be compared with a single identity."},
        {"key": "ownership_map", "label": "Object ownership relationship", "why": "The tested object must be tied to a known authorized identity."},
        {"key": "comparable_response", "label": "Comparable response observation", "why": "A status/shape/field comparison is required before concluding an authorization difference."},
    ],
    "broken_function_authorization": [
        {"key": "authenticated_context", "label": "Authenticated test identity", "why": "The function must be observed in an authorized authenticated context."},
        {"key": "second_identity", "label": "Second authorized role context", "why": "Role or function authorization needs a comparison context."},
        {"key": "role_map", "label": "Role relationship", "why": "The intended role boundary must be documented."},
        {"key": "comparable_response", "label": "Comparable response observation", "why": "A like-for-like comparison is needed."},
    ],
    "authentication_session": [
        {"key": "authenticated_context", "label": "Authenticated test identity", "why": "Session behavior requires an authenticated context."},
        {"key": "auth_boundary", "label": "Authentication boundary", "why": "The expected session boundary must be known."},
        {"key": "comparable_response", "label": "Comparable response observation", "why": "A before/after or authenticated/anonymous comparison is needed."},
    ],
    "graphql_authorization": [
        {"key": "authenticated_context", "label": "Authenticated test identity", "why": "GraphQL authorization requires an authenticated observation."},
        {"key": "operation_context", "label": "Operation or field context", "why": "The relevant query/field relationship must be known."},
        {"key": "comparable_response", "label": "Comparable response observation", "why": "A field or shape comparison is needed."},
    ],
    "websocket_authorization": [
        {"key": "authenticated_context", "label": "Authenticated test identity", "why": "The websocket/session context must be known."},
        {"key": "channel_context", "label": "Channel/topic relationship", "why": "Expected authorization needs a channel/topic mapping."},
        {"key": "comparable_response", "label": "Comparable observation", "why": "A like-for-like authorized comparison is needed."},
    ],
}

DEFAULT_REQUIREMENTS = [
    {"key": "endpoint", "label": "Affected endpoint or asset", "why": "A concrete affected surface is needed."},
    {"key": "evidence", "label": "Direct supporting evidence", "why": "At least one direct observation should support the candidate."},
    {"key": "expected_behavior", "label": "Expected behavior", "why": "The security expectation should be explicit."},
]

BUG_FAMILY_ALIASES = {
    "bola": "broken_object_authorization",
    "bola / idor": "broken_object_authorization",
    "idor": "broken_object_authorization",
    "broken object authorization": "broken_object_authorization",
    "broken_object_authorization": "broken_object_authorization",
    "bfla": "broken_function_authorization",
    "broken function authorization": "broken_function_authorization",
    "broken_function_authorization": "broken_function_authorization",
    "authentication/session": "authentication_session",
    "authentication session": "authentication_session",
    "authentication_session": "authentication_session",
    "graphql authorization": "graphql_authorization",
    "graphql_authorization": "graphql_authorization",
    "websocket authorization": "websocket_authorization",
    "websocket_authorization": "websocket_authorization",
}

def _canonical_family(value: str) -> str:
    raw = str(value or "").strip()
    lowered = raw.lower().replace("-", " ")
    return BUG_FAMILY_ALIASES.get(lowered, BUG_FAMILY_ALIASES.get(raw.lower(), raw))

STAGE_VALUE_DEFAULTS = {
    "subdomains": 65,
    "dns": 55,
    "urls": 70,
    "javascript": 78,
    "endpoint_validation": 72,
    "fingerprint": 58,
    "ports": 40,
    "nuclei": 45,
    "report": 15,
}

SECRET_HEADER_RE = re.compile(r"^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$", re.I)
SAFE_CAPTURE_HEADERS = {"content-type", "accept", "cache-control", "etag", "last-modified", "server", "x-powered-by", "vary", "allow"}
SENSITIVE_QUERY_RE = re.compile(r"(token|secret|password|passwd|api[_-]?key|session|auth|code)", re.I)


def _loads(value: Any, default: Any) -> Any:
    return safe_json_loads(value, default, expected_type=type(default))


def _clamp(value: float | int, low: int = 0, high: int = 100) -> int:
    return int(max(low, min(high, round(float(value)))))


def _table_exists(db: Database, table: str) -> bool:
    return bool(db.one("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)))


def _latest_run(db: Database, target: str = "") -> str:
    if target:
        row = db.one(
            "SELECT r.id FROM runs r JOIN run_targets rt ON rt.run_id=r.id WHERE r.status='success' AND rt.target=? ORDER BY COALESCE(r.finished_at,r.started_at) DESC LIMIT 1",
            (target,),
        )
    else:
        row = db.one("SELECT id FROM runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
    return str(row["id"]) if row else ""


def _previous_run(db: Database, target: str, current_run: str = "") -> str:
    params: list[Any] = [target]
    sql = "SELECT r.id FROM runs r JOIN run_targets rt ON rt.run_id=r.id WHERE r.status='success' AND rt.target=?"
    if current_run:
        current = db.one("SELECT COALESCE(finished_at,started_at) ts FROM runs WHERE id=?", (current_run,))
        if current and current["ts"]:
            sql += " AND COALESCE(r.finished_at,r.started_at) < ?"
            params.append(str(current["ts"]))
    sql += " ORDER BY COALESCE(r.finished_at,r.started_at) DESC LIMIT 1"
    row = db.one(sql, tuple(params))
    return str(row["id"]) if row else ""


def _latest_analysis(db: Database, target: str = "") -> str:
    if target:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' AND target IN (?, '*') ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1", (target,))
    else:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
    return str(row["id"]) if row else ""


def _case_and_candidates(db: Database, case_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case:
        raise ReconError(f"Security case not found: {case_id}")
    rows = db.all(
        "SELECT bc.* FROM security_case_members m JOIN bug_candidates bc ON bc.candidate_id=m.member_id WHERE m.case_id=? AND m.member_type='candidate' ORDER BY bc.priority_score DESC",
        (case_id,),
    )
    return dict(case), [dict(r) for r in rows]


def _redact_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return str(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    clean = []
    for key, value in pairs:
        clean.append((key, "[redacted]" if SENSITIVE_QUERY_RE.search(key) else value[:160]))
    query = urllib.parse.urlencode(clean, doseq=True)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _evidence_presence(db: Database, case: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, bool]:
    case_id = str(case["case_id"])
    target = str(case.get("target") or "")
    analysis_id = str(case.get("analysis_id") or _latest_analysis(db, target))
    endpoint_values = {str(c.get("endpoint") or "") for c in candidates if str(c.get("endpoint") or "")}
    imported = db.all("SELECT observation_json FROM imported_http_evidence WHERE case_id=? ORDER BY created_at DESC LIMIT 200", (case_id,))
    imported_obs = [_loads(r["observation_json"], {}) for r in imported]
    validation_obs = db.all(
        "SELECT vo.observation_json FROM validation_observations vo JOIN validation_runs vr ON vr.run_id=vo.run_id WHERE vr.case_id=? ORDER BY vo.created_at DESC LIMIT 200",
        (case_id,),
    )
    validation_json = [_loads(r["observation_json"], {}) for r in validation_obs]
    all_obs = imported_obs + validation_json
    contexts = {str(o.get("context") or o.get("authentication_context") or o.get("auth_context") or "").strip().lower() for o in all_obs}
    contexts.discard("")
    behavioral_contexts = set()
    if analysis_id:
        for row in db.all("SELECT DISTINCT context FROM behavioral_observations WHERE analysis_id=? AND target=?", (analysis_id, target)):
            behavioral_contexts.add(str(row["context"] or "").strip().lower())
    contexts |= behavioral_contexts
    authenticated = {c for c in contexts if c not in {"anonymous", "anon", "unauthenticated", "public", "unknown"}}
    second_identity = len(authenticated) >= 2 or any(token in " ".join(sorted(authenticated)) for token in ["user b", "account b", "second", "role b"])

    relations = db.all("SELECT source_type,source_value,relation,destination_type,destination_value FROM identity_relations WHERE analysis_id=? AND target=? LIMIT 500", (analysis_id, target)) if analysis_id else []
    relation_text = " ".join(" ".join(str(r[k] or "") for k in r.keys()).lower() for r in relations)
    ownership_map = any(x in relation_text for x in ["owner", "owns", "ownership", "belongs", "object"])
    role_map = any(x in relation_text for x in ["role", "admin", "user", "privilege", "function"])
    channel_context = any(x in relation_text for x in ["channel", "topic", "subscription", "socket"])
    operation_context = any(x in relation_text for x in ["graphql", "operation", "field", "query"])

    comparable = False
    if analysis_id:
        comparable = bool(db.one("SELECT 1 FROM authentication_boundary_diffs WHERE analysis_id=? AND target=? LIMIT 1", (analysis_id, target))) or bool(
            db.one("SELECT 1 FROM response_shape_diffs WHERE analysis_id=? AND target=? LIMIT 1", (analysis_id, target))
        )
    if len({str(o.get("shape_hash") or "") for o in all_obs if o.get("shape_hash")}) >= 2:
        comparable = True
    if len({o.get("status_code") for o in all_obs if o.get("status_code") is not None}) >= 2:
        comparable = True
    endpoint = bool(endpoint_values) or bool(db.one("SELECT 1 FROM endpoint_intelligence WHERE target=? LIMIT 1", (target,)))
    direct_evidence = any(_loads(c.get("supporting_evidence_json"), []) for c in candidates) or bool(all_obs)
    auth_boundary = bool(db.one("SELECT 1 FROM authentication_boundaries WHERE analysis_id=? AND target=? LIMIT 1", (analysis_id, target))) if analysis_id else False

    return {
        "endpoint": endpoint,
        "evidence": bool(direct_evidence),
        "expected_behavior": bool(any(str(c.get("summary") or "").strip() for c in candidates)),
        "authenticated_context": bool(authenticated),
        "second_identity": bool(second_identity),
        "ownership_map": bool(ownership_map),
        "role_map": bool(role_map),
        "auth_boundary": bool(auth_boundary),
        "comparable_response": bool(comparable),
        "operation_context": bool(operation_context),
        "channel_context": bool(channel_context),
    }


def evidence_gap_for_case(db: Database, case_id: str, *, persist: bool = True) -> dict[str, Any]:
    case, candidates = _case_and_candidates(db, case_id)
    family_raw = str(case.get("primary_family") or (candidates[0].get("bug_family") if candidates else ""))
    family = _canonical_family(family_raw)
    requirements = list(DEFAULT_REQUIREMENTS)
    requirements.extend(BUG_FAMILY_REQUIREMENTS.get(family, []))
    present = _evidence_presence(db, case, candidates)
    items = []
    for req in requirements:
        key = req["key"]
        ok = bool(present.get(key, False))
        items.append({**req, "status": "present" if ok else "missing"})
    have = sum(1 for i in items if i["status"] == "present")
    coverage = _clamp(100 * have / max(1, len(items)))
    missing = [i for i in items if i["status"] == "missing"]
    next_actions = []
    action_map = {
        "second_identity": "Capture the same authorized workflow with a second permitted test identity and import only redacted metadata.",
        "ownership_map": "Document which authorized test identity owns the object before comparing access behavior.",
        "role_map": "Document the expected role/function boundary for the two authorized contexts.",
        "comparable_response": "Capture a like-for-like response comparison using the same method and endpoint shape.",
        "authenticated_context": "Add an authorized authenticated context label without storing the raw credential.",
        "auth_boundary": "Record the expected authentication boundary from existing observations or a redacted capture.",
        "operation_context": "Link the relevant GraphQL operation/field context from existing evidence.",
        "channel_context": "Link the websocket channel/topic relationship from existing evidence.",
        "endpoint": "Link the concrete endpoint or asset to the case.",
        "evidence": "Attach at least one direct, redacted observation to the case.",
        "expected_behavior": "Write the expected security behavior before validation.",
    }
    for item in missing[:5]:
        next_actions.append(action_map.get(item["key"], f"Collect evidence for {item['label']}."))
    result = {
        "case_id": case_id,
        "target": case.get("target"),
        "bug_family": family,
        "coverage": coverage,
        "requirements": items,
        "missing_count": len(missing),
        "next_actions": next_actions,
        "automation": "manual_only" if family in {"broken_object_authorization", "broken_function_authorization"} else "evidence_guided",
        "generated_at": utc_now(),
    }
    if persist:
        db.execute(
            "INSERT INTO evidence_gap_snapshots(case_id,coverage,requirements_json,next_actions_json,created_at) VALUES(?,?,?,?,?)",
            (case_id, coverage, json_dumps(items), json_dumps(next_actions), utc_now()),
        )
        db.execute("UPDATE security_cases SET evidence_gap_score=?,updated_at=? WHERE case_id=?", (100 - coverage, utc_now(), case_id))
        db.audit("evidence_gap_scored", target=str(case.get("target") or ""), entity_type="case", entity_value=case_id, details={"coverage": coverage, "missing": len(missing)})
    return result


def case_autopilot(db: Database, case_id: str, *, actor: str = "system", persist: bool = True) -> dict[str, Any]:
    case, candidates = _case_and_candidates(db, case_id)
    gap = evidence_gap_for_case(db, case_id, persist=persist)
    readiness = _clamp(0.55 * gap["coverage"] + 0.45 * int(case.get("report_readiness") or 0))
    tasks: list[dict[str, Any]] = []
    for index, action in enumerate(gap["next_actions"], start=1):
        tasks.append({"rank": index, "type": "evidence", "title": action, "status": "open"})
    if not tasks:
        state = str(case.get("state") or "")
        if state not in {"confirmed", "ready_for_report", "reported", "closed"}:
            tasks.append({"rank": 1, "type": "decision", "title": "Review the collected evidence and record an analyst decision.", "status": "open"})
        elif state == "confirmed":
            tasks.append({"rank": 1, "type": "report", "title": "Build an evidence-linked report draft and run report quality checks.", "status": "open"})
    if persist:
        db.execute("DELETE FROM case_autopilot_tasks WHERE case_id=? AND status='open'", (case_id,))
        for task in tasks:
            task_id = f"task-{uuid.uuid4().hex[:16]}"
            db.execute(
                "INSERT INTO case_autopilot_tasks(task_id,case_id,task_type,title,rank,status,details_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (task_id, case_id, task["type"], task["title"], int(task["rank"]), "open", json_dumps({"source": "case_autopilot"}), utc_now(), utc_now()),
            )
        db.execute("UPDATE security_cases SET autopilot_score=?,updated_at=? WHERE case_id=?", (readiness, utc_now(), case_id))
        db.execute(
            "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
            (case_id, "autopilot_refreshed", actor, json_dumps({"tasks": len(tasks), "evidence_coverage": gap["coverage"]}), utc_now()),
        )
        db.audit("case_autopilot_refreshed", actor=actor, target=str(case.get("target") or ""), entity_type="case", entity_value=case_id, details={"tasks": len(tasks)})
    return {"case_id": case_id, "target": case.get("target"), "evidence": gap, "autopilot_score": readiness, "tasks": tasks, "generated_at": utc_now()}


def case_autopilot_queue(db: Database, *, target: str = "", limit: int = 100, persist: bool = True) -> list[dict[str, Any]]:
    params: list[Any] = []
    sql = "SELECT case_id FROM security_cases WHERE state NOT IN ('reported','closed','rejected')"
    if target:
        sql += " AND target=?"
        params.append(target)
    sql += " ORDER BY priority_score DESC,updated_at DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))
    out = []
    for row in db.all(sql, tuple(params)):
        try:
            out.append(case_autopilot(db, str(row["case_id"]), persist=persist))
        except Exception as exc:
            out.append({"case_id": str(row["case_id"]), "error": str(exc)})
    return out


def authentication_contexts(db: Database, *, target: str = "", analysis_id: str = "", persist: bool = True) -> list[dict[str, Any]]:
    analysis_id = analysis_id or _latest_analysis(db, target)
    targets = [target] if target else [str(r["target"]) for r in db.all("SELECT DISTINCT target FROM behavioral_observations WHERE analysis_id=? ORDER BY target", (analysis_id,))]
    results: list[dict[str, Any]] = []
    for tgt in targets:
        contexts: dict[str, dict[str, Any]] = {}
        if analysis_id:
            for row in db.all("SELECT endpoint,context,auth_state,status_code,shape_hash,confidence FROM behavioral_observations WHERE analysis_id=? AND target=?", (analysis_id, tgt)):
                label = str(row["context"] or "unknown")
                item = contexts.setdefault(label, {"label": label, "endpoints": set(), "statuses": set(), "shape_hashes": set(), "confidence": [], "sources": {"behavioral"}})
                if row["endpoint"]: item["endpoints"].add(str(row["endpoint"]))
                if row["status_code"] is not None: item["statuses"].add(int(row["status_code"]))
                if row["shape_hash"]: item["shape_hashes"].add(str(row["shape_hash"]))
                item["confidence"].append(int(row["confidence"] or 0))
            for row in db.all("SELECT entity_type,entity_value,confidence FROM identity_entities WHERE analysis_id=? AND target=?", (analysis_id, tgt)):
                if str(row["entity_type"]).lower() in {"identity", "role", "auth_context", "principal", "user"}:
                    label = str(row["entity_value"] or "unknown")
                    item = contexts.setdefault(label, {"label": label, "endpoints": set(), "statuses": set(), "shape_hashes": set(), "confidence": [], "sources": set()})
                    item["confidence"].append(int(row["confidence"] or 0)); item["sources"].add("identity_graph")
        for row in db.all("SELECT observation_json FROM imported_http_evidence WHERE target=? ORDER BY created_at DESC LIMIT 500", (tgt,)):
            obs = _loads(row["observation_json"], {})
            label = str(obs.get("context") or obs.get("authentication_context") or "").strip()
            if not label: continue
            item = contexts.setdefault(label, {"label": label, "endpoints": set(), "statuses": set(), "shape_hashes": set(), "confidence": [], "sources": set()})
            if obs.get("url"): item["endpoints"].add(urllib.parse.urlsplit(str(obs["url"])).path or str(obs["url"]))
            if obs.get("status_code") is not None: item["statuses"].add(int(obs["status_code"]))
            if obs.get("shape_hash"): item["shape_hashes"].add(str(obs["shape_hash"]))
            item["sources"].add("imported_http")
        if _table_exists(db, "browser_capture_events"):
            for row in db.all("SELECT context_label,url,status_code,metadata_json FROM browser_capture_events WHERE target=? ORDER BY created_at DESC LIMIT 500", (tgt,)):
                label = str(row["context_label"] or "").strip()
                if not label:
                    continue
                item = contexts.setdefault(label, {"label": label, "endpoints": set(), "statuses": set(), "shape_hashes": set(), "confidence": [], "sources": set()})
                if row["url"]:
                    item["endpoints"].add(urllib.parse.urlsplit(str(row["url"])).path or str(row["url"]))
                if row["status_code"] is not None:
                    item["statuses"].add(int(row["status_code"]))
                metadata = _loads(row["metadata_json"], {})
                shape = metadata.get("response_shape")
                if shape is not None:
                    item["shape_hashes"].add(sha256_text(json_dumps(shape)))
                item["confidence"].append(70)
                item["sources"].add("browser_capture")
        for label, item in sorted(contexts.items()):
            lower = label.lower()
            auth_state = "anonymous" if lower in {"anonymous", "anon", "public", "unauthenticated"} else "authenticated"
            confidence = _clamp(sum(item["confidence"]) / max(1, len(item["confidence"])) if item["confidence"] else 60)
            result = {
                "target": tgt,
                "analysis_id": analysis_id,
                "context_id": sha256_text(f"{tgt}|{label}")[:20],
                "label": label,
                "auth_state": auth_state,
                "endpoint_count": len(item["endpoints"]),
                "status_classes": sorted({int(x) // 100 for x in item["statuses"]}),
                "response_shapes": len(item["shape_hashes"]),
                "confidence": confidence,
                "sources": sorted(item["sources"]),
            }
            results.append(result)
            if persist:
                db.execute(
                    "INSERT INTO auth_context_profiles(target,context_id,label,auth_state,endpoint_count,response_shape_count,confidence,sources_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(target,context_id) DO UPDATE SET label=excluded.label,auth_state=excluded.auth_state,endpoint_count=excluded.endpoint_count,response_shape_count=excluded.response_shape_count,confidence=excluded.confidence,sources_json=excluded.sources_json,updated_at=excluded.updated_at",
                    (tgt, result["context_id"], label, auth_state, result["endpoint_count"], result["response_shapes"], confidence, json_dumps(result["sources"]), utc_now()),
                )
    return results


def differential_intelligence(db: Database, *, target: str = "", analysis_id: str = "", limit: int = 200, persist: bool = True) -> list[dict[str, Any]]:
    analysis_id = analysis_id or _latest_analysis(db, target)
    if not analysis_id:
        return []
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)
    rows: list[dict[str, Any]] = []
    for r in db.all(f"SELECT target,endpoint,previous_boundary,current_boundary,transition,confidence,severity,evidence_json,created_at FROM authentication_boundary_diffs WHERE analysis_id=?{target_clause} ORDER BY confidence DESC LIMIT ?", tuple(params + [limit])):
        rows.append({"kind": "authentication_boundary", **dict(r), "details": _loads(r["evidence_json"], {})})
    shape_params: list[Any] = [analysis_id]
    if target: shape_params.append(target)
    for r in db.all(f"SELECT target,endpoint,previous_status_code,current_status_code,added_keys_json,removed_keys_json,type_changes_json,sensitive_added_json,transition,confidence,severity,created_at FROM response_shape_diffs WHERE analysis_id=?{target_clause} ORDER BY confidence DESC LIMIT ?", tuple(shape_params + [limit])):
        item = dict(r)
        sensitive_added = _loads(r["sensitive_added_json"], [])
        status_changed = r["previous_status_code"] != r["current_status_code"]
        dimensions = []
        if status_changed: dimensions.append("status_difference")
        if _loads(r["added_keys_json"], []): dimensions.append("field_added")
        if _loads(r["removed_keys_json"], []): dimensions.append("field_removed")
        if _loads(r["type_changes_json"], []): dimensions.append("type_change")
        if sensitive_added: dimensions.append("sensitive_field_exposure")
        item.update({"kind": "response_shape", "dimensions": dimensions, "sensitive_added": sensitive_added})
        rows.append(item)
    rows.sort(key=lambda x: (int(x.get("confidence") or 0), str(x.get("severity") or "")), reverse=True)
    rows = rows[:limit]
    if persist:
        for row in rows:
            diff_id = sha256_text(f"{analysis_id}|{row.get('kind')}|{row.get('target')}|{row.get('endpoint')}|{row.get('transition')}|{row.get('created_at')}")[:24]
            db.execute(
                "INSERT INTO differential_findings(diff_id,analysis_id,target,endpoint,diff_kind,confidence,severity,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(diff_id) DO NOTHING",
                (diff_id, analysis_id, str(row.get("target") or ""), str(row.get("endpoint") or ""), str(row.get("kind") or ""), int(row.get("confidence") or 0), str(row.get("severity") or "info"), json_dumps(row), utc_now()),
            )
    return rows


def recon_coverage(db: Database, *, target: str, run_id: str = "", persist: bool = True) -> dict[str, Any]:
    run_id = run_id or _latest_run(db, target)
    if not run_id:
        return {"target": target, "run_id": "", "overall": 0, "components": {}, "blind_spots": ["No successful run available"]}
    stages = {str(r["stage"]): dict(r) for r in db.all("SELECT stage,status,metrics_json FROM stage_runs WHERE run_id=? AND target=?", (run_id, target))}
    def stage_score(name: str) -> int:
        row = stages.get(name)
        if not row: return 0
        if str(row.get("status")) != "success": return 20 if str(row.get("status")) == "skipped" else 0
        metrics = _loads(row.get("metrics_json"), {})
        if "skipped" in metrics: return 25
        return 100
    analysis_id = _latest_analysis(db, target)
    auth_context_count = len(authentication_contexts(db, target=target, analysis_id=analysis_id, persist=False)) if analysis_id else 0
    endpoint_count = int((db.one("SELECT COUNT(*) c FROM endpoint_intelligence WHERE target=?", (target,)) or {"c": 0})["c"])
    shape_count = int((db.one("SELECT COUNT(*) c FROM response_shape_fingerprints WHERE analysis_id=? AND target=?", (analysis_id, target)) or {"c": 0})["c"]) if analysis_id else 0
    components = {
        "subdomain": stage_score("subdomains"),
        "dns": stage_score("dns"),
        "http": stage_score("fingerprint"),
        "javascript": stage_score("javascript"),
        "api": _clamp(30 + min(70, endpoint_count * 2)) if endpoint_count else 15,
        "response_shape": _clamp(20 + min(80, shape_count * 4)) if shape_count else 10,
        "authenticated": _clamp(auth_context_count * 28),
        "role": _clamp(max(0, auth_context_count - 1) * 35),
    }
    weights = {"subdomain": .10, "dns": .08, "http": .15, "javascript": .15, "api": .16, "response_shape": .12, "authenticated": .14, "role": .10}
    overall = _clamp(sum(components[k] * weights[k] for k in components))
    blind = []
    if components["javascript"] < 50: blind.append("JavaScript coverage is weak")
    if components["api"] < 50: blind.append("API/endpoint coverage is weak")
    if components["authenticated"] < 50: blind.append("Authenticated context coverage is weak")
    if components["role"] < 50: blind.append("Role comparison coverage is weak")
    if components["response_shape"] < 50: blind.append("Response-shape coverage is weak")
    result = {"target": target, "run_id": run_id, "analysis_id": analysis_id, "overall": overall, "components": components, "blind_spots": blind, "generated_at": utc_now()}
    if persist:
        db.execute(
            "INSERT INTO recon_coverage_snapshots(run_id,target,overall,components_json,blind_spots_json,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,target) DO UPDATE SET overall=excluded.overall,components_json=excluded.components_json,blind_spots_json=excluded.blind_spots_json,created_at=excluded.created_at",
            (run_id, target, overall, json_dumps(components), json_dumps(blind), utc_now()),
        )
    return result


def attack_surface_graph(db: Database, *, target: str, limit: int = 1200) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    def add_node(kind: str, value: str, **meta: Any) -> str:
        value = str(value or "")
        key = f"{kind}:{value}"
        if key not in nodes:
            nodes[key] = {"id": key, "kind": kind, "value": value, **meta}
        return key
    root = add_node("target", target)
    for row in db.all("SELECT host,confidence,resolved FROM assets WHERE target=? ORDER BY confidence DESC,last_seen DESC LIMIT ?", (target, limit)):
        nid = add_node("host", str(row["host"]), confidence=int(row["confidence"] or 0), resolved=bool(row["resolved"]))
        edges.append({"source": root, "target": nid, "relation": "contains"})
    for row in db.all("SELECT endpoint,kind,primary_category,confidence FROM endpoint_intelligence WHERE target=? ORDER BY confidence DESC,last_seen DESC LIMIT ?", (target, limit)):
        endpoint = str(row["endpoint"])
        eid = add_node("endpoint", endpoint, category=str(row["primary_category"]), confidence=int(row["confidence"] or 0))
        host = urllib.parse.urlsplit(endpoint).hostname if endpoint.startswith(("http://", "https://")) else ""
        parent = add_node("host", host) if host else root
        edges.append({"source": parent, "target": eid, "relation": "exposes"})
    for row in db.all("SELECT js_url,kind,value FROM js_indicators WHERE target=? ORDER BY last_seen DESC LIMIT ?", (target, min(limit, 600))):
        jid = add_node("javascript", str(row["js_url"]))
        vid = add_node(str(row["kind"] or "indicator"), str(row["value"]))
        edges.append({"source": jid, "target": vid, "relation": "reveals"})
    analysis_id = _latest_analysis(db, target)
    if analysis_id:
        for row in db.all(
            "SELECT endpoint,context,auth_state,confidence FROM behavioral_observations "
            "WHERE analysis_id=? AND target=? AND context<>'' ORDER BY confidence DESC LIMIT ?",
            (analysis_id, target, min(limit, 600)),
        ):
            label = str(row["context"] or "unknown")
            context_id = add_node(
                "context", label, auth_state=str(row["auth_state"] or "unknown"),
                confidence=int(row["confidence"] or 0), source="behavioral"
            )
            endpoint = str(row["endpoint"] or "")
            if endpoint:
                endpoint_id = add_node("endpoint", endpoint)
                edges.append({"source": context_id, "target": endpoint_id, "relation": "observes"})
    if _table_exists(db, "browser_capture_events"):
        for row in db.all(
            "SELECT context_label,url,status_code FROM browser_capture_events "
            "WHERE target=? ORDER BY created_at DESC LIMIT ?",
            (target, min(limit, 600)),
        ):
            label = str(row["context_label"] or "unknown")
            context_id = add_node("context", label, source="browser_capture")
            url = str(row["url"] or "")
            if url:
                endpoint_id = add_node("endpoint", url, status_code=row["status_code"])
                edges.append({"source": context_id, "target": endpoint_id, "relation": "captured"})
    for row in db.all("SELECT candidate_id,endpoint,bug_family,candidate_state,priority_score FROM bug_candidates WHERE target=? ORDER BY priority_score DESC LIMIT 300", (target,)):
        cid = add_node("candidate", str(row["candidate_id"]), family=str(row["bug_family"]), state=str(row["candidate_state"]), priority=int(row["priority_score"] or 0))
        endpoint = str(row["endpoint"] or "")
        parent = add_node("endpoint", endpoint) if endpoint else root
        edges.append({"source": parent, "target": cid, "relation": "candidate"})
    for row in db.all("SELECT source_type,source_value,relation,destination_type,destination_value FROM asset_edges WHERE target=? ORDER BY last_seen DESC LIMIT ?", (target, limit)):
        sid = add_node(str(row["source_type"]), str(row["source_value"]))
        did = add_node(str(row["destination_type"]), str(row["destination_value"]))
        edges.append({"source": sid, "target": did, "relation": str(row["relation"] or "related")})
    coverage = recon_coverage(db, target=target, persist=False)
    return {"target": target, "nodes": list(nodes.values())[:limit], "edges": edges[:limit * 2], "coverage": coverage, "generated_at": utc_now()}


def change_intelligence(db: Database, *, target: str, run_id: str = "", persist: bool = True) -> dict[str, Any]:
    run_id = run_id or _latest_run(db, target)
    previous = _previous_run(db, target, run_id)
    if not run_id:
        return {"target": target, "current_run": "", "previous_run": "", "changes": [], "important": []}
    changes: list[dict[str, Any]] = []
    important: list[dict[str, Any]] = []
    current_assets = {str(r["host"]) for r in db.all("SELECT host FROM assets WHERE target=? AND last_run_id=?", (target, run_id))}
    current_urls = {str(r["url"]) for r in db.all("SELECT url FROM urls WHERE target=? AND last_run_id=?", (target, run_id))}
    current_js = {str(r["url"]) for r in db.all("SELECT url FROM js_files WHERE target=? AND last_run_id=?", (target, run_id))}
    if previous:
        prev_assets = {str(r["host"]) for r in db.all("SELECT host FROM assets WHERE target=? AND last_run_id=?", (target, previous))}
        prev_urls = {str(r["url"]) for r in db.all("SELECT url FROM urls WHERE target=? AND last_run_id=?", (target, previous))}
        prev_js = {str(r["url"]) for r in db.all("SELECT url FROM js_files WHERE target=? AND last_run_id=?", (target, previous))}
    else:
        prev_assets = prev_urls = prev_js = set()
    for kind, added, removed in [
        ("subdomain", current_assets - prev_assets, prev_assets - current_assets),
        ("url", current_urls - prev_urls, prev_urls - current_urls),
        ("javascript", current_js - prev_js, prev_js - current_js),
    ]:
        if added: changes.append({"type": kind, "change": "added", "count": len(added), "examples": sorted(added)[:8]})
        if removed: changes.append({"type": kind, "change": "removed", "count": len(removed), "examples": sorted(removed)[:8]})
    analysis_id = _latest_analysis(db, target)
    if analysis_id:
        boundary_count = int((db.one("SELECT COUNT(*) c FROM authentication_boundary_diffs WHERE analysis_id=? AND target=?", (analysis_id, target)) or {"c": 0})["c"])
        shape_count = int((db.one("SELECT COUNT(*) c FROM response_shape_diffs WHERE analysis_id=? AND target=?", (analysis_id, target)) or {"c": 0})["c"])
        sensitive = [dict(r) for r in db.all("SELECT endpoint,severity,confidence,sensitive_added_json FROM response_shape_diffs WHERE analysis_id=? AND target=? AND sensitive_added_json NOT IN ('[]','') ORDER BY confidence DESC LIMIT 20", (analysis_id, target))]
        if boundary_count: changes.append({"type": "authentication_boundary", "change": "changed", "count": boundary_count})
        if shape_count: changes.append({"type": "response_shape", "change": "changed", "count": shape_count})
        for row in sensitive[:5]: important.append({"type": "sensitive_response_expansion", "endpoint": row["endpoint"], "confidence": row["confidence"], "severity": row["severity"]})
    for row in db.all("SELECT candidate_id,title,priority_score,candidate_state FROM bug_candidates WHERE target=? AND source_run_id=? ORDER BY priority_score DESC LIMIT 8", (target, run_id)):
        if int(row["priority_score"] or 0) >= 70:
            important.append({"type": "candidate", "candidate_id": row["candidate_id"], "title": row["title"], "priority": row["priority_score"], "state": row["candidate_state"]})
    result = {"target": target, "current_run": run_id, "previous_run": previous, "changes": changes, "important": important, "generated_at": utc_now()}
    if persist:
        db.execute(
            "INSERT INTO change_intelligence_snapshots(run_id,target,previous_run_id,summary_json,created_at) VALUES(?,?,?,?,?) ON CONFLICT(run_id,target) DO UPDATE SET previous_run_id=excluded.previous_run_id,summary_json=excluded.summary_json,created_at=excluded.created_at",
            (run_id, target, previous, json_dumps(result), utc_now()),
        )
    return result


def target_memory(db: Database, *, target: str, persist: bool = True) -> dict[str, Any]:
    technologies = [str(r["technology"]) for r in db.all("SELECT technology,MAX(confidence) c FROM technology_observations WHERE target=? GROUP BY technology ORDER BY c DESC LIMIT 20", (target,))]
    endpoints = [dict(r) for r in db.all("SELECT primary_category,COUNT(*) c FROM endpoint_intelligence WHERE target=? GROUP BY primary_category ORDER BY c DESC LIMIT 20", (target,))]
    contexts = authentication_contexts(db, target=target, persist=False)
    candidates = [dict(r) for r in db.all("SELECT bug_family,COUNT(*) c,SUM(CASE WHEN analyst_decision='confirmed_by_analyst' THEN 1 ELSE 0 END) confirmed FROM bug_candidates WHERE target=? GROUP BY bug_family ORDER BY c DESC LIMIT 20", (target,))]
    noisy = [dict(r) for r in db.all("SELECT bug_family,COUNT(*) c FROM bug_candidates WHERE target=? AND analyst_decision IN ('rejected','duplicate','out_of_scope') GROUP BY bug_family ORDER BY c DESC LIMIT 10", (target,))]
    important_categories = [r["primary_category"] for r in endpoints[:6]]
    architecture = {"technologies": technologies, "endpoint_categories": endpoints, "auth_contexts": contexts}
    history = {"candidate_families": candidates, "historical_noise": noisy}
    confidence = _clamp(25 + min(35, len(technologies) * 3) + min(20, len(endpoints) * 2) + min(20, len(contexts) * 5))
    memory = {
        "target": target,
        "architecture": architecture,
        "important_areas": important_categories,
        "history": history,
        "confidence": confidence,
        "updated_at": utc_now(),
    }
    if persist:
        db.execute(
            "INSERT INTO target_memory(target,memory_json,confidence,updated_at) VALUES(?,?,?,?) ON CONFLICT(target) DO UPDATE SET memory_json=excluded.memory_json,confidence=excluded.confidence,updated_at=excluded.updated_at",
            (target, json_dumps(memory), confidence, utc_now()),
        )
    return memory


def false_positive_learning(db: Database, *, target: str = "", persist: bool = True) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if target:
        where = " WHERE target=?"
        params.append(target)
    rows = db.all(
        "SELECT target,bug_family,COUNT(*) total,SUM(CASE WHEN analyst_decision='confirmed_by_analyst' THEN 1 ELSE 0 END) confirmed,"
        "SUM(CASE WHEN analyst_decision IN ('rejected','duplicate','out_of_scope') THEN 1 ELSE 0 END) rejected,"
        "SUM(CASE WHEN analyst_decision='needs_more_evidence' THEN 1 ELSE 0 END) needs_more FROM bug_candidates" + where + " GROUP BY target,bug_family ORDER BY total DESC",
        tuple(params),
    )
    results = []
    for r in rows:
        total = int(r["total"] or 0); confirmed = int(r["confirmed"] or 0); rejected = int(r["rejected"] or 0); needs_more = int(r["needs_more"] or 0)
        decided = confirmed + rejected
        precision = round(100 * confirmed / max(1, decided), 1)
        recommendation = "keep"
        if total >= 8 and precision < 15: recommendation = "shadow_review"
        elif total >= 8 and precision < 30: recommendation = "tune"
        elif total >= 8 and precision >= 60: recommendation = "healthy"
        item = {"target": r["target"], "bug_family": r["bug_family"], "total": total, "confirmed": confirmed, "rejected": rejected, "needs_more": needs_more, "precision": precision, "recommendation": recommendation}
        results.append(item)
        if persist:
            db.execute(
                "INSERT INTO false_positive_learning(target,bug_family,total,confirmed,rejected,needs_more,precision,recommendation,updated_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(target,bug_family) DO UPDATE SET total=excluded.total,confirmed=excluded.confirmed,rejected=excluded.rejected,needs_more=excluded.needs_more,precision=excluded.precision,recommendation=excluded.recommendation,updated_at=excluded.updated_at",
                (r["target"], r["bug_family"], total, confirmed, rejected, needs_more, precision, recommendation, utc_now()),
            )
    return results


def stage_value_analysis(db: Database, *, target: str = "", limit: int = 100) -> list[dict[str, Any]]:
    params: list[Any] = []
    join = ""
    where = "WHERE sr.status='success'"
    if target:
        where += " AND sr.target=?"
        params.append(target)
    rows = db.all(
        "SELECT sr.stage,COUNT(*) executions,AVG(COALESCE(sr.duration_seconds,0)) avg_seconds,SUM(CASE WHEN sr.metrics_json IS NOT NULL THEN 1 ELSE 0 END) measured FROM stage_runs sr " + where + " GROUP BY sr.stage ORDER BY avg_seconds DESC LIMIT ?",
        tuple(params + [limit]),
    )
    out = []
    for r in rows:
        stage = str(r["stage"])
        avg = float(r["avg_seconds"] or 0)
        candidates = 0
        if target:
            candidates = int((db.one("SELECT COUNT(*) c FROM bug_candidates WHERE target=? AND source_run_id IN (SELECT run_id FROM stage_runs WHERE target=? AND stage=? AND status='success')", (target, target, stage)) or {"c": 0})["c"])
        base = STAGE_VALUE_DEFAULTS.get(stage, 50)
        efficiency = _clamp(base + min(20, candidates * 2) - min(25, avg / 30))
        out.append({"stage": stage, "executions": int(r["executions"] or 0), "average_seconds": round(avg, 2), "candidates": candidates, "value_score": efficiency})
    return out


def smart_recon_plan(db: Database, *, target: str, persist: bool = True) -> dict[str, Any]:
    memory = target_memory(db, target=target, persist=persist)
    change = change_intelligence(db, target=target, persist=persist)
    coverage = recon_coverage(db, target=target, persist=persist)
    values = {r["stage"]: r for r in stage_value_analysis(db, target=target)}
    recent_change_count = sum(int(c.get("count") or 0) for c in change.get("changes", []))
    prioritize = []
    defer = []
    if coverage["components"].get("javascript", 0) < 70 or any(c.get("type") == "javascript" for c in change["changes"]): prioritize.append("javascript")
    if coverage["components"].get("api", 0) < 70: prioritize.append("urls")
    if coverage["components"].get("http", 0) < 70: prioritize.append("fingerprint")
    if coverage["components"].get("subdomain", 0) < 70 or recent_change_count > 20: prioritize.append("subdomains")
    for stage in ["subdomains", "dns", "urls", "javascript", "fingerprint"]:
        score = int(values.get(stage, {}).get("value_score", STAGE_VALUE_DEFAULTS.get(stage, 50)))
        if score < 35 and stage not in prioritize: defer.append(stage)
    prioritize = list(dict.fromkeys(prioritize or ["urls", "javascript", "fingerprint"]))
    avg_seconds = sum(float(values.get(s, {}).get("average_seconds", 0)) for s in prioritize)
    request_estimate = max(300, 800 * len(prioritize) + 10 * recent_change_count)
    plan = {
        "target": target,
        "mode": "incremental" if change.get("previous_run") else "baseline",
        "prioritize": prioritize,
        "defer": defer,
        "reasons": {
            "coverage": coverage,
            "recent_change_count": recent_change_count,
            "target_memory_confidence": memory["confidence"],
        },
        "estimated_runtime_minutes": max(5, round(avg_seconds / 60 + 5)),
        "estimated_requests": int(request_estimate),
        "requires_user_confirmation": True,
        "active_modules_automatically_enabled": False,
        "generated_at": utc_now(),
    }
    if persist:
        plan_id = f"plan-{uuid.uuid4().hex[:16]}"
        db.execute("INSERT INTO smart_recon_plans(plan_id,target,plan_json,status,created_at) VALUES(?,?,?,?,?)", (plan_id, target, json_dumps(plan), "proposed", utc_now()))
        plan["plan_id"] = plan_id
    return plan


def build_evidence_linked_report(db: Database, case_id: str, *, actor: str = "analyst", persist: bool = True) -> dict[str, Any]:
    case, candidates = _case_and_candidates(db, case_id)
    gap = evidence_gap_for_case(db, case_id, persist=False)
    confirmed = str(case.get("state") or "") in {"confirmed", "ready_for_report", "reported", "closed"} or any(str(c.get("analyst_decision")) == "confirmed_by_analyst" for c in candidates)
    evidence_links: list[dict[str, Any]] = []
    seen_refs: set[tuple[str, str]] = set()

    def add_ref(ref: dict[str, Any], ref_type: str, ref_id: str) -> None:
        key = (ref_type, ref_id)
        if not ref_id or key in seen_refs:
            return
        seen_refs.add(key)
        evidence_links.append(ref)

    for c in candidates:
        candidate_id = str(c["candidate_id"])
        linked = db.all(
            "SELECT er.evidence_id,er.evidence_type,er.polarity,er.summary,er.trust_score,er.observation_quality,er.created_at,l.relation,l.weight "
            "FROM candidate_evidence_links l JOIN evidence_records er ON er.evidence_id=l.evidence_id "
            "WHERE l.candidate_id=? ORDER BY er.trust_score DESC,er.observation_quality DESC,er.created_at DESC LIMIT 100",
            (candidate_id,),
        )
        for row in linked:
            add_ref({
                "candidate_id": candidate_id,
                "evidence_id": str(row["evidence_id"]),
                "evidence_type": str(row["evidence_type"]),
                "polarity": str(row["polarity"]),
                "summary": str(row["summary"] or "")[:600],
                "trust_score": int(row["trust_score"] or 0),
                "observation_quality": int(row["observation_quality"] or 0),
                "relation": str(row["relation"] or "supports"),
                "weight": int(row["weight"] or 0),
                "created_at": str(row["created_at"] or ""),
            }, "evidence", str(row["evidence_id"]))

        # Legacy candidate support is reduced to bounded summaries only. Raw payloads
        # and arbitrary nested evidence are intentionally not copied into reports.
        for index, ev in enumerate(_loads(c.get("supporting_evidence_json"), [])):
            if isinstance(ev, dict):
                summary = str(ev.get("summary") or ev.get("reason") or ev.get("type") or "Candidate support")[:400]
                kind = str(ev.get("type") or ev.get("kind") or "candidate_support")[:80]
            else:
                summary = str(ev)[:400]
                kind = "candidate_support"
            add_ref({
                "candidate_id": candidate_id,
                "evidence_type": kind,
                "polarity": "supporting",
                "summary": summary,
                "source": "bounded_candidate_summary",
            }, "legacy", f"{candidate_id}:{index}:{sha256_text(summary)[:12]}")

    for row in db.all(
        "SELECT observation_id,source_type,created_at,observation_json FROM imported_http_evidence "
        "WHERE case_id=? ORDER BY created_at DESC LIMIT 50",
        (case_id,),
    ):
        obs = _loads(row["observation_json"], {})
        safe_summary = {
            "method": str(obs.get("method") or "")[:12],
            "url": _redact_url(str(obs.get("url") or "")) if obs.get("url") else "",
            "status_code": obs.get("status_code"),
            "context": str(obs.get("context") or obs.get("authentication_context") or "")[:120],
        }
        add_ref({
            "observation_id": str(row["observation_id"]),
            "source_type": str(row["source_type"]),
            "created_at": str(row["created_at"]),
            "summary": safe_summary,
        }, "observation", str(row["observation_id"]))

    claims = []
    if confirmed:
        claims.append({"claim": str(case.get("summary") or case.get("title") or "Confirmed security behavior"), "supported": bool(evidence_links), "evidence_refs": evidence_links[:20]})
    else:
        claims.append({"claim": "Candidate remains unconfirmed and must not be presented as a confirmed vulnerability.", "supported": True, "evidence_refs": []})
    body = {
        "title": str(case.get("title") or "Security finding"),
        "summary": str(case.get("summary") or ""),
        "affected_asset": str(case.get("target") or ""),
        "preconditions": [i["label"] for i in gap["requirements"] if i["key"] in {"authenticated_context", "second_identity", "role_map", "ownership_map"} and i["status"] == "present"],
        "observed_behavior": "Derived from linked, redacted evidence. Review before submission.",
        "expected_behavior": "Access and behavior should remain within the documented authorization and ownership boundaries.",
        "impact": "Analyst review required; impact is not automatically inferred as confirmed.",
        "evidence_links": evidence_links,
        "claims": claims,
        "reproduction": "Use only program-authorized test identities and the bounded/manual validation workflow described by the case.",
        "redaction": "Secrets, cookies, authorization values, raw references and raw sensitive bodies are excluded.",
    }
    readiness = _clamp(0.55 * gap["coverage"] + (30 if confirmed else 0) + (15 if evidence_links else 0))
    result = {"case_id": case_id, "confirmed": confirmed, "readiness": readiness, "body": body, "blocked": not confirmed, "block_reason": "Analyst confirmation is required before a vulnerability claim can be generated." if not confirmed else ""}
    if persist:
        draft_id = f"rpt-{uuid.uuid4().hex[:16]}"
        db.execute(
            "INSERT INTO report_drafts(draft_id,case_id,title,body_json,status,readiness_score,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (draft_id, case_id, body["title"], json_dumps(body), "draft", readiness, actor, utc_now(), utc_now()),
        )
        for claim in claims:
            claim_id = f"clm-{uuid.uuid4().hex[:16]}"
            db.execute("INSERT INTO report_claims(claim_id,draft_id,case_id,claim,supported,evidence_refs_json,created_at) VALUES(?,?,?,?,?,?,?)", (claim_id, draft_id, case_id, claim["claim"], 1 if claim["supported"] else 0, json_dumps(claim["evidence_refs"]), utc_now()))
        result["draft_id"] = draft_id
        db.audit("evidence_linked_report_created", actor=actor, target=str(case.get("target") or ""), entity_type="case", entity_value=case_id, details={"draft_id": draft_id, "readiness": readiness, "confirmed": confirmed})
    return result


def import_browser_capture(paths: AppPaths, db: Database, *, target: str, file_path: str | Path, context_label: str, actor: str = "analyst", limit: int = 1000) -> dict[str, Any]:
    path = Path(file_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ReconError(f"Capture file not found: {path}")
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ReconError("Capture file exceeds the 20 MB metadata-only import limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ReconError(f"Invalid capture JSON: {exc}") from exc
    entries = payload.get("entries") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise ReconError("Browser capture must be a JSON list or an object containing entries[]")
    imported = 0; skipped = 0
    for raw in entries[: max(1, min(limit, 5000))]:
        if not isinstance(raw, dict): skipped += 1; continue
        url = _redact_url(str(raw.get("url") or ""))
        if not url: skipped += 1; continue
        host = urllib.parse.urlsplit(url).hostname or ""
        if not (host == target or host.endswith("." + target)):
            skipped += 1; continue
        headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
        safe_headers = {str(k): str(v)[:200] for k, v in headers.items() if str(k).strip().lower() in SAFE_CAPTURE_HEADERS and not SECRET_HEADER_RE.match(str(k))}
        record = {
            "url": url,
            "method": str(raw.get("method") or "GET").upper()[:12],
            "status_code": int(raw.get("status_code") or raw.get("status") or 0) if str(raw.get("status_code") or raw.get("status") or "0").isdigit() else None,
            "content_type": str(raw.get("content_type") or safe_headers.get("Content-Type") or "")[:160],
            "navigation": str(raw.get("navigation") or raw.get("type") or "")[:80],
            "context": context_label[:120],
            "headers": safe_headers,
            "response_shape": raw.get("response_shape") if isinstance(raw.get("response_shape"), (dict, list)) else None,
        }
        event_id = f"cap-{uuid.uuid4().hex[:20]}"
        db.execute(
            "INSERT INTO browser_capture_events(event_id,target,context_label,url,method,status_code,content_type,metadata_json,source_file,imported_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, target, context_label[:120], url, record["method"], record["status_code"], record["content_type"], json_dumps(record), path.name, actor, utc_now()),
        )
        imported += 1
    db.audit("browser_capture_imported", actor=actor, target=target, entity_type="capture", entity_value=path.name, details={"imported": imported, "skipped": skipped, "context": context_label})
    authentication_contexts(db, target=target, persist=True)
    return {"target": target, "context": context_label, "imported": imported, "skipped": skipped, "source_file": str(path), "raw_secrets_stored": False}


def operator_diagnostics(paths: AppPaths, config: Config, db: Database, *, persist: bool = True) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def add(check_id: str, label: str, status: str, detail: str, action: str = "") -> None:
        checks.append({"id": check_id, "label": label, "status": status, "detail": detail, "recommended_action": action})
    try:
        integrity = db.integrity()
        add("DB-INTEGRITY", "Database integrity", "ok" if str(integrity).lower() == "ok" else "error", str(integrity), "Restore the latest verified backup if integrity is not OK.")
    except Exception as exc:
        add("DB-INTEGRITY", "Database integrity", "error", str(exc), "Run backup verification and repair diagnostics.")
    schema = str(db.meta_get("schema_version") or "unknown")
    expected_schema = str(SCHEMA_VERSION)
    add("DB-SCHEMA", "Database schema", "ok" if schema == expected_schema else "warn", f"Schema {schema}; expected {expected_schema}", "Run the current Recon Monitor migration if the schema is older.")
    disk = shutil.disk_usage(paths.root)
    free_gb = disk.free / (1024 ** 3)
    add("FS-DISK", "Free disk space", "ok" if free_gb >= 2 else "warn", f"{free_gb:.1f} GB free", "Run retention preview or free disk space." if free_gb < 2 else "")
    for name, path in [("config.env", paths.config), ("target policy", paths.policy), ("database", paths.db)]:
        exists = path.exists()
        add(f"FILE-{name.upper().replace('.','-').replace(' ','-')}", name, "ok" if exists else "warn", str(path), "Run init/setup if the file is missing." if not exists else "")
    running = db.all("SELECT id,started_at FROM runs WHERE status='running' ORDER BY started_at")
    stale = []
    now = time.time()
    for r in running:
        stale.append(str(r["id"]))
    add("RUN-STATE", "Run state", "warn" if stale else "ok", f"{len(stale)} run(s) marked running", "Use repair --dry-run before changing stale state." if stale else "")
    failed = db.all("SELECT run_id,target,stage,error,finished_at FROM stage_runs WHERE status='failed' ORDER BY finished_at DESC LIMIT 10")
    add("STAGE-FAIL", "Recent failed stages", "warn" if failed else "ok", f"{len(failed)} recent failure(s)", "Review the Operations Center and stage errors." if failed else "")
    auth_enabled = config.bool("DASHBOARD_AUTH_ENABLED", False)
    host = config.get("DASHBOARD_HOST", "127.0.0.1")
    remote = host not in {"127.0.0.1", "localhost", "::1", ""}
    status = "error" if remote and not auth_enabled else "ok"
    add("DASHBOARD-BIND", "Dashboard exposure", status, f"host={host or '127.0.0.1'}, auth={'enabled' if auth_enabled else 'disabled'}", "Enable authentication before remote binding." if status == "error" else "")
    plugins_failed = db.all("SELECT plugin_name,status,created_at FROM plugin_health_history WHERE status NOT IN ('ok','healthy') ORDER BY created_at DESC LIMIT 20")
    add("PLUGIN-HEALTH", "Plugin health", "warn" if plugins_failed else "ok", f"{len(plugins_failed)} non-healthy recent record(s)", "Review plugin health or disable the failing plugin." if plugins_failed else "")
    overall = "ok"
    if any(c["status"] == "error" for c in checks): overall = "error"
    elif any(c["status"] == "warn" for c in checks): overall = "warn"
    result = {"version": WORKSPACE_V7_VERSION, "overall": overall, "checks": checks, "python": platform.python_version(), "platform": platform.platform(), "generated_at": utc_now()}
    if persist:
        diag_id = f"diag-{uuid.uuid4().hex[:18]}"
        db.execute("INSERT INTO operator_diagnostics(diag_id,overall,checks_json,created_at) VALUES(?,?,?,?)", (diag_id, overall, json_dumps(checks), utc_now()))
        result["diag_id"] = diag_id
    return result


def safety_center(paths: AppPaths, config: Config, db: Database) -> dict[str, Any]:
    targets = [str(r["target"]) for r in db.all("SELECT DISTINCT target FROM scope_snapshots ORDER BY target")]
    latest_scopes = []
    for target in targets:
        row = db.one("SELECT target,authorization_status,scope_json,created_at FROM scope_snapshots WHERE target=? ORDER BY created_at DESC LIMIT 1", (target,))
        if row: latest_scopes.append({"target": target, "authorization_status": row["authorization_status"], "scope": _loads(row["scope_json"], {}), "created_at": row["created_at"]})
    active_config = config.bool("ENABLE_ACTIVE_MODULES", False)
    authorized = config.bool("I_HAVE_AUTHORIZATION", False)
    remote_host = config.get("DASHBOARD_HOST", "127.0.0.1")
    remote = remote_host not in {"127.0.0.1", "localhost", "::1", ""}
    audit = {"valid": True}
    try:
        from platform_v6 import verify_audit_chain
        audit = verify_audit_chain(db)
    except Exception as exc:
        audit = {"valid": False, "error": str(exc)}
    scope_ready = bool(latest_scopes)
    safe = bool(authorized and scope_ready and (not remote or config.bool("DASHBOARD_AUTH_ENABLED", False)) and audit.get("valid", False))
    return {
        "status": "SAFE TO RUN" if safe else "ACTION REQUIRED",
        "scope_ready": scope_ready,
        "authorized": authorized,
        "active_modules_enabled": active_config,
        "dashboard_host": remote_host,
        "dashboard_auth": config.bool("DASHBOARD_AUTH_ENABLED", False),
        "api_remote_allowed": config.bool("API_ALLOW_REMOTE", False),
        "audit_integrity": audit,
        "scopes": latest_scopes,
        "validation_policy": {"automatic_live": False, "manual_only_families": ["broken_object_authorization", "broken_function_authorization", "ssrf", "xss_execution", "file_upload", "path_traversal", "race", "payment", "account_recovery", "role_modification"]},
        "generated_at": utc_now(),
    }


def cockpit(db: Database, *, target: str = "") -> dict[str, Any]:
    params = (target,) if target else ()
    case_where = " WHERE target=?" if target else ""
    cases = int((db.one("SELECT COUNT(*) c FROM security_cases" + case_where + (" AND" if target else " WHERE") + " state NOT IN ('reported','closed','rejected')", params) or {"c": 0})["c"])
    candidate_where = " WHERE target=?" if target else ""
    candidates = int((db.one("SELECT COUNT(*) c FROM bug_candidates" + candidate_where + (" AND" if target else " WHERE") + " priority_score>=70 AND analyst_decision='unreviewed'", params) or {"c": 0})["c"])
    needs_evidence = int((db.one("SELECT COUNT(*) c FROM security_cases" + case_where + (" AND" if target else " WHERE") + " state='needs_evidence'", params) or {"c": 0})["c"])
    validation_ready = int((db.one("SELECT COUNT(*) c FROM security_cases" + case_where + (" AND" if target else " WHERE") + " state='ready_for_validation'", params) or {"c": 0})["c"])
    attention = []
    sql = "SELECT case_id,target,title,state,priority_score,evidence_gap_score,autopilot_score FROM security_cases"
    if target: sql += " WHERE target=?"
    sql += " ORDER BY priority_score DESC,updated_at DESC LIMIT 10"
    for r in db.all(sql, params):
        detail = f"{r['state']} · priority {r['priority_score']} · evidence gap {r['evidence_gap_score']}%"
        attention.append({"kind": "case", "id": r["case_id"], "target": r["target"], "title": r["title"], "detail": detail, "href": f"/case?id={urllib.parse.quote(str(r['case_id']))}"})
    if target:
        change = change_intelligence(db, target=target, persist=False)
    else:
        change = {}
    return {"target": target, "open_cases": cases, "high_value_candidates": candidates, "needs_evidence": needs_evidence, "validation_ready": validation_ready, "attention": attention, "change": change, "generated_at": utc_now()}


def universal_search(db: Database, query: str, *, limit: int = 50) -> dict[str, list[dict[str, Any]]]:
    q = str(query or "").strip()
    if not q:
        return {}
    like = f"%{q}%"
    results: dict[str, list[dict[str, Any]]] = {}
    specs = [
        ("Cases", "SELECT target,case_id value,title||' · '||state extra,updated_at seen FROM security_cases WHERE case_id LIKE ? OR title LIKE ? OR summary LIKE ? LIMIT ?", (like, like, like, limit)),
        ("Stories", "SELECT target,story_id value,title||' · '||status extra,updated_at seen FROM security_stories WHERE story_id LIKE ? OR title LIKE ? OR summary LIKE ? LIMIT ?", (like, like, like, limit)),
        ("Candidates", "SELECT target,candidate_id value,title||' · '||bug_family||' · '||candidate_state extra,updated_at seen FROM bug_candidates WHERE candidate_id LIKE ? OR endpoint LIKE ? OR title LIKE ? OR summary LIKE ? LIMIT ?", (like, like, like, like, limit)),
        ("Endpoints", "SELECT target,endpoint value,primary_category||' · '||confidence||'%' extra,last_seen seen FROM endpoint_intelligence WHERE endpoint LIKE ? OR primary_category LIKE ? LIMIT ?", (like, like, limit)),
        ("Assets", "SELECT target,host value,'confidence '||confidence||'%' extra,last_seen seen FROM assets WHERE host LIKE ? LIMIT ?", (like, limit)),
        ("JavaScript", "SELECT target,value,kind||' @ '||js_url extra,last_seen seen FROM js_indicators WHERE value LIKE ? OR js_url LIKE ? LIMIT ?", (like, like, limit)),
        ("Evidence", "SELECT target,evidence_id value,evidence_type||' · '||polarity extra,created_at seen FROM evidence_records WHERE evidence_id LIKE ? OR source_artifact LIKE ? OR evidence_type LIKE ? LIMIT ?", (like, like, like, limit)),
        ("Captures", "SELECT target,event_id value,context_label||' · '||method||' '||url extra,created_at seen FROM browser_capture_events WHERE event_id LIKE ? OR url LIKE ? OR context_label LIKE ? LIMIT ?", (like, like, like, limit)),
    ]
    for name, sql, params in specs:
        try:
            results[name] = [dict(r) for r in db.all(sql, params)]
        except sqlite3.OperationalError:
            results[name] = []
    return results


def workspace_v7_sync(paths: AppPaths, config: Config, db: Database, *, target: str = "", actor: str = "system") -> dict[str, Any]:
    targets = [target] if target else [str(r["target"]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
    output: dict[str, Any] = {"version": WORKSPACE_V7_VERSION, "targets": {}, "cases": 0}
    for tgt in targets:
        if not tgt: continue
        entry: dict[str, Any] = {}
        entry["memory"] = target_memory(db, target=tgt, persist=True)
        entry["coverage"] = recon_coverage(db, target=tgt, persist=True)
        entry["changes"] = change_intelligence(db, target=tgt, persist=True)
        entry["contexts"] = authentication_contexts(db, target=tgt, persist=True)
        entry["differentials"] = differential_intelligence(db, target=tgt, persist=True)
        entry["learning"] = false_positive_learning(db, target=tgt, persist=True)
        output["targets"][tgt] = entry
    cases = [str(r["case_id"]) for r in db.all("SELECT case_id FROM security_cases WHERE state NOT IN ('reported','closed','rejected') ORDER BY priority_score DESC LIMIT 500")]
    for case_id in cases:
        try:
            case_autopilot(db, case_id, actor=actor, persist=True)
            output["cases"] += 1
        except Exception:
            continue
    output["diagnostics"] = operator_diagnostics(paths, config, db, persist=True)
    output["safety"] = safety_center(paths, config, db)
    db.audit("workspace_v7_sync", actor=actor, entity_type="workspace", entity_value=WORKSPACE_V7_VERSION, details={"targets": len(output["targets"]), "cases": output["cases"]})
    return output

def _safe_error_value(value: Any, key: str = "") -> Any:
    if re.search(r"token|cookie|secret|authorization|password|csrf|credential", key, re.I):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(k): _safe_error_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_error_value(v, key) for v in value[:50]]
    text = str(value) if not isinstance(value, (int, float, bool, type(None))) else value
    if isinstance(text, str) and len(text) > 1000:
        return text[:1000] + "…"
    return text


ERROR_CATALOG = {
    "RM-DASH-ORIGIN-001": {"component": "dashboard", "summary": "Dashboard origin validation rejected a form POST", "action": "Use one local loopback address, refresh the page, and inspect safe diagnostics."},
    "RM-DASH-CSRF-002": {"component": "dashboard", "summary": "Dashboard CSRF validation rejected a form POST", "action": "Reload the page to obtain a fresh session token and retry."},
    "RM-DB-INTEGRITY-001": {"component": "database", "summary": "Database integrity check failed", "action": "Stop writes, verify the latest backup, and run a restore drill before recovery."},
    "RM-RUN-STALE-001": {"component": "execution", "summary": "A run is marked running without recent progress", "action": "Run repair preview; only repair stale execution state after confirming no live run owns the lock."},
    "RM-PLUGIN-HEALTH-001": {"component": "plugins", "summary": "A plugin health check is failing", "action": "Review plugin health and disable or update the failing plugin."},
}


def record_error_event(db: Database, error_code: str, *, component: str = "", summary: str = "", details: dict[str, Any] | None = None) -> str:
    catalog = ERROR_CATALOG.get(error_code, {})
    error_id = f"ERR-{uuid.uuid4().hex[:12].upper()}"
    safe = _safe_error_value(dict(details or {}))
    db.execute(
        "INSERT INTO error_events(error_id,component,error_code,summary,safe_details_json,resolved,created_at) VALUES(?,?,?,?,?,?,?)",
        (error_id, component or str(catalog.get("component") or "unknown"), error_code, summary or str(catalog.get("summary") or error_code), json_dumps(safe), 0, utc_now()),
    )
    return error_id


def recent_error_events(db: Database, *, limit: int = 100) -> list[dict[str, Any]]:
    rows = db.all("SELECT * FROM error_events ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 500)),))
    out = []
    for row in rows:
        item = dict(row)
        item["details"] = _loads(item.pop("safe_details_json", "{}"), {})
        item["catalog"] = ERROR_CATALOG.get(str(item.get("error_code") or ""), {})
        out.append(item)
    return out


def safe_repair(paths: AppPaths, db: Database, *, dry_run: bool = True, actor: str = "analyst", max_age_hours: int = 24) -> dict[str, Any]:
    action_id = f"repair-{uuid.uuid4().hex[:16]}"
    stale = db.repair_stale_state(max_age_hours, dry_run=True)
    expired_sessions = []
    if paths.sessions.exists():
        cutoff = time.time() - 7 * 86400
        for file in paths.sessions.glob("*.json"):
            try:
                if file.stat().st_mtime < cutoff:
                    expired_sessions.append(str(file))
            except OSError:
                continue
    preview = {"stale_state": stale, "expired_session_files": len(expired_sessions), "safe_actions": ["repair stale database execution state", "delete session files older than 7 days"], "destructive_scope": "none outside stale state and expired sessions"}
    db.execute("INSERT INTO recovery_actions(action_id,action_type,status,details_json,created_by,created_at) VALUES(?,?,?,?,?,?)", (action_id, "safe_repair", "preview" if dry_run else "running", json_dumps(preview), actor, utc_now()))
    if dry_run:
        return {"action_id": action_id, "dry_run": True, **preview}
    repaired = db.repair_stale_state(max_age_hours, dry_run=False)
    deleted = 0
    for name in expired_sessions:
        try:
            Path(name).unlink(missing_ok=True); deleted += 1
        except OSError:
            continue
    result = {"action_id": action_id, "dry_run": False, "stale_state": repaired, "expired_sessions_deleted": deleted}
    db.execute("UPDATE recovery_actions SET status='completed',details_json=?,executed_at=? WHERE action_id=?", (json_dumps(result), utc_now(), action_id))
    db.audit("safe_repair_completed", actor=actor, entity_type="recovery", entity_value=action_id, details=result)
    return result


def browser_compatibility(user_agent: str) -> dict[str, Any]:
    ua = str(user_agent or "")
    family = "unknown"; notes = []
    if "Safari/" in ua and "Chrome/" not in ua and "Chromium/" not in ua:
        family = "safari"; notes.append("Safari privacy features can emit Origin:null on loopback form submissions; Recon Monitor handles the narrow same-origin validation workflow explicitly.")
    elif "Firefox/" in ua:
        family = "firefox"
    elif "Chrome/" in ua or "Chromium/" in ua:
        family = "chromium"
    return {"family": family, "supported": family in {"safari", "firefox", "chromium"}, "notes": notes, "user_agent_hash": sha256_text(ua)[:16] if ua else ""}

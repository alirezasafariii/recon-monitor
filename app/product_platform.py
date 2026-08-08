from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, parse_int, safe_json_loads, utc_now

PLATFORM_VERSION = "6.0.4"

# Heavy platform summaries are generated at analysis/sync time. Dashboard GET
# requests serve snapshots or a short-lived process cache instead of rescanning
# candidates, files, plugins, and the full SQLite database on every page load.
_MEMO: dict[str, tuple[float, Any]] = {}


def _memo_get(key: str, ttl_seconds: int) -> Any | None:
    item = _MEMO.get(key)
    if not item:
        return None
    created, value = item
    if time.monotonic() - created > max(1, ttl_seconds):
        _MEMO.pop(key, None)
        return None
    return value


def _memo_set(key: str, value: Any) -> Any:
    _MEMO[key] = (time.monotonic(), value)
    return value


def invalidate_platform_cache() -> None:
    _MEMO.clear()

CASE_STATES = ["new", "triaged", "reviewing", "needs_evidence", "ready_for_validation", "confirmed", "rejected", "ready_for_report", "reported", "closed"]
RULE_STATES = ["draft", "shadow", "candidate", "active", "deprecated", "disabled"]
NOTIFICATION_MODES = ["immediate", "digest", "system_warning", "disabled"]

USEFUL_DECISIONS = {"confirmed_by_analyst", "needs_more_evidence"}
NEGATIVE_DECISIONS = {"rejected", "duplicate", "out_of_scope"}


def _loads(value: Any, fallback: Any) -> Any:
    return safe_json_loads(value, fallback, expected_type=type(fallback))


def _latest_analysis(db: Database, target: str | None = None) -> str:
    if target:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' AND target IN (?, '*') ORDER BY finished_at DESC LIMIT 1", (target,))
    else:
        row = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
    return str(row["id"]) if row else ""


def _latest_run(db: Database, target: str | None = None) -> str:
    if target:
        row = db.one("SELECT run_id FROM run_targets WHERE target=? ORDER BY started_at DESC LIMIT 1", (target,))
    else:
        row = db.one("SELECT id FROM runs ORDER BY started_at DESC LIMIT 1")
    return str(row[0]) if row else ""


def _candidate_rule_ids(candidate: dict[str, Any]) -> list[str]:
    values = _loads(candidate.get("rule_ids_json"), [])
    return [str(item) for item in values if str(item).strip()]


def engine_quality_snapshot(db: Database, analysis_id: str | None = None, target: str | None = None, *, max_age_seconds: int = 300, refresh: bool = False) -> dict[str, Any]:
    """Serve the latest persisted quality summary or compute it once.

    Full quality calculation parses every candidate and rule lineage, so normal
    dashboard requests should use the snapshot produced by platform_sync.
    """
    analysis_id = analysis_id or _latest_analysis(db, target)
    cache_key = f"quality:{db.path}:{analysis_id}:{target or '*'}"
    if not refresh:
        cached = _memo_get(cache_key, max_age_seconds)
        if cached is not None:
            return cached
        if analysis_id:
            if target:
                row = db.one(
                    "SELECT metrics_json,created_at FROM engine_quality_snapshots "
                    "WHERE analysis_id=? AND target IN (?, '*') "
                    "ORDER BY CASE WHEN target=? THEN 0 ELSE 1 END,created_at DESC LIMIT 1",
                    (analysis_id, target, target),
                )
            else:
                row = db.one(
                    "SELECT metrics_json,created_at FROM engine_quality_snapshots WHERE analysis_id=? ORDER BY created_at DESC LIMIT 1",
                    (analysis_id,),
                )
            if row:
                payload = _loads(row["metrics_json"], {})
                if isinstance(payload, dict) and payload:
                    payload = dict(payload)
                    payload["snapshot_created_at"] = row["created_at"]
                    payload["snapshot_source"] = "persisted"
                    return _memo_set(cache_key, payload)
    payload = dict(engine_quality(db, analysis_id, target, persist=refresh))
    payload["snapshot_source"] = "computed"
    return _memo_set(cache_key, payload)


def run_completeness_snapshot(db: Database, run_id: str | None = None, *, refresh: bool = False) -> dict[str, Any]:
    run_id = run_id or _latest_run(db)
    if not run_id:
        return {"run_id": "", "score": 0, "dimensions": {}, "warnings": ["No runs available."]}
    cache_key = f"completeness:{db.path}:{run_id}"
    if not refresh:
        cached = _memo_get(cache_key, 120)
        if cached is not None:
            return cached
        row = db.one("SELECT score,metrics_json,created_at FROM run_completeness WHERE run_id=?", (run_id,))
        if row:
            payload = _loads(row["metrics_json"], {})
            if isinstance(payload, dict) and payload:
                payload = dict(payload)
                payload["snapshot_created_at"] = row["created_at"]
                return _memo_set(cache_key, payload)
    return _memo_set(cache_key, run_completeness(db, run_id, persist=refresh))


def storage_health_snapshot(paths: AppPaths, db: Database, *, refresh: bool = False) -> dict[str, Any]:
    cache_key = f"storage:{paths.root}"
    if not refresh:
        cached = _memo_get(cache_key, 300)
        if cached is not None:
            return cached
        row = db.one("SELECT metrics_json,created_at FROM storage_snapshots ORDER BY created_at DESC LIMIT 1")
        if row:
            payload = _loads(row["metrics_json"], {})
            if isinstance(payload, dict) and payload:
                payload = dict(payload)
                payload["snapshot_created_at"] = row["created_at"]
                payload["snapshot_source"] = "persisted"
                return _memo_set(cache_key, payload)
    if not refresh:
        def file_size(path: Path) -> int:
            try:
                return path.stat().st_size
            except OSError:
                return 0
        database_bytes = file_size(paths.db) + file_size(Path(str(paths.db) + "-wal")) + file_size(Path(str(paths.db) + "-shm"))
        object_count = parse_int((db.one("SELECT COUNT(*) count FROM object_store") or {"count": 0})["count"], 0)
        object_bytes = parse_int((db.one("SELECT COALESCE(SUM(size),0) size FROM object_store") or {"size": 0})["size"], 0)
        backups = parse_int((db.one("SELECT COUNT(*) count FROM backup_catalog") or {"count": 0})["count"], 0)
        payload = {
            "database_bytes": database_bytes, "state_bytes": 0, "output_bytes": 0, "reports_bytes": 0,
            "logs_bytes": 0, "backups_bytes": 0, "object_count": object_count, "object_bytes": object_bytes,
            "backup_count": backups, "estimated_total_bytes": database_bytes + object_bytes, "generated_at": utc_now(),
            "snapshot_source": "quick", "retention_preview": {"keep_confirmed_evidence": True, "raw_artifact_days": 90, "keep_backups": 10, "eligible_temporary_objects": 0},
        }
        return _memo_set(cache_key, payload)
    payload = dict(storage_health(paths, db, persist=True))
    payload["snapshot_source"] = "computed"
    return _memo_set(cache_key, payload)


def engine_quality(db: Database, analysis_id: str | None = None, target: str | None = None, *, persist: bool = False) -> dict[str, Any]:
    analysis_id = analysis_id or _latest_analysis(db, target)
    params: list[Any] = []
    where: list[str] = []
    if analysis_id:
        where.append("analysis_id=?"); params.append(analysis_id)
    if target:
        where.append("target=?"); params.append(target)
    clause = " WHERE " + " AND ".join(where) if where else ""
    candidates = [dict(row) for row in db.all(f"SELECT * FROM bug_candidates{clause}", tuple(params))]
    evidence_count = 0
    parser_rows: list[dict[str, Any]] = []
    if analysis_id:
        evidence_count = parse_int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"], 0)
        parser_rows = [dict(row) for row in db.all("SELECT parser_name,COUNT(*) count,ROUND(AVG(observation_quality),1) quality,ROUND(AVG(trust_score),1) trust FROM evidence_records WHERE analysis_id=? GROUP BY parser_name ORDER BY count DESC", (analysis_id,))]
    reviewed = [row for row in candidates if str(row.get("analyst_decision")) != "unreviewed"]
    useful = [row for row in reviewed if str(row.get("analyst_decision")) in USEFUL_DECISIONS]
    negative = [row for row in reviewed if str(row.get("analyst_decision")) in NEGATIVE_DECISIONS]
    strong = [row for row in candidates if str(row.get("candidate_state")) in {"strong_candidate", "confirmed_by_analyst"}]
    strong_reviewed = [row for row in strong if str(row.get("analyst_decision")) != "unreviewed"]
    strong_useful = [row for row in strong_reviewed if str(row.get("analyst_decision")) in USEFUL_DECISIONS]
    duplicate_count = sum(1 for row in candidates if str(row.get("analyst_decision")) == "duplicate")
    family: dict[str, dict[str, Any]] = {}
    for name in sorted({str(row.get("bug_family") or "unknown") for row in candidates}):
        rows = [row for row in candidates if str(row.get("bug_family") or "unknown") == name]
        family_reviewed = [row for row in rows if str(row.get("analyst_decision")) != "unreviewed"]
        family_useful = [row for row in family_reviewed if str(row.get("analyst_decision")) in USEFUL_DECISIONS]
        family_negative = [row for row in family_reviewed if str(row.get("analyst_decision")) in NEGATIVE_DECISIONS]
        family[name] = {
            "total": len(rows), "reviewed": len(family_reviewed), "useful": len(family_useful), "negative": len(family_negative),
            "precision_proxy": round(len(family_useful) / max(1, len(family_reviewed)), 3),
            "avg_likelihood": round(sum(parse_int(row.get("calibrated_likelihood"), parse_int(row.get("likelihood_score"), 0)) for row in rows) / max(1, len(rows)), 1),
            "avg_coverage": round(sum(parse_int(row.get("evidence_coverage"), 0) for row in rows) / max(1, len(rows)), 1),
            "avg_exploitability": round(sum(parse_int(row.get("exploitability_confidence"), 0) for row in rows) / max(1, len(rows)), 1),
        }
    rule_stats: dict[str, Counter[str]] = defaultdict(Counter)
    for row in candidates:
        decision = str(row.get("analyst_decision") or "unreviewed")
        for rule_id in _candidate_rule_ids(row):
            rule_stats[rule_id]["generated"] += 1
            if decision in USEFUL_DECISIONS: rule_stats[rule_id]["useful"] += 1
            elif decision in NEGATIVE_DECISIONS: rule_stats[rule_id]["negative"] += 1
            else: rule_stats[rule_id]["unreviewed"] += 1
    rules = []
    for rule_id, counts in rule_stats.items():
        reviewed_count = counts["useful"] + counts["negative"]
        precision = round(counts["useful"] / max(1, reviewed_count), 3)
        noise = round(counts["negative"] / max(1, reviewed_count), 3)
        rules.append({"rule_id": rule_id, **dict(counts), "precision_proxy": precision, "noise_proxy": noise})
    rules.sort(key=lambda row: (-row["noise_proxy"], -row["generated"], row["rule_id"]))
    avg_coverage = round(sum(parse_int(row.get("evidence_coverage"), 0) for row in candidates) / max(1, len(candidates)), 1)
    avg_observation = round(sum(parse_int(row.get("observation_quality"), 0) for row in candidates) / max(1, len(candidates)), 1)
    reviewed_precision = round(len(useful) / max(1, len(reviewed)), 3)
    strong_precision = round(len(strong_useful) / max(1, len(strong_reviewed)), 3)
    backlog = len([row for row in candidates if str(row.get("analyst_decision")) == "unreviewed"])
    noise_rate = round(len(negative) / max(1, len(reviewed)), 3)
    candidate_rate = round(len(candidates) * 1000 / max(1, evidence_count), 2)
    health = 100
    health -= min(25, int(noise_rate * 35))
    health -= 15 if avg_coverage < 45 else 7 if avg_coverage < 65 else 0
    health -= 12 if avg_observation < 55 else 5 if avg_observation < 70 else 0
    health -= min(18, backlog // 25)
    health = max(0, min(100, health))
    warnings = []
    if len(reviewed) < 10: warnings.append("Calibration sample is still small; probability values remain provisional.")
    if noise_rate > .5: warnings.append("Reviewed candidates show a high negative-decision rate.")
    if avg_coverage < 50: warnings.append("Average evidence coverage is low.")
    if backlog > 100: warnings.append("Unreviewed candidate backlog is large.")
    if rules and rules[0]["noise_proxy"] >= .6 and rules[0]["negative"] >= 3: warnings.append(f"Rule {rules[0]['rule_id']} is a leading noise contributor.")
    budget = noise_budget_status(db, analysis_id, target=target) if analysis_id else noise_budget_status(db, target=target)
    learned = learn_target_profile(db, target, analysis_id, persist=True) if target else None
    if budget.get("overflow_count", 0): warnings.append(f"Noise budget overflow: {budget['overflow_count']} candidate(s) routed outside Review now.")
    payload = {
        "version": PLATFORM_VERSION, "analysis_id": analysis_id, "target": target or "*", "generated_at": utc_now(),
        "health_score": health, "candidates": len(candidates), "evidence_records": evidence_count, "reviewed": len(reviewed),
        "useful": len(useful), "negative": len(negative), "unreviewed_backlog": backlog, "strong_candidates": len(strong),
        "reviewed_precision_proxy": reviewed_precision, "strong_precision_proxy": strong_precision,
        "false_positive_proxy": noise_rate, "duplicate_rate": round(duplicate_count / max(1, len(candidates)), 3),
        "candidate_rate_per_1000_evidence": candidate_rate, "average_evidence_coverage": avg_coverage,
        "average_observation_quality": avg_observation, "families": family, "rules": rules[:100], "parsers": parser_rows,
        "warnings": warnings, "noise_budget": budget, "target_learning": learned,
    }
    if persist and analysis_id:
        db.execute("INSERT INTO engine_quality_snapshots(analysis_id,target,health_score,metrics_json,created_at) VALUES(?,?,?,?,?)", (analysis_id, target or "*", health, json_dumps(payload), utc_now()))
    return payload



def seed_noise_budgets(db: Database) -> int:
    now = utc_now()
    defaults = {"quiet": (10, 0.35), "balanced": (50, 0.50), "research": (200, 0.75)}
    inserted = 0
    for profile, (maximum, noise) in defaults.items():
        exists = db.one("SELECT 1 FROM rule_noise_budgets WHERE target='*' AND profile=?", (profile,))
        db.execute(
            "INSERT INTO rule_noise_budgets(target,profile,maximum_candidates,maximum_noise_rate,created_at,updated_at) "
            "VALUES('*',?,?,?,?,?) ON CONFLICT(target,profile) DO NOTHING",
            (profile, maximum, noise, now, now),
        )
        inserted += 0 if exists else 1
    return inserted


def noise_budget_status(db: Database, analysis_id: str | None = None, *, profile: str = "balanced", target: str | None = None) -> dict[str, Any]:
    seed_noise_budgets(db)
    analysis_id = analysis_id or _latest_analysis(db, target)
    run = db.one("SELECT target,mode FROM analysis_runs WHERE id=?", (analysis_id,)) if analysis_id else None
    target = target or (str(run["target"]) if run else "*")
    profile = profile or (str(run["mode"]) if run and str(run["mode"]) in {"quiet", "balanced", "research"} else "balanced")
    row = db.one(
        "SELECT * FROM rule_noise_budgets WHERE target=? AND profile=?", (target, profile)
    ) or db.one("SELECT * FROM rule_noise_budgets WHERE target='*' AND profile=?", (profile,))
    maximum = parse_int(row["maximum_candidates"], 50) if row else 50
    maximum_noise = float(row["maximum_noise_rate"]) if row else 0.5
    candidates = [dict(r) for r in db.all("SELECT candidate_id,candidate_state,analyst_decision,investigation_value,priority_score FROM bug_candidates WHERE analysis_id=? ORDER BY investigation_value DESC,priority_score DESC", (analysis_id,))] if analysis_id else []
    reviewed = [r for r in candidates if str(r.get("analyst_decision")) != "unreviewed"]
    negative = [r for r in reviewed if str(r.get("analyst_decision")) in NEGATIVE_DECISIONS]
    noise_rate = round(len(negative) / max(1, len(reviewed)), 3)
    overflow = max(0, len(candidates) - maximum)
    overflow_ids = [str(r["candidate_id"]) for r in candidates[maximum:]]
    return {
        "analysis_id": analysis_id, "target": target, "profile": profile, "maximum_candidates": maximum,
        "maximum_noise_rate": maximum_noise, "candidate_count": len(candidates), "reviewed_noise_rate": noise_rate,
        "within_candidate_budget": len(candidates) <= maximum, "within_noise_budget": noise_rate <= maximum_noise or len(reviewed) < 5,
        "overflow_count": overflow, "overflow_candidate_ids": overflow_ids,
        "routing": "overflow candidates remain stored and are routed outside Review now; no evidence is deleted.",
    }


def learn_target_profile(db: Database, target: str, analysis_id: str | None = None, *, persist: bool = True) -> dict[str, Any]:
    analysis_id = analysis_id or _latest_analysis(db, target)
    candidates = [dict(r) for r in db.all("SELECT * FROM bug_candidates WHERE target=? ORDER BY updated_at DESC LIMIT 5000", (target,))]
    endpoints = [str(r[0] or "") for r in db.all("SELECT endpoint FROM endpoint_contracts WHERE target=? ORDER BY created_at DESC LIMIT 5000", (target,))]
    boundaries = [str(r[0] or "unknown") for r in db.all("SELECT boundary FROM authentication_boundaries WHERE target=? ORDER BY created_at DESC LIMIT 5000", (target,))]
    families = Counter(str(r.get("bug_family") or "unknown") for r in candidates)
    decisions = Counter(str(r.get("analyst_decision") or "unreviewed") for r in candidates)
    noisy_paths = Counter()
    common_prefixes = Counter()
    for candidate in candidates:
        endpoint = str(candidate.get("endpoint") or "")
        decision = str(candidate.get("analyst_decision") or "unreviewed")
        path = urllib.parse.urlsplit(endpoint if "://" in endpoint else "https://local" + (endpoint if endpoint.startswith("/") else "/" + endpoint)).path
        segments = [seg for seg in path.split("/") if seg]
        prefix = "/" + "/".join(segments[:2]) if segments else "/"
        if prefix: common_prefixes[prefix] += 1
        if decision in NEGATIVE_DECISIONS and endpoint: noisy_paths[prefix] += 1
    reviewed = sum(v for k, v in decisions.items() if k != "unreviewed")
    confidence = min(100, round((len(candidates) + reviewed * 3 + len(endpoints)) / 3))
    baseline = {
        "analysis_id": analysis_id, "candidate_count": len(candidates), "reviewed_count": reviewed,
        "common_families": families.most_common(12), "common_endpoint_prefixes": common_prefixes.most_common(20),
        "normal_authentication_boundaries": Counter(boundaries).most_common(10),
        "decision_distribution": dict(decisions),
        "interpretation": "Target-specific history adjusts prioritization context only; it never suppresses raw evidence or confirms security.",
    }
    known_noise = [{"path_prefix": key, "negative_decisions": value} for key, value in noisy_paths.most_common(20) if value >= 2]
    payload = {"target": target, "confidence": confidence, "baseline": baseline, "known_noise": known_noise, "updated_at": utc_now()}
    if persist:
        db.execute(
            "INSERT INTO target_learning_profiles(target,baseline_json,known_noise_json,confidence,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(target) DO UPDATE SET baseline_json=excluded.baseline_json,known_noise_json=excluded.known_noise_json,confidence=excluded.confidence,updated_at=excluded.updated_at",
            (target, json_dumps(baseline), json_dumps(known_noise), confidence, utc_now()),
        )
    return payload


def target_learning_profiles(db: Database) -> dict[str, Any]:
    rows = [dict(r) for r in db.all("SELECT * FROM target_learning_profiles ORDER BY confidence DESC,target")]
    for row in rows:
        row["baseline"] = _loads(row.pop("baseline_json", "{}"), {})
        row["known_noise"] = _loads(row.pop("known_noise_json", "[]"), [])
    return {"profiles": rows, "count": len(rows)}

def seed_rule_governance(db: Database) -> int:
    now = utc_now(); inserted = 0
    rows = db.all("SELECT DISTINCT rule_id,rule_version,category,description,enabled FROM analysis_rules")
    shadow = {str(row[0]) for row in db.all("SELECT DISTINCT rule_id FROM shadow_rule_results")}
    for row in rows:
        state = "shadow" if str(row["rule_id"]) in shadow else "active" if parse_int(row["enabled"], 1) else "disabled"
        exists = db.one("SELECT rule_id FROM rule_governance WHERE rule_id=? AND rule_version=?", (row["rule_id"], row["rule_version"]))
        db.execute("INSERT INTO rule_governance(rule_id,rule_version,bug_family,state,owner,description,known_noise_json,activation_metrics_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id,rule_version) DO UPDATE SET description=excluded.description,updated_at=excluded.updated_at", (row["rule_id"], row["rule_version"], row["category"], state, "core", row["description"], "[]", "{}", now, now))
        inserted += 0 if exists else 1
    for rule_id in shadow:
        db.execute("INSERT INTO rule_governance(rule_id,rule_version,bug_family,state,owner,description,known_noise_json,activation_metrics_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id,rule_version) DO UPDATE SET state='shadow',updated_at=excluded.updated_at", (rule_id, "shadow", "experimental", "shadow", "core", "Experimental rule evaluated outside the primary review queue.", "[]", "{}", now, now))
    return inserted


def rule_governance(db: Database) -> dict[str, Any]:
    seed_rule_governance(db)
    rows = [dict(row) for row in db.all("SELECT * FROM rule_governance ORDER BY CASE state WHEN 'active' THEN 1 WHEN 'candidate' THEN 2 WHEN 'shadow' THEN 3 ELSE 4 END,bug_family,rule_id")]
    return {"states": RULE_STATES, "rules": rows, "counts": dict(Counter(str(row["state"]) for row in rows))}


def set_rule_state(db: Database, rule_id: str, rule_version: str, state: str, *, actor: str = "analyst", note: str = "") -> dict[str, Any]:
    if state not in RULE_STATES: raise ReconError(f"Invalid rule state: {state}")
    row = db.one("SELECT * FROM rule_governance WHERE rule_id=? AND rule_version=?", (rule_id, rule_version))
    if not row: raise ReconError("Rule governance record not found")
    old = str(row["state"])
    db.execute("UPDATE rule_governance SET state=?,updated_at=? WHERE rule_id=? AND rule_version=?", (state, utc_now(), rule_id, rule_version))
    db.audit("rule_state_changed", actor=actor, entity_type="rule", entity_value=f"{rule_id}@{rule_version}", details={"old": old, "new": state, "note": note})
    return {"ok": True, "rule_id": rule_id, "rule_version": rule_version, "old": old, "state": state}


def _case_state_for_candidate(candidate: dict[str, Any]) -> str:
    decision = str(candidate.get("analyst_decision") or "unreviewed")
    state = str(candidate.get("candidate_state") or "")
    if decision == "confirmed_by_analyst": return "confirmed"
    if decision in {"rejected", "duplicate", "out_of_scope"}: return "rejected"
    if decision == "needs_more_evidence" or state in {"insufficient_evidence", "weak_signal", "possible"}: return "needs_evidence"
    if state == "strong_candidate": return "ready_for_validation"
    return "new"


def sync_security_cases(db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    analysis_id = analysis_id or _latest_analysis(db)
    if not analysis_id: return {"analysis_id": "", "created": 0, "updated": 0, "stories": 0}
    candidates = [dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY investigation_value DESC,priority_score DESC", (analysis_id,))]
    created = updated = 0; now = utc_now()
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        key = str(candidate.get("bundle_id") or candidate.get("candidate_fingerprint") or candidate.get("candidate_id"))
        grouped[key].append(candidate)
    for key, members in grouped.items():
        primary = max(members, key=lambda row: parse_int(row.get("investigation_value"), parse_int(row.get("priority_score"), 0)))
        case_id = "CASE-" + hashlib.sha256(f"{primary['target']}|{key}".encode()).hexdigest()[:12].upper()
        state = _case_state_for_candidate(primary)
        title = str(primary.get("title") or primary.get("bug_family") or "Security review")
        summary = str(primary.get("summary") or "Correlated security candidate review")
        priority = max(parse_int(row.get("investigation_value"), parse_int(row.get("priority_score"), 0)) for row in members)
        existing = db.one("SELECT case_id,state,assigned_to FROM security_cases WHERE case_id=?", (case_id,))
        if existing:
            preserved_state = str(existing["state"])
            if preserved_state not in {"new", "needs_evidence", "ready_for_validation"}: state = preserved_state
            db.execute("UPDATE security_cases SET analysis_id=?,source_run_id=?,target=?,title=?,summary=?,primary_family=?,priority_score=?,updated_at=? WHERE case_id=?", (analysis_id, primary["source_run_id"], primary["target"], title, summary, primary["bug_family"], priority, now, case_id)); updated += 1
        else:
            db.execute("INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'unknown',0,?,?)", (case_id, key, analysis_id, primary["source_run_id"], primary["target"], title, summary, primary["bug_family"], priority, state, "", now, now)); created += 1
            db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (case_id, "created", "system", json_dumps({"analysis_id": analysis_id, "source": "candidate_sync"}), now))
        db.execute("DELETE FROM security_case_members WHERE case_id=? AND member_type='candidate'", (case_id,))
        for member in members:
            db.execute("INSERT OR REPLACE INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?,?,?,?,?,?)", (case_id, "candidate", member["candidate_id"], "supports_case", json_dumps({"family": member["bug_family"], "state": member["candidate_state"], "investigation_value": member["investigation_value"]}), now))
            if member.get("alert_id"):
                db.execute("INSERT OR REPLACE INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?,?,?,?,?,?)", (case_id, "alert", str(member["alert_id"]), "source_alert", "{}", now))
        _update_report_readiness(db, case_id)
    stories = sync_security_stories(db, analysis_id)
    return {"analysis_id": analysis_id, "created": created, "updated": updated, "cases": len(grouped), "stories": stories["stories"]}


def list_cases(
    db: Database, *, state: str | None = None, target: str | None = None, q: str | None = None,
    family: str | None = None, assigned_to: str | None = None, validation_state: str | None = None,
    scope_status: str | None = None, min_priority: int = 0, min_readiness: int = 0,
    sort: str = "priority", limit: int = 200, offset: int = 0,
) -> list[dict[str, Any]]:
    where: list[str] = []
    params: list[Any] = []
    if state:
        where.append("state=?"); params.append(state)
    if target:
        where.append("target=?"); params.append(target)
    if q:
        where.append("(case_id LIKE ? OR title LIKE ? OR summary LIKE ?)")
        params.extend([f"%{q}%"] * 3)
    if family:
        where.append("primary_family=?"); params.append(family)
    if assigned_to == "__unassigned__":
        where.append("assigned_to=''")
    elif assigned_to:
        where.append("assigned_to=?"); params.append(assigned_to)
    if validation_state:
        where.append("validation_state=?"); params.append(validation_state)
    if scope_status:
        where.append("scope_status=?"); params.append(scope_status)
    if min_priority:
        where.append("priority_score>=?"); params.append(max(0, min(100, int(min_priority))))
    if min_readiness:
        where.append("report_readiness>=?"); params.append(max(0, min(100, int(min_readiness))))
    clause = " WHERE " + " AND ".join(where) if where else ""
    order = {
        "updated": "updated_at DESC,priority_score DESC",
        "readiness": "report_readiness DESC,priority_score DESC,updated_at DESC",
        "oldest": "updated_at ASC,priority_score DESC",
        "priority": "CASE state WHEN 'ready_for_validation' THEN 1 WHEN 'reviewing' THEN 2 WHEN 'needs_evidence' THEN 3 WHEN 'new' THEN 4 ELSE 5 END,priority_score DESC,updated_at DESC",
    }.get(sort, "CASE state WHEN 'ready_for_validation' THEN 1 WHEN 'reviewing' THEN 2 WHEN 'needs_evidence' THEN 3 WHEN 'new' THEN 4 ELSE 5 END,priority_score DESC,updated_at DESC")
    params.extend((max(1, min(2000, limit)), max(0, offset)))
    return [dict(row) for row in db.all(f"SELECT * FROM security_cases{clause} ORDER BY {order} LIMIT ? OFFSET ?", tuple(params))]


def case_detail(db: Database, case_id: str) -> dict[str, Any]:
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case: raise ReconError(f"Case not found: {case_id}")
    members = [dict(row) for row in db.all("SELECT * FROM security_case_members WHERE case_id=? ORDER BY member_type,created_at", (case_id,))]
    candidates=[]; alerts=[]
    for member in members:
        if member["member_type"] == "candidate":
            row=db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (member["member_id"],))
            if row: candidates.append(dict(row))
        elif member["member_type"] == "alert":
            row=db.one("SELECT * FROM alerts WHERE id=?", (member["member_id"],))
            if row: alerts.append(dict(row))
    events=[dict(row) for row in db.all("SELECT * FROM security_case_events WHERE case_id=? ORDER BY created_at DESC,id DESC", (case_id,))]
    packages=[dict(row) for row in db.all("SELECT * FROM validation_packages WHERE case_id=? ORDER BY created_at DESC", (case_id,))]
    drafts=[dict(row) for row in db.all("SELECT * FROM report_drafts WHERE case_id=? ORDER BY updated_at DESC", (case_id,))]
    return {"case": dict(case), "members": members, "candidates": candidates, "alerts": alerts, "events": events, "validation_packages": packages, "report_drafts": drafts}


def set_case_state(db: Database, case_id: str, state: str, *, assigned_to: str | None = None, note: str = "", actor: str = "analyst") -> dict[str, Any]:
    if state not in CASE_STATES: raise ReconError(f"Invalid case state: {state}")
    row=db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not row: raise ReconError(f"Case not found: {case_id}")
    old=str(row["state"]); owner=str(row["assigned_to"] or "") if assigned_to is None else assigned_to
    db.execute("UPDATE security_cases SET state=?,assigned_to=?,updated_at=? WHERE case_id=?", (state, owner, utc_now(), case_id))
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (case_id, "state_changed", actor, json_dumps({"old": old, "new": state, "assigned_to": owner, "note": note}), utc_now()))
    db.audit("case_state_changed", actor=actor, target=str(row["target"]), entity_type="case", entity_value=case_id, details={"old": old, "new": state, "assigned_to": owner, "note": note})
    readiness=_update_report_readiness(db,case_id)
    return {"ok": True, "case_id": case_id, "old": old, "state": state, "assigned_to": owner, "report_readiness": readiness}


def sync_security_stories(db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    analysis_id=analysis_id or _latest_analysis(db)
    if not analysis_id: return {"analysis_id":"","stories":0}
    bundles=[dict(row) for row in db.all("SELECT * FROM candidate_bundles WHERE analysis_id=?", (analysis_id,))]
    now=utc_now(); count=0
    for bundle in bundles:
        story_id="STORY-"+hashlib.sha256(f"{bundle['target']}|{bundle['bundle_key']}".encode()).hexdigest()[:12].upper()
        timeline=[]
        for member_id in _loads(bundle.get("members_json"),[]):
            row=db.one("SELECT candidate_id,title,candidate_state,created_at,updated_at,bug_family FROM bug_candidates WHERE candidate_id=?", (str(member_id),))
            if row: timeline.append({"time":row["created_at"],"event":"candidate_observed","candidate_id":row["candidate_id"],"family":row["bug_family"],"state":row["candidate_state"],"title":row["title"]})
        db.execute("INSERT INTO security_stories(story_id,story_key,analysis_id,target,title,summary,priority_score,status,timeline_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'open',?,?,?) ON CONFLICT(story_id) DO UPDATE SET analysis_id=excluded.analysis_id,title=excluded.title,summary=excluded.summary,priority_score=excluded.priority_score,timeline_json=excluded.timeline_json,updated_at=excluded.updated_at", (story_id,bundle["bundle_key"],analysis_id,bundle["target"],bundle["title"],bundle["summary"],bundle["priority_score"],json_dumps(timeline),now,now)); count+=1
    return {"analysis_id":analysis_id,"stories":count}


def list_stories(db: Database, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
    return [dict(row) for row in db.all("SELECT * FROM security_stories ORDER BY priority_score DESC,updated_at DESC LIMIT ? OFFSET ?", (max(1,min(1000,limit)),max(0,offset)))]


def build_validation_package(db: Database, case_id: str, *, actor: str = "analyst") -> dict[str, Any]:
    detail=case_detail(db,case_id); case=detail["case"]; candidates=detail["candidates"]
    endpoints=sorted({str(row.get("endpoint") or row.get("source_ref") or "") for row in candidates if str(row.get("endpoint") or row.get("source_ref") or "")})
    package={
        "case_id":case_id,"target":case["target"],"title":case["title"],"primary_family":case["primary_family"],
        "affected_endpoints":endpoints,"known_parameters":[],"authentication_context":"Review stored evidence; do not infer authorization from a 401/403 alone.",
        "expected_boundary":"Document the expected identity, role, tenant, object or business invariant before validation.",
        "why_suspicious":[str(row.get("summary") or row.get("title")) for row in candidates[:5]],
        "safe_stop_conditions":["Stop if scope becomes uncertain.","Stop if unrelated user data appears.","Do not use non-authorized accounts or objects.","Do not perform destructive or high-volume actions."],
        "evidence_to_capture":["Redacted request metadata","Status and redacted response shape","Expected versus observed boundary","Analyst conclusion and reason code"],
        "generated_at":utc_now(),"generated_by":actor,"note":"Context package only; it contains no payloads and performs no validation automatically.",
    }
    for row in candidates:
        trace=db.all("SELECT e.evidence_type,e.summary,e.source_tool,e.source_artifact,e.trust_score,e.observation_quality FROM candidate_evidence_links l JOIN evidence_records e ON e.evidence_id=l.evidence_id WHERE l.candidate_id=? ORDER BY l.weight DESC LIMIT 20", (row["candidate_id"],))
        if trace: package.setdefault("evidence",[]).extend(dict(item) for item in trace)
    package_id="VAL-"+hashlib.sha256(f"{case_id}|{utc_now()}".encode()).hexdigest()[:12].upper()
    db.execute("INSERT INTO validation_packages(package_id,case_id,package_json,created_by,created_at) VALUES(?,?,?,?,?)", (package_id,case_id,json_dumps(package),actor,utc_now()))
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (case_id,"validation_package_created",actor,json_dumps({"package_id":package_id}),utc_now()))
    return {"package_id":package_id,**package}


def _update_report_readiness(db: Database, case_id: str) -> int:
    detail=case_detail(db,case_id) if db.one("SELECT case_id FROM security_cases WHERE case_id=?",(case_id,)) else None
    if not detail:return 0
    case=detail["case"]; candidates=detail["candidates"]
    evidence = 0
    coverage = 0
    confirmed = str(case.get("state")) in {"confirmed","ready_for_report","reported","closed"}
    if candidates:
        evidence=sum(parse_int(row.get("evidence_strength"),0) for row in candidates)/len(candidates)
        coverage=sum(parse_int(row.get("evidence_coverage"),0) for row in candidates)/len(candidates)
    scope = 100 if str(case.get("scope_status")) == "in_scope" else 40 if str(case.get("scope_status")) == "unknown" else 0
    state_score = 100 if confirmed else 70 if str(case.get("state")) == "ready_for_validation" else 45 if str(case.get("state")) in {"reviewing","needs_evidence"} else 25
    readiness=max(0,min(100,round(evidence*.30+coverage*.25+scope*.20+state_score*.25)))
    db.execute("UPDATE security_cases SET report_readiness=?,updated_at=? WHERE case_id=?",(readiness,utc_now(),case_id))
    return readiness


def build_report_draft(db: Database, case_id: str, *, actor: str = "analyst") -> dict[str, Any]:
    detail=case_detail(db,case_id); case=detail["case"]; candidates=detail["candidates"]
    readiness=_update_report_readiness(db,case_id)
    affected=sorted({str(row.get("endpoint") or row.get("asset") or row.get("source_ref") or "") for row in candidates if str(row.get("endpoint") or row.get("asset") or row.get("source_ref") or "")})
    evidence=[]
    for row in candidates:
        evidence.extend(str(item.get("text") if isinstance(item,dict) else item) for item in _loads(row.get("supporting_evidence_json"),[])[:4])
    draft={
        "title":case["title"],"affected_asset":affected,"summary":case["summary"],"observed_behavior":evidence[:8],
        "expected_behavior":"[Analyst must document the expected security boundary or business invariant.]",
        "security_impact":"[Impact must be supported by authorized validation before submission.]",
        "reproduction_notes":"[Add redacted, authorized reproduction steps manually.]",
        "scope_confirmation":case.get("scope_status","unknown"),"redaction_status":"pending_review",
        "report_readiness":readiness,"generated_at":utc_now(),"generated_by":actor,
        "disclaimer":"Draft only. Unverified candidates are not represented as confirmed vulnerabilities.",
    }
    draft_id="RPT-"+hashlib.sha256(f"{case_id}|{utc_now()}".encode()).hexdigest()[:12].upper()
    db.execute("INSERT INTO report_drafts(draft_id,case_id,title,body_json,status,readiness_score,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(draft_id,case_id,case["title"],json_dumps(draft),"draft",readiness,actor,utc_now(),utc_now()))
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(case_id,"report_draft_created",actor,json_dumps({"draft_id":draft_id,"readiness":readiness}),utc_now()))
    from platform_v6 import report_quality
    quality=report_quality(db,draft_id=draft_id,persist=True)
    return {"draft_id":draft_id,**draft,"quality":quality}


def _policy_data(paths: AppPaths) -> dict[str, Any]:
    if not paths.policy.exists(): return {"schema":0,"defaults":{},"targets":[]}
    return _loads(paths.policy.read_text(encoding="utf-8",errors="replace"), {"schema":0,"defaults":{},"targets":[]})


def scope_center(paths: AppPaths, db: Database, *, persist: bool = False) -> dict[str, Any]:
    policy=_policy_data(paths); defaults=policy.get("defaults",{}) if isinstance(policy,dict) else {}; targets=[]; now=utc_now()
    for raw in policy.get("targets",[]) if isinstance(policy,dict) else []:
        if not isinstance(raw,dict): continue
        active=raw.get("active",{}) if isinstance(raw.get("active"),dict) else {}
        confirmation=str(active.get("confirmation") or "")
        modules=dict(defaults.get("modules",{})); modules.update(raw.get("modules",{}) if isinstance(raw.get("modules"),dict) else {})
        active_modules=[name for name in ("ports","nuclei") if modules.get(name)]
        status="confirmed" if not active_modules or confirmation else "confirmation_required"
        item={"name":str(raw.get("name") or ""),"roots":raw.get("roots",[]),"include":raw.get("include",[]),"exclude":raw.get("exclude",[]),"active_modules":active_modules,"confirmation_present":bool(confirmation),"authorization_status":status,"limits":{**defaults.get("limits",{}),**(raw.get("limits",{}) if isinstance(raw.get("limits"),dict) else {})}}
        targets.append(item)
        if persist:
            db.execute("INSERT INTO scope_snapshots(target,policy_hash,scope_json,authorization_status,created_at) VALUES(?,?,?,?,?)",(item["name"],hashlib.sha256(json_dumps(item).encode()).hexdigest(),json_dumps(item),status,now))
    return {"policy_schema":policy.get("schema",0) if isinstance(policy,dict) else 0,"targets":targets,"defaults":defaults,"generated_at":now}


def run_completeness(db: Database, run_id: str | None = None, *, persist: bool = True) -> dict[str, Any]:
    run_id=run_id or _latest_run(db)
    if not run_id:return {"run_id":"","score":0,"dimensions":{}}
    stages=[dict(row) for row in db.all("SELECT target,stage,status,metrics_json,error FROM stage_runs WHERE run_id=?",(run_id,))]
    expected={"subdomains","dns","urls","javascript","endpoint_validation","fingerprint","ports","nuclei","report"}
    by_stage={stage:[] for stage in expected}
    for row in stages: by_stage.setdefault(str(row["stage"]),[]).append(row)
    dimensions={}
    weights={"subdomains":12,"dns":10,"urls":12,"javascript":18,"endpoint_validation":10,"fingerprint":15,"ports":4,"nuclei":4,"report":15}
    total_weight=0; earned=0
    for stage,weight in weights.items():
        rows=by_stage.get(stage,[])
        if not rows:
            status="not_observed"; score=0
        else:
            success=sum(1 for row in rows if row["status"] in {"success","skipped"})
            failed=sum(1 for row in rows if row["status"]=="failed")
            score=round(success/max(1,len(rows))*100)
            status="complete" if score==100 and not failed else "partial" if score>0 else "failed"
        dimensions[stage]={"status":status,"score":score,"weight":weight,"records":len(rows)}
        # Optional active stages do not penalize completeness when explicitly skipped/not configured.
        if stage in {"ports","nuclei"} and (not rows or all(row["status"]=="skipped" for row in rows)): continue
        total_weight+=weight; earned+=score*weight/100
    score=round(earned/max(1,total_weight)*100)
    warnings=[]
    if dimensions["javascript"]["score"]<60:warnings.append("JavaScript coverage is incomplete.")
    if dimensions["endpoint_validation"]["score"]<40:warnings.append("Endpoint validation coverage is limited; behavioral conclusions may be sparse.")
    if dimensions["report"]["score"]<100:warnings.append("Run finalization/report stage is incomplete.")
    payload={"run_id":run_id,"score":score,"dimensions":dimensions,"warnings":warnings,"generated_at":utc_now()}
    if persist: db.execute("INSERT OR REPLACE INTO run_completeness(run_id,score,metrics_json,created_at) VALUES(?,?,?,?)",(run_id,score,json_dumps(payload),utc_now()))
    return payload


def storage_health(paths: AppPaths, db: Database, *, persist: bool = False) -> dict[str, Any]:
    def tree_size(path: Path) -> int:
        if not path.exists():return 0
        if path.is_file():return path.stat().st_size
        total=0
        for root,_,files in os.walk(path):
            for name in files:
                try:total+=(Path(root)/name).stat().st_size
                except OSError:pass
        return total
    db_size=tree_size(paths.db)+tree_size(Path(str(paths.db)+"-wal"))+tree_size(Path(str(paths.db)+"-shm"))
    parts={"database_bytes":db_size,"state_bytes":tree_size(paths.state),"output_bytes":tree_size(paths.output),"reports_bytes":tree_size(paths.reports),"logs_bytes":tree_size(paths.logs),"backups_bytes":tree_size(paths.root/"backups")}
    object_count=parse_int((db.one("SELECT COUNT(*) count FROM object_store") or {"count":0})["count"],0)
    object_bytes=parse_int((db.one("SELECT COALESCE(SUM(size),0) size FROM object_store") or {"size":0})["size"],0)
    backups=parse_int((db.one("SELECT COUNT(*) count FROM backup_catalog") or {"count":0})["count"],0)
    total=max(parts.values()) if False else sum(value for key,value in parts.items() if key not in {"state_bytes"})
    payload={**parts,"object_count":object_count,"object_bytes":object_bytes,"backup_count":backups,"estimated_total_bytes":total,"generated_at":utc_now(),"retention_preview":{"keep_confirmed_evidence":True,"raw_artifact_days":90,"keep_backups":10,"eligible_temporary_objects":parse_int((db.one("SELECT COUNT(*) count FROM object_store WHERE reference_count<=0") or {"count":0})["count"],0)}}
    if persist:db.execute("INSERT INTO storage_snapshots(metrics_json,created_at) VALUES(?,?)",(json_dumps(payload),utc_now()))
    return payload


def operations_center(paths: AppPaths, db: Database, *, refresh: bool = False, deep_check: bool = False) -> dict[str, Any]:
    """Build an operational summary without blocking normal dashboard requests.

    Full SQLite integrity/FK checks and recursive storage scans run only during
    explicit refresh/platform sync. Ordinary views use persisted snapshots.
    """
    cache_key = f"operations:{paths.root}"
    if not refresh:
        cached = _memo_get(cache_key, 30)
        if cached is not None:
            return cached
    integrity = {"integrity_check": "not_run", "foreign_key_violations": []}
    if deep_check:
        integrity = {"integrity_check": db.integrity(), "foreign_key_violations": db.foreign_key_violations()}
    latest_run = _latest_run(db)
    completeness = run_completeness_snapshot(db, latest_run, refresh=refresh) if latest_run else {"score": 0, "warnings": ["No runs available."]}
    storage = storage_health_snapshot(paths, db, refresh=refresh)
    scope = scope_center(paths, db, persist=refresh)
    quality = engine_quality_snapshot(db, refresh=refresh)
    backups = [dict(row) for row in db.all("SELECT backup_id,created_at,verified_at,size FROM backup_catalog ORDER BY created_at DESC LIMIT 5")]
    failed_stages = parse_int((db.one("SELECT COUNT(*) count FROM stage_runs WHERE status='failed'") or {"count": 0})["count"], 0)
    schedules = [dict(row) for row in db.all("SELECT * FROM schedule_policies ORDER BY target")]
    notifications = [dict(row) for row in db.all("SELECT * FROM notification_policies ORDER BY target,event_type")]
    plugin_key = f"plugins:{paths.root}"
    plugins = None if refresh else _memo_get(plugin_key, 60)
    if plugins is None:
        try:
            from plugins import PluginManager
            plugins = PluginManager(paths, db).health()
        except Exception as exc:
            plugins = [{"name": "plugin-manager", "ok": False, "status": "error", "detail": str(exc)}]
        _memo_set(plugin_key, plugins)
    score = 100
    if deep_check and integrity.get("integrity_check") != "ok": score -= 45
    score -= min(20, failed_stages * 3)
    if not backups: score -= 12
    elif not backups[0].get("verified_at"): score -= 6
    if completeness.get("score", 0) < 60: score -= 12
    if quality.get("health_score", 100) < 60: score -= 10
    degraded_plugins = sum(1 for item in plugins if not item.get("ok"))
    score -= min(10, degraded_plugins * 2)
    score = max(0, min(100, score))
    warnings = []
    if not backups: warnings.append("No catalogued backup exists.")
    elif not backups[0].get("verified_at"): warnings.append("Latest backup has not been verified.")
    warnings.extend(completeness.get("warnings", []))
    warnings.extend(quality.get("warnings", [])[:3])
    if degraded_plugins: warnings.append(f"{degraded_plugins} plugin(s) are degraded or invalid.")
    payload = {"program_health_score": score, "database": integrity, "failed_stages": failed_stages, "latest_run": latest_run, "run_completeness": completeness, "engine_quality": quality, "scope": scope, "storage": storage, "backups": backups, "schedules": schedules, "notifications": notifications, "plugins": plugins, "warnings": warnings, "generated_at": utc_now(), "deep_check": deep_check}
    return _memo_set(cache_key, payload)

def set_schedule_policy(db: Database, target: str, cadence: str, *, enabled: bool = True, max_runtime_minutes: int = 120, request_budget: int = 10000, quiet_hours: str = "", actor: str = "admin") -> dict[str, Any]:
    now=utc_now(); db.execute("INSERT INTO schedule_policies(target,cadence,enabled,max_runtime_minutes,request_budget,quiet_hours,last_run_at,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,NULL,NULL,?,?) ON CONFLICT(target) DO UPDATE SET cadence=excluded.cadence,enabled=excluded.enabled,max_runtime_minutes=excluded.max_runtime_minutes,request_budget=excluded.request_budget,quiet_hours=excluded.quiet_hours,updated_at=excluded.updated_at",(target,cadence,1 if enabled else 0,max_runtime_minutes,request_budget,quiet_hours,now,now)); db.audit("schedule_policy_updated",actor=actor,target=target,entity_type="schedule",entity_value=target,details={"cadence":cadence,"enabled":enabled,"max_runtime_minutes":max_runtime_minutes,"request_budget":request_budget,"quiet_hours":quiet_hours}); return {"ok":True,"target":target,"cadence":cadence,"enabled":enabled}


def set_notification_policy(db: Database, target: str, event_type: str, mode: str, *, minimum_score: int = 70, actor: str = "admin") -> dict[str, Any]:
    if mode not in NOTIFICATION_MODES:raise ReconError(f"Invalid notification mode: {mode}")
    now=utc_now(); db.execute("INSERT INTO notification_policies(target,event_type,mode,minimum_score,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?) ON CONFLICT(target,event_type) DO UPDATE SET mode=excluded.mode,minimum_score=excluded.minimum_score,enabled=1,updated_at=excluded.updated_at",(target,event_type,mode,minimum_score,now,now)); db.audit("notification_policy_updated",actor=actor,target=target,entity_type="notification_policy",entity_value=event_type,details={"mode":mode,"minimum_score":minimum_score}); return {"ok":True,"target":target,"event_type":event_type,"mode":mode}


def incremental_checkpoint(db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    analysis_id=analysis_id or _latest_analysis(db)
    if not analysis_id:return {"analysis_id":"","dirty_entities":0}
    run=db.one("SELECT source_run_id,target,finished_at FROM analysis_runs WHERE id=?",(analysis_id,))
    if not run:raise ReconError("Analysis not found")
    counts={
        "candidates":parse_int((db.one("SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=?",(analysis_id,)) or {"count":0})["count"],0),
        "evidence":parse_int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?",(analysis_id,)) or {"count":0})["count"],0),
        "contracts":parse_int((db.one("SELECT COUNT(*) count FROM endpoint_contracts WHERE analysis_id=?",(analysis_id,)) or {"count":0})["count"],0),
        "behavioral_diffs":parse_int((db.one("SELECT COUNT(*) count FROM authentication_boundary_diffs WHERE analysis_id=?",(analysis_id,)) or {"count":0})["count"],0)+parse_int((db.one("SELECT COUNT(*) count FROM response_shape_diffs WHERE analysis_id=?",(analysis_id,)) or {"count":0})["count"],0),
    }
    fingerprint=hashlib.sha256(json_dumps(counts).encode()).hexdigest()
    db.execute("INSERT INTO incremental_checkpoints(analysis_id,source_run_id,target,fingerprint,metrics_json,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(analysis_id) DO UPDATE SET fingerprint=excluded.fingerprint,metrics_json=excluded.metrics_json,created_at=excluded.created_at",(analysis_id,run["source_run_id"],run["target"],fingerprint,json_dumps(counts),utc_now()))
    previous=db.one("SELECT fingerprint,metrics_json FROM incremental_checkpoints WHERE target=? AND analysis_id<>? ORDER BY created_at DESC LIMIT 1",(run["target"],analysis_id))
    previous_counts=_loads(previous["metrics_json"],{}) if previous else {}
    dirty={key:counts[key]-parse_int(previous_counts.get(key),0) for key in counts}
    return {"analysis_id":analysis_id,"source_run_id":run["source_run_id"],"target":run["target"],"fingerprint":fingerprint,"metrics":counts,"previous":previous_counts,"dirty":dirty,"dirty_entities":sum(abs(value) for value in dirty.values())}


def platform_sync(paths: AppPaths, db: Database, analysis_id: str | None = None) -> dict[str, Any]:
    invalidate_platform_cache()
    analysis_id=analysis_id or _latest_analysis(db)
    seed_rule_governance(db); seed_noise_budgets(db)
    cases=sync_security_cases(db,analysis_id) if analysis_id else {"cases":0,"stories":0}
    analysis_row=db.one("SELECT target FROM analysis_runs WHERE id=?",(analysis_id,)) if analysis_id else None
    learned=learn_target_profile(db,str(analysis_row["target"]),analysis_id,persist=True) if analysis_row else None
    quality=engine_quality(db,analysis_id,target=str(analysis_row["target"]) if analysis_row else None,persist=True) if analysis_id else engine_quality(db)
    checkpoint=incremental_checkpoint(db,analysis_id) if analysis_id else {"analysis_id":""}
    latest_run=_latest_run(db)
    completeness=run_completeness(db,latest_run,persist=True) if latest_run else {"run_id":"","score":0}
    scope=scope_center(paths,db)
    storage=storage_health(paths,db,persist=True)
    from platform_v6 import platform_v6_sync
    suite_v6=platform_v6_sync(paths,db,run_id=latest_run or None,analysis_id=analysis_id or None)
    return {"version":PLATFORM_VERSION,"analysis_id":analysis_id,"quality":quality,"cases":cases,"checkpoint":checkpoint,"run_completeness":completeness,"scope_targets":len(scope.get("targets",[])),"storage":storage,"target_learning":learned,"noise_budget":noise_budget_status(db,analysis_id,target=str(analysis_row["target"]) if analysis_row else None) if analysis_id else {},"suite_v6":suite_v6}

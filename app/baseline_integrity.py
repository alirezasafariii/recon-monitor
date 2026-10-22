"""Exclude proven incomplete comparison baselines without deleting evidence."""
from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from core import ReconError, json_dumps, safe_json_loads, utc_now
from scan_coverage import count, stage_coverage


def ensure_baseline_integrity_schema(db: Any) -> None:
    db.conn.executescript("""
        CREATE TABLE IF NOT EXISTS recon_baseline_reviews (
          target TEXT NOT NULL,
          run_id TEXT NOT NULL,
          state TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          actor TEXT NOT NULL,
          detected_at TEXT NOT NULL,
          recovered_at TEXT,
          PRIMARY KEY(target,run_id)
        );
        CREATE TABLE IF NOT EXISTS successful_recon_integrity (
          target TEXT PRIMARY KEY,
          run_id TEXT NOT NULL,
          coverage_json TEXT NOT NULL,
          committed_at TEXT NOT NULL
        );
    """)
    db.execute("INSERT INTO schema_meta(key,value) VALUES('recon_baseline_integrity_schema_version','1') "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    for table in ("js_files", "js_availability_history"):
        if "comparison_quarantined" not in {row[1] for row in db.all(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN comparison_quarantined INTEGER NOT NULL DEFAULT 0")


def record_baseline_receipt(db: Any, target: str, run_id: str, *, replace: bool = True) -> None:
    observations = [{"stage": row["stage"], **stage_coverage(str(row["stage"]), dict(row))}
                    for row in db.all("SELECT stage,status,metrics_json FROM stage_runs WHERE target=? AND run_id=? AND stage<>'report'", (target, run_id))]
    suffix = (" ON CONFLICT(target) DO UPDATE SET run_id=excluded.run_id,coverage_json=excluded.coverage_json,committed_at=excluded.committed_at"
              if replace else " ON CONFLICT(target) DO NOTHING")
    db.execute("INSERT INTO successful_recon_integrity(target,run_id,coverage_json,committed_at) VALUES(?,?,?,?)" + suffix,
               (target, run_id, json_dumps(observations), utc_now()))


def baseline_review(db: Any, target: str, run_id: str) -> dict[str, Any] | None:
    # BaseDatabase remains supported by offline tools and older fixtures.
    if not db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_baseline_reviews'"):
        return None
    row = db.one("SELECT * FROM recon_baseline_reviews WHERE target=? AND run_id=?", (target, run_id))
    return dict(row) if row else None


def baseline_run_excluded(db: Any, target: str, run_id: str) -> bool:
    review = baseline_review(db, target, run_id)
    return bool(review and review["state"] == "quarantined")


def exclusion_sql(db: Any, target_column: str, run_column: str) -> str:
    """SQL for internal, constant column names; historical outcomes stay intact."""
    if not db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_baseline_reviews'"):
        return ""
    return (" AND NOT EXISTS (SELECT 1 FROM recon_baseline_reviews br WHERE br.target="
            + target_column + " AND br.run_id=" + run_column + " AND br.state='quarantined')")


def js_observation_sql(db: Any, alias: str) -> str:
    if not db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_baseline_reviews'"):
        return ""
    return " AND " + alias + ".comparison_quarantined=0"


def refresh_js_observation(db: Any, table: str, target: str, url: str, run_id: str) -> None:
    if table not in {"js_files", "js_availability_history"}:
        raise ValueError("Unsupported JavaScript comparison table")
    if db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_baseline_reviews'"):
        source = "run_id" if table == "js_availability_history" else "last_run_id"
        db.execute(f"UPDATE {table} SET comparison_quarantined=0 WHERE target=? AND url=? AND {source}=?", (target, url, run_id))


def collection_gaps(db: Any, target: str, run_id: str, *, working: bool = False) -> list[dict[str, Any]]:
    gaps = []
    target_row = db.one("SELECT status FROM run_targets WHERE run_id=? AND target=?", (run_id, target))
    # During resume, stage rows describe new working evidence, not the frozen
    # snapshot. Never revoke a healthy committed snapshot because its resume is
    # currently unfinished. Frozen snapshot evidence below is still applicable.
    receipt = db.one("SELECT coverage_json FROM successful_recon_integrity WHERE target=? AND run_id=?", (target, run_id))
    if receipt and not working:
        for coverage in safe_json_loads(receipt["coverage_json"], [], expected_type=list):
            if isinstance(coverage, dict) and coverage.get("status") in {"access_restricted", "partial", "failed", "interrupted"}:
                gaps.append({key: coverage.get(key, "") for key in ("stage", "status", "reason")})
    elif target_row and (working or target_row["status"] != "running"):
        for row in db.all("SELECT stage,status,metrics_json FROM stage_runs WHERE run_id=? AND target=? AND stage<>'report'", (run_id, target)):
            coverage = stage_coverage(str(row["stage"]), dict(row))
            if coverage["status"] in {"access_restricted", "partial", "failed", "interrupted"}:
                gaps.append({"stage": row["stage"], "status": coverage["status"], "reason": coverage["reason"]})
    if not working:
        frozen = db.execute("SELECT row_json FROM successful_recon_state WHERE target=? AND table_name='fingerprints' AND committed_run_id=?", (target, run_id))
        try:
            for row in frozen:
                data = safe_json_loads(row["row_json"], {}, expected_type=dict)
                if data.get("last_run_id") == run_id and count(data.get("status_code")) in {401, 403}:
                    gaps.append({"stage": "fingerprint", "status": "access_restricted",
                                 "reason": "Committed HTTP response restricted content visibility.",
                                 "url": str(data.get("url") or ""), "status_code": count(data.get("status_code"))})
                    break  # One positive observation establishes the gap.
        finally:
            frozen.close()
    if working:
        for row in db.all("SELECT url,status_code FROM fingerprints WHERE target=? AND last_run_id=? AND status_code IN (401,403) LIMIT 1", (target, run_id)):
            gaps.append({"stage": "fingerprint", "status": "access_restricted",
                         "reason": "Collected HTTP response restricted content visibility.",
                         "url": row["url"], "status_code": row["status_code"]})
    return gaps


def review_committed_baseline(db: Any, target: str, *, paths: Any = None,
                              run_id: str = "", actor: str = "automatic") -> dict[str, Any]:
    commit = db.one("SELECT * FROM successful_recon_commits WHERE target=?", (target,))
    source = run_id or (str(commit["run_id"]) if commit else "")
    if not source:
        return {"target": target, "run_id": "", "action": "no_baseline", "baseline_changed": False}
    source_row = db.one("SELECT status FROM run_targets WHERE run_id=? AND target=?", (source, target))
    if paths is not None and source_row and source_row["status"] != "running":
        from scan_finalization import _audit_legacy_origins
        _audit_legacy_origins(paths, db, source, target=target)
    with db._lock, (nullcontext() if db.conn.in_transaction else db.transaction()):
        gaps = collection_gaps(db, target, source)
        if not gaps:
            return {"target": target, "run_id": source, "action": "no_proven_gap", "baseline_changed": False}
        # Re-read the identity under the write transaction. Repair of an old
        # historical run must never quarantine a newer healthy replacement.
        current = db.one("SELECT * FROM successful_recon_commits WHERE target=?", (target,))
        registry = db.one("SELECT * FROM target_baselines WHERE target=?", (target,))
        previous = baseline_review(db, target, source)
        if not previous or previous["state"] != "quarantined":
            evidence = {"gaps": gaps,
                        "snapshot": dict(current) if current and current["run_id"] == source else {},
                        "baseline": dict(registry) if registry else {}}
            db.execute("INSERT INTO recon_baseline_reviews(target,run_id,state,evidence_json,actor,detected_at) "
                       "VALUES(?,?,'quarantined',?,?,?) ON CONFLICT(target,run_id) DO UPDATE SET "
                       "state='quarantined',evidence_json=excluded.evidence_json,actor=excluded.actor,recovered_at=NULL",
                       (target, source, json_dumps(evidence), actor, utc_now()))
            # Per-observation flags survive a same-ID recovery. Only an actual
            # new JS observation may clear its flag, so old rows are not made
            # trustworthy merely because the core snapshot recovered.
            db.execute("UPDATE js_files SET comparison_quarantined=1 WHERE target=? AND last_run_id=?", (target, source))
            db.execute("UPDATE js_availability_history SET comparison_quarantined=1 WHERE target=? AND run_id=?", (target, source))
        changed = bool(current and current["run_id"] == source and registry
                       and registry["last_refreshed_run_id"] == source and registry["state"] != "quarantined")
        if changed:
            db.execute("UPDATE target_baselines SET state='quarantined',reason='baseline_coverage_incomplete',updated_at=? "
                       "WHERE target=? AND last_refreshed_run_id=?", (utc_now(), target, source))
        db.execute("DELETE FROM change_intelligence_snapshots WHERE target=? AND (run_id=? OR previous_run_id=?)",
                   (target, source, source))
        return {"target": target, "run_id": source,
                "action": "already_quarantined" if previous and previous["state"] == "quarantined" else "quarantined",
                "baseline_changed": changed, "gaps": gaps}


def recover_baseline_review(db: Any, target: str, run_id: str) -> None:
    # A verified, collection-complete resume may repair the same run ID.
    db.execute("UPDATE recon_baseline_reviews SET state='recovered',recovered_at=? "
               "WHERE target=? AND run_id=? AND state='quarantined'", (utc_now(), target, run_id))


def repair_baselines(paths: Any, db: Any, *, run_id: str = "", target: str = "") -> dict[str, Any]:
    if not run_id and not target:
        raise ReconError("platform baseline-repair requires --run RUN_ID or --target TARGET")
    if run_id:
        run = db.one("SELECT status FROM runs WHERE id=?", (run_id,))
        if not run:
            raise ReconError("Run not found: " + run_id)
        if run["status"] == "running":
            raise ReconError("Cannot repair baselines for a running scan")
        rows = db.all("SELECT target FROM run_targets WHERE run_id=?" + (" AND target=?" if target else ""),
                      (run_id, target) if target else (run_id,))
    else:
        rows = db.all("SELECT target FROM target_baselines WHERE target=?", (target,))
    if not rows:
        raise ReconError("No matching target baseline history")
    # Preflight every target before changing any registry state. Collection on
    # another run may already be using its baseline; maintenance must wait.
    with db.transaction():
        for row in rows:
            if db.one("SELECT 1 FROM run_targets WHERE target=? AND status='running' LIMIT 1", (row["target"],)):
                raise ReconError("Cannot repair a baseline while its target is running: " + row["target"])
        reviews = [review_committed_baseline(db, str(row["target"]), paths=paths, run_id=run_id, actor="cli-baseline-repair") for row in rows]
    from scan_finalization import finalize_run_diagnostics
    finalized = sorted({str(review["run_id"]) for review in reviews if review["run_id"]})
    for source in finalized:
        finalize_run_diagnostics(paths, db, source)
    return {"reviews": reviews, "finalized_runs": finalized,
            "baseline_changed": any(review["baseline_changed"] for review in reviews),
            "baseline_rebuild_required_targets": sorted({review["target"] for review in reviews if not db.target_has_history(review["target"])}),
            "collection_changed": False, "historical_outcomes_changed": False, "network_requests": 0}

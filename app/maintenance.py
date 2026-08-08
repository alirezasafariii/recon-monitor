from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
import tarfile
from pathlib import Path
from typing import Any

from core import (
    APP_VERSION,
    AppPaths,
    Config,
    Database,
    Logger,
    PolicySet,
    TargetPolicy,
    atomic_write_text,
    collect_tool_versions,
    json_dumps,
    normalize_host,
    parse_int,
    utc_now,
    valid_domain,
)


def initialize_project(paths: AppPaths, logger: Logger) -> dict[str, Any]:
    paths.ensure()
    created: list[str] = []
    config_example = paths.root / "config.env.example"
    if not paths.config.exists() and config_example.exists():
        shutil.copy2(config_example, paths.config)
        os.chmod(paths.config, 0o600)
        created.append(str(paths.config))
    policy_example = paths.root / "policies" / "targets.json.example"
    if not paths.policy.exists():
        if paths.legacy_targets.exists():
            migrate_targets_txt(paths, logger)
            created.append(str(paths.policy))
        elif policy_example.exists():
            shutil.copy2(policy_example, paths.policy)
            created.append(str(paths.policy))
    db = Database(paths.db)
    db.close()
    return {"created": created, "database": str(paths.db)}


def migrate_targets_txt(paths: AppPaths, logger: Logger) -> Path:
    targets: list[dict[str, Any]] = []
    if paths.legacy_targets.exists():
        for raw in paths.legacy_targets.read_text(encoding="utf-8", errors="replace").splitlines():
            value = normalize_host(raw.split("#", 1)[0])
            if valid_domain(value):
                targets.append({"name": value, "roots": [value]})
    payload = {
        "schema": 3,
        "defaults": {
            "modules": {
                "subdomains": True,
                "dns": True,
                "urls": True,
                "javascript": True,
                "endpoint_validation": False,
                "fingerprint": True,
                "screenshots": False,
                "ports": False,
                "nuclei": False,
            },
            "analysis": {
                "asset_graph": True,
                "semantic_change_classification": True,
                "explainable_risk": True,
                "track_confirmation_state": True,
                "stable_confirmations": 2
            },
            "alert": {
                "minimum_score": 70,
                "cooldown_hours": 24,
                "confirmed_only": False
            },
            "limits": {
                "request_rate": 3,
                "dns_rate": 100,
                "timeout_seconds": 900,
                "retries": 1,
                "crawl_depth": 2,
                "max_urls": 10000,
                "max_js_files": 200,
                "max_js_bytes": 5000000,
                "http_threads": 20,
                "naabu_rate": 50,
                "nuclei_rate": 3,
                "max_runtime_minutes": 120,
                "max_http_requests": 10000,
                "max_dns_queries": 5000,
                "max_download_mb": 500,
                "max_new_assets": 5000,
                "dns_workers": 10,
                "http_workers": 20,
                "js_workers": 5,
                "screenshot_workers": 2,
            },
        },
        "targets": targets,
    }
    atomic_write_text(paths.policy, json_dumps(payload, pretty=True) + "\n")
    logger.info("Migrated legacy targets.txt to target policy", targets=len(targets), policy=str(paths.policy))
    return paths.policy


def migrate_v1_database(paths: AppPaths, logger: Logger) -> dict[str, int]:
    legacy = paths.root / "recon.db"
    if not legacy.exists():
        return {"assets": 0, "urls": 0, "javascript": 0, "fingerprints": 0}
    db = Database(paths.db)
    source = sqlite3.connect(legacy)
    source.row_factory = sqlite3.Row
    imported = {"assets": 0, "urls": 0, "javascript": 0, "fingerprints": 0}
    now = utc_now()
    try:
        tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "assets" in tables:
            for row in source.execute("SELECT domain,asset,type,first_seen,last_seen FROM assets"):
                if row["type"] != "subdomain":
                    continue
                target = str(row["domain"])
                host = str(row["asset"])
                cursor = db.execute(
                    "INSERT OR IGNORE INTO assets(target,host,sources_json,confidence,wildcard,resolved,first_seen,last_seen,last_run_id) VALUES(?,?,?,25,0,0,?,?,NULL)",
                    (target, host, json_dumps(["v1-import"]), row["first_seen"] or now, row["last_seen"] or now),
                )
                imported["assets"] += max(0, cursor.rowcount)
        if "urls" in tables:
            for row in source.execute("SELECT domain,url,first_seen,last_seen FROM urls"):
                cursor = db.execute(
                    "INSERT OR IGNORE INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) VALUES(?,?,?,?,?,?,NULL)",
                    (row["domain"], row["url"], "url", "v1-import", row["first_seen"] or now, row["last_seen"] or now),
                )
                imported["urls"] += max(0, cursor.rowcount)
        if "javascript" in tables:
            columns = {row[1] for row in source.execute("PRAGMA table_info(javascript)")}
            if {"domain", "url", "sha256"}.issubset(columns):
                for row in source.execute("SELECT * FROM javascript"):
                    raw_hash = str(row["sha256"])
                    local_path = str(row["local_path"] or "") if "local_path" in columns else ""
                    cursor = db.execute(
                        "INSERT OR IGNORE INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_run_id) VALUES(?,?,?,?,?,?,?,?,NULL)",
                        (row["domain"], row["url"], raw_hash, raw_hash, local_path, int(row["content_length"] or 0) if "content_length" in columns else 0, row["first_seen"] or now, row["last_seen"] or now),
                    )
                    imported["javascript"] += max(0, cursor.rowcount)
        if "fingerprints" in tables:
            for row in source.execute("SELECT * FROM fingerprints"):
                fields = set(row.keys())
                cursor = db.execute(
                    """
                    INSERT OR IGNORE INTO fingerprints(
                      target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_length,
                      first_seen,last_seen,last_run_id
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
                    """,
                    (
                        row["domain"], row["url"], row["fingerprint_hash"], row["status_code"], row["title"],
                        row["webserver"] if "webserver" in fields else "", json_dumps([row["technology"]] if "technology" in fields and row["technology"] else []),
                        int(row["content_length"] or 0) if "content_length" in fields else 0,
                        row["first_seen"] or now, row["last_seen"] or now,
                    ),
                )
                imported["fingerprints"] += max(0, cursor.rowcount)
    finally:
        source.close()
        db.close()
    logger.info("Imported legacy v1 database", **imported)
    return imported


def backup_state(paths: AppPaths, logger: Logger) -> Path:
    paths.backups.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = paths.backups / f"recon-monitor-backup-{stamp}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in (paths.config, paths.policy, paths.db, paths.root / "recon.db"):
            if path.exists():
                tar.add(path, arcname=str(path.relative_to(paths.root)))
        if paths.reports.exists():
            tar.add(paths.reports, arcname="reports")
    logger.info("Backup created", archive=str(archive))
    return archive


def retention(paths: AppPaths, config: Config, db: Database, logger: Logger, dry_run: bool = False) -> dict[str, Any]:
    keep_runs = config.int("KEEP_RUNS_PER_TARGET", 30, 1, 10000)
    raw_days = config.int("KEEP_RAW_DATA_DAYS", 30, 1, 3650)
    report_days = config.int("KEEP_REPORTS_DAYS", 365, 1, 3650)
    cutoff_raw = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=raw_days)
    cutoff_reports = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=report_days)
    removed_runs = 0
    archived_runs = 0

    targets = [row[0] for row in db.all("SELECT DISTINCT target FROM run_targets")]
    for target in targets:
        rows = db.all(
            "SELECT run_id,run_dir,started_at FROM run_targets WHERE target=? ORDER BY started_at DESC",
            (target,),
        )
        for index, row in enumerate(rows):
            run_dir = Path(str(row["run_dir"]))
            try:
                started = dt.datetime.fromisoformat(str(row["started_at"]).replace("Z", "+00:00"))
            except ValueError:
                started = dt.datetime.now(dt.timezone.utc)
            if index >= keep_runs or started < cutoff_raw:
                if run_dir.exists():
                    archive = run_dir.with_suffix(".tar.gz")
                    if not archive.exists() and not dry_run:
                        with tarfile.open(archive, "w:gz") as tar:
                            tar.add(run_dir, arcname=run_dir.name)
                        archived_runs += 1
                    if not dry_run:
                        shutil.rmtree(run_dir)
                    removed_runs += 1

    removed_reports = 0
    if paths.reports.exists():
        for report in paths.reports.rglob("*.html"):
            if report.name == "latest.html":
                continue
            modified = dt.datetime.fromtimestamp(report.stat().st_mtime, dt.timezone.utc)
            if modified < cutoff_reports:
                if not dry_run:
                    report.unlink(missing_ok=True)
                removed_reports += 1

    # Blob garbage collection: keep hashes referenced by the database.
    referenced = {str(row[0]) for row in db.all("SELECT blob_path FROM js_files WHERE blob_path<>''")}
    removed_blobs = 0
    for directory in (paths.blobs / "js", paths.blobs / "sourcemaps"):
        if not directory.exists():
            continue
        for file in directory.rglob("*"):
            if file.is_file() and str(file) not in referenced and file.suffix == ".js":
                if not dry_run:
                    file.unlink(missing_ok=True)
                removed_blobs += 1

    result = {
        "dry_run": dry_run,
        "runs_removed": removed_runs,
        "runs_archived": archived_runs,
        "reports_removed": removed_reports,
        "blobs_removed": removed_blobs,
    }
    logger.info("Retention completed", **result)
    return result


def record_versions_snapshot(paths: AppPaths) -> Path:
    tools = collect_tool_versions(
        ["python3", "sqlite3", "subfinder", "assetfinder", "dnsx", "waybackurls", "katana", "httpx", "notify", "naabu", "nuclei"]
    )
    payload = {"generated_at": utc_now(), "recon_monitor": APP_VERSION, "tools": tools}
    path = paths.state / "tool-versions.json"
    atomic_write_text(path, json_dumps(payload, pretty=True) + "\n")
    return path

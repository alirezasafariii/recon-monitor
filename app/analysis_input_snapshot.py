from __future__ import annotations

"""Immutable collection inputs for Analysis and historical replay."""

import contextlib
import json
from pathlib import Path
from typing import Any, Mapping

from core import (
    ReconError,
    atomic_write_bytes,
    json_dumps,
    sha256_bytes,
    sha256_text,
    utc_now,
)
from storage import ContentAddressedStore, _CAS_LOCK

ANALYSIS_INPUT_SNAPSHOT_VERSION = 2
CAS_MARKER_PREFIX = "cas://sha256/"

# Collection/run-state inputs only. Analysis output tables must stay writable
# in main while historical inputs are shadowed in TEMP.
INPUT_TABLES = (
    "assets",
    "dns_records",
    "urls",
    "fingerprints",
    "ports",
    "findings",
    "endpoint_intelligence",
    "endpoint_validations",
    "js_files",
    "js_indicators",
    "technology_observations",
    "alerts",
    "change_incidents",
    "incident_events",
    "run_targets",
    "stage_runs",
)


def _ensure_schema(paths: Any, db: Any) -> None:
    ContentAddressedStore(paths, db)
    with db._lock:
        db.conn.execute(
            """CREATE TABLE IF NOT EXISTS analysis_input_snapshots (
              run_id TEXT NOT NULL,
              scope TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              integrity_hash TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY(run_id,scope)
            )"""
        )
        db.conn.execute(
            "INSERT INTO schema_meta(key,value) "
            "VALUES('analysis_input_snapshot_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(ANALYSIS_INPUT_SNAPSHOT_VERSION),),
        )


def _decode_snapshot(
    row: Mapping[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], str]:
    payload = str(row["payload_json"])
    if sha256_text(payload) != str(row["integrity_hash"] or ""):
        raise ReconError("Analysis input snapshot integrity mismatch")
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReconError("Analysis input snapshot is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ReconError("Analysis input snapshot has invalid structure")
    snapshot: dict[str, list[dict[str, Any]]] = {}
    for table, rows in decoded.items():
        if table not in INPUT_TABLES or not isinstance(rows, list):
            raise ReconError(
                "Analysis input snapshot contains unsupported input data"
            )
        snapshot[table] = [
            dict(item) for item in rows if isinstance(item, Mapping)
        ]
    return snapshot, payload


def _selected_targets(
    db: Any,
    run_id: str,
    target: str | None,
) -> list[str]:
    if target:
        return [str(target)]
    targets = {
        str(row["target"])
        for row in db.all(
            "SELECT target FROM main.run_targets "
            "WHERE run_id=? ORDER BY target",
            (run_id,),
        )
        if str(row["target"] or "")
    }
    if targets:
        return sorted(targets)
    for table in INPUT_TABLES:
        columns = {
            str(row["name"])
            for row in db.all(f'PRAGMA main.table_info("{table}")')
        }
        if "target" not in columns or "last_run_id" not in columns:
            continue
        rows = db.all(
            f'SELECT DISTINCT target FROM main."{table}" '
            "WHERE last_run_id=?",
            (run_id,),
        )
        targets.update(
            str(row["target"])
            for row in rows
            if str(row["target"] or "")
        )
    return sorted(targets)


def _later_run_exists(
    db: Any,
    run_id: str,
    targets: list[str],
) -> bool:
    if not targets:
        return False
    marks = ",".join("?" for _ in targets)
    return db.one(
        f"""SELECT 1
            FROM main.run_targets old
            JOIN main.run_targets newer
              ON newer.target=old.target
             AND newer.run_id<>old.run_id
             AND (
                  newer.started_at>old.started_at
                  OR (
                      newer.started_at=old.started_at
                      AND newer.rowid>old.rowid
                  )
             )
            WHERE old.run_id=? AND old.target IN ({marks})
            LIMIT 1""",
        (run_id, *targets),
    ) is not None


def _cas_owner_key(
    run_id: str,
    scope: str,
    row: Mapping[str, Any],
) -> str:
    identity = "\0".join(
        (
            str(row.get("target") or ""),
            str(row.get("url") or ""),
            str(row.get("raw_hash") or ""),
        )
    )
    return f"{run_id}:{scope}:{sha256_text(identity)}"


def _freeze_js_blob(
    paths: Any,
    db: Any,
    run_id: str,
    scope: str,
    row: Mapping[str, Any],
) -> str:
    source = Path(str(row.get("blob_path") or "").strip())
    if not str(row.get("blob_path") or "").strip():
        return ""
    if not source.is_file():
        raise ReconError(
            f"Analysis input artifact is missing: {source.name}"
        )
    data = source.read_bytes()
    digest = sha256_bytes(data)
    declared = str(row.get("raw_hash") or "").strip().lower()
    if (
        len(declared) == 64
        and all(ch in "0123456789abcdef" for ch in declared)
        and declared != digest
    ):
        raise ReconError(
            "Analysis input artifact hash does not match js_files.raw_hash"
        )

    destination = paths.objects / digest[:2] / digest[2:4] / digest
    if destination.exists():
        if sha256_bytes(destination.read_bytes()) != digest:
            raise ReconError(
                "Analysis input CAS artifact integrity mismatch"
            )
    else:
        atomic_write_bytes(destination, data, 0o600)

    relative = str(
        destination.resolve().relative_to(paths.state.resolve())
    )
    now = utc_now()
    db.conn.execute(
        "INSERT INTO object_store("
        "sha256,relative_path,size,content_type,reference_count,"
        "created_at,last_accessed"
        ") VALUES(?,?,?,?,0,?,?) "
        "ON CONFLICT(sha256) DO UPDATE SET "
        "relative_path=excluded.relative_path,"
        "size=excluded.size,last_accessed=excluded.last_accessed",
        (
            digest,
            relative,
            len(data),
            "application/javascript",
            now,
            now,
        ),
    )
    db.conn.execute(
        "INSERT INTO cas_references("
        "owner_kind,owner_key,sha256,created_at,updated_at"
        ") VALUES('analysis_input_snapshot',?,?,?,?) "
        "ON CONFLICT(owner_kind,owner_key) DO UPDATE SET "
        "sha256=excluded.sha256,updated_at=excluded.updated_at",
        (
            _cas_owner_key(run_id, scope, row),
            digest,
            now,
            now,
        ),
    )
    db.conn.execute(
        "UPDATE object_store SET reference_count=("
        "SELECT COUNT(*) FROM cas_references "
        "WHERE cas_references.sha256=object_store.sha256"
        ") WHERE sha256=?",
        (digest,),
    )
    return CAS_MARKER_PREFIX + digest


def _capture_snapshot(
    paths: Any,
    db: Any,
    run_id: str,
    scope: str,
    targets: list[str],
) -> tuple[dict[str, list[dict[str, Any]]], str]:
    snapshot: dict[str, list[dict[str, Any]]] = {}
    db.conn.execute("BEGIN IMMEDIATE")
    try:
        for table in INPUT_TABLES:
            columns = [
                str(row["name"])
                for row in db.all(
                    f'PRAGMA main.table_info("{table}")'
                )
            ]
            if not columns:
                continue
            sql = f'SELECT * FROM main."{table}"'
            params: tuple[Any, ...] = ()
            if "target" in columns:
                if not targets:
                    snapshot[table] = []
                    continue
                marks = ",".join("?" for _ in targets)
                sql += f" WHERE target IN ({marks})"
                params = tuple(targets)
            elif "run_id" in columns:
                sql += " WHERE run_id=?"
                params = (run_id,)

            records: list[dict[str, Any]] = []
            cursor = db.execute(sql, params)
            while True:
                page = cursor.fetchmany(500)
                if not page:
                    break
                for raw in page:
                    row = dict(raw)
                    if table == "js_files":
                        row["blob_path"] = _freeze_js_blob(
                            paths,
                            db,
                            run_id,
                            scope,
                            row,
                        )
                    records.append(row)
            snapshot[table] = records

        payload = json_dumps(snapshot)
        db.conn.execute(
            "INSERT INTO analysis_input_snapshots("
            "run_id,scope,payload_json,integrity_hash,created_at"
            ") VALUES(?,?,?,?,?)",
            (
                run_id,
                scope,
                payload,
                sha256_text(payload),
                utc_now(),
            ),
        )
        db.conn.execute("COMMIT")
        return snapshot, payload
    except BaseException:
        if db.conn.in_transaction:
            db.conn.execute("ROLLBACK")
        raise


def _filter_snapshot_for_target(
    snapshot: Mapping[str, list[dict[str, Any]]],
    target: str,
) -> dict[str, list[dict[str, Any]]]:
    return {
        table: [
            dict(row)
            for row in rows
            if "target" not in row
            or str(row.get("target") or "") == target
        ]
        for table, rows in snapshot.items()
    }


def _merge_snapshots(
    snapshots: list[Mapping[str, list[dict[str, Any]]]],
) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, dict[str, dict[str, Any]]] = {}
    for snapshot in snapshots:
        for table, rows in snapshot.items():
            bucket = merged.setdefault(table, {})
            for row in rows:
                bucket[json_dumps(row)] = dict(row)
    return {
        table: list(rows.values())
        for table, rows in merged.items()
    }


def _load_or_capture(
    paths: Any,
    db: Any,
    run_id: str,
    target: str | None,
    *,
    replay: bool,
) -> tuple[dict[str, list[dict[str, Any]]], str]:
    _ensure_schema(paths, db)
    scope = str(target or "*")

    with db._lock:
        stored = db.one(
            "SELECT payload_json,integrity_hash "
            "FROM analysis_input_snapshots "
            "WHERE run_id=? AND scope=?",
            (run_id, scope),
        )
        if stored is not None:
            return _decode_snapshot(stored)

        # Derive a target replay only from a frozen aggregate, never live rows.
        if target:
            aggregate = db.one(
                "SELECT payload_json,integrity_hash "
                "FROM analysis_input_snapshots "
                "WHERE run_id=? AND scope='*'",
                (run_id,),
            )
            if aggregate is not None:
                aggregate_snapshot, _ = _decode_snapshot(aggregate)
                snapshot = _filter_snapshot_for_target(
                    aggregate_snapshot,
                    str(target),
                )
                payload = json_dumps(snapshot)
                db.execute(
                    "INSERT OR IGNORE INTO analysis_input_snapshots("
                    "run_id,scope,payload_json,integrity_hash,created_at"
                    ") VALUES(?,?,?,?,?)",
                    (
                        run_id,
                        scope,
                        payload,
                        sha256_text(payload),
                        utc_now(),
                    ),
                )
                return snapshot, payload

        # Derive an aggregate only when every source target is already frozen.
        if not target:
            targets = _selected_targets(db, run_id, None)
            parts: list[dict[str, list[dict[str, Any]]]] = []
            complete = bool(targets)
            for current_target in targets:
                part = db.one(
                    "SELECT payload_json,integrity_hash "
                    "FROM analysis_input_snapshots "
                    "WHERE run_id=? AND scope=?",
                    (run_id, current_target),
                )
                if part is None:
                    complete = False
                    break
                decoded, _ = _decode_snapshot(part)
                parts.append(decoded)
            if complete and parts:
                snapshot = _merge_snapshots(parts)
                payload = json_dumps(snapshot)
                db.execute(
                    "INSERT OR IGNORE INTO analysis_input_snapshots("
                    "run_id,scope,payload_json,integrity_hash,created_at"
                    ") VALUES(?,?,?,?,?)",
                    (
                        run_id,
                        scope,
                        payload,
                        sha256_text(payload),
                        utc_now(),
                    ),
                )
                return snapshot, payload

        if replay:
            raise ReconError(
                "This historical run has no immutable analysis input snapshot; "
                "run a fresh scan."
            )

        targets = _selected_targets(db, run_id, target)
        if _later_run_exists(db, run_id, targets):
            raise ReconError(
                "Historical analysis inputs were not preserved; "
                "run a fresh scan."
            )

    # Match storage.py lock ordering: CAS before Database.
    with _CAS_LOCK, db._lock:
        stored = db.one(
            "SELECT payload_json,integrity_hash "
            "FROM analysis_input_snapshots "
            "WHERE run_id=? AND scope=?",
            (run_id, scope),
        )
        if stored is not None:
            return _decode_snapshot(stored)
        return _capture_snapshot(
            paths,
            db,
            run_id,
            scope,
            targets,
        )


def _resolve_cas_blob(
    paths: Any,
    db: Any,
    value: str,
) -> str:
    value = str(value or "")
    if not value.startswith(CAS_MARKER_PREFIX):
        return value
    digest = value[len(CAS_MARKER_PREFIX):].strip().lower()
    if (
        len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest)
    ):
        raise ReconError(
            "Analysis input snapshot contains invalid CAS identity"
        )
    row = db.one(
        "SELECT relative_path FROM main.object_store WHERE sha256=?",
        (digest,),
    )
    if row is None:
        raise ReconError(
            "Analysis input CAS artifact is missing from object_store"
        )
    path = (paths.state / str(row["relative_path"])).resolve()
    try:
        path.relative_to(paths.objects.resolve())
    except ValueError as exc:
        raise ReconError(
            "Analysis input CAS artifact leaves object store"
        ) from exc
    if not path.is_file() or sha256_bytes(path.read_bytes()) != digest:
        raise ReconError(
            "Analysis input CAS artifact integrity mismatch"
        )
    return str(path)


@contextlib.contextmanager
def analysis_inputs(
    paths: Any,
    db: Any,
    run_id: str,
    target: str | None,
    *,
    replay: bool = False,
):
    snapshot, payload = _load_or_capture(
        paths,
        db,
        str(run_id),
        target,
        replay=replay,
    )
    scope = str(target or "*")
    installed: list[str] = []

    # TEMP tables are connection-local. Keep the connection lock through the
    # Analysis call so another thread cannot observe the shadowed inventory.
    with db._lock:
        try:
            for table, rows in snapshot.items():
                if table not in INPUT_TABLES:
                    raise ReconError(
                        "Unsupported analysis snapshot table"
                    )
                existing = db.one(
                    "SELECT 1 FROM sqlite_temp_master "
                    "WHERE type='table' AND name=?",
                    (table,),
                )
                if existing is not None:
                    raise ReconError(
                        "Nested analysis input contexts are not supported"
                    )
                db.execute(
                    f'CREATE TEMP TABLE "{table}" AS '
                    f'SELECT * FROM main."{table}" WHERE 0'
                )
                installed.append(table)
                available = {
                    str(row["name"])
                    for row in db.all(
                        f'PRAGMA temp.table_info("{table}")'
                    )
                }
                for raw in rows:
                    item = {
                        key: value
                        for key, value in dict(raw).items()
                        if key in available
                    }
                    if table == "js_files" and item.get("blob_path"):
                        item["blob_path"] = _resolve_cas_blob(
                            paths,
                            db,
                            str(item["blob_path"]),
                        )
                    if not item:
                        continue
                    columns = list(item)
                    names = ",".join(
                        '"' + name.replace('"', '""') + '"'
                        for name in columns
                    )
                    placeholders = ",".join("?" for _ in columns)
                    db.execute(
                        f'INSERT INTO temp."{table}" ({names}) '
                        f'VALUES ({placeholders})',
                        tuple(item[name] for name in columns),
                    )
                for column in (
                    "target",
                    "last_run_id",
                    "run_id",
                    "id",
                    "endpoint",
                    "url",
                    "js_url",
                    "incident_id",
                ):
                    if column in available:
                        db.execute(
                            f'CREATE INDEX temp."snapshot_{table}_{column}" '
                            f'ON "{table}" ("{column}")'
                        )

            artifacts = sum(
                1
                for row in snapshot.get("js_files", [])
                if str(row.get("blob_path") or "").startswith(
                    CAS_MARKER_PREFIX
                )
            )
            yield {
                "version": ANALYSIS_INPUT_SNAPSHOT_VERSION,
                "scope": scope,
                "integrity_hash": sha256_text(payload),
                "tables": len(snapshot),
                "artifacts": artifacts,
            }
        finally:
            for table in reversed(installed):
                db.execute(
                    f'DROP TABLE IF EXISTS temp."{table}"'
                )

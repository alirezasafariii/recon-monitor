"""Immutable collection inputs for Analysis replay.

A first Analysis run snapshots the mutable Recon inputs it can consume. Replay
installs those rows as TEMP tables, which shadow the live collection tables on
the same SQLite connection while Analysis output tables remain live.

JavaScript artifacts are retained through the content-addressed store and are
serialized into the snapshot as portable cas:<sha256> references.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

from core import AppPaths, Database, ReconError, json_dumps, sha256_bytes, utc_now
from storage import ContentAddressedStore

ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION = 2
CAS_OWNER_KIND = "analysis_input_snapshot"

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
    "entity_tags",
    "alerts",
    "change_incidents",
    "incident_events",
    "run_targets",
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ensure_schema(db: Database) -> None:
    with db._lock:
        db.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_input_snapshots (
              run_id TEXT NOT NULL,
              scope TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              integrity_hash TEXT NOT NULL,
              schema_version INTEGER NOT NULL DEFAULT 2,
              created_at TEXT NOT NULL,
              PRIMARY KEY(run_id,scope)
            );
            CREATE INDEX IF NOT EXISTS idx_analysis_input_snapshots_created
              ON analysis_input_snapshots(created_at);
            """
        )
        snapshot_columns = {
            str(row[1])
            for row in db.conn.execute(
                "PRAGMA table_info(analysis_input_snapshots)"
            )
        }
        if "schema_version" not in snapshot_columns:
            # Existing snapshots predate immutable entity-tag capture. Mark
            # them explicitly as v1 so replay can fail closed instead of
            # falling back to live business-context state.
            db.conn.execute(
                "ALTER TABLE analysis_input_snapshots "
                "ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1"
            )
        db.conn.execute(
            "INSERT INTO schema_meta(key,value) "
            "VALUES('analysis_input_snapshot_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION),),
        )


def _capture_rows(
    db: Database,
    run_id: str,
    target: str | None,
) -> dict[str, list[dict[str, Any]]]:
    scope = target or "*"
    snapshot: dict[str, list[dict[str, Any]]] = {}
    with db.transaction():
        later = db.one(
            """SELECT 1 FROM run_targets old JOIN run_targets newer
               ON newer.target=old.target AND newer.run_id<>old.run_id
              AND (newer.started_at>old.started_at OR
                   (newer.started_at=old.started_at AND newer.rowid>old.rowid))
              WHERE old.run_id=? AND (?='*' OR old.target=?) LIMIT 1""",
            (run_id, scope, scope),
        )
        if later:
            raise ReconError(
                "Historical analysis inputs were not preserved; run a fresh scan."
            )

        for table in INPUT_TABLES:
            columns = [
                str(row["name"])
                for row in db.all(f'PRAGMA main.table_info("{table}")')
            ]
            if not columns:
                continue
            sql = f'SELECT * FROM main."{table}"'
            params: tuple[Any, ...] = ()
            if target and "target" in columns:
                sql += " WHERE target=?"
                params = (target,)
            records: list[dict[str, Any]] = []
            cursor = db.execute(sql, params)
            while True:
                page = cursor.fetchmany(500)
                if not page:
                    break
                records.extend(dict(row) for row in page)
            snapshot[table] = records
    return snapshot


def _freeze_js_artifacts(
    paths: AppPaths,
    db: Database,
    run_id: str,
    scope: str,
    snapshot: dict[str, list[dict[str, Any]]],
) -> None:
    rows = snapshot.get("js_files", [])
    if not rows:
        return

    store = ContentAddressedStore(paths, db)
    owner_prefix = f"{run_id}\n{scope}\n"
    references: dict[str, str] = {}

    for index, row in enumerate(rows):
        raw_path = str(row.get("blob_path") or "").strip()
        if not raw_path:
            continue
        source = Path(raw_path)
        if not source.is_file():
            raise ReconError(
                f"Analysis input artifact is missing: {source.name or 'javascript'}"
            )
        data = source.read_bytes()
        digest, _path, _created = store.put(
            data,
            content_type="application/javascript",
        )
        if sha256_bytes(data) != digest:
            raise ReconError("Analysis input artifact integrity mismatch")
        row["blob_path"] = f"cas:{digest}"
        url = str(row.get("url") or "")
        references[f"{owner_prefix}{index}\n{url}"] = digest

    store.sync_references(
        CAS_OWNER_KIND,
        references,
        owner_prefix=owner_prefix,
    )


def _resolve_blob_path(
    paths: AppPaths,
    db: Database,
    value: Any,
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("cas:"):
        digest = text[4:].strip().lower()
        if (
            len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ReconError("Invalid Analysis input CAS reference")
        row = db.one(
            "SELECT relative_path FROM object_store WHERE sha256=?",
            (digest,),
        )
        if not row:
            raise ReconError("Analysis input artifact metadata is missing")
        path = (paths.state / str(row["relative_path"])).resolve()
        try:
            path.relative_to(paths.objects.resolve())
        except ValueError as exc:
            raise ReconError(
                "Analysis input artifact path is outside CAS"
            ) from exc
        if (
            not path.is_file()
            or sha256_bytes(path.read_bytes()) != digest
        ):
            raise ReconError("Analysis input artifact integrity mismatch")
        return str(path)

    # Compatibility for snapshots created by the earlier experimental branch.
    path = Path(text)
    if (
        path.is_file()
        and len(path.name) == 64
        and all(ch in "0123456789abcdef" for ch in path.name.lower())
        and sha256_bytes(path.read_bytes()) == path.name.lower()
    ):
        return str(path)
    raise ReconError("Analysis input artifact is not portable or is missing")


def _merge_target_snapshots(
    db: Database,
    run_id: str,
) -> dict[str, Any] | None:
    parts = db.all(
        "SELECT * FROM analysis_input_snapshots "
        "WHERE run_id=? AND scope<>?",
        (run_id, "*"),
    )
    if not parts:
        return None

    expected = {
        str(row[0])
        for row in db.all(
            "SELECT target FROM main.run_targets WHERE run_id=?",
            (run_id,),
        )
    }
    scopes = {str(row["scope"]) for row in parts}
    if expected and not expected <= scopes:
        return None

    merged: dict[str, dict[str, dict[str, Any]]] = {}
    for part in parts:
        snapshot_version = int(part["schema_version"] or 1)
        if snapshot_version < ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION:
            raise ReconError(
                "Analysis input snapshot predates immutable entity-tag "
                "capture; run a fresh scan."
            )
        payload = str(part["payload_json"])
        if _digest(payload) != str(part["integrity_hash"]):
            raise ReconError("Analysis input snapshot integrity mismatch")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ReconError("Analysis input snapshot payload is invalid")
        for table, rows in decoded.items():
            if table not in INPUT_TABLES or not isinstance(rows, list):
                raise ReconError("Analysis input snapshot payload is invalid")
            bucket = merged.setdefault(table, {})
            for row in rows:
                if not isinstance(row, dict):
                    raise ReconError(
                        "Analysis input snapshot payload is invalid"
                    )
                bucket[json_dumps(row)] = row

    snapshot = {
        table: list(rows.values())
        for table, rows in merged.items()
    }
    payload = json_dumps(snapshot)
    integrity_hash = _digest(payload)
    db.execute(
        "INSERT INTO analysis_input_snapshots("
        "run_id,scope,payload_json,integrity_hash,schema_version,created_at"
        ") VALUES(?,?,?,?,?,?)",
        (
            run_id,
            "*",
            payload,
            integrity_hash,
            ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION,
            utc_now(),
        ),
    )
    return {
        "payload_json": payload,
        "integrity_hash": integrity_hash,
        "schema_version": ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION,
    }


@contextlib.contextmanager
def analysis_inputs(
    paths: AppPaths,
    db: Database,
    run_id: str,
    target: str | None,
    *,
    replay: bool = False,
) -> Iterator[dict[str, Any]]:
    scope = target or "*"
    _ensure_schema(db)

    with db._lock:
        stored = db.one(
            "SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope=?",
            (run_id, scope),
        )
        if stored is None and target is None:
            stored = _merge_target_snapshots(db, run_id)

        if stored is not None:
            snapshot_version = int(stored["schema_version"] or 1)
            if snapshot_version < ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION:
                raise ReconError(
                    "Analysis input snapshot predates immutable entity-tag "
                    "capture; run a fresh scan."
                )
            payload = str(stored["payload_json"])
            if _digest(payload) != str(stored["integrity_hash"]):
                raise ReconError("Analysis input snapshot integrity mismatch")
            snapshot = json.loads(payload)
            if not isinstance(snapshot, dict):
                raise ReconError("Analysis input snapshot payload is invalid")
            if "entity_tags" not in snapshot:
                raise ReconError(
                    "Analysis input snapshot is missing immutable entity tags"
                )
        else:
            if replay:
                raise ReconError(
                    "This historical run has no immutable analysis snapshot; "
                    "run a fresh scan."
                )
            snapshot = _capture_rows(db, run_id, target)
            _freeze_js_artifacts(paths, db, run_id, scope, snapshot)
            payload = json_dumps(snapshot)
            integrity_hash = _digest(payload)
            db.execute(
                "INSERT INTO analysis_input_snapshots("
                "run_id,scope,payload_json,integrity_hash,schema_version,created_at"
                ") VALUES(?,?,?,?,?,?)",
                (
                    run_id,
                    scope,
                    payload,
                    integrity_hash,
                    ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION,
                    utc_now(),
                ),
            )
            snapshot_version = ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION

        installed: list[str] = []
        try:
            for table, raw_rows in snapshot.items():
                if table not in INPUT_TABLES or not isinstance(raw_rows, list):
                    raise ReconError(
                        "Unsupported Analysis input snapshot table"
                    )
                if db.one(
                    "SELECT 1 FROM sqlite_temp_master "
                    "WHERE type='table' AND name=?",
                    (table,),
                ):
                    raise ReconError(
                        "Nested Analysis input contexts are not supported"
                    )
                if not db.one(
                    "SELECT 1 FROM main.sqlite_master "
                    "WHERE type='table' AND name=?",
                    (table,),
                ):
                    raise ReconError(
                        f"Analysis input snapshot table is unavailable: {table}"
                    )

                db.execute(
                    f'CREATE TEMP TABLE "{table}" AS '
                    f'SELECT * FROM main."{table}" WHERE 0'
                )
                installed.append(table)
                current_columns = {
                    str(row["name"])
                    for row in db.all(
                        f'PRAGMA temp.table_info("{table}")'
                    )
                }

                for raw_row in raw_rows:
                    if not isinstance(raw_row, dict):
                        raise ReconError(
                            "Analysis input snapshot payload is invalid"
                        )
                    row = dict(raw_row)
                    unknown = set(row) - current_columns
                    if unknown:
                        raise ReconError(
                            "Analysis input snapshot schema is incompatible: "
                            f"{table}.{sorted(unknown)[0]}"
                        )
                    if table == "js_files" and row.get("blob_path"):
                        row["blob_path"] = _resolve_blob_path(
                            paths,
                            db,
                            row["blob_path"],
                        )
                    columns = list(row)
                    if not columns:
                        continue
                    names = ",".join(
                        '"' + name.replace('"', '""') + '"'
                        for name in columns
                    )
                    placeholders = ",".join("?" for _ in columns)
                    db.execute(
                        f'INSERT INTO temp."{table}" ({names}) '
                        f"VALUES ({placeholders})",
                        tuple(row[name] for name in columns),
                    )

                for column in (
                    "target",
                    "last_run_id",
                    "id",
                    "endpoint",
                    "url",
                    "js_url",
                    "incident_id",
                    "entity_type",
                    "entity_value",
                    "tag",
                ):
                    if column in current_columns:
                        index_name = f"snapshot_{table}_{column}"
                        db.execute(
                            f'CREATE INDEX temp."{index_name}" '
                            f'ON "{table}" ("{column}")'
                        )

            yield {
                "schema_version": snapshot_version,
                "scope": scope,
                "integrity_hash": _digest(payload),
                "tables": len(snapshot),
            }
        finally:
            for table in reversed(installed):
                db.execute(f'DROP TABLE temp."{table}"')

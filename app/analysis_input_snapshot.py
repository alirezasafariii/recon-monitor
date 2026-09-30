"""Immutable collection inputs for Analysis replay.

Analysis captures a new immutable revision when resumed Recon inputs change.
Replay selects the latest captured revision, or an explicit historical revision,
and installs its rows as TEMP tables while Analysis output tables remain live.

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
              revision INTEGER NOT NULL DEFAULT 1,
              PRIMARY KEY(run_id,scope)
            );
            CREATE INDEX IF NOT EXISTS idx_analysis_input_snapshots_created
              ON analysis_input_snapshots(created_at);
            CREATE TABLE IF NOT EXISTS analysis_input_snapshot_versions (
              run_id TEXT NOT NULL,
              scope TEXT NOT NULL,
              revision INTEGER NOT NULL CHECK(revision>0),
              payload_json TEXT NOT NULL,
              integrity_hash TEXT NOT NULL,
              schema_version INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY(run_id,scope,revision)
            );
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
        if "revision" not in snapshot_columns:
            db.conn.execute(
                "ALTER TABLE analysis_input_snapshots "
                "ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"
            )
        # The established table remains the latest-revision pointer. Archive
        # legacy snapshots verbatim before a resumed capture can advance it.
        db.conn.execute(
            "INSERT OR IGNORE INTO analysis_input_snapshot_versions "
            "(run_id,scope,revision,payload_json,integrity_hash,schema_version,created_at) "
            "SELECT run_id,scope,revision,payload_json,integrity_hash,schema_version,created_at "
            "FROM analysis_input_snapshots"
        )
        db.conn.execute(
            "INSERT INTO schema_meta(key,value) "
            "VALUES('analysis_input_snapshot_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION),),
        )


def _has_later_run(db: Database, run_id: str, target: str | None) -> bool:
    scope = target or "*"
    return db.one(
        """SELECT 1 FROM main.run_targets old JOIN main.run_targets newer
           ON newer.target=old.target AND newer.run_id<>old.run_id
          AND (newer.started_at>old.started_at OR
               (newer.started_at=old.started_at AND newer.rowid>old.rowid))
          WHERE old.run_id=? AND (?='*' OR old.target=?) LIMIT 1""",
        (run_id, scope, scope),
    ) is not None


def _capture_rows(
    db: Database,
    run_id: str,
    target: str | None,
) -> dict[str, list[dict[str, Any]]]:
    snapshot: dict[str, list[dict[str, Any]]] = {}
    with db.transaction():
        if _has_later_run(db, run_id, target):
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
    snapshot: dict[str, list[dict[str, Any]]],
) -> None:
    rows = snapshot.get("js_files", [])
    if not rows:
        return

    store = ContentAddressedStore(paths, db)
    for row in rows:
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


def _pin_js_artifacts(
    paths: AppPaths,
    db: Database,
    run_id: str,
    scope: str,
    integrity_hash: str,
    snapshot: dict[str, list[dict[str, Any]]],
) -> None:
    # A different input payload owns different references. Advancing the head
    # must never release JavaScript artifacts used by historical revisions.
    owner_prefix = f"{run_id}\n{scope}\n{integrity_hash}\n"
    references = {
        f"{owner_prefix}{index}\n{row.get('url') or ''}": str(row["blob_path"])[4:]
        for index, row in enumerate(snapshot.get("js_files", []))
        if str(row.get("blob_path") or "").startswith("cas:")
    }
    if not references:
        return
    store = ContentAddressedStore(paths, db)

    store.sync_references(
        CAS_OWNER_KIND,
        references,
        owner_prefix=owner_prefix,
    )


def _decode_snapshot(stored: Any) -> dict[str, list[dict[str, Any]]]:
    if int(stored["schema_version"] or 1) < ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION:
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
        raise ReconError("Analysis input snapshot is missing immutable entity tags")
    return snapshot


def _store_snapshot(
    paths: AppPaths,
    db: Database,
    run_id: str,
    scope: str,
    snapshot: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    snapshot = {
        table: sorted(rows, key=json_dumps)
        for table, rows in snapshot.items()
    }
    payload = json_dumps(snapshot)
    integrity_hash = _digest(payload)
    current = db.one(
        "SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope=?",
        (run_id, scope),
    )
    if current is not None and str(current["payload_json"]) == payload:
        return dict(current)
    _pin_js_artifacts(paths, db, run_id, scope, integrity_hash, snapshot)
    with db.transaction():
        revision = int(db.one(
            "SELECT COALESCE(MAX(revision),0)+1 FROM analysis_input_snapshot_versions "
            "WHERE run_id=? AND scope=?",
            (run_id, scope),
        )[0])
        stored = {
            "run_id": run_id, "scope": scope, "revision": revision,
            "payload_json": payload, "integrity_hash": integrity_hash,
            "schema_version": ANALYSIS_INPUT_SNAPSHOT_SCHEMA_VERSION,
            "created_at": utc_now(),
        }
        values = tuple(stored[key] for key in (
            "run_id", "scope", "revision", "payload_json", "integrity_hash", "schema_version", "created_at",
        ))
        db.execute(
            "INSERT INTO analysis_input_snapshot_versions "
            "(run_id,scope,revision,payload_json,integrity_hash,schema_version,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            values,
        )
        db.execute(
            "INSERT INTO analysis_input_snapshots "
            "(run_id,scope,revision,payload_json,integrity_hash,schema_version,created_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(run_id,scope) DO UPDATE SET "
            "revision=excluded.revision,payload_json=excluded.payload_json,"
            "integrity_hash=excluded.integrity_hash,schema_version=excluded.schema_version,"
            "created_at=excluded.created_at",
            values,
        )
    return stored


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
        "WHERE run_id=? AND scope<>? ORDER BY scope",
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
        decoded = _decode_snapshot(part)
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

    return {
        table: list(rows.values())
        for table, rows in merged.items()
    }


@contextlib.contextmanager
def analysis_inputs(
    paths: AppPaths,
    db: Database,
    run_id: str,
    target: str | None,
    *,
    replay: bool = False,
    refresh: bool = False,
    revision: int | None = None,
) -> Iterator[dict[str, Any]]:
    if revision is not None and (not replay or isinstance(revision, bool) or not isinstance(revision, int) or revision < 1):
        raise ReconError("A positive Analysis input revision can only be selected for replay")
    scope = target or "*"
    _ensure_schema(db)

    with db._lock:
        if any(db.one(
            "SELECT 1 FROM sqlite_temp_master WHERE type='table' AND name=?", (table,),
        ) for table in INPUT_TABLES):
            raise ReconError("Nested Analysis input contexts are not supported")
        stored = db.one(
            "SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope=?",
            (run_id, scope),
        )
        if stored is not None and revision is None:
            _decode_snapshot(stored)
        if revision is not None:
            stored = db.one(
                "SELECT * FROM analysis_input_snapshot_versions "
                "WHERE run_id=? AND scope=? AND revision=?",
                (run_id, scope, revision),
            )
            if stored is None:
                raise ReconError("Requested Analysis input snapshot revision does not exist")
        elif refresh and not replay and not _has_later_run(db, run_id, target):
            snapshot = _capture_rows(db, run_id, target)
            _freeze_js_artifacts(paths, db, snapshot)
            stored = _store_snapshot(paths, db, run_id, scope, snapshot)
        elif target is None and (stored is None or (refresh and not replay)):
            merged = _merge_target_snapshots(db, run_id)
            if merged is not None:
                stored = _store_snapshot(paths, db, run_id, scope, merged)

        if stored is None:
            if replay:
                raise ReconError(
                    "This historical run has no immutable analysis snapshot; "
                    "run a fresh scan."
                )
            snapshot = _capture_rows(db, run_id, target)
            _freeze_js_artifacts(paths, db, snapshot)
            stored = _store_snapshot(paths, db, run_id, scope, snapshot)

        snapshot = _decode_snapshot(stored)
        payload = str(stored["payload_json"])
        snapshot_version = int(stored["schema_version"])

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
                "revision": int(stored["revision"]),
                "tables": len(snapshot),
            }
        finally:
            for table in reversed(installed):
                db.execute(f'DROP TABLE temp."{table}"')

from __future__ import annotations

"""CAS owners and JS availability belonging to a committed Recon snapshot.

Call handoff functions inside storage.cas_transaction, before replacing the
mutable comparison view. Historical run observations and work receipts remain
intact for diagnostics and same-run resume.
"""

from typing import Any

from core import ReconError, json_dumps, sha256_text, utc_now
from storage import ensure_cas_reference_schema

SNAPSHOT_OWNER_KIND = "successful_recon_snapshot"


def ensure_artifact_snapshot_schema(db: Any) -> None:
    ensure_cas_reference_schema(db)
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS successful_recon_cas_state (
          target TEXT NOT NULL,
          owner_kind TEXT NOT NULL,
          owner_key TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          PRIMARY KEY(target,owner_kind,owner_key)
        );
        CREATE TABLE IF NOT EXISTS successful_recon_js_availability (
          target TEXT NOT NULL,
          url TEXT NOT NULL,
          run_id TEXT NOT NULL,
          state TEXT NOT NULL,
          status_code INTEGER,
          content_type TEXT NOT NULL DEFAULT '',
          error TEXT NOT NULL DEFAULT '',
          raw_hash TEXT NOT NULL DEFAULT '',
          semantic_hash TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL,
          PRIMARY KEY(target,url)
        );
        """
    )


def _refresh_reference_counts(db: Any) -> None:
    db.execute(
        "UPDATE object_store SET reference_count=(SELECT COUNT(*) FROM "
        "cas_references r WHERE r.sha256=object_store.sha256)"
    )


def discard_artifact_snapshot(db: Any, target: str) -> None:
    prefix = target + "\n"
    db.execute("DELETE FROM successful_recon_cas_state WHERE target=?", (target,))
    db.execute("DELETE FROM successful_recon_js_availability WHERE target=?", (target,))
    db.execute(
        "DELETE FROM cas_references WHERE owner_kind=? AND substr(owner_key,1,?)=?",
        (SNAPSHOT_OWNER_KIND, len(prefix), prefix),
    )
    _refresh_reference_counts(db)


def seed_committed_availability(db: Any, target: str, run_id: str) -> None:
    """Recover per-URL history during a trusted legacy upgrade, never live rows."""
    rows = db.all(
        "SELECT h.* FROM js_availability_history h "
        "JOIN run_targets rt ON rt.run_id=h.run_id AND rt.target=h.target "
        "LEFT JOIN target_run_lifecycle l ON l.run_id=rt.run_id AND l.target=rt.target "
        "WHERE h.target=? AND rt.rowid<=(SELECT rowid FROM run_targets WHERE run_id=? AND target=?) "
        "AND (l.collection_status='success' AND l.baseline_eligible=1 OR "
        "((l.run_id IS NULL OR l.collection_status='not_run') AND rt.status='success' "
        "AND NOT EXISTS(SELECT 1 FROM stage_runs s WHERE s.run_id=rt.run_id AND s.target=rt.target "
        "AND s.status IN ('partial','failed','interrupted','running')))) "
        "ORDER BY rt.started_at DESC,rt.rowid DESC", (target, run_id, target),
    )
    for row in rows:
        db.execute(
            "INSERT OR IGNORE INTO successful_recon_js_availability "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (target, row["url"], row["run_id"], row["state"], row["status_code"],
             row["content_type"], row["error"], row["raw_hash"], row["semantic_hash"], row["observed_at"]),
        )


def commit_artifact_snapshot(db: Any, target: str, run_id: str) -> None:
    prefix = target + "\n"
    owners = {
        (str(row["owner_kind"]), str(row["owner_key"])): str(row["sha256"])
        for row in db.all(
            "SELECT owner_kind,owner_key,sha256 FROM cas_references "
            "WHERE owner_kind IN ('js_file','source_map','source_map_source') "
            "AND substr(owner_key,1,?)=?",
            (len(prefix), prefix),
        )
    }
    # Older installations may not yet have explicit current JS owners. The
    # stored digest, rather than an old absolute blob path, identifies the CAS.
    for row in db.all(
        "SELECT j.url,j.raw_hash FROM js_files j JOIN object_store o "
        "ON o.sha256=j.raw_hash WHERE j.target=?", (target,),
    ):
        owners[("js_file", prefix + str(row["url"]))] = str(row["raw_hash"])

    db.execute("DELETE FROM successful_recon_cas_state WHERE target=?", (target,))
    db.execute(
        "DELETE FROM cas_references WHERE owner_kind=? AND substr(owner_key,1,?)=?",
        (SNAPSHOT_OWNER_KIND, len(prefix), prefix),
    )
    now = utc_now()
    for (kind, key), digest in owners.items():
        db.execute(
            "INSERT INTO successful_recon_cas_state VALUES(?,?,?,?)",
            (target, kind, key, digest),
        )
        db.execute(
            "INSERT INTO cas_references(owner_kind,owner_key,sha256,created_at,updated_at) "
            "VALUES(?,?,?,?,?)",
            (SNAPSHOT_OWNER_KIND, prefix + sha256_text(json_dumps([kind, key])), digest, now, now),
        )
    _refresh_reference_counts(db)

    # Keep the last committed observation per URL, even when a later complete
    # collection does not request that URL. Never consult failed run history.
    db.execute(
        "INSERT INTO successful_recon_js_availability "
        "SELECT target,url,run_id,state,status_code,content_type,error,raw_hash,semantic_hash,observed_at "
        "FROM js_availability_history WHERE target=? AND run_id=? "
        "ON CONFLICT(target,url) DO UPDATE SET run_id=excluded.run_id,state=excluded.state,"
        "status_code=excluded.status_code,content_type=excluded.content_type,error=excluded.error,"
        "raw_hash=excluded.raw_hash,semantic_hash=excluded.semantic_hash,observed_at=excluded.observed_at",
        (target, run_id),
    )


def restore_artifact_owners(db: Any, target: str) -> None:
    prefix = target + "\n"
    db.execute(
        "DELETE FROM cas_references WHERE owner_kind IN ('js_file','source_map','source_map_source') "
        "AND substr(owner_key,1,?)=?", (len(prefix), prefix),
    )
    now = utc_now()
    db.execute(
        "INSERT INTO cas_references(owner_kind,owner_key,sha256,created_at,updated_at) "
        "SELECT owner_kind,owner_key,sha256,?,? FROM successful_recon_cas_state WHERE target=?",
        (now, now, target),
    )
    # Snapshot payloads can outlive a backup move. Rebase CAS-backed JS paths
    # from local object metadata; never resurrect an absolute source path.
    object_root = (db.path.parent / "objects" / "sha256").resolve()
    for row in db.all(
        "SELECT j.url,o.relative_path FROM js_files j JOIN object_store o "
        "ON o.sha256=j.raw_hash WHERE j.target=?", (target,),
    ):
        path = (db.path.parent / str(row["relative_path"])).resolve()
        if not path.is_relative_to(object_root):
            raise ReconError("Committed JavaScript CAS path is outside the object store")
        db.execute("UPDATE js_files SET blob_path=? WHERE target=? AND url=?", (str(path), target, row["url"]))
    _refresh_reference_counts(db)

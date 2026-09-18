from __future__ import annotations

import datetime as dt
import mimetypes
import threading
from pathlib import Path
from typing import Any, Mapping

from core import AppPaths, Database, atomic_write_bytes, sha256_bytes, utc_now


CAS_REFERENCE_SCHEMA_VERSION = 1
_CAS_LOCK = threading.RLock()


class ContentAddressedStore:
    """Content-addressed object storage with explicit owner references.

    object_store.reference_count is derived from cas_references. Writing the
    same bytes repeatedly does not create new logical references; callers bind
    stable owners (for example one current JavaScript URL) to object digests.
    """

    def __init__(self, paths: AppPaths, db: Database):
        self.paths = paths
        self.db = db
        self.paths.objects.mkdir(parents=True, exist_ok=True)
        self._ensure_reference_schema()

    def _ensure_reference_schema(self) -> None:
        with self.db._lock:
            self.db.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cas_references (
                  owner_kind TEXT NOT NULL,
                  owner_key TEXT NOT NULL,
                  sha256 TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  PRIMARY KEY(owner_kind,owner_key),
                  FOREIGN KEY(sha256) REFERENCES object_store(sha256) ON DELETE RESTRICT
                );
                CREATE INDEX IF NOT EXISTS idx_cas_references_sha256
                  ON cas_references(sha256);
                """
            )
            self.db.conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('cas_reference_schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(CAS_REFERENCE_SCHEMA_VERSION),),
            )

    def _path(self, digest: str) -> Path:
        return self.paths.objects / digest[:2] / digest[2:4] / digest

    def _relative_path(self, path: Path) -> str:
        return str(path.resolve().relative_to(self.paths.state.resolve()))

    def _row_path(self, relative_path: str) -> Path:
        path = (self.paths.state / str(relative_path)).resolve()
        path.relative_to(self.paths.objects.resolve())
        return path

    def put(
        self,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> tuple[str, Path, bool]:
        digest = sha256_bytes(data)
        path = self._path(digest)
        now = utc_now()
        with _CAS_LOCK:
            created = not path.exists()
            if created:
                atomic_write_bytes(path, data, 0o600)
            rel = self._relative_path(path)
            self.db.execute(
                "INSERT INTO object_store(sha256,relative_path,size,content_type,reference_count,created_at,last_accessed) "
                "VALUES(?,?,?,?,0,?,?) "
                "ON CONFLICT(sha256) DO UPDATE SET "
                "relative_path=excluded.relative_path,size=excluded.size,"
                "content_type=excluded.content_type,last_accessed=excluded.last_accessed",
                (digest, rel, len(data), content_type, now, now),
            )
        return digest, path, created

    def put_file(
        self,
        source: Path,
        *,
        content_type: str = "",
    ) -> tuple[str, Path, bool]:
        guessed = (
            content_type
            or mimetypes.guess_type(source.name)[0]
            or "application/octet-stream"
        )
        return self.put(source.read_bytes(), content_type=guessed)

    def get(self, digest: str) -> bytes:
        with _CAS_LOCK:
            row = self.db.one(
                "SELECT relative_path FROM object_store WHERE sha256=?",
                (digest,),
            )
            if not row:
                raise FileNotFoundError(digest)
            path = self._row_path(str(row["relative_path"]))
            data = path.read_bytes()
            self.db.execute(
                "UPDATE object_store SET last_accessed=? WHERE sha256=?",
                (utc_now(), digest),
            )
            return data

    @staticmethod
    def _owner(kind: str, key: str) -> tuple[str, str]:
        owner_kind = str(kind or "").strip()
        owner_key = str(key or "").strip()
        if not owner_kind or not owner_key:
            raise ValueError("CAS references require owner_kind and owner_key")
        return owner_kind[:80], owner_key

    def _refresh_counts_locked(self, digests: set[str] | None = None) -> None:
        if digests:
            for digest in digests:
                self.db.conn.execute(
                    "UPDATE object_store SET reference_count=("
                    "SELECT COUNT(*) FROM cas_references WHERE cas_references.sha256=object_store.sha256"
                    ") WHERE sha256=?",
                    (digest,),
                )
            return
        self.db.conn.execute(
            "UPDATE object_store SET reference_count=("
            "SELECT COUNT(*) FROM cas_references WHERE cas_references.sha256=object_store.sha256"
            ")"
        )

    def set_reference(self, owner_kind: str, owner_key: str, digest: str) -> None:
        kind, key = self._owner(owner_kind, owner_key)
        digest = str(digest or "").strip().lower()
        with _CAS_LOCK, self.db._lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                object_row = self.db.conn.execute(
                    "SELECT relative_path FROM object_store WHERE sha256=?",
                    (digest,),
                ).fetchone()
                if not object_row:
                    raise FileNotFoundError(digest)
                self._row_path(str(object_row["relative_path"])).stat()
                old = self.db.conn.execute(
                    "SELECT sha256 FROM cas_references WHERE owner_kind=? AND owner_key=?",
                    (kind, key),
                ).fetchone()
                old_digest = str(old["sha256"]) if old else ""
                now = utc_now()
                self.db.conn.execute(
                    "INSERT INTO cas_references(owner_kind,owner_key,sha256,created_at,updated_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(owner_kind,owner_key) DO UPDATE SET "
                    "sha256=excluded.sha256,updated_at=excluded.updated_at",
                    (kind, key, digest, now, now),
                )
                touched = {digest}
                if old_digest:
                    touched.add(old_digest)
                self._refresh_counts_locked(touched)
                self.db.conn.execute("COMMIT")
            except Exception:
                self.db.conn.execute("ROLLBACK")
                raise

    def sync_references(
        self,
        owner_kind: str,
        references: Mapping[str, str],
        *,
        owner_prefix: str = "",
    ) -> dict[str, int]:
        kind = str(owner_kind or "").strip()[:80]
        if not kind:
            raise ValueError("CAS references require owner_kind")
        desired = {
            self._owner(kind, key)[1]: str(digest or "").strip().lower()
            for key, digest in references.items()
            if str(key or "").strip() and str(digest or "").strip()
        }
        prefix = str(owner_prefix or "")
        if prefix and any(not key.startswith(prefix) for key in desired):
            raise ValueError("CAS reference owner is outside the requested owner_prefix")
        with _CAS_LOCK, self.db._lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self.db.conn.execute(
                    "SELECT owner_key,sha256 FROM cas_references WHERE owner_kind=?",
                    (kind,),
                ).fetchall()
                existing = {
                    str(row["owner_key"]): str(row["sha256"])
                    for row in rows
                    if not prefix or str(row["owner_key"]).startswith(prefix)
                }
                for digest in desired.values():
                    row = self.db.conn.execute(
                        "SELECT relative_path FROM object_store WHERE sha256=?",
                        (digest,),
                    ).fetchone()
                    if not row:
                        raise FileNotFoundError(digest)
                    self._row_path(str(row["relative_path"])).stat()

                touched = set(existing.values()) | set(desired.values())
                removed = 0
                for key in set(existing) - set(desired):
                    self.db.conn.execute(
                        "DELETE FROM cas_references WHERE owner_kind=? AND owner_key=?",
                        (kind, key),
                    )
                    removed += 1

                now = utc_now()
                changed = 0
                for key, digest in desired.items():
                    if existing.get(key) == digest:
                        self.db.conn.execute(
                            "UPDATE cas_references SET updated_at=? WHERE owner_kind=? AND owner_key=?",
                            (now, kind, key),
                        )
                        continue
                    self.db.conn.execute(
                        "INSERT INTO cas_references(owner_kind,owner_key,sha256,created_at,updated_at) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(owner_kind,owner_key) DO UPDATE SET "
                        "sha256=excluded.sha256,updated_at=excluded.updated_at",
                        (kind, key, digest, now, now),
                    )
                    changed += 1
                self._refresh_counts_locked(touched)
                self.db.conn.execute("COMMIT")
                return {"changed": changed, "removed": removed, "owners": len(desired)}
            except Exception:
                self.db.conn.execute("ROLLBACK")
                raise

    def drop_reference(self, owner_kind: str, owner_key: str) -> bool:
        kind, key = self._owner(owner_kind, owner_key)
        with _CAS_LOCK, self.db._lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.conn.execute(
                    "SELECT sha256 FROM cas_references WHERE owner_kind=? AND owner_key=?",
                    (kind, key),
                ).fetchone()
                if not row:
                    self.db.conn.execute("COMMIT")
                    return False
                digest = str(row["sha256"])
                self.db.conn.execute(
                    "DELETE FROM cas_references WHERE owner_kind=? AND owner_key=?",
                    (kind, key),
                )
                self._refresh_counts_locked({digest})
                self.db.conn.execute("COMMIT")
                return True
            except Exception:
                self.db.conn.execute("ROLLBACK")
                raise

    def _digest_from_object_path(self, raw_path: str) -> str:
        if not str(raw_path or "").strip():
            return ""
        try:
            path = Path(str(raw_path)).resolve()
            path.relative_to(self.paths.objects.resolve())
        except (OSError, ValueError):
            return ""
        digest = path.name.lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            return ""
        row = self.db.one(
            "SELECT 1 FROM object_store WHERE sha256=? AND relative_path=?",
            (digest, self._relative_path(path)),
        )
        return digest if row else ""

    def reconcile_reference_counts(self) -> dict[str, int]:
        """Seed legacy JS owners and derive reference_count from owner rows."""
        seeded = 0
        with _CAS_LOCK, self.db._lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                now = utc_now()
                js_rows = self.db.conn.execute(
                    "SELECT target,url,blob_path FROM js_files WHERE COALESCE(blob_path,'')<>''"
                ).fetchall()
                for row in js_rows:
                    digest = self._digest_from_object_path(str(row["blob_path"]))
                    if not digest:
                        continue
                    key = f"{row['target']}\n{row['url']}"
                    existing = self.db.conn.execute(
                        "SELECT sha256 FROM cas_references WHERE owner_kind='js_file' AND owner_key=?",
                        (key,),
                    ).fetchone()
                    if existing and str(existing["sha256"]) == digest:
                        continue
                    self.db.conn.execute(
                        "INSERT INTO cas_references(owner_kind,owner_key,sha256,created_at,updated_at) "
                        "VALUES('js_file',?,?,?,?) ON CONFLICT(owner_kind,owner_key) DO UPDATE SET "
                        "sha256=excluded.sha256,updated_at=excluded.updated_at",
                        (key, digest, now, now),
                    )
                    seeded += 1

                legacy_marker = self.db.conn.execute(
                    "SELECT value FROM schema_meta WHERE key='cas_reference_legacy_bootstrap_v1'"
                ).fetchone()
                legacy_protected = 0
                if legacy_marker is None:
                    legacy_rows = self.db.conn.execute(
                        "SELECT sha256 FROM object_store WHERE reference_count>0"
                    ).fetchall()
                    for legacy_row in legacy_rows:
                        digest = str(legacy_row["sha256"])
                        known = self.db.conn.execute(
                            "SELECT 1 FROM cas_references WHERE sha256=? LIMIT 1",
                            (digest,),
                        ).fetchone()
                        if known:
                            continue
                        self.db.conn.execute(
                            "INSERT OR IGNORE INTO cas_references("
                            "owner_kind,owner_key,sha256,created_at,updated_at"
                            ") VALUES('legacy_unclassified',?,?,?,?)",
                            (digest, digest, now, now),
                        )
                        legacy_protected += 1
                    self.db.conn.execute(
                        "INSERT INTO schema_meta(key,value) "
                        "VALUES('cas_reference_legacy_bootstrap_v1','1') "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
                    )
                else:
                    legacy_protected = int(
                        self.db.conn.execute(
                            "SELECT COUNT(*) FROM cas_references "
                            "WHERE owner_kind='legacy_unclassified'"
                        ).fetchone()[0]
                    )

                self._refresh_counts_locked()
                self.db.conn.execute("COMMIT")
            except Exception:
                self.db.conn.execute("ROLLBACK")
                raise

        missing_files = 0
        for row in self.db.all(
            "SELECT relative_path FROM object_store WHERE reference_count>0"
        ):
            try:
                if not self._row_path(str(row["relative_path"])).is_file():
                    missing_files += 1
            except ValueError:
                missing_files += 1
        unreferenced = int(
            (
                self.db.one(
                    "SELECT COUNT(*) count FROM object_store WHERE reference_count<=0"
                )
                or {"count": 0}
            )["count"]
        )
        return {
            "seeded_legacy_references": seeded,
            "legacy_protected_objects": legacy_protected,
            "missing_referenced_files": missing_files,
            "unreferenced_objects": unreferenced,
        }

    def release(self, digest: str) -> None:
        """Compatibility shim: tracked owner references cannot be released by digest."""
        digest = str(digest or "").strip().lower()
        self.reconcile_reference_counts()
        tracked = self.db.one(
            "SELECT COUNT(*) count FROM cas_references WHERE sha256=?",
            (digest,),
        )
        if tracked and int(tracked["count"]) > 0:
            return
        self.db.execute(
            "UPDATE object_store SET reference_count=0 WHERE sha256=?",
            (digest,),
        )

    def retention_candidates(self, *, cutoff: dt.datetime) -> list[dict[str, Any]]:
        self.reconcile_reference_counts()
        cutoff_utc = cutoff.astimezone(dt.timezone.utc)
        rows = self.db.all(
            "SELECT sha256,relative_path,size,content_type,reference_count,created_at,last_accessed "
            "FROM object_store WHERE reference_count<=0 ORDER BY last_accessed,sha256"
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            last_text = str(row["last_accessed"] or row["created_at"] or "")
            try:
                last_dt = dt.datetime.fromisoformat(last_text.replace("Z", "+00:00"))
            except ValueError:
                continue
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=dt.timezone.utc)
            if last_dt >= cutoff_utc:
                continue
            try:
                path = self._row_path(str(row["relative_path"]))
            except ValueError:
                continue
            result.append(
                {
                    "sha256": str(row["sha256"]),
                    "path": str(path),
                    "size": int(row["size"]),
                    "content_type": str(row["content_type"] or ""),
                    "reference_count": int(row["reference_count"]),
                    "last_accessed": last_text,
                    "exists": path.is_file(),
                }
            )
        return result

    def delete_if_unreferenced(
        self,
        digest: str,
        *,
        expected_path: str | Path | None = None,
        expected_last_accessed: str = "",
    ) -> dict[str, Any]:
        digest = str(digest or "").strip().lower()
        with _CAS_LOCK:
            self.reconcile_reference_counts()
            with self.db._lock:
                self.db.conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self.db.conn.execute(
                        "SELECT sha256,relative_path,size,content_type,reference_count,created_at,last_accessed "
                        "FROM object_store WHERE sha256=?",
                        (digest,),
                    ).fetchone()
                    if not row:
                        self.db.conn.execute("COMMIT")
                        return {"deleted": False, "reason": "missing_metadata", "bytes": 0}
                    refs = int(
                        self.db.conn.execute(
                            "SELECT COUNT(*) FROM cas_references WHERE sha256=?",
                            (digest,),
                        ).fetchone()[0]
                    )
                    if refs > 0 or int(row["reference_count"]) > 0:
                        self.db.conn.execute("COMMIT")
                        return {
                            "deleted": False,
                            "reason": "referenced",
                            "bytes": 0,
                            "reference_count": max(refs, int(row["reference_count"])),
                        }
                    if (
                        expected_last_accessed
                        and str(row["last_accessed"] or "") != expected_last_accessed
                    ):
                        self.db.conn.execute("COMMIT")
                        return {
                            "deleted": False,
                            "reason": "recently_accessed",
                            "bytes": 0,
                        }
                    path = self._row_path(str(row["relative_path"]))
                    if expected_path is not None and path != Path(expected_path).resolve():
                        self.db.conn.execute("COMMIT")
                        return {"deleted": False, "reason": "path_changed", "bytes": 0}
                    metadata = dict(row)
                    self.db.conn.execute(
                        "DELETE FROM object_store WHERE sha256=?",
                        (digest,),
                    )
                    self.db.conn.execute("COMMIT")
                except Exception:
                    self.db.conn.execute("ROLLBACK")
                    raise

            size = path.stat().st_size if path.exists() else 0
            try:
                path.unlink(missing_ok=True)
            except Exception:
                with self.db._lock:
                    self.db.conn.execute(
                        "INSERT OR IGNORE INTO object_store("
                        "sha256,relative_path,size,content_type,reference_count,created_at,last_accessed"
                        ") VALUES(?,?,?,?,0,?,?)",
                        (
                            metadata["sha256"],
                            metadata["relative_path"],
                            metadata["size"],
                            metadata["content_type"],
                            metadata["created_at"],
                            metadata["last_accessed"],
                        ),
                    )
                raise
            return {"deleted": True, "reason": "unreferenced", "bytes": int(size)}

    def gc(self, *, dry_run: bool = False) -> dict[str, Any]:
        self.reconcile_reference_counts()
        rows = self.db.all(
            "SELECT sha256,relative_path,size FROM object_store WHERE reference_count<=0"
        )
        removed = 0
        bytes_removed = 0
        skipped_referenced = 0
        for row in rows:
            if dry_run:
                removed += 1
                bytes_removed += int(row["size"])
                continue
            outcome = self.delete_if_unreferenced(str(row["sha256"]))
            if outcome.get("deleted"):
                removed += 1
                bytes_removed += int(outcome.get("bytes") or 0)
            elif outcome.get("reason") == "referenced":
                skipped_referenced += 1
        return {
            "dry_run": dry_run,
            "objects_removed": removed,
            "bytes_removed": bytes_removed,
            "skipped_referenced": skipped_referenced,
        }

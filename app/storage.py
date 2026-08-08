from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

from core import AppPaths, Database, atomic_write_bytes, sha256_bytes, utc_now


class ContentAddressedStore:
    def __init__(self, paths: AppPaths, db: Database):
        self.paths = paths
        self.db = db
        self.paths.objects.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        return self.paths.objects / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes, *, content_type: str = "application/octet-stream") -> tuple[str, Path, bool]:
        digest = sha256_bytes(data)
        path = self._path(digest)
        created = not path.exists()
        if created:
            atomic_write_bytes(path, data, 0o600)
        rel = str(path.relative_to(self.paths.state))
        now = utc_now()
        self.db.execute(
            "INSERT INTO object_store(sha256,relative_path,size,content_type,reference_count,created_at,last_accessed) "
            "VALUES(?,?,?,?,1,?,?) ON CONFLICT(sha256) DO UPDATE SET reference_count=object_store.reference_count+1,last_accessed=excluded.last_accessed",
            (digest, rel, len(data), content_type, now, now),
        )
        return digest, path, created

    def put_file(self, source: Path, *, content_type: str = "") -> tuple[str, Path, bool]:
        guessed = content_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        return self.put(source.read_bytes(), content_type=guessed)

    def get(self, digest: str) -> bytes:
        row = self.db.one("SELECT relative_path FROM object_store WHERE sha256=?", (digest,))
        if not row:
            raise FileNotFoundError(digest)
        path = self.paths.state / str(row["relative_path"])
        self.db.execute("UPDATE object_store SET last_accessed=? WHERE sha256=?", (utc_now(), digest))
        return path.read_bytes()

    def release(self, digest: str) -> None:
        self.db.execute("UPDATE object_store SET reference_count=MAX(0,reference_count-1) WHERE sha256=?", (digest,))

    def gc(self, *, dry_run: bool = False) -> dict[str, Any]:
        rows = self.db.all("SELECT sha256,relative_path,size FROM object_store WHERE reference_count<=0")
        removed = 0; bytes_removed = 0
        for row in rows:
            path = self.paths.state / str(row["relative_path"])
            if not dry_run:
                path.unlink(missing_ok=True)
                self.db.execute("DELETE FROM object_store WHERE sha256=?", (row["sha256"],))
            removed += 1; bytes_removed += int(row["size"])
        return {"dry_run": dry_run, "objects_removed": removed, "bytes_removed": bytes_removed}

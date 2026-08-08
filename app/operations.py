from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sqlite3
import statistics
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any, Iterable

from core import APP_VERSION, AppPaths, Config, Database, Logger, ReconError, atomic_write_text, json_dumps, normalize_url, safe_json_loads, sha256_bytes, utc_now
from storage import ContentAddressedStore


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class BackupManager:
    def __init__(self, paths: AppPaths, db: Database, logger: Logger):
        self.paths = paths; self.db = db; self.logger = logger

    def create(self, *, include_objects: bool = False) -> dict[str, Any]:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_id = f"backup-{stamp}-{uuid.uuid4().hex[:6]}"
        archive = self.paths.backups / f"{backup_id}.tar.gz"
        manifest: dict[str, Any] = {"backup_id": backup_id, "created_at": utc_now(), "version": APP_VERSION, "files": {}}
        self.paths.backups.mkdir(parents=True, exist_ok=True)
        # Use SQLite online backup for a consistent database snapshot.
        snapshot = self.paths.backups / f".{backup_id}.db"
        source = sqlite3.connect(self.paths.db)
        destination = sqlite3.connect(snapshot)
        try:
            source.backup(destination)
        finally:
            source.close(); destination.close()
        try:
            with tarfile.open(archive, "w:gz") as tar:
                candidates = [self.paths.config, self.paths.policy, snapshot, self.paths.root / "targets.txt"]
                for path in candidates:
                    if not path.exists(): continue
                    arcname = "state/recon-v2.db" if path == snapshot else str(path.relative_to(self.paths.root))
                    tar.add(path, arcname=arcname)
                    manifest["files"][arcname] = {"sha256": sha256_file(path), "size": path.stat().st_size}
                for directory in (self.paths.reports, self.paths.state / "sessions"):
                    if directory.exists(): tar.add(directory, arcname=str(directory.relative_to(self.paths.root)))
                if include_objects and self.paths.objects.exists(): tar.add(self.paths.objects, arcname=str(self.paths.objects.relative_to(self.paths.root)))
                data = (json_dumps(manifest, pretty=True) + "\n").encode()
                info = tarfile.TarInfo("BACKUP-MANIFEST.json"); info.size=len(data); info.mtime=time.time()
                tar.addfile(info, __import__('io').BytesIO(data))
        finally:
            snapshot.unlink(missing_ok=True)
        digest=sha256_file(archive)
        self.db.execute("INSERT INTO backup_catalog(backup_id,path,sha256,size,created_at,metadata_json) VALUES(?,?,?,?,?,?)", (backup_id,str(archive),digest,archive.stat().st_size,manifest["created_at"],json_dumps(manifest)))
        self.db.audit("backup_created", entity_type="backup", entity_value=backup_id, details={"path":str(archive),"sha256":digest})
        self.logger.info("Backup created", backup_id=backup_id, archive=str(archive))
        return {"backup_id":backup_id,"path":str(archive),"sha256":digest,"size":archive.stat().st_size}

    def list(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.all("SELECT * FROM backup_catalog ORDER BY created_at DESC")]

    def _resolve_backup(self, backup_id: str) -> sqlite3.Row:
        if backup_id == "latest":
            row = self.db.one("SELECT * FROM backup_catalog ORDER BY created_at DESC LIMIT 1")
        else:
            row = self.db.one("SELECT * FROM backup_catalog WHERE backup_id=?", (backup_id,))
        if not row:
            raise ReconError(f"Backup not found: {backup_id}")
        return row

    @staticmethod
    def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
        members = tar.getmembers()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ReconError(f"Unsafe backup member: {member.name}")
            if member.issym() or member.islnk():
                raise ReconError(f"Backup links are not allowed: {member.name}")
        return members

    @staticmethod
    def _extract_members(tar: tarfile.TarFile, destination: Path, members: Iterable[tarfile.TarInfo]) -> None:
        destination = destination.resolve()
        for member in members:
            output = (destination / member.name).resolve()
            if output != destination and destination not in output.parents:
                raise ReconError(f"Unsafe backup extraction path: {member.name}")
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ReconError(f"Could not read backup member: {member.name}")
            with source, output.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            try:
                output.chmod(member.mode & 0o777)
            except OSError:
                pass

    def verify(self, backup_id: str) -> dict[str, Any]:
        row = self._resolve_backup(backup_id)
        resolved_id = str(row["backup_id"])
        path = Path(str(row["path"]))
        actual = sha256_file(path) if path.exists() else ""
        checks: dict[str, Any] = {
            "archive_exists": path.exists(),
            "archive_checksum": bool(actual and actual == str(row["sha256"])),
            "manifest": False,
            "member_hashes": False,
            "database_present": False,
            "database_integrity": False,
            "database_foreign_keys": False,
        }
        errors: list[str] = []
        if not checks["archive_checksum"]:
            errors.append("archive checksum mismatch or archive missing")
        else:
            try:
                with tempfile.TemporaryDirectory(prefix="recon-backup-verify-") as temp:
                    root = Path(temp)
                    with tarfile.open(path, "r:gz") as tar:
                        members = self._safe_members(tar)
                        names = {member.name for member in members}
                        checks["manifest"] = "BACKUP-MANIFEST.json" in names
                        checks["database_present"] = "state/recon-v2.db" in names
                        if not checks["manifest"]:
                            errors.append("backup manifest missing")
                        if not checks["database_present"]:
                            errors.append("database snapshot missing")
                        self._extract_members(tar, root, members)
                    manifest_path = root / "BACKUP-MANIFEST.json"
                    manifest = safe_json_loads(manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else "", {}, expected_type=dict)
                    declared_files = manifest.get("files", {}) if isinstance(manifest, dict) else {}
                    hash_ok = bool(declared_files)
                    if isinstance(declared_files, dict):
                        for rel, metadata in declared_files.items():
                            candidate = root / str(rel)
                            expected = str(metadata.get("sha256") or "") if isinstance(metadata, dict) else ""
                            if not candidate.is_file() or not expected or sha256_file(candidate) != expected:
                                hash_ok = False
                                errors.append(f"manifest hash mismatch: {rel}")
                                break
                    checks["member_hashes"] = hash_ok
                    database = root / "state" / "recon-v2.db"
                    if database.is_file():
                        conn = sqlite3.connect(database)
                        try:
                            integrity = conn.execute("PRAGMA integrity_check").fetchone()
                            checks["database_integrity"] = bool(integrity and str(integrity[0]) == "ok")
                            violations = list(conn.execute("PRAGMA foreign_key_check"))
                            checks["database_foreign_keys"] = not violations
                            if not checks["database_integrity"]:
                                errors.append("database integrity check failed")
                            if violations:
                                errors.append(f"database foreign-key violations: {len(violations)}")
                        finally:
                            conn.close()
            except (OSError, tarfile.TarError, sqlite3.Error, ReconError) as exc:
                errors.append(str(exc))
        ok = all(checks.values())
        if ok:
            self.db.execute("UPDATE backup_catalog SET verified_at=? WHERE backup_id=?", (utc_now(), resolved_id))
        return {
            "backup_id": resolved_id,
            "ok": ok,
            "checks": checks,
            "errors": errors,
            "expected": str(row["sha256"]),
            "actual": actual,
            "path": str(path),
        }

    def drill(self, backup_id: str = "latest") -> dict[str, Any]:
        verification = self.verify(backup_id)
        if not verification["ok"]:
            raise ReconError("Backup verification failed; restore drill was not started")
        path = Path(str(verification["path"]))
        with tempfile.TemporaryDirectory(prefix="recon-backup-drill-") as temp:
            root = Path(temp)
            with tarfile.open(path, "r:gz") as tar:
                members = self._safe_members(tar)
                self._extract_members(tar, root, members)
            database = root / "state" / "recon-v2.db"
            conn = sqlite3.connect(database)
            try:
                schema = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
                tables = int(conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0])
                runs = int(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0])
                alerts = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            finally:
                conn.close()
        self.db.audit("backup_restore_drill", entity_type="backup", entity_value=str(verification["backup_id"]), details={"schema_version":str(schema[0]) if schema else "unknown", "tables":tables, "runs":runs, "alerts":alerts})
        return {
            "backup_id": verification["backup_id"],
            "ok": True,
            "schema_version": str(schema[0]) if schema else "unknown",
            "tables": tables,
            "runs": runs,
            "alerts": alerts,
            "message": "Backup was extracted and opened in an isolated temporary directory.",
        }

    def restore(self, backup_id: str, *, force: bool = False) -> dict[str, Any]:
        verification = self.verify(backup_id)
        if not verification["ok"]:
            raise ReconError("Backup verification failed")
        if not force:
            raise ReconError("Restore requires --force")
        safety = self.create(include_objects=False)
        resolved_id = str(verification["backup_id"])
        path = Path(str(verification["path"]))
        with tempfile.TemporaryDirectory(prefix="recon-restore-") as temp:
            root = Path(temp)
            with tarfile.open(path, "r:gz") as tar:
                members = self._safe_members(tar)
                self._extract_members(tar, root, members)
            restored_database = root / "state" / "recon-v2.db"
            if not restored_database.is_file():
                raise ReconError("Verified backup did not contain a database snapshot")
            # Close the live SQLite handle before replacing the database file.
            # Copying over a WAL-backed database while a connection remains open
            # can leave the process attached to the old inode.
            try:
                self.db.audit("backup_restore_started", entity_type="backup", entity_value=resolved_id, details={"safety_backup":safety["backup_id"]})
            finally:
                self.db.close()
            for suffix in ("-wal", "-shm"):
                Path(str(self.paths.db) + suffix).unlink(missing_ok=True)
            for rel in ("config.env", "policies/targets.json", "targets.txt"):
                src = root / rel
                if src.exists():
                    dst = self.paths.root / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            self.paths.db.parent.mkdir(parents=True, exist_ok=True)
            temporary_db = self.paths.db.with_name(f".{self.paths.db.name}.restore-{uuid.uuid4().hex}.tmp")
            shutil.copy2(restored_database, temporary_db)
            os.replace(temporary_db, self.paths.db)
        restored = Database(self.paths.db)
        try:
            integrity = restored.integrity()
            foreign_keys = restored.foreign_key_violations()
            if integrity != "ok" or foreign_keys:
                raise ReconError(f"Restored database validation failed: integrity={integrity}, foreign_keys={len(foreign_keys)}")
            # The database snapshot is taken before a newly-created backup is
            # catalogued. Re-register both the source and safety archives so a
            # later recovery remains discoverable from the restored database.
            for record in (
                {"backup_id": resolved_id, "path": str(path), "sha256": str(verification["actual"]), "size": path.stat().st_size},
                safety,
            ):
                restored.execute(
                    "INSERT OR IGNORE INTO backup_catalog(backup_id,path,sha256,size,created_at,metadata_json) VALUES(?,?,?,?,?,?)",
                    (record["backup_id"], record["path"], record["sha256"], int(record["size"]), utc_now(), json_dumps({"recovered_catalog_entry": True})),
                )
            restored.audit("backup_restored", entity_type="backup", entity_value=resolved_id, details={"safety_backup":safety["backup_id"]})
        finally:
            restored.close()
        return {"restored": resolved_id, "safety_backup": safety["backup_id"], "integrity": "ok", "foreign_key_violations": 0}


def benchmark(paths: AppPaths, db: Database) -> dict[str, Any]:
    results: dict[str, Any] = {"version":APP_VERSION,"generated_at":utc_now()}
    samples=[f"https://Example.COM:443/a//b?utm_source=x&id={i%50}&z={i}" for i in range(10000)]
    started=time.perf_counter(); normalized=[normalize_url(x) for x in samples]; results["url_normalization_10000_seconds"]=round(time.perf_counter()-started,4)
    started=time.perf_counter()
    with db.transaction():
        for i in range(5000):
            db.execute("INSERT OR REPLACE INTO schema_meta(key,value) VALUES(?,?)",(f"bench_{i}",str(i)))
    results["sqlite_writes_5000_seconds"]=round(time.perf_counter()-started,4)
    db.execute("DELETE FROM schema_meta WHERE key LIKE 'bench_%'")
    payload=("const api='/api/v1/users';\n"*10000).encode()
    store=ContentAddressedStore(paths,db); started=time.perf_counter(); digest,path,created=store.put(payload,content_type="application/javascript")
    results["cas_write_seconds"]=round(time.perf_counter()-started,4); results["cas_digest"]=digest; results["cas_created"]=created
    started=time.perf_counter(); db.all("SELECT host,confidence FROM assets ORDER BY confidence DESC,last_seen DESC LIMIT 1000")
    results["search_query_seconds"]=round(time.perf_counter()-started,6)
    return results


class UpdateManager:
    """Checksum-verified updater with private GitHub Release support and rollback.

    Update sources, in priority order:
    1. RECON_UPDATE_MANIFEST when explicitly configured (legacy/trusted manifest mode).
    2. An authenticated GitHub repository, using the ``gh`` CLI.

    The GitHub path is intentionally delegated to ``gh`` so private-repository
    credentials remain in the user's GitHub CLI/keychain instead of Recon
    Monitor configuration files.
    """

    DEFAULT_UPDATE_REPO = "alirezasafariii/recon-monitor"

    def __init__(self, paths: AppPaths, config: Config, db: Database, logger: Logger):
        self.paths = paths
        self.config = config
        self.db = db
        self.logger = logger

    @staticmethod
    def _version_key(value: Any) -> tuple[int, int, int] | None:
        match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", str(value or "").strip())
        return tuple(int(part) for part in match.groups()) if match else None

    @classmethod
    def _is_newer(cls, available: Any, current: Any = APP_VERSION) -> bool:
        available_key = cls._version_key(available)
        current_key = cls._version_key(current)
        if available_key is not None and current_key is not None:
            return available_key > current_key
        return bool(available) and str(available).lstrip("v") != str(current).lstrip("v")

    def _repo(self, override: str = "") -> str:
        return (override or self.config.get("RECON_UPDATE_REPO", "") or self.DEFAULT_UPDATE_REPO).strip()

    def _manifest_check(self, source: str) -> dict[str, Any]:
        if source.startswith("https://"):
            with urllib.request.urlopen(source, timeout=10) as response:
                data = json.load(response)
        elif source.startswith("file://"):
            data = json.loads(Path(source[7:]).read_text(encoding="utf-8"))
        else:
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        available = str(data.get("version") or "").lstrip("v")
        return {
            "configured": True,
            "source": "manifest",
            "current": APP_VERSION,
            "available": available,
            "update_available": self._is_newer(available),
            "manifest": data,
        }

    def _github_release(self, repo: str) -> dict[str, Any]:
        gh = shutil.which("gh")
        if not gh:
            raise ReconError("GitHub CLI (gh) is required for private GitHub updates. Install it with: brew install gh")
        command = [gh, "release", "view", "--repo", repo, "--json", "tagName,name,publishedAt,url,assets"]
        result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            hint = " Run 'gh auth login' first." if "auth" in detail.lower() or "login" in detail.lower() else ""
            raise ReconError(f"Could not read latest GitHub Release from {repo}: {detail or 'gh release view failed'}.{hint}")
        data = safe_json_loads(result.stdout, {}, expected_type=dict)
        if not data:
            raise ReconError(f"GitHub returned an empty release response for {repo}")
        return data

    def check(self, repo: str = "") -> dict[str, Any]:
        manifest_source = self.config.get("RECON_UPDATE_MANIFEST", "").strip()
        if manifest_source:
            return self._manifest_check(manifest_source)
        repository = self._repo(repo)
        try:
            release = self._github_release(repository)
        except ReconError as exc:
            return {
                "configured": True,
                "source": "github",
                "repo": repository,
                "current": APP_VERSION,
                "reachable": False,
                "update_available": False,
                "message": str(exc),
            }
        tag = str(release.get("tagName") or "")
        available = tag.lstrip("v")
        assets = release.get("assets") if isinstance(release.get("assets"), list) else []
        asset_names = [str(item.get("name")) for item in assets if isinstance(item, dict) and item.get("name")]
        return {
            "configured": True,
            "source": "github",
            "repo": repository,
            "reachable": True,
            "current": APP_VERSION,
            "available": available,
            "tag": tag,
            "update_available": self._is_newer(available),
            "release_name": release.get("name"),
            "published_at": release.get("publishedAt"),
            "release_url": release.get("url"),
            "assets": asset_names,
        }

    @staticmethod
    def _expected_release_assets(version: str) -> tuple[str, str]:
        clean = str(version).lstrip("v")
        return f"recon-monitor-v{clean}.zip", f"recon-monitor-v{clean}.zip.sha256"

    def install_latest(self, repo: str = "", *, force: bool = False) -> dict[str, Any]:
        status = self.check(repo)
        if not status.get("reachable", status.get("source") == "manifest"):
            raise ReconError(str(status.get("message") or "Update source is not reachable"))
        if status.get("source") != "github":
            manifest = status.get("manifest") if isinstance(status.get("manifest"), dict) else {}
            url = str(manifest.get("url") or "")
            expected = str(manifest.get("sha256") or "")
            if not url:
                raise ReconError("Configured update manifest is missing url")
            if not status.get("update_available") and not force:
                return {"updated": False, "reason": "already-current", **status}
            with tempfile.TemporaryDirectory(prefix="recon-update-download-") as temp:
                target = Path(temp) / Path(urllib.parse.urlparse(url).path).name
                if url.startswith("https://"):
                    urllib.request.urlretrieve(url, target)
                elif url.startswith("file://"):
                    shutil.copy2(Path(url[7:]), target)
                else:
                    shutil.copy2(Path(url), target)
                result = self.install(target, expected)
                result.update({"source": "manifest", "target_version": status.get("available")})
                return result

        if not status.get("update_available") and not force:
            return {"updated": False, "reason": "already-current", **status}
        repository = str(status["repo"])
        tag = str(status.get("tag") or f"v{status.get('available')}")
        version = str(status.get("available") or "")
        zip_name, sha_name = self._expected_release_assets(version)
        assets = set(str(item) for item in status.get("assets", []))
        missing = [name for name in (zip_name, sha_name) if name not in assets]
        if missing:
            raise ReconError(f"Release {tag} is missing required asset(s): {', '.join(missing)}")
        gh = shutil.which("gh")
        if not gh:
            raise ReconError("GitHub CLI (gh) is required for private GitHub updates")
        with tempfile.TemporaryDirectory(prefix="recon-github-update-") as temp:
            download = subprocess.run(
                [gh, "release", "download", tag, "--repo", repository, "--dir", temp, "--pattern", zip_name, "--pattern", sha_name],
                text=True, capture_output=True, timeout=120, check=False,
            )
            if download.returncode != 0:
                raise ReconError(f"GitHub Release download failed: {(download.stderr or download.stdout).strip()}")
            package = Path(temp) / zip_name
            checksum_file = Path(temp) / sha_name
            if not package.is_file() or not checksum_file.is_file():
                raise ReconError("GitHub Release download completed without the expected ZIP/checksum pair")
            fields = checksum_file.read_text(encoding="utf-8", errors="replace").strip().split()
            if not fields or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
                raise ReconError("Release checksum file is malformed")
            expected = fields[0].lower()
            result = self.install(package, expected)
            result.update({
                "updated": True,
                "source": "github",
                "repo": repository,
                "release": tag,
                "target_version": version,
                "dashboard_restart_required": True,
            })
            return result

    @staticmethod
    def _program_items(root: Path) -> tuple[str, ...]:
        fixed = [
            "app", "docs", "tests", "fixtures", "plugins",
            "recon-monitor.sh", "install.sh", "upgrade-v2.sh", "upgrade-v3.sh",
            "README.md", "README_FA.md", "CHANGELOG.md", "MANIFEST.sha256",
            "config.env.example", "tool-compatibility.json",
            "release-public-key.pem", "release-public-key.sha256",
        ]
        migrations = sorted(path.name for path in root.glob("MIGRATION-*.md") if path.is_file())
        return tuple(dict.fromkeys([*fixed, *migrations]))

    @staticmethod
    def _validate_zip_members(zf: zipfile.ZipFile, destination: Path) -> None:
        destination = destination.resolve()
        for member in zf.infolist():
            member_path = Path(member.filename)
            output = (destination / member.filename).resolve()
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ReconError(f"Unsafe release package path: {member.filename}")
            if destination != output and destination not in output.parents:
                raise ReconError(f"Unsafe release package path: {member.filename}")
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ReconError(f"Release package symlinks are not allowed: {member.filename}")

    @staticmethod
    def _package_version(source: Path) -> str:
        core = source / "app" / "core.py"
        if not core.is_file():
            raise ReconError("Invalid release package: app/core.py is missing")
        match = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', core.read_text(encoding="utf-8"), re.MULTILINE)
        if not match:
            raise ReconError("Invalid release package: APP_VERSION was not found")
        return match.group(1)

    def install(self, package: Path, expected_sha256: str = "", signature: Path | None = None, public_key: Path | None = None) -> dict[str, Any]:
        if not package.exists():
            raise ReconError(f"Package not found: {package}")
        actual = sha256_file(package)
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise ReconError("Package checksum mismatch")
        signature_verified = False
        if signature or public_key:
            if not signature or not public_key:
                raise ReconError("Both signature and public key are required")
            if not signature.exists() or not public_key.exists():
                raise ReconError("Release signature or public key not found")
            openssl = shutil.which("openssl")
            if not openssl:
                raise ReconError("OpenSSL is required for release-signature verification")
            verification = subprocess.run(
                [openssl, "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(package)],
                text=True, capture_output=True, check=False,
            )
            if verification.returncode != 0:
                raise ReconError("Release signature verification failed")
            signature_verified = True

        backup = BackupManager(self.paths, self.db, self.logger).create()
        release_backup = self.paths.releases / f"program-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
        current_items = self._program_items(self.paths.root)
        with tarfile.open(release_backup, "w:gz") as tar:
            for item in current_items:
                path = self.paths.root / item
                if path.exists():
                    tar.add(path, arcname=item)

        target_version = ""
        with tempfile.TemporaryDirectory(prefix="recon-update-") as temp:
            temp_root = Path(temp).resolve()
            try:
                with zipfile.ZipFile(package) as zf:
                    self._validate_zip_members(zf, temp_root)
                    zf.extractall(temp_root)
            except zipfile.BadZipFile as exc:
                raise ReconError("Release package is not a valid ZIP archive") from exc
            candidates = [p for p in Path(temp).iterdir() if p.is_dir()]
            source = candidates[0] if len(candidates) == 1 else Path(temp)
            target_version = self._package_version(source)
            if self._version_key(target_version) is None:
                raise ReconError(f"Invalid release version: {target_version}")
            program_items = self._program_items(source)
            for item in program_items:
                src = source / item
                if not src.exists():
                    continue
                dst = self.paths.root / item
                if item == "plugins" and dst.exists():
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                    continue
                if dst.is_dir():
                    shutil.rmtree(dst)
                elif dst.exists():
                    dst.unlink()
                if src.is_dir():
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)

        for rel in ("recon-monitor.sh", "install.sh", "upgrade-v2.sh", "upgrade-v3.sh", "app/recon_monitor.py"):
            executable = self.paths.root / rel
            if executable.exists():
                executable.chmod(executable.stat().st_mode | 0o111)

        try:
            checks = (
                [str(self.paths.root / "recon-monitor.sh"), "init", "--no-wizard"],
                [sys.executable, "-m", "compileall", "-q", str(self.paths.app), str(self.paths.root / "tests")],
                [str(self.paths.root / "recon-monitor.sh"), "test"],
                [str(self.paths.root / "recon-monitor.sh"), "test", "--integration"],
            )
            for command in checks:
                result = subprocess.run(command, cwd=self.paths.root, text=True, capture_output=True, timeout=240, check=False)
                if result.returncode != 0:
                    output = (result.stderr or result.stdout)[-3000:]
                    raise ReconError(f"Post-update validation failed: {' '.join(command)}\n{output}")
        except Exception as exc:
            with tarfile.open(release_backup, "r:gz") as tar:
                self._safe_tar_restore(tar, self.paths.root)
            try:
                self.db.close()
            except Exception:
                pass
            backup_archive = Path(str(backup["path"]))
            with tempfile.TemporaryDirectory(prefix="recon-update-rollback-") as temp:
                with tarfile.open(backup_archive, "r:gz") as tar:
                    members = BackupManager._safe_members(tar)
                    BackupManager._extract_members(tar, Path(temp), members)
                shutil.copy2(Path(temp) / "state/recon-v2.db", self.paths.db)
            raise ReconError(f"Update rolled back after validation failure: {exc}") from exc

        self.db.audit(
            "update_installed",
            entity_type="release",
            entity_value=actual,
            details={
                "from_version": APP_VERSION,
                "to_version": target_version,
                "program_backup": str(release_backup),
                "data_backup": backup["backup_id"],
                "signature_verified": signature_verified,
            },
        )
        atomic_write_text(self.paths.releases / "last-program-backup.txt", str(release_backup) + "\n")
        return {
            "installed": str(package),
            "from_version": APP_VERSION,
            "to_version": target_version,
            "sha256": actual,
            "signature_verified": signature_verified,
            "validation": "passed",
            "program_backup": str(release_backup),
            "data_backup": backup["backup_id"],
        }

    @staticmethod
    def _safe_tar_restore(tar: tarfile.TarFile, destination: Path) -> None:
        members = BackupManager._safe_members(tar)
        BackupManager._extract_members(tar, destination, members)

    def rollback(self) -> dict[str, Any]:
        marker = self.paths.releases / "last-program-backup.txt"
        if not marker.exists():
            raise ReconError("No program rollback is available")
        archive = Path(marker.read_text(encoding="utf-8").strip())
        if not archive.exists():
            raise ReconError("Rollback archive is missing")
        with tarfile.open(archive, "r:gz") as tar:
            self._safe_tar_restore(tar, self.paths.root)
        self.db.audit("update_rolled_back", entity_type="release", entity_value=str(archive))
        return {"rolled_back": str(archive), "dashboard_restart_required": True}


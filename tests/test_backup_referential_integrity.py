from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database, ReconError, utc_now
from operations import BackupManager, sha256_file
from storage import ContentAddressedStore


class LoggerStub:
    def info(self, *args, **kwargs):
        pass

    warn = info
    error = info


class BackupReferentialIntegrityTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        paths = AppPaths.from_root(root)
        paths.ensure()
        paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n',
            encoding="utf-8",
        )
        paths.policy.write_text(
            json.dumps(
                {
                    "defaults": {},
                    "targets": [
                        {
                            "name": "example.com",
                            "roots": ["example.com"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return temp, paths, Database(paths.db)

    def test_default_backup_includes_referenced_cas_object(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, object_path, _ = store.put(
                b"const backup = true;",
                content_type="application/javascript",
            )
            store.set_reference(
                "fixture",
                "example.com/app.js",
                digest,
            )

            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()
            self.assertTrue(created["referential_integrity"])
            self.assertEqual(created["referenced_artifacts"], 1)

            rel = object_path.relative_to(paths.root).as_posix()
            with tarfile.open(Path(created["path"]), "r:gz") as tar:
                names = {member.name for member in tar.getmembers()}
                self.assertIn(rel, names)
                manifest_file = tar.extractfile("BACKUP-MANIFEST.json")
                self.assertIsNotNone(manifest_file)
                manifest = json.loads(manifest_file.read().decode("utf-8"))
                self.assertEqual(
                    manifest["objects_mode"],
                    "referenced_only",
                )
                self.assertIn(
                    rel,
                    manifest["referential_integrity"]["required_files"],
                )
                self.assertEqual(
                    manifest["referential_integrity"]["required_files"][rel][
                        "sha256"
                    ],
                    digest,
                )

            verified = manager.verify(created["backup_id"])
            self.assertTrue(verified["ok"], verified)
            self.assertTrue(
                verified["checks"]["referential_integrity"]
            )
            self.assertEqual(
                verified["referential_integrity"]["recoverable_count"],
                1,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_backup_creation_fails_closed_when_referenced_object_is_missing(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, object_path, _ = store.put(b"missing")
            store.set_reference("fixture", "missing-owner", digest)
            object_path.unlink()

            manager = BackupManager(paths, db, LoggerStub())
            with self.assertRaisesRegex(
                ReconError,
                "referential-integrity preflight failed",
            ):
                manager.create()
            self.assertEqual(
                int(
                    db.one(
                        "SELECT COUNT(*) count FROM backup_catalog"
                    )["count"]
                ),
                0,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_verify_rejects_archive_missing_referenced_object(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, object_path, _ = store.put(b"tamper-me")
            store.set_reference("fixture", "tamper-owner", digest)
            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()
            archive = Path(created["path"])
            rel = object_path.relative_to(paths.root).as_posix()

            with tempfile.TemporaryDirectory() as unpacked_name:
                unpacked = Path(unpacked_name)
                with tarfile.open(archive, "r:gz") as tar:
                    tar.extractall(unpacked)
                (unpacked / rel).unlink()
                rebuilt = archive.with_name(archive.stem + "-tampered.tar.gz")
                with tarfile.open(rebuilt, "w:gz") as tar:
                    for candidate in sorted(unpacked.rglob("*")):
                        tar.add(
                            candidate,
                            arcname=candidate.relative_to(unpacked).as_posix(),
                            recursive=False,
                        )
                rebuilt.replace(archive)

            db.execute(
                "UPDATE backup_catalog SET sha256=?,size=? WHERE backup_id=?",
                (
                    sha256_file(archive),
                    archive.stat().st_size,
                    created["backup_id"],
                ),
            )
            verified = manager.verify(created["backup_id"])
            self.assertFalse(verified["ok"])
            self.assertFalse(
                verified["checks"]["referential_integrity"]
            )
            self.assertTrue(
                any(
                    "referenced artifact missing from backup" in error
                    for error in verified["errors"]
                ),
                verified,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_restore_recovers_referenced_cas_artifact(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, object_path, _ = store.put(
                b"restore-cas-fixture"
            )
            store.set_reference("fixture", "restore-owner", digest)
            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()

            store.drop_reference("fixture", "restore-owner")
            object_path.unlink()
            self.assertFalse(object_path.exists())

            restored = manager.restore(
                created["backup_id"],
                force=True,
            )
            self.assertTrue(restored["referential_integrity"])
            self.assertGreaterEqual(
                restored["referenced_artifacts"],
                1,
            )
            self.assertTrue(object_path.exists())
            self.assertEqual(
                hashlib.sha256(object_path.read_bytes()).hexdigest(),
                digest,
            )

            reopened = Database(paths.db)
            try:
                verified = BackupManager(
                    paths,
                    reopened,
                    LoggerStub(),
                ).verify(created["backup_id"])
                self.assertTrue(verified["ok"], verified)
                row = reopened.one(
                    "SELECT COUNT(*) count FROM cas_references "
                    "WHERE sha256=?",
                    (digest,),
                )
                self.assertGreaterEqual(int(row["count"]), 1)
            finally:
                reopened.close()
        finally:
            try:
                db.close()
            except Exception:
                pass
            temp.cleanup()

    def test_legacy_js_blob_reference_is_included_and_verified(self):
        temp, paths, db = self.project()
        try:
            legacy = paths.blobs / "js" / "legacy.js"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text(
                "console.log('legacy');",
                encoding="utf-8",
            )
            now = utc_now()
            db.execute(
                "INSERT INTO js_files("
                "target,url,raw_hash,semantic_hash,blob_path,content_length,"
                "first_seen,last_seen,last_run_id"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "example.com",
                    "https://example.com/legacy.js",
                    "raw",
                    "semantic",
                    str(legacy),
                    legacy.stat().st_size,
                    now,
                    now,
                    "RUN-LEGACY",
                ),
            )

            manager = BackupManager(paths, db, LoggerStub())
            created = manager.create()
            rel = legacy.relative_to(paths.root).as_posix()
            with tarfile.open(Path(created["path"]), "r:gz") as tar:
                self.assertIn(
                    rel,
                    {member.name for member in tar.getmembers()},
                )
            verified = manager.verify(created["backup_id"])
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(
                verified["referential_integrity"]["required_count"],
                1,
            )
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

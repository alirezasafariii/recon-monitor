from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database, utc_now
from platform_v6 import apply_retention, retention_preview
from storage import ContentAddressedStore


OLD = "2000-01-01T00:00:00Z"


class CasRetentionIntegrityTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        return temp, paths, db

    def test_put_deduplicates_without_reference_leak(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, path, created = store.put(b"abc")
            digest2, path2, created2 = store.put(b"abc")
            self.assertEqual(digest, digest2)
            self.assertEqual(path, path2)
            self.assertTrue(created)
            self.assertFalse(created2)
            self.assertEqual(
                int(
                    db.one(
                        "SELECT reference_count FROM object_store WHERE sha256=?",
                        (digest,),
                    )["reference_count"]
                ),
                0,
            )

            owner = "example.com\nhttps://example.com/app.js"
            store.set_reference("js_file", owner, digest)
            store.set_reference("js_file", owner, digest)
            self.assertEqual(
                int(
                    db.one(
                        "SELECT reference_count FROM object_store WHERE sha256=?",
                        (digest,),
                    )["reference_count"]
                ),
                1,
            )

            newer, _, _ = store.put(b"def")
            store.set_reference("js_file", owner, newer)
            self.assertEqual(
                int(
                    db.one(
                        "SELECT reference_count FROM object_store WHERE sha256=?",
                        (digest,),
                    )["reference_count"]
                ),
                0,
            )
            self.assertEqual(
                int(
                    db.one(
                        "SELECT reference_count FROM object_store WHERE sha256=?",
                        (newer,),
                    )["reference_count"]
                ),
                1,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_reconcile_seeds_current_js_and_protects_unknown_legacy_objects(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            js_digest, js_path, _ = store.put(b"current-js")
            unknown_digest, _, _ = store.put(b"legacy-map")
            db.execute(
                "UPDATE object_store SET reference_count=7 WHERE sha256 IN (?,?)",
                (js_digest, unknown_digest),
            )
            now = utc_now()
            db.execute(
                "INSERT INTO js_files("
                "target,url,raw_hash,semantic_hash,blob_path,content_length,"
                "first_seen,last_seen,last_run_id"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "example.com",
                    "https://example.com/app.js",
                    js_digest,
                    js_digest,
                    str(js_path),
                    js_path.stat().st_size,
                    now,
                    now,
                    "RUN-LEGACY",
                ),
            )

            result = store.reconcile_reference_counts()
            self.assertEqual(result["missing_referenced_files"], 0)
            self.assertEqual(
                db.one(
                    "SELECT owner_kind FROM cas_references WHERE sha256=?",
                    (js_digest,),
                )["owner_kind"],
                "js_file",
            )
            self.assertEqual(
                db.one(
                    "SELECT owner_kind FROM cas_references WHERE sha256=?",
                    (unknown_digest,),
                )["owner_kind"],
                "legacy_unclassified",
            )
            self.assertEqual(
                int(
                    db.one(
                        "SELECT reference_count FROM object_store WHERE sha256=?",
                        (unknown_digest,),
                    )["reference_count"]
                ),
                1,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_retention_deletes_only_old_unreferenced_cas_objects(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            stale_digest, stale_path, _ = store.put(b"stale")
            live_digest, live_path, _ = store.put(b"live")
            store.set_reference("js_file", "example.com\n/app.js", live_digest)
            db.execute(
                "UPDATE object_store SET last_accessed=? WHERE sha256 IN (?,?)",
                (OLD, stale_digest, live_digest),
            )

            preview = retention_preview(paths, db, persist=True)
            cas = [
                item
                for item in preview["candidates"]
                if item.get("storage_kind") == "cas_object"
            ]
            self.assertIn(stale_digest, {item["sha256"] for item in cas})
            self.assertNotIn(live_digest, {item["sha256"] for item in cas})

            result = apply_retention(
                paths,
                db,
                preview["preview_id"],
                actor="test",
                confirmation=f"DELETE_RETENTION_PREVIEW_{preview['preview_id']}",
            )
            self.assertEqual(result["errors"], [])
            self.assertFalse(stale_path.exists())
            self.assertIsNone(
                db.one(
                    "SELECT 1 FROM object_store WHERE sha256=?",
                    (stale_digest,),
                )
            )
            self.assertTrue(live_path.exists())
            self.assertIsNotNone(
                db.one(
                    "SELECT 1 FROM object_store WHERE sha256=?",
                    (live_digest,),
                )
            )
        finally:
            db.close()
            temp.cleanup()

    def test_legacy_blob_path_referenced_by_js_files_is_protected(self):
        temp, paths, db = self.project()
        try:
            legacy_dir = paths.blobs / "js"
            legacy_dir.mkdir(parents=True, exist_ok=True)
            legacy = legacy_dir / "legacy.js"
            legacy.write_text("console.log('legacy')", encoding="utf-8")
            os.utime(legacy, (946684800, 946684800))
            now = utc_now()
            db.execute(
                "INSERT INTO js_files("
                "target,url,raw_hash,semantic_hash,blob_path,content_length,"
                "first_seen,last_seen,last_run_id"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "example.com",
                    "https://example.com/legacy.js",
                    "legacy-raw",
                    "legacy-sem",
                    str(legacy),
                    legacy.stat().st_size,
                    now,
                    now,
                    "RUN-LEGACY",
                ),
            )

            preview = retention_preview(paths, db, persist=True)
            matching = [
                item
                for item in preview["candidates"]
                if Path(str(item.get("path") or "")).resolve() == legacy.resolve()
            ]
            self.assertEqual(len(matching), 1)
            self.assertTrue(matching[0]["protected"])

            result = apply_retention(
                paths,
                db,
                preview["preview_id"],
                actor="test",
                confirmation=f"DELETE_RETENTION_PREVIEW_{preview['preview_id']}",
            )
            self.assertTrue(legacy.exists())
            self.assertEqual(result["errors"], [])
        finally:
            db.close()
            temp.cleanup()

    def test_retention_revalidates_reference_added_after_preview(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, path, _ = store.put(b"race")
            db.execute(
                "UPDATE object_store SET last_accessed=? WHERE sha256=?",
                (OLD, digest),
            )
            preview = retention_preview(paths, db, persist=True)
            self.assertIn(
                digest,
                {
                    item.get("sha256")
                    for item in preview["candidates"]
                    if item.get("storage_kind") == "cas_object"
                },
            )

            store.set_reference("js_file", "example.com\n/race.js", digest)
            result = apply_retention(
                paths,
                db,
                preview["preview_id"],
                actor="test",
                confirmation=f"DELETE_RETENTION_PREVIEW_{preview['preview_id']}",
            )
            self.assertTrue(path.exists())
            self.assertIn(
                "referenced",
                {item["reason"] for item in result["skipped"]},
            )
        finally:
            db.close()
            temp.cleanup()

    def test_retention_revalidates_access_after_preview(self):
        temp, paths, db = self.project()
        try:
            store = ContentAddressedStore(paths, db)
            digest, path, _ = store.put(b"recently-read")
            db.execute(
                "UPDATE object_store SET last_accessed=? WHERE sha256=?",
                (OLD, digest),
            )
            preview = retention_preview(paths, db, persist=True)
            self.assertEqual(store.get(digest), b"recently-read")

            result = apply_retention(
                paths,
                db,
                preview["preview_id"],
                actor="test",
                confirmation=f"DELETE_RETENTION_PREVIEW_{preview['preview_id']}",
            )
            self.assertTrue(path.exists())
            self.assertIn(
                "recently_accessed",
                {item["reason"] for item in result["skipped"]},
            )
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

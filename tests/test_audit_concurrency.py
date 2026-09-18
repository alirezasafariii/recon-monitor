from __future__ import annotations

import concurrent.futures
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database
from platform_v6 import verify_audit_chain


class AuditConcurrencyTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        return temp, paths, db

    def test_concurrent_database_connections_preserve_one_linear_chain(self):
        temp, paths, db = self.project()
        try:
            workers = 8
            events_per_worker = 20
            start = threading.Barrier(workers)

            def write_events(worker: int) -> None:
                local = Database(paths.db)
                try:
                    start.wait(timeout=10)
                    for index in range(events_per_worker):
                        local.audit(
                            "concurrent_fixture",
                            actor=f"worker-{worker}",
                            entity_type="fixture",
                            entity_value=f"{worker}:{index}",
                            details={"worker": worker, "index": index},
                        )
                finally:
                    local.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(write_events, worker) for worker in range(workers)]
                for future in futures:
                    future.result(timeout=30)

            expected = workers * events_per_worker
            self.assertEqual(
                int(db.one("SELECT COUNT(*) count FROM audit_log")["count"]),
                expected,
            )
            self.assertEqual(
                int(db.one("SELECT COUNT(*) count FROM audit_integrity")["count"]),
                expected,
            )
            result = verify_audit_chain(db)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["verified"], expected)

            rows = db.all(
                "SELECT audit_id,previous_hash,event_hash "
                "FROM audit_integrity ORDER BY audit_id"
            )
            self.assertEqual(str(rows[0]["previous_hash"]), "")
            for previous, current in zip(rows, rows[1:]):
                self.assertEqual(
                    str(current["previous_hash"]),
                    str(previous["event_hash"]),
                )
        finally:
            db.close()
            temp.cleanup()

    def test_transaction_holds_connection_lock_for_full_scope(self):
        temp, paths, db = self.project()
        try:
            entered = threading.Event()
            release = threading.Event()
            contender_done = threading.Event()
            failures: list[BaseException] = []

            def transaction_owner() -> None:
                try:
                    with db.transaction():
                        db.execute(
                            "INSERT INTO schema_meta(key,value) VALUES('tx-owner','1') "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
                        )
                        entered.set()
                        if not release.wait(timeout=10):
                            raise TimeoutError("test release timeout")
                except BaseException as exc:
                    failures.append(exc)

            def contender() -> None:
                try:
                    if not entered.wait(timeout=10):
                        raise TimeoutError("transaction did not start")
                    db.execute(
                        "INSERT INTO schema_meta(key,value) VALUES('tx-contender','1') "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
                    )
                    contender_done.set()
                except BaseException as exc:
                    failures.append(exc)

            owner_thread = threading.Thread(target=transaction_owner)
            contender_thread = threading.Thread(target=contender)
            owner_thread.start()
            contender_thread.start()

            self.assertTrue(entered.wait(timeout=10))
            time.sleep(0.05)
            self.assertFalse(
                contender_done.is_set(),
                "a second thread executed inside another thread's transaction",
            )
            release.set()
            owner_thread.join(timeout=10)
            contender_thread.join(timeout=10)

            self.assertFalse(owner_thread.is_alive())
            self.assertFalse(contender_thread.is_alive())
            self.assertEqual(failures, [])
            self.assertTrue(contender_done.is_set())
            self.assertEqual(db.meta_get("tx-owner"), "1")
            self.assertEqual(db.meta_get("tx-contender"), "1")
        finally:
            db.close()
            temp.cleanup()

    def test_audit_joins_existing_transaction_and_rolls_back_with_it(self):
        temp, paths, db = self.project()
        try:
            with self.assertRaises(RuntimeError):
                with db.transaction():
                    db.audit(
                        "rolled_back_fixture",
                        actor="test",
                        entity_type="fixture",
                        entity_value="rollback",
                    )
                    raise RuntimeError("rollback")

            self.assertIsNone(
                db.one(
                    "SELECT 1 FROM audit_log WHERE action='rolled_back_fixture'"
                )
            )
            self.assertEqual(
                int(db.one("SELECT COUNT(*) count FROM audit_integrity")["count"]),
                0,
            )
            self.assertTrue(verify_audit_chain(db)["ok"])
        finally:
            db.close()
            temp.cleanup()

    def test_audit_inside_existing_transaction_commits_as_one_chain_entry(self):
        temp, paths, db = self.project()
        try:
            with db.transaction():
                db.audit(
                    "transactional_fixture",
                    actor="test",
                    entity_type="fixture",
                    entity_value="commit",
                )
                db.execute(
                    "INSERT INTO schema_meta(key,value) VALUES('audit-fixture','ok')"
                )

            self.assertEqual(db.meta_get("audit-fixture"), "ok")
            result = verify_audit_chain(db)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["verified"], 1)
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

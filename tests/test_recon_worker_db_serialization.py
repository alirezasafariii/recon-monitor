from __future__ import annotations

import concurrent.futures
import inspect
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from execution import BudgetManager, WorkQueue
from stages import stage_endpoint_validation, stage_javascript


class _Limits:
    max_runtime_minutes = 120


class _Policy:
    limits = _Limits()


class _ConcurrentBudgetDB:
    """Fake DB that fails if budget_consume overlaps."""

    def __init__(self):
        self.guard = threading.Lock()
        self.in_transaction = False
        self.used = 0

    def budget_consume(
        self,
        run_id,
        target,
        metric,
        amount,
    ):
        with self.guard:
            if self.in_transaction:
                raise RuntimeError(
                    "cannot start a transaction within a transaction"
                )
            self.in_transaction = True

        try:
            time.sleep(0.001)

            with self.guard:
                self.used += amount
                used = self.used

            return used, 100000, True
        finally:
            with self.guard:
                self.in_transaction = False


class _WorkDB:
    def __init__(self):
        self.calls = []

    def work_start(self, work_id, worker_id):
        self.calls.append(
            ("start", work_id, worker_id)
        )

    def work_finish(self, work_id, result):
        self.calls.append(
            ("finish", work_id, dict(result))
        )

    def work_fail(self, work_id, error, retry=True):
        self.calls.append(
            ("fail", work_id, error, retry)
        )


class _Writer:
    def __init__(self, db):
        self.db = db
        self.submissions = 0

    def submit(self, fn):
        self.submissions += 1
        return fn(self.db)


class ReconWorkerSerializationTests(unittest.TestCase):

    def test_budget_consume_is_serialized_across_workers(self):
        db = _ConcurrentBudgetDB()

        manager = BudgetManager(
            db=db,
            run_id="run",
            target="target",
            policy=_Policy(),
            started_monotonic=time.monotonic(),
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=16
        ) as pool:
            results = list(
                pool.map(
                    lambda _: manager.consume(
                        "http_requests",
                        1,
                    ),
                    range(100),
                )
            )

        self.assertEqual(len(results), 100)
        self.assertEqual(db.used, 100)


    def test_workqueue_lifecycle_uses_database_writer(self):
        db = _WorkDB()
        writer = _Writer(db)

        queue = WorkQueue(
            db=db,
            run_id="run",
            target="target",
            stage="stage",
            writer=writer,
        )

        queue.start(10, "worker-a")
        queue.finish(10, {"ok": True})
        queue.fail(11, "boom", retry=True)

        self.assertEqual(writer.submissions, 3)

        self.assertEqual(
            db.calls,
            [
                ("start", 10, "worker-a"),
                ("finish", 10, {"ok": True}),
                ("fail", 11, "boom", True),
            ],
        )


    def test_endpoint_validation_has_no_direct_worker_db_lifecycle_writes(self):
        source = inspect.getsource(
            stage_endpoint_validation
        )

        self.assertNotIn(
            "ctx.db.work_start",
            source,
        )
        self.assertNotIn(
            "ctx.db.work_finish",
            source,
        )
        self.assertNotIn(
            "ctx.db.work_fail",
            source,
        )

        self.assertIn(
            "queue.start",
            source,
        )
        self.assertIn(
            "queue.finish",
            source,
        )
        self.assertIn(
            "queue.fail",
            source,
        )


    def test_javascript_has_no_direct_work_lifecycle_writes(self):
        source = inspect.getsource(
            stage_javascript
        )

        self.assertNotIn(
            "ctx.db.work_start",
            source,
        )
        self.assertNotIn(
            "ctx.db.work_finish",
            source,
        )
        self.assertNotIn(
            "ctx.db.work_fail",
            source,
        )

        self.assertIn(
            "work_queue.start",
            source,
        )
        self.assertIn(
            "work_queue.finish",
            source,
        )
        self.assertIn(
            "work_queue.fail",
            source,
        )


if __name__ == "__main__":
    unittest.main()

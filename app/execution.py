from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from core import Database, ReconError, TargetPolicy, safe_json_loads, utc_now


class BudgetExceeded(ReconError):
    def __init__(self, metric: str, used: int, limit: int):
        super().__init__(f"Run budget exhausted: {metric} {used}/{limit}")
        self.metric = metric
        self.used = used
        self.limit = limit


@dataclass(slots=True)
class BudgetManager:
    db: Database
    run_id: str
    target: str
    policy: TargetPolicy
    started_monotonic: float

    @classmethod
    def create(cls, db: Database, run_id: str, target: str, policy: TargetPolicy) -> "BudgetManager":
        limits = {
            "http_requests": policy.limits.max_http_requests,
            "dns_queries": policy.limits.max_dns_queries,
            "download_bytes": policy.limits.max_download_mb * 1024 * 1024,
            "new_assets": policy.limits.max_new_assets,
        }
        db.budget_init(run_id, target, limits)
        return cls(db, run_id, target, policy, time.monotonic())

    def check_runtime(self) -> None:
        limit = self.policy.limits.max_runtime_minutes * 60
        elapsed = int(time.monotonic() - self.started_monotonic)
        if elapsed > limit:
            raise BudgetExceeded("runtime_seconds", elapsed, limit)

    def consume(self, metric: str, amount: int = 1) -> tuple[int, int]:
        self.check_runtime()
        used, limit_value, allowed = self.db.budget_consume(self.run_id, self.target, metric, amount)
        if limit_value and not allowed:
            raise BudgetExceeded(metric, used, limit_value)
        return used, limit_value

    def snapshot(self) -> dict[str, dict[str, int]]:
        rows = self.db.all(
            "SELECT metric,used,limit_value FROM run_budgets WHERE run_id=? AND target=? ORDER BY metric",
            (self.run_id, self.target),
        )
        return {str(r["metric"]): {"used": int(r["used"]), "limit": int(r["limit_value"])} for r in rows}


class WorkQueue:
    """Persistent item queue that makes interrupted stages idempotent."""

    def __init__(self, db: Database, run_id: str, target: str, stage: str, writer: DatabaseWriter | None = None):
        self.db = db
        self.writer = writer
        self.run_id = run_id
        self.target = target
        self.stage = stage

    def _write(self, fn):
        return self.writer.submit(fn) if self.writer else fn(self.db)

    def enqueue(self, item_key: str, payload: Mapping[str, Any] | None = None) -> int:
        return self._write(lambda db: db.enqueue_work(self.run_id, self.target, self.stage, item_key, payload))

    def completed(self, item_key: str) -> bool:
        return self.db.work_status(self.run_id, self.target, self.stage, item_key) == "completed"

    def run_item(self, item_key: str, fn: Callable[[], Mapping[str, Any] | None], payload: Mapping[str, Any] | None = None, worker_id: str = "local") -> Mapping[str, Any]:
        work_id = self.enqueue(item_key, payload)
        status = self.db.work_status(self.run_id, self.target, self.stage, item_key)
        if status == "completed":
            row = self.db.one("SELECT result_json FROM work_items WHERE id=?", (work_id,))
            return safe_json_loads(row["result_json"], {}, expected_type=dict) if row else {}
        self._write(lambda db: db.work_start(work_id, worker_id))
        try:
            result = dict(fn() or {})
        except Exception as exc:
            self._write(lambda db: db.work_fail(work_id, str(exc), retry=True))
            raise
        self._write(lambda db: db.work_finish(work_id, result))
        return result

    def counts(self) -> dict[str, int]:
        rows = self.db.all(
            "SELECT status,COUNT(*) AS count FROM work_items WHERE run_id=? AND target=? AND stage=? GROUP BY status",
            (self.run_id, self.target, self.stage),
        )
        return {str(r["status"]): int(r["count"]) for r in rows}


class DatabaseWriter:
    """Single-writer queue for worker-produced database mutations.

    Existing synchronous code can keep using Database directly; new concurrent
    workers should submit mutations here to avoid sharing cursors/transactions.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self._queue: queue.Queue[tuple[Callable[[Database], Any] | None, queue.Queue[Any] | None]] = queue.Queue()
        self._thread = threading.Thread(target=self._loop, name="recon-db-writer", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        db = Database(self.db_path)
        try:
            while True:
                fn, response = self._queue.get()
                if fn is None:
                    break
                try:
                    value = fn(db)
                except Exception as exc:
                    value = exc
                if response is not None:
                    response.put(value)
        finally:
            db.close()

    def submit(self, fn: Callable[[Database], Any], *, wait: bool = True) -> Any:
        response: queue.Queue[Any] | None = queue.Queue(maxsize=1) if wait else None
        self._queue.put((fn, response))
        if not wait:
            return None
        value = response.get()
        if isinstance(value, Exception):
            raise value
        return value

    def close(self) -> None:
        self._queue.put((None, None))
        self._thread.join(timeout=10)

from __future__ import annotations

import datetime as dt
import math
from dataclasses import asdict, dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Mapping

from core import ReconError, safe_json_loads
from worker_scope import WORKER_CAPABILITIES, task_scope_policy
from worker_artifacts import WorkerArtifactError, decode_artifact


RETRY_DELAY_SECONDS = 5
RATE_LIMIT_DELAY_SECONDS = 60
SAFETY_ERRORS = {
    "outside_scope_or_invalid_url", "non_public_resolution_blocked",
    "redirect_outside_scope", "redirect_scheme_downgrade_blocked",
    "redirect_limit_exceeded", "response_budget_exceeded",
}


@dataclass(frozen=True)
class WorkerOutcome:
    ok: bool
    retry: bool = False
    reason: str = "completed"
    error: str = ""
    retry_delay_seconds: int = 0

    def metadata(self) -> dict[str, Any]:
        return asdict(self)


def worker_failure(error: str, *, retry: bool, reason: str = "worker_exception") -> WorkerOutcome:
    return WorkerOutcome(False, retry, reason, error[:500], RETRY_DELAY_SECONDS if retry else 0)


def _retry_delay(value: Any, minimum: int, now: dt.datetime | None) -> int:
    if not isinstance(value, str) or not value.strip():
        return minimum
    value = value.strip()
    try:
        if value.isascii() and value.isdigit():
            return max(minimum, int(value))
        deadline = parsedate_to_datetime(value)
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=dt.timezone.utc)
        current = now or dt.datetime.now(dt.timezone.utc)
        return max(minimum, math.ceil((deadline - current).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return minimum


def classify_worker_result(
    payload: Mapping[str, Any], result: Any, *, now: dt.datetime | None = None,
) -> WorkerOutcome:
    """Judge the transport result against the leased task, never the client's ok flag."""
    invalid = worker_failure("Invalid remote worker result", retry=False, reason="invalid_worker_result")
    kind = payload.get("kind")
    if kind not in WORKER_CAPABILITIES or not isinstance(result, dict):
        return invalid
    try:
        policy = task_scope_policy(payload)
    except ReconError as exc:
        return worker_failure(str(exc), retry=False, reason="invalid_task")
    if not isinstance(result.get("url"), str) or not policy.url_in_scope(result["url"]):
        return worker_failure("outside_scope_or_invalid_url", retry=False, reason="stopped_for_safety")
    status = result.get("status_code")
    transport = result.get("transport_status")
    if type(status) is not int or status not in range(0, 600) or not isinstance(transport, str) or transport not in {"ok", "error", "stopped_for_safety"}:
        return invalid
    if any(key in result and type(result[key]) is not bool for key in ("truncated", "redirect_outside_scope")):
        return invalid
    error = str(result.get("transport_error") or "")[:500]
    if result.get("truncated") or result.get("redirect_outside_scope") or error in SAFETY_ERRORS:
        return worker_failure(error or "Unsafe or incomplete remote response", retry=False, reason="stopped_for_safety")
    if status == 429 and transport in {"ok", "stopped_for_safety"} and error in {"", "http_error"}:
        return WorkerOutcome(False, True, "rate_limited", "HTTP 429", _retry_delay(result.get("retry_after"), RATE_LIMIT_DELAY_SECONDS, now))
    if transport == "stopped_for_safety":
        return worker_failure(error or "Transport stopped for safety", retry=False, reason="stopped_for_safety")
    if transport == "error":
        return worker_failure(error or "Transport failed", retry=True, reason="transport_error")
    if status < 200 or error not in {"", "http_error"}:
        return invalid
    # HEAD records an HTTP observation, including 401/404/5xx. GET must succeed.
    if kind == "http_head":
        return WorkerOutcome(True)
    if 200 <= status < 300:
        try:
            decode_artifact(payload, result)
        except WorkerArtifactError as exc:
            return worker_failure(str(exc), retry=exc.retryable, reason="artifact_missing" if exc.retryable else "invalid_artifact")
        return WorkerOutcome(True)
    retry = status in {408, 425} or status >= 500
    delay = _retry_delay(result.get("retry_after"), RETRY_DELAY_SECONDS, now) if retry else 0
    return WorkerOutcome(False, retry, "http_error", f"HTTP {status}", delay)


def worker_retry_ready(work: Mapping[str, Any], *, now: dt.datetime | None = None) -> bool:
    """Use persisted controller decisions so 429/transport retries cannot hot-loop."""
    if work["status"] != "retry_pending" or not work["finished_at"]:
        return True
    result = safe_json_loads(work["result_json"], {}, expected_type=dict)
    outcome = result.get("_worker_outcome")
    delay = outcome.get("retry_delay_seconds") if isinstance(outcome, dict) else None
    if type(delay) is not int or delay < RETRY_DELAY_SECONDS:
        delay = RETRY_DELAY_SECONDS
    try:
        finished = dt.datetime.fromisoformat(str(work["finished_at"]).replace("Z", "+00:00"))
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=dt.timezone.utc)
        return ((now or dt.datetime.now(dt.timezone.utc)) - finished).total_seconds() >= delay
    except (ValueError, TypeError, OverflowError):
        return False

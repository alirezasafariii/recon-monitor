"""Collection visibility, separate from successful execution of a stage.

These diagnostics never supply vulnerability evidence or authorize requests.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping

COVERAGE_VERSION = "1.0.0"


def metrics_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        result = json.loads(value or "{}")
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError, OverflowError):
        return 0


def origin_probe_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    failed, restricted, boundary = set(), set(), set()
    statuses: Counter[str] = Counter()
    for row in rows:
        url = str(row.get("url") or "")
        status = count(row.get("status_code"))
        if status:
            statuses[str(status)] += 1
        if status in {401, 403}:
            restricted.add(url)
        if row.get("redirect_outside_scope"):
            boundary.add(url)
        transport = row.get("transport_status")
        if (transport == "error" or (not status and row.get("error")
                and row.get("error") != "rate_limit_cooldown")):
            failed.add(url)
    reasons = []
    if failed:
        reasons.append("origin_probe_failed")
    if restricted:
        reasons.append("http_access_restricted")
    if boundary:
        reasons.append("origin_redirect_outside_scope")
    return {
        "origin_probe_coverage_version": COVERAGE_VERSION,
        "origin_probe_observed": len(rows),
        "origin_probe_failed": len(failed),
        "origin_probe_failed_origins": sorted(failed),
        "origin_access_restricted": len(restricted),
        "origin_access_restricted_origins": sorted(restricted),
        "origin_scope_boundary_origins": sorted(boundary),
        "origin_http_status_counts": dict(sorted(statuses.items())),
        "origin_coverage_pending_origins": sorted(failed | restricted | boundary),
        "origin_coverage_reasons": reasons,
        "origin_coverage_status": "partial" if reasons else "complete" if rows else "unknown",
    }


def stage_coverage(stage: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """A running stage cannot reuse the preceding attempt's successful metrics."""
    raw = str(row.get("status") or "not_observed")
    metrics = metrics_dict(row.get("metrics_json")) if raw != "running" else {}
    # A historical audit adds visibility metadata without rewriting the
    # original collector outcome or its baseline decision.
    metrics.update(metrics_dict(metrics.get("coverage_audit")))
    execution = "success" if raw in {"success", "skipped"} else raw
    if raw == "partial" and metrics.get("execution_status") == "success":
        execution = "success"
    result = {"execution_status": execution,
              "execution_score": 100 if execution == "success" else 0,
              "status": raw, "score": 0, "reason": ""}

    def outcome(status: str, reason: str, score: int = 0) -> dict[str, Any]:
        return {**result, "status": status, "score": score, "reason": reason}

    if raw in {"running", "queued", "pending"}:
        return outcome("running", "This attempt is still running; final coverage is not available.")
    if raw in {"failed", "interrupted"}:
        return outcome(raw, "The stage did not finish successfully.")
    if raw == "skipped" or metrics.get("skipped"):
        return outcome("skipped", str(metrics.get("skipped") or "Module skipped."))
    if raw not in {"success", "partial"}:
        return outcome("not_observed", "No terminal stage observation is available.")
    if count(metrics.get("origin_access_restricted")) or count(metrics.get("http_access_restricted")):
        return outcome("access_restricted", "HTTP 401/403 restricted content visibility.")
    if (raw == "partial" or metrics.get("collection_status") == "partial"
            or metrics.get("origin_coverage_status") == "partial"):
        # A collector can finish normally while preserving incomplete evidence.
        return outcome("partial", ", ".join(metrics.get("collection_reasons") or [])
                       or "Collection preserved incomplete evidence.")
    if metrics.get("collection_status") == "no_input":
        return outcome("no_input", "No input was collected; content coverage is not established.")
    if stage == "javascript":
        if "files" not in metrics or "downloaded" not in metrics:
            return outcome("unknown", "Historical metrics do not establish JavaScript coverage.")
        if not count(metrics["files"]) and not count(metrics["downloaded"]):
            return outcome("no_input", "No JavaScript artifact was collected.")
        if (count(metrics.get("errors")) or count(metrics.get("downloaded"))
                + count(metrics.get("not_found")) + count(metrics.get("reused_work_items")) < count(metrics.get("files"))):
            return outcome("partial", "Some selected JavaScript observations are incomplete.")
    if stage == "endpoint_validation" and metrics.get("checked") == 0:
        return outcome("no_input", "No endpoint was checked.")
    if stage == "fingerprint" and metrics.get("probed") == 0:
        return outcome("no_input", "No HTTP service was probed.")
    if stage == "fingerprint" and count(metrics.get("probed")) > count(metrics.get("live")):
        return outcome("partial", "Some HTTP probes produced no usable response.")
    return outcome("complete", "Configured collection work completed.", 100)

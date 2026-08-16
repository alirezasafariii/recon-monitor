from __future__ import annotations

"""Diagnostic collection-completeness snapshot for Recon Monitor runs.

Collection quality describes how much of the configured recon surface was
actually observable in a run.  It is intentionally non-evidentiary: these
signals must never satisfy vulnerability admission, promote a candidate, or
turn missing collection into negative vulnerability evidence.
"""

from pathlib import Path
from typing import Any, Mapping

from core import atomic_write_text, json_dumps, safe_json_loads, utc_now

COLLECTION_QUALITY_VERSION = "1.0.0"
COLLECTION_QUALITY_RULE_VERSION = "2026.08.16.1"
DIMENSION_STATUSES = {
    "complete",
    "partial",
    "degraded",
    "failed",
    "skipped",
    "unavailable",
    "unknown",
}


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(value)
    except (TypeError, ValueError):
        return {}


def _int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return max(0, default)


def _stage_record(ctx: Any, stage: str) -> dict[str, Any]:
    try:
        row = ctx.db.one(
            "SELECT status,metrics_json,error FROM stage_runs "
            "WHERE run_id=? AND target=? AND stage=?",
            (ctx.run_id, ctx.policy.name, stage),
        )
    except Exception as exc:
        return {
            "available": False,
            "status": "unavailable",
            "metrics": {},
            "error": f"{type(exc).__name__}: {exc}",
        }
    if not row:
        return {
            "available": False,
            "status": "unknown",
            "metrics": {},
            "error": "",
        }
    data = _as_mapping(row)
    metrics = safe_json_loads(data.get("metrics_json"), {}, expected_type=dict)
    return {
        "available": True,
        "status": str(data.get("status") or "unknown").strip().lower(),
        "metrics": metrics,
        "error": str(data.get("error") or ""),
    }


def _module_enabled(ctx: Any, name: str, default: bool = True) -> bool:
    modules = getattr(ctx.policy, "modules", {})
    if isinstance(modules, Mapping):
        return bool(modules.get(name, default))
    return default


def _limit(ctx: Any, name: str) -> int:
    limits = getattr(ctx.policy, "limits", None)
    return _int(getattr(limits, name, 0), 0)


def _base_dimension(ctx: Any, stage: str, *, enabled: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not enabled:
        return (
            {
                "status": "skipped",
                "stage": stage,
                "stage_status": "skipped",
                "reason": "Module disabled by target policy.",
                "metrics": {},
            },
            None,
        )

    record = _stage_record(ctx, stage)
    stage_status = record["status"]
    base = {
        "status": "unknown",
        "stage": stage,
        "stage_status": stage_status,
        "reason": "",
        "metrics": dict(record.get("metrics") or {}),
    }
    if record.get("error"):
        base["stage_error"] = record["error"]

    if not record["available"]:
        base["status"] = "unavailable" if stage_status == "unavailable" else "unknown"
        base["reason"] = (
            "Stage metadata could not be read."
            if stage_status == "unavailable"
            else "No stage metadata is available for this run; collection completeness is unknown."
        )
        return base, None

    if stage_status == "success":
        return base, record

    if stage_status == "failed":
        base["status"] = "failed"
        base["reason"] = "Collection stage failed."
    elif stage_status in {"running", "pending", "queued"}:
        base["status"] = "partial"
        base["reason"] = f"Collection stage is {stage_status}; results may be incomplete."
    elif stage_status in {"skipped", "disabled"}:
        base["status"] = "skipped"
        base["reason"] = f"Collection stage was {stage_status}."
    else:
        base["status"] = "unknown"
        base["reason"] = f"Unrecognized historical stage status: {stage_status or 'unknown'}."
    return base, None


def _dns_dimension(ctx: Any) -> dict[str, Any]:
    base, record = _base_dimension(ctx, "dns", enabled=_module_enabled(ctx, "dns", True))
    if record is None:
        return base

    metrics = record["metrics"]
    raw_rrtypes = metrics.get("successful_rrtypes")
    if not isinstance(raw_rrtypes, (list, tuple, set)):
        base["status"] = "unknown"
        base["reason"] = (
            "DNS stage succeeded but this run does not record RR-type coverage; "
            "do not interpret missing DNS evidence as a negative observation."
        )
        return base

    expected = ("A", "AAAA", "CNAME", "NS")
    observable = sorted({str(value).upper() for value in raw_rrtypes if str(value).strip()})
    not_collected = [rrtype for rrtype in expected if rrtype not in observable]
    base["observable"] = observable
    base["not_collected"] = not_collected
    base["wildcard_candidates"] = _int(metrics.get("wildcard_candidates"))

    if not_collected:
        base["status"] = "degraded"
        base["reason"] = (
            "DNS collection completed with partial RR-type visibility; "
            f"not collected: {', '.join(not_collected)}."
        )
    else:
        base["status"] = "complete"
        base["reason"] = "DNS A/AAAA/CNAME/NS collection completed successfully."
    return base


def _urls_dimension(ctx: Any) -> dict[str, Any]:
    base, record = _base_dimension(ctx, "urls", enabled=_module_enabled(ctx, "urls", True))
    if record is None:
        return base

    metrics = record["metrics"]
    if "truncated" not in metrics or "urls" not in metrics:
        base["status"] = "unknown"
        base["reason"] = (
            "URL stage succeeded but historical metrics do not record truncation and collected-count metadata."
        )
        return base

    truncated = bool(metrics.get("truncated"))
    base["collected"] = _int(metrics.get("urls"))
    base["limit"] = _limit(ctx, "max_urls")
    base["truncated"] = truncated
    base["not_collected"] = ["urls_beyond_configured_limit"] if truncated else []

    if truncated:
        base["status"] = "partial"
        base["reason"] = "URL discovery exceeded the configured maximum and was truncated."
    else:
        base["status"] = "complete"
        base["reason"] = "URL collection completed without recorded truncation."
    return base


def _javascript_dimension(ctx: Any) -> dict[str, Any]:
    base, record = _base_dimension(
        ctx,
        "javascript",
        enabled=_module_enabled(ctx, "javascript", True),
    )
    if record is None:
        return base

    metrics = record["metrics"]
    if "files" not in metrics or "downloaded" not in metrics:
        base["status"] = "unknown"
        base["reason"] = (
            "JavaScript stage succeeded but historical metrics do not contain "
            "files/downloaded completeness metadata."
        )
        return base

    files = _int(metrics.get("files"))
    downloaded = _int(metrics.get("downloaded"))
    no_work = files == 0 and downloaded == 0
    if "errors" not in metrics and not no_work:
        base["status"] = "unknown"
        base["reason"] = (
            "JavaScript stage succeeded but historical metrics do not contain "
            "error completeness metadata for a non-empty collection."
        )
        return base

    errors = _int(metrics.get("errors"), 0)
    limit = _limit(ctx, "max_js_files")
    truncation_possible = bool(limit and files >= limit)
    reasons: list[str] = []
    not_collected: list[str] = []

    if downloaded < files:
        reasons.append(f"downloaded {downloaded}/{files} selected JavaScript files")
        not_collected.append("undownloaded_javascript_files")
    if errors:
        reasons.append(f"{errors} JavaScript collection errors")
    if truncation_possible:
        reasons.append("selected JavaScript count reached max_js_files")
        not_collected.append("javascript_candidates_beyond_limit_possible")

    base.update(
        {
            "files_selected": files,
            "downloaded": downloaded,
            "errors": errors,
            "limit": limit,
            "truncation_possible": truncation_possible,
            "not_collected": not_collected,
        }
    )
    if reasons:
        base["status"] = "partial"
        base["reason"] = "; ".join(reasons) + "."
    elif no_work:
        base["status"] = "complete"
        base["reason"] = "JavaScript stage completed successfully with no selected JavaScript files."
    else:
        base["status"] = "complete"
        base["reason"] = "Selected JavaScript collection completed without recorded gaps."
    return base


def _overall_status(dimensions: Mapping[str, Mapping[str, Any]]) -> str:
    statuses = [
        str(value.get("status") or "unknown")
        for value in dimensions.values()
        if str(value.get("status") or "unknown") != "skipped"
    ]
    if not statuses:
        return "unknown"
    if any(status == "failed" for status in statuses):
        return "degraded"
    if any(status in {"partial", "degraded"} for status in statuses):
        return "degraded"
    if any(status in {"unknown", "unavailable"} for status in statuses):
        return "unknown"
    if all(status == "complete" for status in statuses):
        return "complete"
    return "unknown"


def snapshot_collection_quality(ctx: Any, *, persist: bool = True) -> dict[str, Any]:
    """Build a non-evidentiary collection-quality snapshot for one target run."""

    dimensions = {
        "dns": _dns_dimension(ctx),
        "urls": _urls_dimension(ctx),
        "javascript": _javascript_dimension(ctx),
    }
    counts = {status: 0 for status in sorted(DIMENSION_STATUSES)}
    for value in dimensions.values():
        status = str(value.get("status") or "unknown")
        counts[status if status in counts else "unknown"] += 1

    result: dict[str, Any] = {
        "version": COLLECTION_QUALITY_VERSION,
        "rule_version": COLLECTION_QUALITY_RULE_VERSION,
        "generated_at": utc_now(),
        "run_id": str(ctx.run_id),
        "target": str(ctx.policy.name),
        "status": _overall_status(dimensions),
        "dimensions": dimensions,
        "status_counts": counts,
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "numeric_score": None,
        "absence_semantics": (
            "unknown/unavailable/not_collected describe collection visibility only; "
            "they are never target evidence and must not be interpreted as proof of absence."
        ),
    }

    if persist:
        output = Path(ctx.run_dir) / "collection-quality.json"
        result["output"] = str(output)
        atomic_write_text(output, json_dumps(result, pretty=True) + "\n")
    return result

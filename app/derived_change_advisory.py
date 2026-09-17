from __future__ import annotations

"""Offline advisory context derived from successful Recon change artifacts.

This module does not create target evidence and does not participate in
Canonical Admission. It only answers whether a hypothesis is close to a recent,
collection-complete source-map/chunk change from the same source run.
"""

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from core import Database, json_dumps

DERIVED_CHANGE_ADVISORY_VERSION = "1.0.0"
DERIVED_CHANGE_ADVISORY_RULE_VERSION = "2026.09.18.1"

EXPECTED_COLLECTION_STAGES = (
    "subdomains",
    "dns",
    "ports",
    "urls",
    "javascript",
    "endpoint_validation",
    "fingerprint",
    "nuclei",
)

_ALLOWED_STATE_TYPES = {"source_map_source", "javascript_chunk"}
_ALLOWED_CHANGES = {"added", "removed", "changed"}
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_SIGNALS = 5000

_STOPWORDS = {
    "api",
    "app",
    "application",
    "asset",
    "assets",
    "chunk",
    "chunks",
    "client",
    "code",
    "com",
    "example",
    "file",
    "http",
    "https",
    "javascript",
    "main",
    "module",
    "modules",
    "page",
    "script",
    "source",
    "src",
    "static",
    "test",
    "www",
}


def _collection_complete(db: Database, run_id: str, target: str) -> tuple[bool, list[str]]:
    rows = db.all(
        "SELECT stage,status FROM stage_runs WHERE run_id=? AND target=?",
        (run_id, target),
    )
    statuses = {str(row["stage"]): str(row["status"]) for row in rows}
    incomplete = [
        stage for stage in EXPECTED_COLLECTION_STAGES
        if statuses.get(stage) != "success"
    ]
    return not incomplete, incomplete


def _tokens(value: Any) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]{4,}", str(value or "").lower())
        if token not in _STOPWORDS
    }


def _flatten_strings(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            result.append(str(key))
            result.extend(_flatten_strings(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            result.extend(_flatten_strings(item))
    elif value is not None:
        result.append(str(value))
    return result


def _normalized_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme and parsed.netloc:
        return parsed.path or "/"
    return text if text.startswith("/") else ""


def _signal_affinity(
    row: Mapping[str, Any],
    *,
    endpoint: str,
    source_ref: str,
    summary: str,
) -> tuple[int | None, list[str]]:
    payload = {
        "item": row.get("item"),
        "before": row.get("before"),
        "after": row.get("after"),
    }
    values = [value for value in _flatten_strings(payload) if value]
    if not values:
        return None, []
    lowered = [value.lower() for value in values]
    reasons: list[str] = []
    score = 0

    source = str(source_ref or "").strip()
    if source and any(source.lower() == value for value in lowered):
        score = max(score, 92)
        reasons.append("exact source reference changed")
    elif source and any(source.lower() in value or value in source.lower() for value in lowered if len(value) >= 8):
        score = max(score, 82)
        reasons.append("source reference overlaps changed artifact")

    endpoint_path = _normalized_path(endpoint)
    if endpoint_path and endpoint_path != "/":
        endpoint_lower = endpoint_path.lower()
        if any(endpoint_lower in value for value in lowered):
            score = max(score, 84)
            reasons.append("endpoint path appears in changed artifact")

    primary_tokens = _tokens(endpoint) | _tokens(source_ref)
    signal_tokens: set[str] = set()
    for value in values:
        signal_tokens |= _tokens(value)
    overlap = sorted(primary_tokens & signal_tokens)
    if len(overlap) >= 3:
        score = max(score, 76)
        reasons.append("multiple endpoint/source tokens overlap: " + ",".join(overlap[:6]))
    elif len(overlap) == 2:
        score = max(score, 62)
        reasons.append("two endpoint/source tokens overlap: " + ",".join(overlap))
    elif len(overlap) == 1:
        score = max(score, 46)
        reasons.append("endpoint/source token overlaps: " + overlap[0])

    # Summary text is weaker because it can contain generic family language.
    summary_overlap = sorted(_tokens(summary) & signal_tokens)
    if score == 0 and len(summary_overlap) >= 2:
        score = 38
        reasons.append("summary tokens overlap changed artifact: " + ",".join(summary_overlap[:6]))

    state_type = str(row.get("state_type") or "")
    change = str(row.get("change") or "")
    before = row.get("before") if isinstance(row.get("before"), Mapping) else {}
    after = row.get("after") if isinstance(row.get("after"), Mapping) else {}
    if score and state_type == "source_map_source" and change == "changed":
        before_semantic = str(before.get("semantic_hash") or "")
        after_semantic = str(after.get("semantic_hash") or "")
        if before_semantic and after_semantic and before_semantic != after_semantic:
            score = min(100, score + 8)
            reasons.append("embedded source semantic hash changed")

    return (score or None), reasons


def _validated_signal(
    row: Mapping[str, Any],
    *,
    run_id: str,
    target: str,
) -> dict[str, Any] | None:
    state_type = str(row.get("state_type") or "").strip()
    change = str(row.get("change") or "").strip()
    signal_type = str(row.get("signal_type") or "").strip()
    if state_type not in _ALLOWED_STATE_TYPES or change not in _ALLOWED_CHANGES:
        return None
    if signal_type != f"{state_type}_{change}":
        return None
    if str(row.get("run_id") or "") != run_id:
        return None
    if str(row.get("target") or "") != target:
        return None
    if not str(row.get("baseline_run_id") or "").strip():
        return None
    item_key = str(row.get("item_key") or "").strip()
    if not item_key or len(item_key) > 2000:
        return None
    before = row.get("before")
    after = row.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return None
    return {
        "signal_type": signal_type,
        "state_type": state_type,
        "change": change,
        "item_key": item_key,
        "item": str(row.get("item") or "")[:2000],
        "baseline_run_id": str(row.get("baseline_run_id") or ""),
        "run_id": run_id,
        "target": target,
        "before": dict(before),
        "after": dict(after),
    }


def derived_change_advisory_context(
    db: Database,
    *,
    source_run_id: str,
    target: str,
    family: str,
    endpoint: str = "",
    source_ref: str = "",
    summary: str = "",
) -> dict[str, Any]:
    """Return a fail-closed, non-evidentiary prioritization context."""
    base: dict[str, Any] = {
        "version": DERIVED_CHANGE_ADVISORY_VERSION,
        "rule_version": DERIVED_CHANGE_ADVISORY_RULE_VERSION,
        "source_run_id": str(source_run_id or ""),
        "target": str(target or ""),
        "family": str(family or ""),
        "eligible": False,
        "available": False,
        "score": None,
        "family_scores": {},
        "signal_count": 0,
        "matched_signal_count": 0,
        "invalid_signal_count": 0,
        "matches": [],
        "reason": "",
        "safety": {
            "advisory_only": True,
            "counts_as_target_evidence": False,
            "can_satisfy_admission": False,
            "can_satisfy_confirmation": False,
            "network_requests": False,
        },
    }
    run_id = str(source_run_id or "").strip()
    target_name = str(target or "").strip()
    family_name = str(family or "").strip()
    if not run_id or not target_name or not family_name:
        base["reason"] = "missing source-run, target, or family identity"
        return base

    complete, incomplete = _collection_complete(db, run_id, target_name)
    if not complete:
        base["reason"] = "collection incomplete: " + ",".join(incomplete)
        base["incomplete_collection_stages"] = incomplete
        return base
    base["eligible"] = True

    row = db.one(
        "SELECT run_dir FROM run_targets WHERE run_id=? AND target=?",
        (run_id, target_name),
    )
    if row is None:
        base["reason"] = "source run target not found"
        return base
    run_dir = Path(str(row["run_dir"] or ""))
    artifact = run_dir / "changes" / "recon-derived-differentials.jsonl"
    base["artifact"] = str(artifact)
    if artifact.is_symlink():
        base["reason"] = "refusing symlinked derived-differential artifact"
        return base
    if not artifact.exists() or not artifact.is_file():
        base["reason"] = "derived-differential artifact not available"
        return base
    try:
        size = artifact.stat().st_size
    except OSError:
        base["reason"] = "derived-differential artifact metadata unavailable"
        return base
    if size > _MAX_ARTIFACT_BYTES:
        base["reason"] = "derived-differential artifact exceeds safety limit"
        return base

    valid: list[dict[str, Any]] = []
    invalid = 0
    try:
        with artifact.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= _MAX_SIGNALS:
                    invalid += 1
                    break
                text = line.strip()
                if not text:
                    continue
                try:
                    raw = json.loads(text)
                except json.JSONDecodeError:
                    invalid += 1
                    continue
                if not isinstance(raw, Mapping):
                    invalid += 1
                    continue
                signal = _validated_signal(raw, run_id=run_id, target=target_name)
                if signal is None:
                    invalid += 1
                    continue
                valid.append(signal)
    except OSError:
        base["reason"] = "derived-differential artifact could not be read"
        return base

    base["available"] = True
    base["signal_count"] = len(valid)
    base["invalid_signal_count"] = invalid
    if not valid:
        base["reason"] = "no valid derived changes for this source run"
        return base

    matches: list[dict[str, Any]] = []
    best_score = 0
    for signal in valid:
        score, reasons = _signal_affinity(
            signal,
            endpoint=endpoint,
            source_ref=source_ref,
            summary=summary,
        )
        if score is None:
            continue
        best_score = max(best_score, score)
        matches.append(
            {
                "signal_type": signal["signal_type"],
                "state_type": signal["state_type"],
                "change": signal["change"],
                "item": signal["item"],
                "item_key": signal["item_key"],
                "baseline_run_id": signal["baseline_run_id"],
                "score": score,
                "reasons": reasons,
            }
        )

    matches.sort(key=lambda item: (int(item["score"]), str(item["signal_type"])), reverse=True)
    base["matches"] = matches[:20]
    base["matched_signal_count"] = len(matches)
    if not best_score:
        base["reason"] = "derived changes exist but do not match this hypothesis surface"
        return base

    base["score"] = best_score
    base["family_scores"] = {family_name: best_score}
    base["reason"] = "matching derived Recon change is available as advisory prioritization context"
    base["context_hash_input"] = json_dumps(
        {
            "source_run_id": run_id,
            "target": target_name,
            "family": family_name,
            "endpoint": endpoint,
            "source_ref": source_ref,
            "score": best_score,
            "matches": base["matches"],
        }
    )
    return base


__all__ = [
    "DERIVED_CHANGE_ADVISORY_VERSION",
    "DERIVED_CHANGE_ADVISORY_RULE_VERSION",
    "EXPECTED_COLLECTION_STAGES",
    "derived_change_advisory_context",
]

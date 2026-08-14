from __future__ import annotations

"""Multi-scan temporal intelligence built only from stored target observations.

The engine looks across a bounded history of completed Analysis snapshots and
emits context-only protocol findings for recurrence, authentication-boundary
drift, response-shape growth and endpoint-contract expansion. Temporal output
is intentionally non-decisive: it can guide a family analyzer toward the right
surface but cannot by itself admit or confirm a vulnerability.
"""

import json
import uuid
from collections import Counter
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, parse_int, utc_now


TEMPORAL_INTELLIGENCE_VERSION = "1.1.0"
TEMPORAL_RULE_VERSION = "2026.08.14.3"
DEFAULT_HISTORY_LIMIT = 6
SNAPSHOT_DECAY = 0.82
PROTECTED_BOUNDARIES = {
    "authentication_required",
    "session_required",
    "bearer_required",
    "api_key_required",
    "role_gated_hint",
    "mixed",
}
PUBLIC_BOUNDARIES = {"public"}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _safe_all(db: Database, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in db.all(sql, params)]
    except Exception:
        return []


def _history_ids(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    limit: int,
) -> list[str]:
    rows = _safe_all(
        db,
        """
        SELECT analysis_id,MAX(seen_at) AS seen_at FROM (
            SELECT analysis_id,created_at AS seen_at FROM endpoint_contracts WHERE target=?
            UNION ALL
            SELECT analysis_id,created_at AS seen_at FROM authentication_boundaries WHERE target=?
            UNION ALL
            SELECT analysis_id,created_at AS seen_at FROM response_shape_fingerprints WHERE target=?
        ) WHERE analysis_id<>?
        GROUP BY analysis_id
        ORDER BY seen_at DESC
        LIMIT ?
        """,
        (target, target, target, analysis_id, max(1, int(limit))),
    )
    return [str(row.get("analysis_id") or "") for row in rows if str(row.get("analysis_id") or "")]


def _insert_temporal_finding(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    kind: str,
    confidence: int,
    severity: str,
    summary: str,
    evidence: Mapping[str, Any],
) -> None:
    finding_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"recon-monitor:{analysis_id}:{target}:temporal:{endpoint}:{kind}",
        )
    )
    payload = dict(evidence)
    payload.update(
        {
            "temporal_intelligence_version": TEMPORAL_INTELLIGENCE_VERSION,
            "rule_version": TEMPORAL_RULE_VERSION,
            "context_only": True,
            "non_decisive": True,
            "independent_evidence_requires_distinct_stored_snapshots": True,
            "active_request_performed": False,
        }
    )
    db.execute(
        """INSERT OR REPLACE INTO protocol_findings(
        finding_id,analysis_id,target,protocol,entity,kind,confidence,severity,summary,evidence_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            finding_id,
            analysis_id,
            target,
            "temporal",
            endpoint,
            kind,
            max(0, min(100, int(confidence))),
            severity,
            summary,
            json_dumps(payload),
            utc_now(),
        ),
    )


def _endpoint_inventory(db: Database, analysis_id: str, target: str) -> list[str]:
    rows = _safe_all(
        db,
        """
        SELECT endpoint FROM endpoint_contracts WHERE analysis_id=? AND target=?
        UNION
        SELECT endpoint FROM authentication_boundaries WHERE analysis_id=? AND target=?
        UNION
        SELECT endpoint FROM response_shape_fingerprints WHERE analysis_id=? AND target=?
        ORDER BY endpoint
        """,
        (analysis_id, target, analysis_id, target, analysis_id, target),
    )
    return [str(row.get("endpoint") or "") for row in rows if str(row.get("endpoint") or "")]


def _snapshot_rows(
    db: Database,
    table: str,
    columns: str,
    *,
    target: str,
    endpoint: str,
    analysis_ids: list[str],
) -> list[dict[str, Any]]:
    if not analysis_ids:
        return []
    placeholders = ",".join("?" for _ in analysis_ids)
    return _safe_all(
        db,
        f"SELECT analysis_id,{columns} FROM {table} WHERE target=? AND endpoint=? "
        f"AND analysis_id IN ({placeholders}) ORDER BY created_at",
        (target, endpoint, *analysis_ids),
    )


def _ordered_unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        value = str(value or "")
        if value and (not out or out[-1] != value):
            out.append(value)
    return out


def _snapshot_weight(age_from_current: int) -> float:
    return round(SNAPSHOT_DECAY ** max(0, int(age_from_current)), 6)


def _weight_map(ids: list[str]) -> dict[str, float]:
    newest_index = len(ids) - 1
    return {
        analysis_id: _snapshot_weight(newest_index - index)
        for index, analysis_id in enumerate(ids)
    }


def _weighted_presence(ids: list[str], seen_ids: set[str]) -> dict[str, Any]:
    weights = _weight_map(ids)
    total = sum(weights.values()) or 1.0
    present = sum(weight for analysis_id, weight in weights.items() if analysis_id in seen_ids)
    return {
        "snapshot_decay": SNAPSHOT_DECAY,
        "snapshot_weights": weights,
        "weighted_presence": round(present / total, 6),
        "weighted_presence_score": int(round((present / total) * 100)),
    }


def _boundary_timeline(boundaries: list[dict[str, Any]], ids: list[str]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in boundaries:
        analysis_id = str(row.get("analysis_id") or "")
        if not analysis_id:
            continue
        existing = by_id.get(analysis_id)
        if existing is None or parse_int(row.get("confidence"), 0) >= parse_int(existing.get("confidence"), 0):
            by_id[analysis_id] = row
    weights = _weight_map(ids)
    timeline: list[dict[str, Any]] = []
    for analysis_id in ids:
        row = by_id.get(analysis_id)
        if row is None:
            continue
        timeline.append(
            {
                "analysis_id": analysis_id,
                "boundary": str(row.get("boundary") or "unknown"),
                "confidence": parse_int(row.get("confidence"), 0),
                "weight": weights.get(analysis_id, 0.0),
            }
        )
    return timeline


def _transition_timeline(boundary_timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    for before, after in zip(boundary_timeline, boundary_timeline[1:]):
        before_boundary = str(before.get("boundary") or "unknown")
        after_boundary = str(after.get("boundary") or "unknown")
        if before_boundary == after_boundary:
            transition = "stable"
        elif before_boundary in PROTECTED_BOUNDARIES and after_boundary in PUBLIC_BOUNDARIES:
            transition = "protected_to_public"
        elif before_boundary in PUBLIC_BOUNDARIES and after_boundary in PROTECTED_BOUNDARIES:
            transition = "public_to_protected"
        else:
            transition = "boundary_changed"
        transitions.append(
            {
                "from_analysis_id": before.get("analysis_id"),
                "to_analysis_id": after.get("analysis_id"),
                "from": before_boundary,
                "to": after_boundary,
                "transition": transition,
                "recency_weight": after.get("weight", 0.0),
            }
        )
    return transitions


def _public_persistence(boundary_timeline: list[dict[str, Any]]) -> dict[str, Any]:
    if not boundary_timeline:
        return {
            "protected_to_public_observed": False,
            "public_persistence_snapshots": 0,
            "public_persistence_weight": 0.0,
        }
    regression_index = -1
    for index, item in enumerate(boundary_timeline):
        boundary = str(item.get("boundary") or "unknown")
        if index == 0:
            continue
        previous = str(boundary_timeline[index - 1].get("boundary") or "unknown")
        if previous in PROTECTED_BOUNDARIES and boundary in PUBLIC_BOUNDARIES:
            regression_index = index
            break
    if regression_index < 0:
        return {
            "protected_to_public_observed": False,
            "public_persistence_snapshots": 0,
            "public_persistence_weight": 0.0,
        }
    after = boundary_timeline[regression_index:]
    public_items = [item for item in after if str(item.get("boundary") or "") in PUBLIC_BOUNDARIES]
    return {
        "protected_to_public_observed": True,
        "public_persistence_snapshots": len(public_items),
        "public_persistence_weight": round(sum(float(item.get("weight") or 0.0) for item in public_items), 6),
        "regression_analysis_id": boundary_timeline[regression_index].get("analysis_id"),
        "latest_boundary": str(boundary_timeline[-1].get("boundary") or "unknown"),
    }


def _sensitive_timeline(shapes: list[dict[str, Any]], ids: list[str]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in shapes:
        analysis_id = str(row.get("analysis_id") or "")
        if not analysis_id:
            continue
        keys = sorted({str(value) for value in _loads(row.get("sensitive_keys_json"), []) if str(value)})
        candidate = {
            "analysis_id": analysis_id,
            "count": len(keys),
            "keys": keys,
            "status_code": row.get("status_code"),
            "confidence": parse_int(row.get("confidence"), 0),
        }
        existing = by_id.get(analysis_id)
        if existing is None or (
            candidate["count"],
            candidate["confidence"],
        ) >= (
            int(existing.get("count") or 0),
            int(existing.get("confidence") or 0),
        ):
            by_id[analysis_id] = candidate
    weights = _weight_map(ids)
    return [
        {
            **by_id[analysis_id],
            "weight": weights.get(analysis_id, 0.0),
        }
        for analysis_id in ids
        if analysis_id in by_id
    ]


def _sensitive_growth_sequence(series: list[dict[str, Any]]) -> dict[str, Any]:
    growth_events: list[dict[str, Any]] = []
    previous_keys: set[str] = set()
    previous_count = 0
    initialized = False
    monotonic = True
    for item in series:
        keys = set(str(value) for value in item.get("keys", []))
        count = int(item.get("count") or 0)
        if initialized and count < previous_count:
            monotonic = False
        new_keys = sorted(keys - previous_keys) if initialized else sorted(keys)
        if initialized and (count > previous_count or new_keys):
            growth_events.append(
                {
                    "analysis_id": item.get("analysis_id"),
                    "previous_count": previous_count,
                    "current_count": count,
                    "new_sensitive_keys": new_keys,
                    "weight": item.get("weight", 0.0),
                }
            )
        previous_keys |= keys
        previous_count = max(previous_count, count)
        initialized = True
    return {
        "growth_event_count": len(growth_events),
        "growth_events": growth_events,
        "monotonic_non_decreasing": monotonic,
        "weighted_growth_score": min(
            100,
            int(round(sum(float(item.get("weight") or 0.0) for item in growth_events) * 45)),
        ),
    }


def generate_temporal_intelligence(
    db: Database,
    analysis_id: str,
    run_id: str,
    targets: Iterable[str],
    *,
    history_limit: int = DEFAULT_HISTORY_LIMIT,
) -> dict[str, Any]:
    del run_id  # Temporal memory is keyed to immutable Analysis snapshots.
    counts = Counter()
    per_target: dict[str, Any] = {}

    for target in sorted(set(str(value) for value in targets if str(value))):
        history = _history_ids(
            db,
            analysis_id=analysis_id,
            target=target,
            limit=history_limit,
        )
        ids = list(reversed(history)) + [analysis_id]
        endpoints = _endpoint_inventory(db, analysis_id, target)
        target_counts = Counter()

        for endpoint in endpoints:
            contracts = _snapshot_rows(
                db,
                "endpoint_contracts",
                "method,auth_boundary,confidence,created_at",
                target=target,
                endpoint=endpoint,
                analysis_ids=ids,
            )
            boundaries = _snapshot_rows(
                db,
                "authentication_boundaries",
                "boundary,confidence,created_at",
                target=target,
                endpoint=endpoint,
                analysis_ids=ids,
            )
            shapes = _snapshot_rows(
                db,
                "response_shape_fingerprints",
                "status_code,sensitive_keys_json,confidence,created_at",
                target=target,
                endpoint=endpoint,
                analysis_ids=ids,
            )

            seen_ids = {
                str(row.get("analysis_id") or "")
                for row in contracts + boundaries + shapes
                if str(row.get("analysis_id") or "")
            }
            if len(seen_ids) >= 3:
                recurrence = len(seen_ids)
                weighted = _weighted_presence(ids, seen_ids)
                confidence = min(94, 44 + recurrence * 6 + weighted["weighted_presence_score"] // 8)
                _insert_temporal_finding(
                    db,
                    analysis_id=analysis_id,
                    target=target,
                    endpoint=endpoint,
                    kind="temporal_endpoint_recurrence_surface",
                    confidence=confidence,
                    severity="informational",
                    summary=f"Endpoint context recurred across {recurrence} stored Analysis snapshots.",
                    evidence={
                        "snapshot_count": recurrence,
                        "analysis_ids": [item for item in ids if item in seen_ids],
                        "history_window": history_limit,
                        "recency_model": "exponential_snapshot_decay",
                        **weighted,
                    },
                )
                counts["recurrence"] += 1
                target_counts["recurrence"] += 1

            boundary_timeline = _boundary_timeline(boundaries, ids)
            boundary_sequence = _ordered_unique(item["boundary"] for item in boundary_timeline)
            if len(boundary_sequence) >= 2:
                transitions = _transition_timeline(boundary_timeline)
                regression = any(item["transition"] == "protected_to_public" for item in transitions)
                persistence = _public_persistence(boundary_timeline)
                confidence = min(
                    98,
                    52
                    + 6 * len(boundary_sequence)
                    + (14 if regression else 0)
                    + min(12, sum(parse_int(row.get("confidence"), 0) for row in boundaries) // max(1, len(boundaries) * 9))
                    + min(10, int(round(float(persistence.get("public_persistence_weight") or 0.0) * 4))),
                )
                _insert_temporal_finding(
                    db,
                    analysis_id=analysis_id,
                    target=target,
                    endpoint=endpoint,
                    kind="temporal_auth_boundary_regression_surface" if regression else "temporal_auth_boundary_drift_surface",
                    confidence=confidence,
                    severity="high" if regression else "medium",
                    summary=(
                        "Stored authentication boundary history includes a protected-to-public regression."
                        if regression
                        else "Authentication boundary changed across multiple stored Analysis snapshots."
                    ),
                    evidence={
                        "boundary_sequence": boundary_sequence,
                        "boundary_timeline": boundary_timeline,
                        "transition_sequence": transitions,
                        "snapshot_ids": [item["analysis_id"] for item in boundary_timeline],
                        "regression_observed": regression,
                        "recency_model": "exponential_snapshot_decay",
                        "snapshot_decay": SNAPSHOT_DECAY,
                        **persistence,
                    },
                )
                counts["auth_boundary_drift"] += 1
                target_counts["auth_boundary_drift"] += 1
                if regression and int(persistence.get("public_persistence_snapshots") or 0) >= 2:
                    counts["persistent_auth_regression"] += 1
                    target_counts["persistent_auth_regression"] += 1

            sensitive_series = _sensitive_timeline(shapes, ids)
            if len(sensitive_series) >= 2:
                current_items = [item for item in sensitive_series if item["analysis_id"] == analysis_id]
                historical_items = [item for item in sensitive_series if item["analysis_id"] != analysis_id]
                if current_items and historical_items:
                    current = current_items[-1]
                    previous_max = max((item["count"] for item in historical_items), default=0)
                    current_count = current["count"]
                    historical_keys = {key for item in historical_items for key in item["keys"]}
                    current_keys = set(current["keys"])
                    new_sensitive = sorted(current_keys - historical_keys)
                    sequence = _sensitive_growth_sequence(sensitive_series)
                    if current_count > previous_max or new_sensitive:
                        confidence = min(
                            96,
                            56
                            + min(20, len(new_sensitive) * 6)
                            + min(12, current_count * 2)
                            + min(8, int(sequence["weighted_growth_score"]) // 12),
                        )
                        _insert_temporal_finding(
                            db,
                            analysis_id=analysis_id,
                            target=target,
                            endpoint=endpoint,
                            kind="temporal_sensitive_response_growth_surface",
                            confidence=confidence,
                            severity="medium" if new_sensitive else "low",
                            summary="Stored response-shape history became more sensitive or data-rich over time.",
                            evidence={
                                "series": sensitive_series,
                                "new_sensitive_keys": new_sensitive,
                                "current_sensitive_count": current_count,
                                "previous_max_sensitive_count": previous_max,
                                "recency_model": "exponential_snapshot_decay",
                                "snapshot_decay": SNAPSHOT_DECAY,
                                **sequence,
                            },
                        )
                        counts["sensitive_growth"] += 1
                        target_counts["sensitive_growth"] += 1
                        if int(sequence["growth_event_count"]) >= 2:
                            counts["sensitive_growth_sequence"] += 1
                            target_counts["sensitive_growth_sequence"] += 1

            if contracts:
                historical_methods = {
                    str(row.get("method") or "UNKNOWN").upper()
                    for row in contracts
                    if str(row.get("analysis_id") or "") != analysis_id
                }
                current_methods = {
                    str(row.get("method") or "UNKNOWN").upper()
                    for row in contracts
                    if str(row.get("analysis_id") or "") == analysis_id
                }
                new_methods = sorted(current_methods - historical_methods)
                if historical_methods and new_methods:
                    state_changing = sorted(set(new_methods) & {"POST", "PUT", "PATCH", "DELETE"})
                    _insert_temporal_finding(
                        db,
                        analysis_id=analysis_id,
                        target=target,
                        endpoint=endpoint,
                        kind="temporal_contract_expansion_surface",
                        confidence=min(90, 58 + len(new_methods) * 8 + (10 if state_changing else 0)),
                        severity="medium" if state_changing else "low",
                        summary="Endpoint contract exposed method semantics not observed in earlier stored snapshots.",
                        evidence={
                            "historical_methods": sorted(historical_methods),
                            "current_methods": sorted(current_methods),
                            "new_methods": new_methods,
                            "new_state_changing_methods": state_changing,
                            "snapshot_decay": SNAPSHOT_DECAY,
                            "recency_model": "exponential_snapshot_decay",
                        },
                    )
                    counts["contract_expansion"] += 1
                    target_counts["contract_expansion"] += 1

        per_target[target] = {
            "history_analysis_ids": history,
            "history_depth": len(history),
            "current_endpoint_count": len(endpoints),
            "snapshot_decay": SNAPSHOT_DECAY,
            **dict(target_counts),
        }

    return {
        "version": TEMPORAL_INTELLIGENCE_VERSION,
        "rule_version": TEMPORAL_RULE_VERSION,
        "history_limit": history_limit,
        "snapshot_decay": SNAPSHOT_DECAY,
        "counts": dict(counts),
        "targets": per_target,
        "safety": {
            "stored_observations_only": True,
            "network_requests": False,
            "context_only": True,
            "can_satisfy_admission_by_itself": False,
            "duplicate_snapshot_evidence_not_counted_as_independent": True,
            "older_snapshots_decay_in_context_weight": True,
            "decay_changes_context_weight_not_target_facts": True,
        },
    }


__all__ = [
    "TEMPORAL_INTELLIGENCE_VERSION",
    "TEMPORAL_RULE_VERSION",
    "SNAPSHOT_DECAY",
    "generate_temporal_intelligence",
]

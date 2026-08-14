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

TEMPORAL_INTELLIGENCE_VERSION = "1.0.1"
TEMPORAL_RULE_VERSION = "2026.08.14.2"
DEFAULT_HISTORY_LIMIT = 6
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
                confidence = min(92, 48 + recurrence * 7)
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
                        "analysis_ids": sorted(seen_ids),
                        "history_window": history_limit,
                    },
                )
                counts["recurrence"] += 1
                target_counts["recurrence"] += 1

            boundary_sequence = _ordered_unique(str(row.get("boundary") or "unknown") for row in boundaries)
            if len(boundary_sequence) >= 2:
                regression = any(
                    before in PROTECTED_BOUNDARIES and after in PUBLIC_BOUNDARIES
                    for before, after in zip(boundary_sequence, boundary_sequence[1:])
                )
                confidence = min(
                    96,
                    58
                    + 7 * len(boundary_sequence)
                    + (14 if regression else 0)
                    + min(10, sum(parse_int(row.get("confidence"), 0) for row in boundaries) // max(1, len(boundaries) * 10)),
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
                        "snapshot_ids": [str(row.get("analysis_id") or "") for row in boundaries],
                        "regression_observed": regression,
                    },
                )
                counts["auth_boundary_drift"] += 1
                target_counts["auth_boundary_drift"] += 1

            sensitive_series: list[dict[str, Any]] = []
            for row in shapes:
                keys = sorted({str(value) for value in _loads(row.get("sensitive_keys_json"), []) if str(value)})
                sensitive_series.append(
                    {
                        "analysis_id": str(row.get("analysis_id") or ""),
                        "count": len(keys),
                        "keys": keys,
                        "status_code": row.get("status_code"),
                    }
                )
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
                    if current_count > previous_max or new_sensitive:
                        confidence = min(94, 60 + min(20, len(new_sensitive) * 6) + min(12, current_count * 2))
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
                            },
                        )
                        counts["sensitive_growth"] += 1
                        target_counts["sensitive_growth"] += 1

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
                        },
                    )
                    counts["contract_expansion"] += 1
                    target_counts["contract_expansion"] += 1

        per_target[target] = {
            "history_analysis_ids": history,
            "history_depth": len(history),
            "current_endpoint_count": len(endpoints),
            **dict(target_counts),
        }

    return {
        "version": TEMPORAL_INTELLIGENCE_VERSION,
        "rule_version": TEMPORAL_RULE_VERSION,
        "history_limit": history_limit,
        "counts": dict(counts),
        "targets": per_target,
        "safety": {
            "stored_observations_only": True,
            "network_requests": False,
            "context_only": True,
            "can_satisfy_admission_by_itself": False,
            "duplicate_snapshot_evidence_not_counted_as_independent": True,
        },
    }


__all__ = [
    "TEMPORAL_INTELLIGENCE_VERSION",
    "TEMPORAL_RULE_VERSION",
    "generate_temporal_intelligence",
]

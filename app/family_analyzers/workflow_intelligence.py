from __future__ import annotations

"""Offline workflow/sequence intelligence for Business Logic and Race analyzers.

This module mines already-normalized analysis results only. It never performs
network requests or executes workflow actions. The output is structural context:
workflow markers, related endpoint count, state-changing methods and single-use
semantics that dedicated analyzers can combine with independent stored behavior.
"""

import re
from functools import lru_cache
from typing import Any, Mapping

from core import Database
from .remaining_common import list_value, loads, normalize


WORKFLOW_INTELLIGENCE_VERSION = "1.0.0"
WORKFLOW_INTELLIGENCE_RULE_VERSION = "2026.08.12.1"

WORKFLOW_MARKERS = {
    "cart", "checkout", "order", "payment", "pay", "price", "quantity", "coupon", "discount",
    "redeem", "claim", "refund", "transfer", "withdraw", "deposit", "balance", "reserve", "booking",
    "confirm", "approve", "cancel", "complete", "finalize", "submit", "quote", "invoice", "settlement",
    "subscription", "trial", "credit", "points", "reward", "referral", "activation", "verify",
}
SINGLE_USE_MARKERS = {
    "redeem", "claim", "refund", "transfer", "withdraw", "reserve", "booking", "confirm", "approve",
    "complete", "finalize", "activation", "verify", "coupon", "discount", "referral", "settlement",
}
SERVER_VALUE_MARKERS = {
    "price", "total", "amount", "balance", "credit", "discount", "fee", "tax", "quantity", "rate",
    "status", "state", "approved", "paid", "refunded",
}
STATEFUL_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


_WORKFLOW_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,80}")


@lru_cache(maxsize=100_000)
def _marker_set_cached(text: str) -> frozenset[str]:
    words = {
        normalize(word)
        for word in _WORKFLOW_WORD_RE.findall(text)
    }

    result = {
        marker
        for marker in WORKFLOW_MARKERS
        if marker in words
        or (
            len(marker) >= 5
            and any(marker in word for word in words)
        )
    }
    return frozenset(result)


def marker_set(text: str) -> set[str]:
    return set(_marker_set_cached(str(text or "")))



_WORKFLOW_CATALOG_CACHE: dict[
    tuple[int, str, str, int],
    tuple[dict[str, Any], ...],
] = {}
_WORKFLOW_CATALOG_CACHE_LIMIT = 32


def _workflow_catalog(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    limit: int,
) -> tuple[dict[str, Any], ...]:
    bounded_limit = max(20, min(1000, int(limit)))
    key = (id(db), str(analysis_id), str(target), bounded_limit)

    cached = _WORKFLOW_CATALOG_CACHE.get(key)
    if cached is not None:
        return cached

    rows = db.all(
        """SELECT r.endpoint_schema_json,r.business_context,a.item,a.category,a.details_json
        FROM analysis_results r JOIN alerts a ON a.id=r.alert_id
        WHERE r.analysis_id=? AND r.target=?
        ORDER BY r.adjusted_score DESC,r.confidence DESC LIMIT ?""",
        (analysis_id, target, bounded_limit),
    )

    catalog: list[dict[str, Any]] = []

    for row in rows:
        schema = loads(row["endpoint_schema_json"], {})
        details = loads(row["details_json"], {})

        if not isinstance(schema, Mapping):
            schema = {}
        if not isinstance(details, Mapping):
            details = {}

        row_endpoint = str(schema.get("endpoint") or row["item"] or "")
        method = str(
            schema.get("method")
            or details.get("method")
            or "UNKNOWN"
        ).upper()

        fields = [
            *list_value(schema.get("body_fields")),
            *list_value(schema.get("query_parameters")),
            *list_value(schema.get("path_parameters")),
        ]

        text_value = " ".join([
            row_endpoint,
            str(row["item"] or ""),
            str(row["category"] or ""),
            str(row["business_context"] or ""),
            " ".join(fields),
        ])

        markers = marker_set(text_value)
        if not markers:
            continue

        server_values: set[str] = set()
        for field in fields:
            normalized = normalize(field)
            if (
                normalized in SERVER_VALUE_MARKERS
                or any(
                    normalized.endswith("_" + marker)
                    for marker in SERVER_VALUE_MARKERS
                )
            ):
                server_values.add(normalized)

        catalog.append({
            "endpoint": row_endpoint,
            "method": method,
            "markers": frozenset(markers),
            "fields": tuple(str(value) for value in fields),
            "server_values": frozenset(server_values),
        })

    frozen = tuple(catalog)

    if len(_WORKFLOW_CATALOG_CACHE) >= _WORKFLOW_CATALOG_CACHE_LIMIT:
        oldest = next(iter(_WORKFLOW_CATALOG_CACHE))
        _WORKFLOW_CATALOG_CACHE.pop(oldest, None)

    _WORKFLOW_CATALOG_CACHE[key] = frozen
    return frozen


def mine_workflow_context(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "",
    semantic_text: str = "",
    limit: int = 500,
) -> dict[str, Any]:
    current_markers = marker_set(
        " ".join([endpoint, semantic_text])
    )

    catalog = _workflow_catalog(
        db,
        analysis_id=analysis_id,
        target=target,
        limit=limit,
    )

    related: list[dict[str, Any]] = []
    catalog_markers: set[str] = set()
    state_methods: set[str] = set()
    single_use: set[str] = set()
    server_values: set[str] = set()
    unique_endpoints: set[str] = set()

    for entry in catalog:
        markers = set(entry["markers"])

        if current_markers and markers and not (markers & current_markers):
            continue

        row_endpoint = str(entry["endpoint"])
        method = str(entry["method"])
        fields = list(entry["fields"])

        unique_endpoints.add(row_endpoint)
        catalog_markers.update(markers)

        if method in STATEFUL_METHODS:
            state_methods.add(method)

        single_use.update(markers & SINGLE_USE_MARKERS)
        server_values.update(entry["server_values"])

        related.append({
            "endpoint": row_endpoint[:300],
            "method": method,
            "markers": sorted(markers),
            "field_names": [
                str(value)[:120]
                for value in fields[:20]
            ],
        })

    return {
        "version": WORKFLOW_INTELLIGENCE_VERSION,
        "rule_version": WORKFLOW_INTELLIGENCE_RULE_VERSION,
        "current_markers": sorted(current_markers),
        "catalog_markers": sorted(catalog_markers),
        "related_endpoint_count": len(unique_endpoints),
        "stateful_methods": sorted(state_methods),
        "single_use_markers": sorted(single_use),
        "server_value_fields": sorted(server_values),
        "related_endpoints": related[:40],
        "network_requests_performed": False,
        "workflow_actions_executed": False,
    }

from __future__ import annotations

"""Compatibility surface for the authenticated API plus vulnerability intelligence.

The established API server remains in ``api_server_core``.  This module keeps the
public ``api_server`` import contract and adds one read-only Investigation Queue
endpoint without changing existing routes or authentication semantics.
"""

import urllib.parse
from typing import Any

import api_server_core as _base
from correlation_engine import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_RULE_VERSION,
    investigation_queue,
)
from meta_ranker import META_RANKER_VERSION, META_RANKER_RULE_VERSION


INVESTIGATION_API_VERSION = "1.0.0"

for _name, _value in vars(_base).items():
    if _name not in {
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__file__",
        "__cached__",
        "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_DO_GET = getattr(_base, "_VI_ORIGINAL_API_DO_GET", _base.APIHandler.do_GET)
_base._VI_ORIGINAL_API_DO_GET = _ORIGINAL_DO_GET


def _latest_analysis_id(db: Any) -> str:
    latest = db.one(
        "SELECT id FROM analysis_runs WHERE status='success' "
        "ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1"
    )
    return str(latest["id"]) if latest else ""


def investigation_queue_payload(
    db: Any,
    *,
    analysis_id: str = "",
    target: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Return the stable API envelope for the cluster-deduplicated queue."""
    selected_analysis = str(analysis_id or "").strip() or _latest_analysis_id(db)
    bounded_limit = max(1, min(500, int(limit or 50)))
    items = (
        investigation_queue(
            db,
            selected_analysis,
            target=str(target or "").strip() or None,
            limit=bounded_limit,
        )
        if selected_analysis
        else []
    )
    return {
        "api_version": INVESTIGATION_API_VERSION,
        "analysis_id": selected_analysis,
        "target": str(target or "").strip() or None,
        "count": len(items),
        "items": items,
        "engines": {
            "meta_ranker": {
                "version": META_RANKER_VERSION,
                "rule_version": META_RANKER_RULE_VERSION,
            },
            "correlation": {
                "version": CORRELATION_ENGINE_VERSION,
                "rule_version": CORRELATION_RULE_VERSION,
            },
        },
        "safety": {
            "status": "investigation_queue_not_confirmed",
            "queue_is_not_vulnerability_confirmation": True,
            "correlation_cannot_satisfy_admission": True,
            "target_evidence_confidence_uses_target_observations_only": True,
        },
    }


def _do_get_with_investigation_queue(self: Any) -> None:
    path = urllib.parse.urlsplit(self.path).path
    if path != "/api/v1/analysis/investigation-queue":
        _ORIGINAL_DO_GET(self)
        return

    auth = self.auth("viewer")
    if not auth:
        return

    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
    analysis_id = str((query.get("analysis_id") or [""])[0]).strip()
    target = str((query.get("target") or [""])[0]).strip()
    limit = _base.parse_int((query.get("limit") or [50])[0], 50, 1, 500)
    db = self.db()
    try:
        payload = investigation_queue_payload(
            db,
            analysis_id=analysis_id,
            target=target,
            limit=limit,
        )
    finally:
        db.close()
    self.send_json(payload)


_base.APIHandler.do_GET = _do_get_with_investigation_queue
APIHandler = _base.APIHandler

"""Infrastructure repository adapters.

Implementations for persistence. Domain code depends only on repository
contracts; SQL details remain in infrastructure.
"""

from __future__ import annotations

from typing import Any


class SQLiteFindingRepository:
    def __init__(self, gateway: Any):
        self._gateway = gateway

    def get(self, finding_id: str) -> dict[str, Any] | None:
        row = self._gateway.one(
            "SELECT * FROM findings WHERE finding_id=?",
            (finding_id,),
        )
        return dict(row) if row else None

    def save(self, finding: dict[str, Any]) -> str:
        raise NotImplementedError(
            "Pending migration of existing findings INSERT/UPSERT semantics from core.py"
        )


class SQLiteEvidenceRepository:
    def __init__(self, gateway: Any):
        self._gateway = gateway

    def save(self, evidence: dict[str, Any]) -> str:
        raise NotImplementedError(
            "Pending migration of existing evidence_records persistence from core.py"
        )

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

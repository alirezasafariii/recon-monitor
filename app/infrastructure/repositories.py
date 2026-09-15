"""Infrastructure repository adapters.

Temporary home for adapters while existing SQLite access is migrated out of
core.py incrementally.
"""

from __future__ import annotations

from typing import Any


class SQLiteFindingRepository:
    def __init__(self, database: Any):
        self._database = database

    def save(self, finding: dict[str, Any]) -> str:
        raise NotImplementedError(
            "Migration placeholder: wire to existing Database API in the next step"
        )

    def get(self, finding_id: str) -> dict[str, Any] | None:
        raise NotImplementedError


class SQLiteEvidenceRepository:
    def __init__(self, database: Any):
        self._database = database

    def save(self, evidence: dict[str, Any]) -> str:
        raise NotImplementedError

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

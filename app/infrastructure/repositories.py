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
        self._gateway.execute(
            """
            INSERT INTO findings(
                target,
                dedup_key,
                template_id,
                name,
                severity,
                matched_at,
                details_json,
                first_seen,
                last_seen,
                last_run_id
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,dedup_key)
            DO UPDATE SET
                last_seen=excluded.last_seen,
                last_run_id=excluded.last_run_id,
                details_json=excluded.details_json
            """,
            (
                finding.get("target"),
                finding.get("dedup_key"),
                finding.get("template_id"),
                finding.get("name"),
                finding.get("severity"),
                finding.get("matched_at"),
                finding.get("details_json"),
                finding.get("first_seen"),
                finding.get("last_seen"),
                finding.get("last_run_id"),
            ),
        )
        return str(finding.get("dedup_key") or "")


class SQLiteEvidenceRepository:
    def __init__(self, gateway: Any):
        self._gateway = gateway

    def save(self, evidence: dict[str, Any]) -> str:
        raise NotImplementedError(
            "Pending migration of existing evidence_records persistence from core.py"
        )

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

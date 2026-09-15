"""Domain-facing interfaces.

This module intentionally contains no infrastructure dependencies.
Implementations belong under app.infrastructure.
"""

from __future__ import annotations

from typing import Any, Protocol


class EvidenceRepository(Protocol):
    """Persistence contract for evidence objects."""

    def save(self, evidence: dict[str, Any]) -> str:
        ...

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        ...


class FindingRepository(Protocol):
    """Persistence contract for potential findings."""

    def save(self, finding: dict[str, Any]) -> str:
        ...

    def get(self, finding_id: str) -> dict[str, Any] | None:
        ...


class RunRepository(Protocol):
    """Persistence contract for run lifecycle state."""

    def update_status(self, run_id: str, status: str) -> None:
        ...

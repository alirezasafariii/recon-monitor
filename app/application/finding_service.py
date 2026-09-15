from __future__ import annotations

from typing import Any


class FindingService:
    """Application boundary for finding persistence operations.

    Keeps callers independent from the concrete repository implementation.
    """

    def __init__(self, repository: Any):
        self.repository = repository

    def create_or_update(self, finding: dict[str, Any]) -> Any:
        return self.repository.save(finding)

    def get(self, finding_id: str) -> Any:
        return self.repository.get(finding_id)

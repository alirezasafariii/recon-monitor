"""Application service boundary.

Services coordinate use-cases while keeping infrastructure details outside
business workflows.
"""

from __future__ import annotations

from typing import Any

from domain.interfaces import EvidenceRepository, FindingRepository


class FindingService:
    def __init__(self, findings: FindingRepository):
        self._findings = findings

    def create_potential_finding(self, finding: dict[str, Any]) -> str:
        return self._findings.save(finding)


class EvidenceService:
    def __init__(self, evidence: EvidenceRepository):
        self._evidence = evidence

    def store(self, item: dict[str, Any]) -> str:
        return self._evidence.save(item)

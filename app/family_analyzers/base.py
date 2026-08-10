from __future__ import annotations

"""Shared, evidence-preserving contract for vulnerability-family analyzers.

Family analyzers may classify, explain and prioritize already-collected target
observations.  They must not turn CWE/WSTG/write-up knowledge into target
evidence and must not perform active validation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from core import Database


FAMILY_ANALYZER_FRAMEWORK_VERSION = "1.0.0"
FAMILY_ANALYZER_RULE_VERSION = "2026.08.10.1"


@dataclass(frozen=True)
class FamilyAnalyzerContext:
    db: Database
    analysis_id: str
    target: str
    endpoint: str
    method: str
    details: Mapping[str, Any]
    business_context: str = "general"


class FamilyAnalyzer(ABC):
    family: str = ""
    analyzer_version: str = "1.0.0"

    @abstractmethod
    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        """Return an evidence-preserving family result or ``None`` when no signal exists."""

    def metadata(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "analyzer_version": self.analyzer_version,
            "framework_version": FAMILY_ANALYZER_FRAMEWORK_VERSION,
            "framework_rule_version": FAMILY_ANALYZER_RULE_VERSION,
            "knowledge_is_non_evidentiary": True,
            "active_validation_performed": False,
        }

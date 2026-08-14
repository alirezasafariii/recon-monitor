from __future__ import annotations

"""Shared, evidence-preserving contract for vulnerability-family analyzers.

Family analyzers may classify, explain and prioritize already-collected target
observations. They must not turn CWE/WSTG/write-up knowledge into target
evidence and must not perform active validation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from core import Database


FAMILY_ANALYZER_FRAMEWORK_VERSION = "1.2.0"
FAMILY_ANALYZER_RULE_VERSION = "2026.08.14.2"

# Temporal/workflow intelligence is generated lazily because the family router
# runs after Semantic + Behavioral Intelligence have populated the current
# Analysis snapshot.  A bounded key set prevents repeated regeneration for each
# endpoint/family context while keeping every Analysis ID isolated.
_CONTEXT_INTELLIGENCE_BOOTSTRAPPED: set[tuple[int, str, str]] = set()
_CONTEXT_INTELLIGENCE_CACHE_MAX = 2048


def clear_context_intelligence_bootstrap_cache() -> None:
    _CONTEXT_INTELLIGENCE_BOOTSTRAPPED.clear()


def _bootstrap_context_intelligence(db: Database, analysis_id: str, target: str) -> None:
    if db is None or not analysis_id or not target:
        return
    key = (id(db), str(analysis_id), str(target))
    if key in _CONTEXT_INTELLIGENCE_BOOTSTRAPPED:
        return
    # Mark before execution to prevent recursive re-entry if optional
    # intelligence code constructs a FamilyAnalyzerContext internally.
    _CONTEXT_INTELLIGENCE_BOOTSTRAPPED.add(key)
    if len(_CONTEXT_INTELLIGENCE_BOOTSTRAPPED) > _CONTEXT_INTELLIGENCE_CACHE_MAX:
        # Analysis IDs are unique; dropping old process-local keys is safe.
        for stale in list(_CONTEXT_INTELLIGENCE_BOOTSTRAPPED)[:
            len(_CONTEXT_INTELLIGENCE_BOOTSTRAPPED) - _CONTEXT_INTELLIGENCE_CACHE_MAX
        ]:
            _CONTEXT_INTELLIGENCE_BOOTSTRAPPED.discard(stale)
    try:
        from temporal_intelligence import generate_temporal_intelligence
        from workflow_state_intelligence import generate_workflow_state_intelligence

        generate_temporal_intelligence(db, analysis_id, "", [target])
        generate_workflow_state_intelligence(db, analysis_id, [target])
    except Exception:
        # Context enrichment is advisory/fail-soft. A missing optional table or
        # legacy database must never make canonical family analysis fail.
        return


@dataclass(frozen=True)
class FamilyAnalyzerContext:
    db: Database
    analysis_id: str
    target: str
    endpoint: str
    method: str
    details: Mapping[str, Any]
    business_context: str = "general"

    def __post_init__(self) -> None:
        """Attach stored Semantic/Behavioral/Temporal context without creating evidence.

        The bridge is fail-soft: older/minimal databases that do not contain
        optional intelligence tables continue with the original details.
        """
        try:
            _bootstrap_context_intelligence(self.db, self.analysis_id, self.target)
            from family_signal_bridge import augment_family_details

            enriched = augment_family_details(
                self.db,
                analysis_id=self.analysis_id,
                target=self.target,
                endpoint=self.endpoint,
                method=self.method,
                details=self.details,
            )
        except Exception:
            return
        object.__setattr__(self, "details", enriched)


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

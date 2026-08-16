from __future__ import annotations

"""Shared, evidence-preserving contract for vulnerability-family analyzers.

Family analyzers may classify, explain and prioritize already-collected target
observations. They must not turn CWE/WSTG/write-up knowledge into target
evidence and must not perform active validation.
"""

import json
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Mapping

from core import Database


FAMILY_ANALYZER_FRAMEWORK_VERSION = "1.3.1"
FAMILY_ANALYZER_RULE_VERSION = "2026.08.14.4"

# Temporal/workflow intelligence is generated lazily because the family router
# runs after Semantic + Behavioral Intelligence have populated the current
# Analysis snapshot. A bounded key set prevents repeated regeneration for each
# endpoint/family context while keeping every Analysis ID isolated.
_CONTEXT_INTELLIGENCE_BOOTSTRAPPED: set[tuple[int, str, str]] = set()
_CONTEXT_INTELLIGENCE_CACHE_MAX = 2048
_GENERATED_PROTOCOL_CONTEXT_CACHE_MAX = 4096
_GENERATED_PROTOCOL_CONTEXT_CACHE: "OrderedDict[tuple[int, str, str, str], tuple[dict[str, Any], ...]]" = OrderedDict()


def clear_context_intelligence_bootstrap_cache() -> None:
    _CONTEXT_INTELLIGENCE_BOOTSTRAPPED.clear()
    _GENERATED_PROTOCOL_CONTEXT_CACHE.clear()


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


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _generated_protocol_rows(
    db: Database,
    analysis_id: str,
    target: str,
    endpoint: str,
) -> tuple[dict[str, Any], ...]:
    """Return a bounded cached snapshot of generated protocol context.

    Family analyzers repeatedly construct contexts for the same endpoint. The
    protocol rows are immutable within one Analysis after bootstrap, so caching
    them preserves the bridge's zero-extra-query reuse contract and prevents
    endpoint/family fan-out from multiplying database reads.
    """

    if db is None or not endpoint:
        return ()
    key = (id(db), str(analysis_id), str(target), str(endpoint))
    cached = _GENERATED_PROTOCOL_CONTEXT_CACHE.get(key)
    if cached is not None:
        _GENERATED_PROTOCOL_CONTEXT_CACHE.move_to_end(key)
        return cached
    try:
        rows = tuple(
            dict(row)
            for row in db.all(
                "SELECT protocol,kind,confidence,severity,evidence_json FROM protocol_findings "
                "WHERE analysis_id=? AND target=? AND entity=? AND protocol IN ('temporal','workflow') "
                "ORDER BY confidence DESC LIMIT 50",
                (analysis_id, target, endpoint),
            )
        )
    except Exception:
        rows = ()
    _GENERATED_PROTOCOL_CONTEXT_CACHE[key] = rows
    _GENERATED_PROTOCOL_CONTEXT_CACHE.move_to_end(key)
    while len(_GENERATED_PROTOCOL_CONTEXT_CACHE) > _GENERATED_PROTOCOL_CONTEXT_CACHE_MAX:
        _GENERATED_PROTOCOL_CONTEXT_CACHE.popitem(last=False)
    return rows


def _attach_generated_protocol_context(
    db: Database,
    analysis_id: str,
    target: str,
    endpoint: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    """Translate generated temporal/workflow records into context-only hints.

    These fields intentionally contain no bypass/accepted/violation/confirmed
    signals. They make cross-endpoint and cross-scan structure visible to family
    analyzers while leaving decisive evidence requirements untouched.
    """

    enriched = dict(details)
    rows = _generated_protocol_rows(db, analysis_id, target, endpoint)
    if not rows:
        return enriched

    workflow_markers = {
        str(value).strip().lower()
        for value in enriched.get("workflow_markers", [])
        if str(value).strip()
    } if isinstance(enriched.get("workflow_markers"), (list, tuple, set)) else set()
    temporal_kinds: list[str] = []
    workflow_kinds: list[str] = []
    context_records: list[dict[str, Any]] = []

    for row in rows:
        protocol = str(row.get("protocol") or "")
        kind = str(row.get("kind") or "")
        evidence = _loads(row.get("evidence_json"), {})
        if not isinstance(evidence, Mapping):
            evidence = {}
        context_records.append({
            "protocol": protocol,
            "kind": kind,
            "confidence": row.get("confidence"),
            "severity": row.get("severity"),
            "context_only": True,
        })
        if protocol == "workflow":
            workflow_kinds.append(kind)
            action = str(evidence.get("action") or "").strip().lower()
            if action:
                workflow_markers.add(action)
            actions = evidence.get("actions")
            if isinstance(actions, list):
                workflow_markers.update(str(value).strip().lower() for value in actions if str(value).strip())
            if kind in {
                "single_use_or_financial_workflow_surface",
                "privileged_workflow_surface",
                "workflow_state_machine_surface",
            }:
                enriched.setdefault("stateful_operation", True)
            if kind == "workflow_state_machine_surface":
                enriched["workflow_sequence_context"] = True
        elif protocol == "temporal":
            temporal_kinds.append(kind)
            if kind == "temporal_endpoint_recurrence_surface":
                enriched["historical_recurrence_surface"] = True
            elif kind in {
                "temporal_auth_boundary_regression_surface",
                "temporal_auth_boundary_drift_surface",
            }:
                enriched["authentication_history_surface"] = True
                # Authentication analyzer can inspect this as lifecycle context,
                # but no violation/bypass flag is synthesized.
                observations = enriched.get("auth_observations")
                auth_observations = list(observations) if isinstance(observations, list) else []
                auth_observations.append({
                    "context": "temporal_boundary_history",
                    "boundary_sequence": list(evidence.get("boundary_sequence") or []),
                    "temporal_context_only": True,
                })
                enriched["auth_observations"] = auth_observations[:50]
            elif kind == "temporal_sensitive_response_growth_surface":
                enriched["sensitive_expansion_surface"] = True
                new_keys = evidence.get("new_sensitive_keys")
                if isinstance(new_keys, list) and new_keys:
                    enriched["temporal_sensitive_keys"] = [str(value) for value in new_keys[:50]]
            elif kind == "temporal_contract_expansion_surface":
                enriched["historical_contract_expansion_surface"] = True
                if evidence.get("new_state_changing_methods"):
                    enriched.setdefault("stateful_operation", True)

    if workflow_markers:
        enriched["workflow_markers"] = sorted(workflow_markers)[:50]
    enriched["_generated_context_intelligence"] = {
        "framework_version": FAMILY_ANALYZER_FRAMEWORK_VERSION,
        "context_only": True,
        "non_decisive": True,
        "network_requests": False,
        "temporal_kinds": sorted(set(temporal_kinds)),
        "workflow_kinds": sorted(set(workflow_kinds)),
        "records": context_records[:50],
    }
    return enriched


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
            enriched = _attach_generated_protocol_context(
                self.db,
                self.analysis_id,
                self.target,
                self.endpoint,
                enriched,
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

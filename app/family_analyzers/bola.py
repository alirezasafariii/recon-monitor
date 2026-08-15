from __future__ import annotations

"""Dedicated BOLA / IDOR family analyzer.

The analyzer executes against stored target observations. OWASP, WSTG, CWE and
curated write-up lessons are supplied by the canonical family specification and
never become supporting evidence or satisfy admission/confirmation.
"""

from typing import Any, Mapping

from family_reasoning import confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .bola_core import BOLA_ENGINE_VERSION, BOLA_RULE_VERSION, analyze_bola_signal as _core_analyze


BOLA_FAMILY_ANALYZER_VERSION = "1.1.0"
BOLA_FAMILY_ANALYZER_RULE_VERSION = "2026.08.15.1"

BOLA_SPEC = get_detection_spec("broken_object_authorization")

# Compatibility exports. The definitions now come from the canonical spec.
BOLA_METHOD = tuple(step.as_dict() for step in BOLA_SPEC.standard.methodology)
BOLA_FALSE_POSITIVE_CHECKS = tuple(BOLA_SPEC.standard.false_positive_checks)


def _observed_types(result: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("type") or "")
        for item in list(result.get("support") or [])
        if isinstance(item, Mapping) and str(item.get("type") or "")
    }


def _contradiction_types(result: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("type") or "")
        for item in list(result.get("contradict") or [])
        if isinstance(item, Mapping) and str(item.get("type") or "")
    }


def _matched_writeup_patterns(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for writeup in BOLA_SPEC.standard.writeups:
        overlap = sorted(observed & set(writeup.signal_hints))
        if not overlap:
            continue
        matches.append({
            "id": writeup.id,
            "source": writeup.source,
            "ref": writeup.ref,
            "url": writeup.url,
            "relation": writeup.relation,
            "matched_signals": overlap,
            "principle": writeup.lesson,
            "non_evidentiary": True,
            "counts_as_target_evidence": False,
        })
    return matches[:8]


def _specific_false_positive_checks(contradictions: set[str]) -> list[dict[str, Any]]:
    mapping = {
        "public_or_shared_object": "Confirm whether the resource is intentionally public/shared before treating cross-identity access as a bypass.",
        "public_boundary_observed": "Separate public endpoint reachability from private object authorization; public routing alone is not BOLA.",
        "cross_context_denied": "A stored unauthorized context was denied; verify that any success belongs to a genuinely unauthorized object context rather than a permitted one.",
        "ownership_enforcement_observed": "Ownership enforcement is recorded; determine whether the decisive success observation bypasses that enforcement or comes from another path.",
        "scope_binding_observed": "Tenant/parent scope binding is recorded; require a concrete mismatched-object success before promotion.",
        "secondary_guard_enforced": "A required secondary guard was enforced in at least one context; do not infer bypass from object-key control alone.",
    }
    return [
        {"signal": signal, "check": mapping[signal]}
        for signal in sorted(contradictions)
        if signal in mapping
    ]


class BolaFamilyAnalyzer(FamilyAnalyzer):
    family = "broken_object_authorization"
    analyzer_version = BOLA_FAMILY_ANALYZER_VERSION

    def analyze(
        self,
        context: FamilyAnalyzerContext,
        *,
        object_ids: list[str],
        structural_fields: list[str],
        **_: Any,
    ) -> dict[str, Any] | None:
        result = _core_analyze(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            object_ids=object_ids,
            structural_fields=structural_fields,
            details=context.details,
            business_context=context.business_context,
        )
        if not result:
            return None

        observed = _observed_types(result)
        contradictions = _contradiction_types(result)
        confirmation_missing = confirmation_gaps(self.family, observed)
        matched_writeups = _matched_writeup_patterns(observed)

        result = dict(result)
        result["family_analyzer"] = {
            **self.metadata(),
            "rule_version": BOLA_FAMILY_ANALYZER_RULE_VERSION,
            "family_spec_version": BOLA_SPEC.version,
            "family_spec_framework": "family_specs",
            "family_spec_strategy": BOLA_SPEC.strategy,
            "taxonomy": BOLA_SPEC.taxonomy(),
            "methodology": [step.as_dict() for step in BOLA_SPEC.standard.methodology],
            "writeup_patterns": matched_writeups,
            "false_positive_checks": list(BOLA_SPEC.standard.false_positive_checks),
            "triggered_false_positive_checks": _specific_false_positive_checks(contradictions),
            "promotion_required": [sorted(group) for group in BOLA_SPEC.promotion_required],
            "confirmation_required": [sorted(group) for group in BOLA_SPEC.confirmation_required],
            "confirmation_missing": confirmation_missing,
            "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
            "next_evidence": list(BOLA_SPEC.next_evidence),
            "validation_level": BOLA_SPEC.validation_level,
            "knowledge_sources_matched": len(matched_writeups),
            "knowledge_does_not_change_target_evidence": True,
        }
        return result


def analyze_bola_signal(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    object_ids: list[str],
    structural_fields: list[str],
    details: Mapping[str, Any],
    business_context: str = "general",
) -> dict[str, Any] | None:
    context = FamilyAnalyzerContext(
        db=db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        method=method,
        details=details,
        business_context=business_context,
    )
    return BolaFamilyAnalyzer().analyze(
        context,
        object_ids=object_ids,
        structural_fields=structural_fields,
    )


__all__ = [
    "BOLA_ENGINE_VERSION",
    "BOLA_RULE_VERSION",
    "BOLA_FAMILY_ANALYZER_VERSION",
    "BOLA_FAMILY_ANALYZER_RULE_VERSION",
    "BOLA_SPEC",
    "BOLA_METHOD",
    "BOLA_FALSE_POSITIVE_CHECKS",
    "BolaFamilyAnalyzer",
    "analyze_bola_signal",
]

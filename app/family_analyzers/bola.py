from __future__ import annotations

"""Dedicated BOLA / IDOR family analyzer.

The detector core remains target-evidence-only. CWE, WSTG and real-world
write-ups shape the reasoning plan and false-positive checks, but never become
supporting evidence and never satisfy admission or confirmation.
"""

from typing import Any, Mapping

from family_reasoning import FAMILY_REASONING, confirmation_gaps
from vulnerability_knowledge import knowledge_for_family, taxonomy_for_family

from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .bola_core import BOLA_ENGINE_VERSION, BOLA_RULE_VERSION, analyze_bola_signal as _core_analyze


BOLA_FAMILY_ANALYZER_VERSION = "1.0.0"
BOLA_FAMILY_ANALYZER_RULE_VERSION = "2026.08.10.1"

BOLA_METHOD = (
    {
        "id": "BOLA-01-object-reference",
        "basis": ["CWE-639", "WSTG-ATHZ-04", "WSTG-APIT-02"],
        "principle": "Identify a client-influenced key or object reference and the operation performed on that object.",
    },
    {
        "id": "BOLA-02-authorization-boundary",
        "basis": ["OWASP API1:2023", "WSTG-ATHZ-02"],
        "principle": "Model the expected identity, tenant, role, sharing, parent/child or secondary-guard relationship for the referenced object.",
    },
    {
        "id": "BOLA-03-horizontal-comparison",
        "basis": ["WSTG-ATHZ-02", "WSTG-ATHZ-04"],
        "principle": "Prefer like-for-like comparison between explicitly authorized identities with the same role and objects whose ownership is known.",
    },
    {
        "id": "BOLA-04-behavioral-decision",
        "basis": ["CWE-639", "OWASP API1:2023"],
        "principle": "Treat successful access or mutation across the expected object boundary as decisive; an identifier alone is only an attack surface signal.",
    },
    {
        "id": "BOLA-05-contradiction-check",
        "basis": ["WSTG-ATHZ-02"],
        "principle": "Actively look for denials, ownership enforcement, scope binding, public/shared visibility and required secondary guards before promoting the hypothesis.",
    },
)

BOLA_FALSE_POSITIVE_CHECKS = (
    "The object is intentionally public, shared or globally readable.",
    "The tested identifier is ignored, normalized to the caller's own object, or otherwise not used as the selected record key.",
    "A mismatched identity/object context is consistently denied or redirected without disclosing private object data.",
    "Tenant or parent/child binding is enforced before the object is read or mutated.",
    "A secondary object token or ownership guard is required and enforced.",
    "The apparent difference is caused by authentication or function-level authorization rather than object-level authorization.",
)


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
    for doc in knowledge_for_family("broken_object_authorization"):
        if str(doc.get("id") or "").startswith("profile:"):
            continue
        signals = {str(value) for value in doc.get("signals", []) if str(value)}
        overlap = sorted(observed & signals)
        if not overlap:
            continue
        matches.append({
            "id": str(doc.get("id") or ""),
            "source": str(doc.get("source") or ""),
            "ref": str(doc.get("ref") or ""),
            "matched_signals": overlap,
            "principle": str(doc.get("principle") or ""),
            "non_evidentiary": True,
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
        policy = FAMILY_REASONING[self.family]
        confirmation_missing = confirmation_gaps(self.family, observed)
        matched_writeups = _matched_writeup_patterns(observed)

        result = dict(result)
        result["family_analyzer"] = {
            **self.metadata(),
            "rule_version": BOLA_FAMILY_ANALYZER_RULE_VERSION,
            "taxonomy": taxonomy_for_family(self.family),
            "methodology": [dict(step) for step in BOLA_METHOD],
            "writeup_patterns": matched_writeups,
            "false_positive_checks": list(BOLA_FALSE_POSITIVE_CHECKS),
            "triggered_false_positive_checks": _specific_false_positive_checks(contradictions),
            "promotion_required": [sorted(group) for group in policy["promotion_required"]],
            "confirmation_required": [sorted(group) for group in policy["confirmation_required"]],
            "confirmation_missing": confirmation_missing,
            "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
            "next_evidence": list(policy.get("next_evidence", ())),
            "validation_level": str(policy.get("validation_level") or "controlled"),
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
    "BOLA_METHOD",
    "BolaFamilyAnalyzer",
    "analyze_bola_signal",
]

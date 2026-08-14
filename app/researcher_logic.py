from __future__ import annotations

import re
from typing import Any, Mapping

from analysis_standards import standards_for_family
from family_detectors.registry import DETECTOR_SPECS

RESEARCHER_LOGIC_VERSION = "1.0.0"
RESEARCHER_LOGIC_RULE_VERSION = "2026.08.14.6.32.1"


def _humanize(value: Any) -> str:
    text = re.sub(r"[_\-]+", " ", str(value or "").strip())
    return re.sub(r"\s+", " ", text).strip()


def _source_free_standard_logic(standards: Mapping[str, Any]) -> dict[str, list[str]]:
    """Return standard concepts without source/ref/url provenance.

    Standards guide the analytical method only. They are never target evidence.
    """
    principle = str(standards.get("principle") or "").strip()
    owasp: list[str] = []
    for item in standards.get("owasp") or []:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "").strip()
        if title:
            owasp.append(title)
    cwe: list[str] = []
    for item in standards.get("cwe") or []:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "").strip()
        if title:
            cwe.append(title)
    wstg: list[str] = []
    for item in standards.get("wstg") or []:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "").strip()
        if title:
            wstg.append(title)
    return {
        "testing_concepts": list(dict.fromkeys(wstg)),
        "risk_concepts": list(dict.fromkeys(owasp)),
        "weakness_concepts": list(dict.fromkeys(cwe)),
        "principles": [principle] if principle else [],
    }


def researcher_logic_for_family(family: str) -> dict[str, Any]:
    """Build the source-free researcher playbook for one vulnerability family.

    This structure is intentionally explanatory. It cannot create, satisfy, or
    promote target evidence. Write-up lessons are reduced to their reasoning
    patterns rather than exposing source names or citations in normal analysis.
    """
    if family not in DETECTOR_SPECS:
        raise KeyError(f"unknown family researcher logic: {family}")
    spec = DETECTOR_SPECS[family]
    standards = standards_for_family(family)
    standard_logic = _source_free_standard_logic(standards)
    required_groups = [sorted(_humanize(value) for value in group) for group in spec.required_groups]
    identity_groups = required_groups[:-1] if required_groups else []
    decisive = sorted(_humanize(value) for value in spec.condition_signals)
    controls = sorted(_humanize(value) for value in spec.blocking_controls)
    overrides = sorted(_humanize(value) for value in spec.override_signals)
    writeup_logic = [
        str(ref.lesson).strip()
        for ref in spec.writeups
        if str(ref.lesson).strip()
    ]

    return {
        "version": RESEARCHER_LOGIC_VERSION,
        "rule_version": RESEARCHER_LOGIC_RULE_VERSION,
        "role": "reasoning_guidance_only_not_target_evidence",
        "security_principle": str(spec.principle or standards.get("principle") or "").strip(),
        "research_strategy": str(spec.strategy or "").strip(),
        "attack_surface_terms": list(dict.fromkeys(_humanize(value) for value in spec.surface_terms if _humanize(value))),
        "identity_preconditions": identity_groups,
        "decisive_condition_signals": decisive,
        "expected_controls": controls,
        "override_conditions": overrides,
        "writeup_logic": list(dict.fromkeys(writeup_logic)),
        "standards_logic": standard_logic,
        "reasoning_sequence": [
            "Establish the family identity from target-specific surface and precondition evidence.",
            "Look for a direct observation of the decisive security condition rather than inferring it from a route name or keyword.",
            "Check for an implemented control or contradictory observation that falsifies exploitability.",
            "Separate a near miss from a vulnerability by testing whether the trust or authorization boundary is actually crossed in the stored evidence.",
            "Treat absent evidence as unknown; do not convert missing telemetry into proof of a vulnerability or proof of safety.",
        ],
        "falsifiers": controls,
        "evidence_policy": "Standards and write-up logic guide interpretation only; admission requires target/source-grounded evidence and they never count as an independent source.",
    }


def validate_researcher_logic() -> list[str]:
    errors: list[str] = []
    for family in DETECTOR_SPECS:
        logic = researcher_logic_for_family(family)
        if not logic.get("security_principle"):
            errors.append(f"{family}:missing_security_principle")
        if not logic.get("decisive_condition_signals"):
            errors.append(f"{family}:missing_decisive_conditions")
        if not logic.get("writeup_logic"):
            errors.append(f"{family}:missing_writeup_logic")
        serialized = repr(logic).lower()
        for forbidden in ("'source':", "'url':", "'ref':"):
            if forbidden in serialized:
                errors.append(f"{family}:provenance_leaked:{forbidden}")
    return errors


_REGISTRY_ERRORS = validate_researcher_logic()
if _REGISTRY_ERRORS:
    raise RuntimeError("Analysis 6.32 researcher logic registry invalid: " + "; ".join(_REGISTRY_ERRORS))

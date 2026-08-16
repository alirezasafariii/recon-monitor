from __future__ import annotations

"""Source-free researcher playbooks for canonical final-analyzer families.

Standards and write-up research define methodology only. This projection strips
source/ref/url provenance and exposes reasoning guidance that cannot create or
satisfy target evidence. Admission is computed independently before this logic
is attached to an assessment.
"""

import re
from typing import Any, Mapping

from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec

RESEARCHER_LOGIC_VERSION = "1.0.0"
RESEARCHER_LOGIC_RULE_VERSION = "2026.08.16.1"


def _humanize(value: Any) -> str:
    text = re.sub(r"[_\-]+", " ", str(value or "").strip())
    return re.sub(r"\s+", " ", text).strip()


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def researcher_logic_for_family(family: str) -> dict[str, Any]:
    """Return an explanatory playbook with zero target-evidence authority."""

    if family not in MIGRATED_FAMILIES:
        raise KeyError(f"family has no canonical final-analyzer spec: {family}")
    spec = get_detection_spec(family)
    promotion_groups = [set(group) for group in spec.promotion_required]
    decisive = set(promotion_groups[-1]) if promotion_groups else set()
    identity_groups: list[list[str]] = []
    for group in promotion_groups[:-1]:
        values = sorted(_humanize(value) for value in (group - decisive) if _humanize(value))
        if values:
            identity_groups.append(values)

    methodology = _unique([str(step.principle).strip() for step in spec.standard.methodology])
    writeup_logic = _unique([str(item.lesson).strip() for item in spec.standard.writeups])
    controls = sorted(_humanize(value) for value in spec.blocking_contradictions)
    overrides = sorted(_humanize(value) for value in spec.override_signals)

    return {
        "version": RESEARCHER_LOGIC_VERSION,
        "rule_version": RESEARCHER_LOGIC_RULE_VERSION,
        "role": "reasoning_guidance_only_not_target_evidence",
        "family": spec.family,
        "family_spec_version": spec.version,
        "security_principle": str(spec.principle).strip(),
        "research_strategy": str(spec.strategy).strip(),
        "attack_surface_terms": _unique([_humanize(value) for value in spec.standard.surface_terms]),
        "attack_surface_fields": _unique([_humanize(value) for value in spec.standard.surface_fields]),
        "identity_preconditions": identity_groups,
        "decisive_condition_signals": sorted(_humanize(value) for value in decisive),
        "expected_controls": controls,
        "override_conditions": overrides,
        "confounders": list(spec.standard.confounders),
        "false_positive_checks": list(spec.standard.false_positive_checks),
        "methodology_logic": methodology,
        "writeup_logic": writeup_logic,
        "reasoning_sequence": [
            "Establish the family identity from target-specific surface and precondition observations.",
            "Require a direct stored observation of the decisive security condition instead of inferring it from names, keywords, standards, or missing telemetry.",
            "Search for implemented controls and contradictory observations that falsify the vulnerable interpretation.",
            "Keep support, contradiction, and unknown evidence separate; absence of evidence is not evidence of vulnerability or safety.",
            "Treat standards and real-world research as methodology provenance only; they never count as an independent target-evidence source.",
        ],
        "evidence_policy": "advisory_only_non_evidentiary",
    }


def _forbidden_key_present(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower() in {"source", "ref", "url", "counts_as_target_evidence"}:
                return True
            if _forbidden_key_present(child):
                return True
    elif isinstance(value, list):
        return any(_forbidden_key_present(child) for child in value)
    return False


def validate_researcher_logic() -> list[str]:
    errors: list[str] = []
    for family in MIGRATED_FAMILIES:
        logic = researcher_logic_for_family(family)
        if not logic.get("security_principle"):
            errors.append(f"{family}:missing_security_principle")
        if not logic.get("decisive_condition_signals"):
            errors.append(f"{family}:missing_decisive_conditions")
        if not logic.get("writeup_logic"):
            errors.append(f"{family}:missing_writeup_logic")
        if _forbidden_key_present(logic):
            errors.append(f"{family}:provenance_leaked_into_source_free_logic")
    return errors


_ERRORS = validate_researcher_logic()
if _ERRORS:
    raise RuntimeError("Final analyzer researcher logic invalid: " + "; ".join(_ERRORS))

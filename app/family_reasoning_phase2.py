from __future__ import annotations

"""Family Reasoning contracts for OWASP/WSTG expansion phase 2.

Each family has its own canonical evidence vocabulary from ``owasp_phase2_catalog``.
The builder only removes repetitive dictionary boilerplate; it does not create a
runtime fallback analyzer or turn taxonomy/knowledge into target evidence.
"""

from owasp_phase2_catalog import PHASE2_FAMILY_ORDER, PHASE2_FAMILY_SPECS

FAMILY_REASONING_PHASE2_VERSION = "1.0.0"
FAMILY_REASONING_RULE_VERSION = "2026.08.13.5"


def _req(key: str, label: str, why: str) -> dict[str, str]:
    return {"key": key, "label": label, "why": why}


def _groups(groups):
    return tuple(frozenset(group) for group in groups)


def _policy(family: str, spec: dict) -> dict:
    manual = spec["validation"] == "manual_only"
    return {
        "label": spec["label"],
        "category": spec["category"],
        "promotion_required": _groups((spec["context"], tuple(spec["unsafe"]) + tuple(spec["direct"]))),
        "min_independent_sources": 2 if manual else 1,
        "blocking_contradictions": frozenset(spec["contradictions"]),
        "override_signals": frozenset(spec["direct"]),
        "confirmation_required": _groups((spec["direct"],)),
        "case_requirements": (
            _req("affected_surface", "Affected security surface", f"Identify the exact target-side surface for {spec['label']}."),
            _req("target_evidence", "Concrete target evidence", "Record stored target observations; OWASP/WSTG/CWE/write-ups are reasoning context only."),
            _req("secure_baseline", "Expected secure behavior", "Document the expected control or invariant and any contradiction evidence."),
            _req("validation_context", "Safe validation context", "Use passive evidence or an explicitly authorized benign controlled test according to the family safety class."),
        ),
        "next_evidence": (
            f"Identify the exact target-side boundary for {spec['label']}.",
            "Collect a second independent target-evidence root and the expected secure baseline.",
            spec["safe"],
        ),
        "validation_level": spec["validation"],
    }


PHASE2_FAMILY_REASONING = {
    family: _policy(family, spec)
    for family, spec in PHASE2_FAMILY_SPECS.items()
}

assert tuple(PHASE2_FAMILY_REASONING) == PHASE2_FAMILY_ORDER

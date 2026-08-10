from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from analysis_standards import standards_for_family
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission

CORPUS_VALIDATOR_VERSION = "1.0.0"
VALID_SPLITS = {"development", "held_out"}
FORBIDDEN_EVIDENCE_SOURCES = {
    "knowledge", "external_writeup", "owasp", "owasp_wstg", "wstg",
    "mitre_cwe", "cwe", "standards", "provenance",
}
FORBIDDEN_EVIDENCE_TYPES = {"knowledge_reference", "wstg_reference", "cwe_reference"}

MIN_REAL_POSITIVE_ROOTS = 40
MIN_SOURCE_PROJECTS = 25
MIN_HELD_OUT_ROOTS = 10
MIN_HELD_OUT_CASES = 30

def _norm(value: Any) -> str:
    return str(value or "").strip()

def _evidence_is_external(item: Mapping[str, Any]) -> bool:
    source = _norm(item.get("source")).lower()
    group = _norm(item.get("source_group")).lower()
    kind = _norm(item.get("type")).lower()
    return source in FORBIDDEN_EVIDENCE_SOURCES or group in FORBIDDEN_EVIDENCE_SOURCES or kind in FORBIDDEN_EVIDENCE_TYPES

def validate_corpus(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(case) for case in cases]
    errors: list[str] = []
    roots_by_split: dict[str, set[str]] = defaultdict(set)
    real_positive_roots: set[str] = set()
    source_projects: set[str] = set()
    source_kinds = Counter()
    split_counts = Counter()
    held_out_roots: set[str] = set()
    family_real_roots: dict[str, set[str]] = defaultdict(set)

    for case in rows:
        cid = _norm(case.get("id"))
        family = _norm(case.get("family"))
        split = _norm(case.get("split"))
        root = _norm(case.get("source_root"))
        project = _norm(case.get("source_project"))
        provenance = case.get("provenance") if isinstance(case.get("provenance"), Mapping) else {}
        source_kind = _norm(provenance.get("source_kind"))
        url = _norm(provenance.get("url"))
        source_date = _norm(case.get("source_date") or provenance.get("source_date"))

        if family not in FAMILY_ADMISSION_POLICIES:
            errors.append(f"{cid}: unknown family {family}")
            continue
        if split not in VALID_SPLITS:
            errors.append(f"{cid}: invalid split {split!r}")
        if not root:
            errors.append(f"{cid}: missing source_root")
        if not project:
            errors.append(f"{cid}: missing source_project")
        if not source_date:
            errors.append(f"{cid}: missing source_date")
        if not url.startswith("https://"):
            errors.append(f"{cid}: provenance URL must be HTTPS")
        if root:
            roots_by_split[split].add(root)
            if split == "held_out":
                held_out_roots.add(root)
        if project:
            source_projects.add(project)
        source_kinds[source_kind] += 1
        split_counts[split] += 1

        support = case.get("support") if isinstance(case.get("support"), list) else []
        contradict = case.get("contradict") if isinstance(case.get("contradict"), list) else []
        for item in [*support, *contradict]:
            if isinstance(item, Mapping) and _evidence_is_external(item):
                errors.append(f"{cid}: external knowledge leaked into target evidence ({_norm(item.get('type'))})")

        expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
        expected_admitted = bool(expected.get("admitted"))
        assessment = assess_admission(family, support, contradict)
        if bool(assessment.get("admitted")) != expected_admitted:
            errors.append(f"{cid}: expected admission={expected_admitted} but engine returned {bool(assessment.get('admitted'))}")

        standards = case.get("standards") if isinstance(case.get("standards"), Mapping) else {}
        canonical = standards_for_family(family)
        expected_wstg = {str(item.get("id")) for item in canonical.get("wstg", [])}
        expected_cwe = {str(item.get("id")) for item in canonical.get("cwe", [])}
        row_wstg = {str(value) for value in standards.get("wstg", [])}
        row_cwe = {str(value) for value in standards.get("cwe", [])}
        if not row_wstg or not row_wstg.issubset(expected_wstg):
            errors.append(f"{cid}: WSTG grounding missing or inconsistent")
        if not row_cwe or not row_cwe.issubset(expected_cwe):
            errors.append(f"{cid}: CWE grounding missing or inconsistent")

        if case.get("case_kind") == "positive" and source_kind == "real_writeup":
            if root in real_positive_roots:
                errors.append(f"{cid}: duplicate real-positive source root {root}")
            real_positive_roots.add(root)
            family_real_roots[family].add(root)

    leakage = roots_by_split.get("development", set()) & roots_by_split.get("held_out", set())
    for root in sorted(leakage):
        errors.append(f"source root crosses development/held_out boundary: {root}")

    held_out_cases = split_counts.get("held_out", 0)
    if len(real_positive_roots) < MIN_REAL_POSITIVE_ROOTS:
        errors.append(f"real positive source roots below floor: {len(real_positive_roots)}/{MIN_REAL_POSITIVE_ROOTS}")
    if len(source_projects) < MIN_SOURCE_PROJECTS:
        errors.append(f"source projects below floor: {len(source_projects)}/{MIN_SOURCE_PROJECTS}")
    if len(held_out_roots) < MIN_HELD_OUT_ROOTS:
        errors.append(f"held-out source roots below floor: {len(held_out_roots)}/{MIN_HELD_OUT_ROOTS}")
    if held_out_cases < MIN_HELD_OUT_CASES:
        errors.append(f"held-out cases below floor: {held_out_cases}/{MIN_HELD_OUT_CASES}")

    return {
        "validator_version": CORPUS_VALIDATOR_VERSION,
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "split_counts": dict(split_counts),
        "source_kind_counts": dict(source_kinds),
        "real_positive_source_roots": len(real_positive_roots),
        "source_project_count": len(source_projects),
        "held_out_root_count": len(held_out_roots),
        "held_out_case_count": held_out_cases,
        "source_root_leakage_count": len(leakage),
        "family_real_source_roots": {k: len(v) for k, v in sorted(family_real_roots.items())},
    }

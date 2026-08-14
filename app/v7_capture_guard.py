from __future__ import annotations

"""Fail-closed integrity checks for Fresh Blind V7 capture preparation.

The production Analysis engine is frozen at ENGINE_BASELINE_COMMIT and the V7
source assignment is frozen at SOURCE_ASSIGNMENT_COMMIT. This module validates
that capture preparation remains bound to the committed 36-source assignment,
contains no engine-seen/Corpus-V1 source, and remains strictly pre-scoring.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import validate_shortlist

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.33.v7.capture.guard.2"
ENGINE_BASELINE_COMMIT = "b8b15261cc4049a1e5e425a83e57b6378a856113"
SOURCE_ASSIGNMENT_COMMIT = "5c2c81075b870fe43db817c59a65f27423012f08"
SHORTLIST = ROOT / "benchmarks/raw/sources/v7_shortlist.json"
PROTOCOL = ROOT / "benchmarks/raw/sources/v7_protocol.json"
EXPECTED_FAMILIES = 36
EXPECTED_AUDIT_FALLBACKS = 4
EXPECTED_LITERAL_ADJUDICATION_SOURCES = 13


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in doc.get("selected") or [] if isinstance(row, Mapping)]


def validate_capture_source_freeze() -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    rows = _rows(shortlist)
    errors: list[str] = []

    if len(rows) != EXPECTED_FAMILIES:
        errors.append(f"selected_source_count:{len(rows)}!=36")
    families = {str(row.get("family") or "").strip() for row in rows}
    roots = {str(row.get("source_root") or "").strip().casefold() for row in rows if str(row.get("source_root") or "").strip()}
    projects = {str(row.get("source_project") or "").strip().casefold() for row in rows if str(row.get("source_project") or "").strip()}
    if len(families) != EXPECTED_FAMILIES:
        errors.append(f"unique_family_count:{len(families)}!=36")
    if len(roots) != EXPECTED_FAMILIES:
        errors.append(f"unique_root_count:{len(roots)}!=36")
    if len(projects) != EXPECTED_FAMILIES:
        errors.append(f"unique_project_count:{len(projects)}!=36")

    if shortlist.get("global_assignment_complete") is not True:
        errors.append("global_assignment_not_complete")
    if shortlist.get("scoring_executed") is not False:
        errors.append("shortlist_scoring_executed")
    if shortlist.get("first_blind_consumed") is not False:
        errors.append("shortlist_first_blind_consumed")
    firewall = shortlist.get("firewall") if isinstance(shortlist.get("firewall"), Mapping) else {}
    if firewall.get("passed") is not True:
        errors.append("shortlist_firewall_not_passed")
    if int(firewall.get("engine_seen_count") or 0) != 0:
        errors.append("shortlist_contains_engine_seen_source")

    forbidden_selection_flags = (
        "selection_uses_detector_scores",
        "selection_uses_admission_results",
        "selection_uses_ranking_results",
        "selection_uses_v6_first_blind_score",
        "selection_uses_v6_first_blind_case_errors",
        "selection_uses_corpus_v1_labels",
        "selection_uses_corpus_v1_evidence",
        "selection_uses_corpus_v1_scores",
    )
    for flag in forbidden_selection_flags:
        if shortlist.get(flag) is not False:
            errors.append(f"forbidden_selection_dependency:{flag}")

    engine_baseline = protocol.get("engine_baseline") if isinstance(protocol.get("engine_baseline"), Mapping) else {}
    freeze = protocol.get("freeze_contract") if isinstance(protocol.get("freeze_contract"), Mapping) else {}
    if str(engine_baseline.get("commit_sha") or "") != ENGINE_BASELINE_COMMIT:
        errors.append("protocol_engine_baseline_drift")
    if str(freeze.get("production_reasoning_baseline_commit") or "") != ENGINE_BASELINE_COMMIT:
        errors.append("protocol_freeze_baseline_drift")
    if protocol.get("scoring_executed") is not False:
        errors.append("protocol_scoring_executed")
    if protocol.get("first_blind_consumed") is not False:
        errors.append("protocol_first_blind_consumed")
    if freeze.get("merge_authorized") is not False:
        errors.append("merge_authorized_before_user_confirmation")

    try:
        hard_check = validate_shortlist(rows, required_count=EXPECTED_FAMILIES)
    except Exception as exc:
        hard_check = {"passed": False, "engine_seen_count": -1, "errors": [f"{type(exc).__name__}:{exc}"]}
    if hard_check.get("passed") is not True or int(hard_check.get("engine_seen_count") or 0) != 0:
        errors.append("recomputed_hard_firewall_failed")

    # There are two different concepts in the frozen selection and they must not
    # be conflated:
    #   1. audit fallback: semantic audit failed, so exact-CWE+context was used;
    #   2. targeted-source provenance: source came through targeted discovery and
    #      therefore its family remains provisional until literal evidence proves it.
    # The frozen shortlist contains 4 of the first kind and 13 of the second.
    audit_fallback_families = sorted(
        str(row.get("family") or "")
        for row in rows
        if row.get("source_family_targeted_fallback_pending_literal_adjudication") is True
        or row.get("source_family_target_is_not_final_until_literal_adjudication") is True
    )
    literal_adjudication_required_families = sorted(
        str(row.get("family") or "")
        for row in rows
        if row.get("source_family_targeted_fallback_pending_literal_adjudication") is True
        or row.get("source_family_target_is_not_final_until_literal_adjudication") is True
        or row.get("v7_target_family_requires_literal_adjudication") is True
    )

    declared_audit_fallback_count = int(shortlist.get("selected_targeted_fallback_count") or 0)
    if declared_audit_fallback_count != EXPECTED_AUDIT_FALLBACKS:
        errors.append(f"declared_audit_fallback_count:{declared_audit_fallback_count}!={EXPECTED_AUDIT_FALLBACKS}")
    if len(audit_fallback_families) != EXPECTED_AUDIT_FALLBACKS:
        errors.append(f"derived_audit_fallback_count:{len(audit_fallback_families)}!={EXPECTED_AUDIT_FALLBACKS}")
    if len(literal_adjudication_required_families) != EXPECTED_LITERAL_ADJUDICATION_SOURCES:
        errors.append(
            f"literal_adjudication_required_count:{len(literal_adjudication_required_families)}!={EXPECTED_LITERAL_ADJUDICATION_SOURCES}"
        )

    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_capture_source_freeze_guard",
        "passed": not errors,
        "errors": errors,
        "engine_baseline_commit": ENGINE_BASELINE_COMMIT,
        "source_assignment_commit": SOURCE_ASSIGNMENT_COMMIT,
        "source_shortlist_sha256": _sha(SHORTLIST),
        "protocol_sha256": _sha(PROTOCOL),
        "family_count": len(families),
        "unique_root_count": len(roots),
        "unique_project_count": len(projects),
        "recomputed_engine_seen_count": hard_check.get("engine_seen_count"),
        "research_preexposed_count": hard_check.get("research_preexposed_count"),
        "audit_fallback_families": audit_fallback_families,
        "audit_fallback_count": len(audit_fallback_families),
        "literal_adjudication_required_families": literal_adjudication_required_families,
        "literal_adjudication_required_count": len(literal_adjudication_required_families),
        # Compatibility fields now explicitly mean audit fallback only.
        "targeted_fallback_families": audit_fallback_families,
        "targeted_fallback_count": len(audit_fallback_families),
        "scoring_executed": False,
        "first_blind_consumed": False,
        "merge_authorized": False,
    }


def assert_capture_source_freeze() -> dict[str, Any]:
    result = validate_capture_source_freeze()
    if not result["passed"]:
        raise RuntimeError("v7 capture source freeze failed: " + "; ".join(result["errors"]))
    return result


__all__ = [
    "VERSION",
    "RULE_VERSION",
    "ENGINE_BASELINE_COMMIT",
    "SOURCE_ASSIGNMENT_COMMIT",
    "EXPECTED_AUDIT_FALLBACKS",
    "EXPECTED_LITERAL_ADJUDICATION_SOURCES",
    "validate_capture_source_freeze",
    "assert_capture_source_freeze",
]

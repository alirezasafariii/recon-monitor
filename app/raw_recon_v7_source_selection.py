from __future__ import annotations

import json
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row
from raw_recon_v7_source_firewall import HARD_SCOPE, RESEARCH_SCOPE
from raw_recon_v7_source_firewall import RULE_VERSION as FIREWALL_RULE_VERSION
from raw_recon_v7_source_firewall import VERSION as FIREWALL_VERSION
from raw_recon_v7_source_firewall import (
    check_candidate,
    engine_exposure_index,
    research_exposure_index,
    validate_shortlist,
)

VERSION = "1.3.0"
RULE_VERSION = "2026.08.14.6.33.v7.unseen.4"
CANDIDATES = ROOT / "benchmarks/raw/sources/v7_candidates.json"
OUT = ROOT / "benchmarks/raw/sources/v7_shortlist.json"


def _targeted_pending_adjudication(row: Mapping[str, Any]) -> bool:
    return bool(
        row.get("v7_targeted_gap_candidate") is True
        and row.get("v7_targeted_exact_cwe") is True
        and row.get("v7_targeted_context_match") is True
        and row.get("v7_target_family_is_candidate_only") is True
        and row.get("v7_target_family_requires_literal_adjudication") is True
        and row.get("scoring_executed") is False
    )


def _quality_key(row: Mapping[str, Any], family: str) -> tuple[Any, ...]:
    passed, hits, score = audit_row(family, row)
    source_type = str(row.get("advisory_source_type") or "").lower()
    kind = str(row.get("source_kind") or "").lower()
    reviewed = int(source_type == "reviewed" or "reviewed" in kind or "repository_advisory" in kind)
    repository_location = int(bool(str(row.get("source_code_location") or row.get("repository_advisory_url") or "").strip()))
    description_length = min(len(str(row.get("description") or "")), 5000)
    published = str(row.get("published_at") or "")
    research_fresh = int(not bool(row.get("v7_research_preexposed")))
    # Fully audited semantic candidates win. Targeted CWE+context candidates are
    # fallback only and remain unlabelled until literal source adjudication.
    semantically_audited = int(passed)
    return (
        semantically_audited, research_fresh, score, reviewed, repository_location,
        description_length, published, str(row.get("source_root") or ""),
        str(row.get("source_project") or ""),
    )


def _prepare_pool(
    family: str,
    rows: list[Any],
    *,
    hard_index: Mapping[str, set[str]],
    research_index: Mapping[str, set[str]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_roots: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        firewall = check_candidate(row, index=hard_index, research_index=research_index)
        if not firewall["allowed"] or firewall["engine_seen"]:
            continue
        passed, hits, score = audit_row(family, row)
        targeted_pending = _targeted_pending_adjudication(row)
        if not passed and not targeted_pending:
            continue
        root = str(row.get("source_root") or "").strip().casefold()
        project = str(row.get("source_project") or "").strip().casefold()
        if not root or not project or root in seen_roots:
            continue
        seen_roots.add(root)
        row.update({
            "family": family,
            "v7_firewall_allowed": True,
            "v7_engine_seen": False,
            "v7_research_preexposed": bool(firewall["research_preexposed"]),
            "v7_firewall_version": FIREWALL_VERSION,
            "v7_firewall_rule_version": FIREWALL_RULE_VERSION,
            "source_family_audit_version": AUDIT_VERSION,
            "source_family_audit_rule_version": AUDIT_RULE_VERSION,
            "source_family_audit_passed": bool(passed),
            "source_family_audit_group_hits": hits,
            "source_family_audit_score": score,
            "source_family_targeted_fallback_pending_literal_adjudication": bool(targeted_pending and not passed),
            "source_selection_track": "fresh_v7_engine_unseen_global_semantic_or_targeted_context_pool",
            "selection_basis": (
                "passive source selected before scoring; hard-blocked against all materialized/scored Analysis corpora and pinned Corpus V1; "
                "research-only preexposure recorded and deprioritized; normal candidates require semantic audit; targeted gap fallback requires exact advisory CWE plus family context and remains candidate-only pending literal source adjudication; global root/project uniqueness enforced"
            ),
            "hard_engine_exposure_scope": HARD_SCOPE,
            "research_preexposure_scope": RESEARCH_SCOPE,
            "selection_uses_v6_score": False,
            "selection_uses_v6_case_errors": False,
            "selection_uses_corpus_v1_labels": False,
            "selection_uses_corpus_v1_evidence": False,
            "selection_uses_corpus_v1_scores": False,
        })
        result.append(row)
    return sorted(result, key=lambda row: _quality_key(row, family), reverse=True)


def _solve(families: list[str], pools: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
    order = sorted(families, key=lambda family: (len(pools[family]), family))
    chosen: dict[str, dict[str, Any]] = {}
    used_roots: set[str] = set()
    used_projects: set[str] = set()

    def visit(index: int) -> bool:
        if index >= len(order):
            return True
        family = order[index]
        for row in pools[family]:
            root = str(row.get("source_root") or "").strip().casefold()
            project = str(row.get("source_project") or "").strip().casefold()
            if root in used_roots or project in used_projects:
                continue
            used_roots.add(root); used_projects.add(project); chosen[family] = row
            if visit(index + 1):
                return True
            chosen.pop(family, None); used_roots.remove(root); used_projects.remove(project)
        return False

    if not visit(0):
        return None
    return [chosen[family] for family in sorted(families)]


def select() -> dict[str, Any]:
    raw = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    if raw.get("scoring_executed") is not False:
        raise RuntimeError("v7 source candidates must remain unscored")
    forbidden_flags = (
        "candidate_selection_uses_v6_first_blind_score",
        "candidate_selection_uses_v6_first_blind_case_errors",
        "candidate_selection_uses_corpus_v1_labels",
        "candidate_selection_uses_corpus_v1_evidence",
        "candidate_selection_uses_corpus_v1_scores",
    )
    if any(raw.get(flag) is not False for flag in forbidden_flags):
        raise RuntimeError("v7 source discovery was contaminated by prior blind/calibration data")
    raw_pools = raw.get("candidates_by_family") if isinstance(raw.get("candidates_by_family"), Mapping) else {}
    families = sorted(str(family) for family in raw_pools)
    if len(families) != 36:
        raise RuntimeError(f"v7 discovery family coverage must be 36, got {len(families)}")

    hard_index = engine_exposure_index()
    research_index = research_exposure_index()
    pools = {
        family: _prepare_pool(
            family,
            list(raw_pools.get(family) or []),
            hard_index=hard_index,
            research_index=research_index,
        )
        for family in families
    }
    missing = sorted(family for family, rows in pools.items() if not rows)
    selected = None if missing else _solve(families, pools)
    if not missing and selected is None:
        raise RuntimeError("v7 global uniqueness solver found no complete 36-family assignment")
    firewall = validate_shortlist(selected or [], required_count=36) if selected is not None else {
        "passed": False, "errors": ["candidate coverage incomplete"], "candidate_count": 0,
        "unique_root_count": 0, "unique_project_count": 0, "engine_seen_count": 0,
        "research_preexposed_count": 0, "rejected": [], "firewall_version": FIREWALL_VERSION,
        "firewall_rule_version": FIREWALL_RULE_VERSION, "hard_scope": HARD_SCOPE,
        "research_scope": RESEARCH_SCOPE, "scoring_executed": False,
    }
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_unscored_source_selection",
        "family_count": 36,
        "selected": selected or [],
        "candidate_counts_after_audit_or_targeted_fallback": {family: len(rows) for family, rows in pools.items()},
        "families_without_candidates": missing,
        "global_assignment_complete": selected is not None,
        "firewall": firewall,
        "hard_engine_exposure_scope": HARD_SCOPE,
        "research_preexposure_scope": RESEARCH_SCOPE,
        "selected_research_preexposed_count": sum(bool(row.get("v7_research_preexposed")) for row in (selected or [])),
        "selected_targeted_fallback_count": sum(bool(row.get("source_family_targeted_fallback_pending_literal_adjudication")) for row in (selected or [])),
        "source_family_audit_version": AUDIT_VERSION,
        "source_family_audit_rule_version": AUDIT_RULE_VERSION,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_ranking_results": False,
        "selection_uses_v6_first_blind_score": False,
        "selection_uses_v6_first_blind_case_errors": False,
        "selection_uses_corpus_v1_labels": False,
        "selection_uses_corpus_v1_evidence": False,
        "selection_uses_corpus_v1_scores": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    return report


def main() -> int:
    report = select()
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "selected_count": len(report["selected"]),
        "families_without_candidates": report["families_without_candidates"],
        "global_assignment_complete": report["global_assignment_complete"],
        "firewall_passed": report["firewall"]["passed"],
        "engine_seen_count": report["firewall"].get("engine_seen_count"),
        "selected_research_preexposed_count": report["selected_research_preexposed_count"],
        "selected_targeted_fallback_count": report["selected_targeted_fallback_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0 if report["global_assignment_complete"] and report["firewall"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION
from v7_source_semantic_audit import audit_row
from raw_recon_v7_source_firewall import RULE_VERSION as FIREWALL_RULE_VERSION
from raw_recon_v7_source_firewall import VERSION as FIREWALL_VERSION
from raw_recon_v7_source_firewall import check_candidate, exposure_index, validate_shortlist
from v7_pre_score_condition_audit import RULE_VERSION as CONDITION_AUDIT_RULE_VERSION
from v7_pre_score_condition_audit import VERSION as CONDITION_AUDIT_VERSION
from v7_pre_score_condition_audit import audit_conditions

VERSION = "1.1.1"
RULE_VERSION = "2026.08.14.6.32.v7.9"
CANDIDATES = ROOT / "benchmarks/raw/sources/v7_candidates_patchable.json"
OUT = ROOT / "benchmarks/raw/sources/v7_shortlist.json"


def _repository_reference(row: Mapping[str, Any]) -> str:
    candidates = [
        str(row.get("upstream_repository_reference") or "").strip(),
        str(row.get("source_code_location") or "").strip(),
    ]
    candidates.extend(str(value).strip() for value in row.get("references") or [] if str(value).strip())
    project = str(row.get("source_project") or "").strip().casefold()
    for value in candidates:
        parsed = urlparse(value)
        if parsed.scheme != "https" or parsed.netloc.casefold() != "github.com":
            continue
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 4:
            continue
        repo = f"{parts[0]}/{parts[1]}".casefold()
        if project and repo != project:
            continue
        if parts[2] in {"commit", "pull"}:
            return value
    return ""


def _quality_key(row: Mapping[str, Any], family: str) -> tuple[Any, ...]:
    passed, hits, score = audit_row(family, row)
    condition_signals, condition_hits = audit_conditions(family, row)
    source_type = str(row.get("advisory_source_type") or "").lower()
    kind = str(row.get("source_kind") or "").lower()
    reviewed = int(source_type == "reviewed" or "reviewed" in kind or "repository_advisory" in kind)
    repository_location = int(bool(_repository_reference(row)))
    condition_score = sum(len(values) for values in condition_hits.values())
    patch_score = int(row.get("patch_probe_passed") is True) + min(int(row.get("patch_file_count") or 0), 10)
    description_length = min(len(str(row.get("description") or "")), 5000)
    published = str(row.get("published_at") or "")
    return (
        int(passed), len(condition_signals), condition_score, patch_score, score, repository_location,
        reviewed, description_length, published,
        str(row.get("source_root") or ""), str(row.get("source_project") or ""),
    )


def _prepare_pool(family: str, rows: list[Any], prior_index: Mapping[str, set[str]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_roots: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        if row.get("patch_probe_passed") is not True:
            continue
        if int(row.get("patch_added_line_count") or 0) <= 0 or int(row.get("patch_removed_line_count") or 0) <= 0:
            continue
        firewall = check_candidate(row, index=prior_index)
        if not firewall["allowed"]:
            continue
        passed, hits, score = audit_row(family, row)
        if not passed:
            continue
        condition_signals, condition_hits = audit_conditions(family, row)
        if not condition_signals:
            continue
        upstream = _repository_reference(row)
        if not upstream:
            continue
        root = str(row.get("source_root") or "").strip().casefold()
        project = str(row.get("source_project") or "").strip().casefold()
        if not root or not project or root in seen_roots:
            continue
        seen_roots.add(root)
        row.update({
            "family": family,
            "v7_firewall_allowed": True,
            "v7_firewall_version": FIREWALL_VERSION,
            "v7_firewall_rule_version": FIREWALL_RULE_VERSION,
            "source_family_audit_version": AUDIT_VERSION,
            "source_family_audit_rule_version": AUDIT_RULE_VERSION,
            "source_family_audit_group_hits": hits,
            "source_family_audit_score": score,
            "pre_score_condition_audit_version": CONDITION_AUDIT_VERSION,
            "pre_score_condition_audit_rule_version": CONDITION_AUDIT_RULE_VERSION,
            "pre_score_expected_condition_signals": condition_signals,
            "pre_score_condition_source_hits": condition_hits,
            "source_selection_track": "fresh_v7_global_semantic_condition_grounded_patchable_pool",
            "upstream_repository_reference": upstream,
            "capture_feasibility_requires_upstream_reference": True,
            "selection_basis": "fresh passive source selected before scoring by preregistered family semantic audit, source-text condition audit, v1-v6 firewall, verified patch feasibility, and global root/project uniqueness",
            "selection_uses_v6_score": False,
            "selection_uses_v6_case_errors": False,
        })
        result.append(row)
    return sorted(result, key=lambda row: _quality_key(row, family), reverse=True)


def _solve(families: list[str], pools: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
    order = sorted(families, key=lambda family: (len(pools[family]), family))
    chosen: dict[str, dict[str, Any]] = {}
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    def visit(index: int) -> bool:
        if index >= len(order): return True
        family = order[index]
        for row in pools[family]:
            root = str(row.get("source_root") or "").strip().casefold()
            project = str(row.get("source_project") or "").strip().casefold()
            if root in used_roots or project in used_projects: continue
            used_roots.add(root); used_projects.add(project); chosen[family] = row
            if visit(index + 1): return True
            chosen.pop(family, None); used_roots.remove(root); used_projects.remove(project)
        return False
    if not visit(0): return None
    return [chosen[family] for family in sorted(families)]


def select() -> dict[str, Any]:
    raw = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    if raw.get("scoring_executed") is not False: raise RuntimeError("v7 source candidates must remain unscored")
    if raw.get("candidate_selection_uses_v6_first_blind_score") is not False or raw.get("candidate_selection_uses_v6_first_blind_case_errors") is not False: raise RuntimeError("v7 source discovery was contaminated by v6 First Blind results")
    raw_pools = raw.get("candidates_by_family") if isinstance(raw.get("candidates_by_family"), Mapping) else {}
    families = sorted(str(family) for family in raw_pools)
    if len(families) != 36: raise RuntimeError(f"v7 discovery family coverage must be 36, got {len(families)}")
    prior_index = exposure_index()
    pools = {family: _prepare_pool(family, list(raw_pools.get(family) or []), prior_index) for family in families}
    missing = sorted(family for family, rows in pools.items() if not rows)
    selected = None if missing else _solve(families, pools)
    if not missing and selected is None: raise RuntimeError("v7 global uniqueness solver found no complete 36-family assignment")
    firewall = validate_shortlist(selected or [], required_count=36) if selected is not None else {
        "passed": False, "errors": ["semantic/condition-grounded/patch-feasible candidate coverage incomplete"], "candidate_count": 0,
        "unique_root_count": 0, "unique_project_count": 0, "rejected": [], "firewall_version": FIREWALL_VERSION,
        "firewall_rule_version": FIREWALL_RULE_VERSION, "scoring_executed": False,
    }
    return {
        "version": VERSION, "rule_version": RULE_VERSION, "evaluation_kind": "fresh_blind_v7_unscored_source_selection",
        "family_count": 36, "selected": selected or [], "semantic_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "families_without_semantic_candidates": missing, "global_assignment_complete": selected is not None, "firewall": firewall,
        "capture_feasibility_requires_upstream_repository_reference": True, "capture_feasibility_requires_verified_patch": True,
        "source_family_audit_version": AUDIT_VERSION, "source_family_audit_rule_version": AUDIT_RULE_VERSION,
        "pre_score_condition_audit_version": CONDITION_AUDIT_VERSION, "pre_score_condition_audit_rule_version": CONDITION_AUDIT_RULE_VERSION,
        "selection_uses_detector_scores": False, "selection_uses_admission_results": False, "selection_uses_ranking_results": False,
        "selection_uses_v6_first_blind_score": False, "selection_uses_v6_first_blind_case_errors": False,
        "active_target_validation_performed": False, "scoring_executed": False, "first_blind_consumed": False,
    }


def main() -> int:
    report = select(); OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"family_count": report["family_count"], "selected_count": len(report["selected"]), "semantic_candidate_counts": report["semantic_candidate_counts"], "families_without_semantic_candidates": report["families_without_semantic_candidates"], "global_assignment_complete": report["global_assignment_complete"], "firewall_passed": report["firewall"]["passed"], "scoring_executed": report["scoring_executed"]}, sort_keys=True))
    return 0 if report["global_assignment_complete"] and report["firewall"]["passed"] else 2

if __name__ == "__main__": raise SystemExit(main())

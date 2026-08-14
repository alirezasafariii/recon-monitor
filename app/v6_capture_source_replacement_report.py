from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

CANDIDATES = ROOT / "benchmarks/raw/sources/v6_candidates.json"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_capture_source_replacement_report.json"

COMMIT_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}")
PULL_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/pull/\d+")
ISSUE_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/issues/\d+")


def _refs(candidate: Mapping[str, Any]) -> list[str]:
    refs = [str(value) for value in candidate.get("references") or [] if str(value)]
    for key in ("source_code_location", "repository_advisory_url", "canonical_advisory_url"):
        value = str(candidate.get(key) or "")
        if value:
            refs.append(value)
    return sorted(set(refs))


def _score(candidate: Mapping[str, Any]) -> tuple[int, list[str]]:
    refs = _refs(candidate)
    reasons: list[str] = []
    score = 0
    commits = [ref for ref in refs if COMMIT_RE.fullmatch(ref)]
    pulls = [ref for ref in refs if PULL_RE.fullmatch(ref)]
    issues = [ref for ref in refs if ISSUE_RE.fullmatch(ref)]
    if commits:
        score += 12 + min(6, len(commits) * 2)
        reasons.append(f"direct_patch_or_change_commit:{len(commits)}")
    if pulls:
        score += 9 + min(4, len(pulls))
        reasons.append(f"pull_request_context:{len(pulls)}")
    if issues:
        score += 4
        reasons.append(f"repository_issue_context:{len(issues)}")
    if str(candidate.get("repository_advisory_url") or ""):
        score += 5
        reasons.append("repository_security_advisory")
    source_location = str(candidate.get("source_code_location") or "")
    if "/commit/" in source_location:
        score += 6
        reasons.append("source_code_location_is_commit")
    elif "/pull/" in source_location:
        score += 4
        reasons.append("source_code_location_is_pull")
    if len(refs) >= 3:
        score += 2
        reasons.append("multiple_independent_references")
    if str(candidate.get("advisory_source_type") or "") == "reviewed":
        score += 2
        reasons.append("reviewed_advisory")
    return score, reasons


def build_report() -> dict[str, Any]:
    candidates_doc = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    candidates_by_family = candidates_doc.get("candidates_by_family") or {}

    selected = {
        str(row.get("family") or ""): dict(row)
        for row in shortlist.get("selected") or []
        if isinstance(row, Mapping)
    }
    selected_roots = {str(row.get("source_root") or "") for row in selected.values()}
    selected_projects = {str(row.get("source_project") or "") for row in selected.values()}

    remaining = sorted({
        str(row.get("family") or "")
        for row in plan.get("requirements") or []
        if isinstance(row, Mapping) and not bool(row.get("evidence_present"))
    })
    rows = []
    for family in remaining:
        current = selected.get(family, {})
        current_root = str(current.get("source_root") or "")
        current_project = str(current.get("source_project") or "")
        alternatives = []
        for raw in candidates_by_family.get(family) or []:
            if not isinstance(raw, Mapping) or raw.get("v6_firewall_allowed") is not True:
                continue
            candidate = dict(raw)
            root = str(candidate.get("source_root") or "")
            project = str(candidate.get("source_project") or "")
            if not root or not project or (root == current_root and project == current_project):
                continue
            # A replacement may reuse neither another selected root nor another selected project.
            other_roots = selected_roots - {current_root}
            other_projects = selected_projects - {current_project}
            if root in other_roots or project in other_projects:
                continue
            score, reasons = _score(candidate)
            alternatives.append({
                "source_root": root,
                "source_project": project,
                "canonical_advisory_url": str(candidate.get("canonical_advisory_url") or ""),
                "source_code_location": str(candidate.get("source_code_location") or ""),
                "references": _refs(candidate),
                "feasibility_score": score,
                "feasibility_reasons": reasons,
                "advisory_source_type": str(candidate.get("advisory_source_type") or ""),
                "severity": str(candidate.get("severity") or ""),
            })
        alternatives.sort(key=lambda row: (-int(row["feasibility_score"]), row["source_root"]))
        current_score, current_reasons = _score(current)
        rows.append({
            "family": family,
            "current_source_root": current_root,
            "current_source_project": current_project,
            "current_feasibility_score": current_score,
            "current_feasibility_reasons": current_reasons,
            "replacement_candidate_count": len(alternatives),
            "recommended_replacements": alternatives[:5],
        })

    improved = [row for row in rows if row["recommended_replacements"] and row["recommended_replacements"][0]["feasibility_score"] > row["current_feasibility_score"]]
    return {
        "evaluation_kind": "fresh_blind_v6_capture_source_replacement_feasibility_unscored",
        "remaining_family_count": len(rows),
        "families_with_better_candidate_count": len(improved),
        "families": rows,
        "policy": "report_only_no_source_mutation; candidates must already be semantic-family candidates and v6_firewall_allowed; unique selected roots/projects are preserved",
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    report = build_report()
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Mapping

import raw_recon_v7_missing5_supplement as github_source
from analysis_standards import FAMILY_STANDARDS
from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.32.v7.31"
OUT = ROOT / "benchmarks/raw/sources/v7_collision_supplement.json"

# These identifiers are the pre-existing canonical grounding for the two
# collision families. They guide source acceptance but NEVER count as target
# evidence, admission evidence, or benchmark labels.
EXPECTED_GROUNDING = {
    "race_condition": {
        "wstg": {"WSTG-BUSL-04"},
        "cwe": {"CWE-362"},
        "owasp": {"A06:2025"},
        "writeup_contains": "GHSL-2025-038",
    },
    "authentication_session": {
        "wstg": {"WSTG-ATHN-04", "WSTG-SESS-01"},
        "cwe": {"CWE-287"},
        "owasp": {"A07:2025", "API2:2023"},
        "writeup_contains": "GHSL-2024-329/330",
    },
}

SOURCES = {
    "race_condition": {
        "project": "qnbs/WorldScript-Studio",
        "pr_number": 339,
        "source_root": "GITHUB-PR-qnbs-WorldScript-Studio-339",
        "source_kind": "github_merged_security_pr_race_toctou_fix",
    },
    "authentication_session": {
        "project": "tammam-alsoleman/decentralized-real-estate-platform",
        "pr_number": 169,
        "source_root": "GITHUB-PR-tammam-alsoleman-decentralized-real-estate-platform-169",
        "source_kind": "github_merged_security_pr_auth_session_binding_fix",
    },
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _grounding(family: str) -> dict[str, Any]:
    standards = FAMILY_STANDARDS[family]
    spec = DETECTOR_SPECS[family]
    wstg = {str(item.get("id") or "") for item in standards.get("wstg", [])}
    cwe = {str(item.get("id") or "") for item in standards.get("cwe", [])}
    owasp = {str(item.get("id") or "") for item in standards.get("owasp", [])}
    writeups = [
        {
            "ref": str(ref.ref),
            "url": str(ref.url),
            "relation": str(ref.relation),
            "lesson": str(ref.lesson),
            "counts_as_target_evidence": bool(ref.counts_as_target_evidence),
        }
        for ref in spec.writeups
    ]
    expected = EXPECTED_GROUNDING[family]
    if not expected["wstg"].issubset(wstg):
        raise RuntimeError(f"{family}: canonical WSTG grounding drifted: {sorted(wstg)}")
    if not expected["cwe"].issubset(cwe):
        raise RuntimeError(f"{family}: canonical CWE grounding drifted: {sorted(cwe)}")
    if not expected["owasp"].issubset(owasp):
        raise RuntimeError(f"{family}: canonical OWASP grounding drifted: {sorted(owasp)}")
    if not any(expected["writeup_contains"] in row["ref"] for row in writeups):
        raise RuntimeError(f"{family}: canonical write-up grounding drifted")
    if any(row["counts_as_target_evidence"] for row in writeups):
        raise RuntimeError(f"{family}: external write-up must never count as target evidence")
    return {
        "role": "source_selection_reasoning_grounding_only_not_target_evidence",
        "principle": str(standards.get("principle") or ""),
        "wstg": sorted(wstg),
        "cwe": sorted(cwe),
        "owasp": sorted(owasp),
        "writeups": writeups,
        "grounding_counts_as_target_evidence": False,
    }


def _candidate(family: str, token: str | None, prior: Mapping[str, set[str]]) -> dict[str, Any]:
    cfg = SOURCES[family]
    project = str(cfg["project"])
    pr_number = int(cfg["pr_number"])
    api = f"https://api.github.com/repos/{project}/pulls/{pr_number}"
    status, pr, error = github_source._request_json(api, token)
    if status != 200 or not isinstance(pr, Mapping):
        raise RuntimeError(f"{family}: PR metadata unavailable status={status} error={error}")
    if pr.get("merged_at") is None:
        raise RuntimeError(f"{family}: selected source PR is not merged")

    patch_status, files, patch_error, patch_api = github_source._patch_files(project, pr_number, token)
    if patch_status != 200 or not files:
        raise RuntimeError(f"{family}: PR patch unavailable status={patch_status} error={patch_error}")
    added, removed, context, patch_text = github_source._patch_parts(files)
    if not added or not patch_text:
        raise RuntimeError(f"{family}: selected PR has no usable added fix lines")

    pr_url = f"https://github.com/{project}/pull/{pr_number}"
    title = str(pr.get("title") or "").strip()
    body = str(pr.get("body") or "").strip()
    row: dict[str, Any] = {
        "source_root": cfg["source_root"],
        "source_project": project,
        "source_kind": cfg["source_kind"],
        "summary": title,
        "description": "\n\n".join(value for value in (title, body) if value),
        "canonical_advisory_url": pr_url,
        "repository_advisory_url": "",
        "source_code_location": pr_url,
        "references": [pr_url],
        "published_at": str(pr.get("created_at") or ""),
        "updated_at": str(pr.get("updated_at") or ""),
        "advisory_source_type": "upstream_pr",
        "pr_number": pr_number,
        "upstream_repository_reference": pr_url,
        "selection_uses_v6_score": False,
        "selection_uses_v6_case_errors": False,
        "scoring_executed": False,
        "active_target_validation_performed": False,
        "standards_grounding": _grounding(family),
    }

    firewall = check_candidate(row, index=prior)
    if not firewall["allowed"]:
        raise RuntimeError(f"{family}: collision replacement rejected by v7 freshness firewall: {firewall}")

    enriched = dict(row)
    enriched["patch_text"] = patch_text
    enriched["description"] = (row["description"] + "\n\nUPSTREAM PATCH\n" + patch_text).strip()
    family_passed, family_hits, family_score = audit_row(family, enriched)
    condition_signals, condition_hits = audit_conditions(family, enriched)
    if not family_passed:
        raise RuntimeError(f"{family}: collision replacement failed family semantic audit: {family_hits}")
    if not condition_signals:
        raise RuntimeError(f"{family}: collision replacement failed pre-score condition audit")

    enriched.update({
        "family": family,
        "freshness_validated": True,
        "v7_firewall_allowed": True,
        "v7_firewall_diagnostics": firewall,
        "patch_probe_passed": True,
        "patch_probe_version": VERSION,
        "patch_probe_rule_version": RULE_VERSION,
        "patch_api_reference": patch_api,
        "patch_route": "pull",
        "patch_file_count": len(files),
        "patch_added_line_count": len(added),
        "patch_removed_line_count": len(removed),
        "patch_context_line_count": len(context),
        "patch_text_sha256": _sha(patch_text),
        "patch_added_lines": added,
        "patch_removed_lines": removed,
        "patch_context_lines": context,
        "source_family_audit_passed": True,
        "source_family_audit_group_hits": family_hits,
        "source_family_audit_score": family_score,
        "pre_score_expected_condition_signals": condition_signals,
        "pre_score_condition_source_hits": condition_hits,
        "collision_replacement": True,
        "collision_replacement_reason": "provide a distinct fresh project while preserving family-specific WSTG/CWE/OWASP/write-up grounding and patch-backed evidence",
    })
    return enriched


def build(token: str | None = None) -> dict[str, Any]:
    prior = exposure_index()
    pools = {family: [_candidate(family, token, prior)] for family in sorted(SOURCES)}
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_collision_replacement_supplement_unscored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(pools),
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "families_without_candidates": [],
        "standards_grounding_required": ["WSTG", "CWE", "OWASP", "primary_or_adjacent_writeup"],
        "grounding_counts_as_target_evidence": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    report = build(os.environ.get("GITHUB_TOKEN"))
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "grounding_counts_as_target_evidence": report["grounding_counts_as_target_evidence"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

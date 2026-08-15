from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Mapping

import raw_recon_v7_missing5_supplement as base
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.32.v7.29"
FAMILIES = tuple(sorted(base.QUERIES))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _revalidate_existing() -> dict[str, list[dict[str, Any]]]:
    old = json.loads(base.OUT.read_text(encoding="utf-8"))
    pools = old.get("candidates_by_family") if isinstance(old, Mapping) else None
    if not isinstance(pools, Mapping):
        raise RuntimeError("existing missing5 supplement has no candidate pools")
    prior = exposure_index()
    kept: dict[str, list[dict[str, Any]]] = {}
    for family in FAMILIES:
        if family == "graphql_data_exposure":
            kept[family] = []
            continue
        accepted: list[dict[str, Any]] = []
        for raw in pools.get(family) or []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            if not check_candidate(row, index=prior)["allowed"]:
                continue
            passed, hits, score = audit_row(family, row)
            signals, condition_hits = audit_conditions(family, row)
            if not passed or not signals:
                continue
            if row.get("patch_probe_passed") is not True or int(row.get("patch_added_line_count") or 0) <= 0:
                continue
            row["source_family_audit_passed"] = True
            row["source_family_audit_group_hits"] = hits
            row["source_family_audit_score"] = score
            row["pre_score_expected_condition_signals"] = signals
            row["pre_score_condition_source_hits"] = condition_hits
            row["revalidated_for_rule_version"] = RULE_VERSION
            accepted.append(row)
        if not accepted:
            raise RuntimeError(f"existing patchable source failed revalidation: {family}")
        kept[family] = accepted[:4]
    return kept


def _graphql_candidate(token: str | None) -> dict[str, Any]:
    family = "graphql_data_exposure"
    project = "hoppscotch/hoppscotch"
    pr_number = 6409
    pr_api = f"https://api.github.com/repos/{project}/pulls/{pr_number}"
    status, pr, error = base._request_json(pr_api, token)
    if status != 200 or not isinstance(pr, Mapping):
        raise RuntimeError(f"Hoppscotch PR metadata unavailable: status={status} error={error}")
    if pr.get("merged_at") is None:
        raise RuntimeError("Hoppscotch security PR is not merged")

    patch_status, files, patch_error, patch_api = base._patch_files(project, pr_number, token)
    if patch_status != 200 or not files:
        raise RuntimeError(f"Hoppscotch PR patch unavailable: status={patch_status} error={patch_error}")
    added, removed, context, patch_text = base._patch_parts(files)
    if not added or not patch_text:
        raise RuntimeError("Hoppscotch PR contains no usable merged patch")

    pr_url = f"https://github.com/{project}/pull/{pr_number}"
    title = str(pr.get("title") or "").strip()
    body = str(pr.get("body") or "").strip()
    row: dict[str, Any] = {
        "source_root": "GITHUB-PR-hoppscotch-hoppscotch-6409",
        "source_project": project,
        "source_kind": "github_merged_security_pr_graphql_private_data_exposure",
        "summary": title,
        "description": "\n\n".join(x for x in (title, body) if x),
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
    }
    firewall = check_candidate(row, index=exposure_index())
    if not firewall["allowed"]:
        raise RuntimeError(f"Hoppscotch source rejected by v7 freshness firewall: {firewall}")

    enriched = dict(row)
    enriched["patch_text"] = patch_text
    enriched["description"] = (row["description"] + "\n\nUPSTREAM PATCH\n" + patch_text).strip()
    family_passed, family_hits, family_score = audit_row(family, enriched)
    condition_signals, condition_hits = audit_conditions(family, enriched)
    if not family_passed:
        raise RuntimeError(f"Hoppscotch source failed GraphQL data-exposure semantic audit: {family_hits}")
    if not condition_signals:
        raise RuntimeError("Hoppscotch source failed pre-score GraphQL condition audit")

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
    })
    return enriched


def build(token: str | None) -> dict[str, Any]:
    pools = _revalidate_existing()
    gql = _graphql_candidate(token)
    pools["graphql_data_exposure"] = [gql]
    missing = sorted(f for f, rows in pools.items() if not rows)
    if missing:
        raise RuntimeError(f"missing patchable families after fast revalidation: {missing}")
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_missing5_revalidated_plus_fresh_graphql_pr_unscored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(FAMILIES),
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "families_without_candidates": missing,
        "diagnostics": {
            "mode": "revalidate_committed_patchable_four_plus_fetch_single_fresh_graphql_pr",
            "graphql_data_exposure": {
                "source_root": gql["source_root"],
                "source_project": gql["source_project"],
                "patch_added_line_count": gql["patch_added_line_count"],
                "pre_score_expected_condition_signals": gql["pre_score_expected_condition_signals"],
            },
        },
        "search_api_call_count": 0,
        "patch_api_call_count": 1,
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
    base.OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "graphql": report["diagnostics"]["graphql_data_exposure"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

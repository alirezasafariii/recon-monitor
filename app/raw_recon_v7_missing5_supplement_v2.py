from __future__ import annotations

import hashlib
import json
import os

import raw_recon_v7_missing5_supplement as base
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION = "1.2.0"
RULE_VERSION = "2026.08.15.6.32.v7.27"

# Broader discovery vocabulary only. Acceptance remains entirely in the existing
# firewall + family semantic + condition audit + real merged-patch gates.
base.QUERIES = {
    "file_upload": (
        '"arbitrary file upload" security',
        '"unrestricted file upload" security',
        '"file upload" "extension validation" security',
        '"file upload" "mime validation" security',
        '"upload" "filename validation" security',
        '"upload" "executable file" security',
        '"uploaded file" security validation',
        '"dangerous file" upload security',
        '"content type" upload security validation',
    ),
    "graphql_authorization": (
        'GraphQL authorization security',
        'GraphQL "access control" security',
        'GraphQL permission security',
        'GraphQL permissions resolver security',
        'GraphQL resolver authorization',
        'GraphQL unauthorized mutation',
        'GraphQL unauthorized query',
        'GraphQL role permission',
        'GraphQL RBAC security',
        'GraphQL authentication authorization resolver',
    ),
    "graphql_data_exposure": (
        'GraphQL "information disclosure"',
        'GraphQL "data exposure" security',
        'GraphQL "private data" security',
        'GraphQL IDOR "private data"',
        'GraphQL "sensitive data" exposure',
        'GraphQL "sensitive fields" security',
        'GraphQL introspection exposure security',
        'GraphQL schema exposure security',
        'GraphQL unauthorized data security',
        'GraphQL response sensitive security',
        'GraphQL private fields exposure',
        'GraphQL data leak security',
    ),
    "security_logging_alerting_failure": (
        'password log redaction security',
        'password logging security redact',
        'token log redaction security',
        'credential log redaction security',
        'secret logging security redact',
        '"sensitive data" logging security redact',
        '"sensitive information" logs security',
        '"access token" logs redact security',
        '"api key" logs redact security',
        '"remove password" logs security',
    ),
    "software_supply_chain_failure": (
        '"dependency confusion" security',
        '"dependency confusion" package security',
        '"malicious dependency" security',
        '"malicious package" security',
        '"compromised dependency" security',
        '"compromised package" security',
        '"supply chain" dependency security',
        '"supply-chain" dependency security',
        '"package integrity" dependency security',
        '"dependency integrity" security package',
        '"dependency hijacking" security',
        '"package hijacking" security',
    ),
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hoppscotch_graphql_exposure(token: str | None) -> dict | None:
    """Source-grounded fallback for the one family whose broad PR search can miss
    a security PR because its title says ownership/IDOR rather than data exposure.
    The advisory and merged PR are fetched from GitHub at runtime and must pass
    the same freshness, semantic, condition and real-patch gates as discovery.
    """
    family = "graphql_data_exposure"
    project = "hoppscotch/hoppscotch"
    ghsa = "GHSA-p25p-g9jp-7q46"
    pr_number = 6409
    advisory_api = f"https://api.github.com/repos/{project}/security-advisories/{ghsa}"
    pr_api = f"https://api.github.com/repos/{project}/pulls/{pr_number}"

    status, advisory, _ = base._request_json(advisory_api, token)
    if status == 403 and token:
        status, advisory, _ = base._request_json(advisory_api, None)
    if status != 200 or not isinstance(advisory, dict):
        return None

    pr_status, pr, _ = base._request_json(pr_api, token)
    if pr_status != 200 or not isinstance(pr, dict) or pr.get("merged_at") is None:
        return None

    patch_status, files, _, patch_api = base._patch_files(project, pr_number, token)
    if patch_status != 200 or not files:
        return None
    added, removed, context, patch_text = base._patch_parts(files)
    if not added or not patch_text:
        return None

    advisory_url = f"https://github.com/{project}/security/advisories/{ghsa}"
    pr_url = f"https://github.com/{project}/pull/{pr_number}"
    summary = str(advisory.get("summary") or "").strip()
    description = str(advisory.get("description") or "").strip()
    pr_title = str(pr.get("title") or "").strip()
    pr_body = str(pr.get("body") or "").strip()
    row = {
        "source_root": ghsa,
        "source_project": project,
        "source_kind": "github_repository_security_advisory_with_merged_patch",
        "summary": summary,
        "description": "\n\n".join(x for x in (summary, description, pr_title, pr_body) if x),
        "canonical_advisory_url": advisory_url,
        "repository_advisory_url": advisory_url,
        "source_code_location": pr_url,
        "references": [advisory_url, pr_url],
        "published_at": str(advisory.get("published_at") or pr.get("created_at") or ""),
        "updated_at": str(advisory.get("updated_at") or pr.get("updated_at") or ""),
        "advisory_source_type": "repository",
        "pr_number": pr_number,
        "upstream_repository_reference": pr_url,
        "selection_uses_v6_score": False,
        "selection_uses_v6_case_errors": False,
        "scoring_executed": False,
        "active_target_validation_performed": False,
    }
    if not check_candidate(row, index=exposure_index())["allowed"]:
        return None

    enriched = dict(row)
    enriched["patch_text"] = patch_text
    enriched["description"] = (row["description"] + "\n\nUPSTREAM PATCH\n" + patch_text).strip()
    family_passed, family_hits, family_score = audit_row(family, enriched)
    condition_signals, condition_hits = audit_conditions(family, enriched)
    if not family_passed or not condition_signals:
        return None

    enriched.update({
        "family": family,
        "freshness_validated": True,
        "v7_firewall_allowed": True,
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
        "targeted_fallback_reason": "broad PR search may not rank an ownership-titled GraphQL exposure fix",
    })
    return enriched


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    report = base.discover(token)
    family = "graphql_data_exposure"
    if not report["candidates_by_family"].get(family):
        fallback = _hoppscotch_graphql_exposure(token)
        if fallback is not None:
            report["candidates_by_family"][family] = [fallback]
            report["family_candidate_counts"][family] = 1
            report["families_without_candidates"] = sorted(
                key for key, rows in report["candidates_by_family"].items() if not rows
            )
            report.setdefault("diagnostics", {}).setdefault(family, {})["targeted_repository_advisory_fallback"] = {
                "accepted": True,
                "source_root": fallback["source_root"],
                "source_project": fallback["source_project"],
                "patch_added_line_count": fallback["patch_added_line_count"],
                "condition_signals": fallback["pre_score_expected_condition_signals"],
            }
        else:
            report.setdefault("diagnostics", {}).setdefault(family, {})["targeted_repository_advisory_fallback"] = {
                "accepted": False
            }

    report["version"] = VERSION
    report["rule_version"] = RULE_VERSION
    report["evaluation_kind"] = "fresh_blind_v7_missing5_patchable_supplement_v2_unscored"
    base.OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "search_api_call_count": report["search_api_call_count"],
        "patch_api_call_count": report["patch_api_call_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

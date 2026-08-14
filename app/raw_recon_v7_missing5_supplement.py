from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.16"
OUT = ROOT / "benchmarks/raw/sources/v7_missing5_supplement.json"

QUERIES: dict[str, tuple[str, ...]] = {
    "file_upload": (
        '"arbitrary file upload" security',
        '"unrestricted file upload" security',
        '"file upload" validation security',
        '"upload" "dangerous file" security',
    ),
    "graphql_authorization": (
        'GraphQL authorization security',
        'GraphQL "access control" security',
        'GraphQL permission security',
        'GraphQL unauthorized mutation',
    ),
    "graphql_data_exposure": (
        'GraphQL "information disclosure"',
        'GraphQL "data exposure" security',
        'GraphQL "sensitive data" exposure',
        'GraphQL introspection exposure security',
    ),
    "security_logging_alerting_failure": (
        'password log redaction security',
        'token log redaction security',
        'secret logging security',
        '"sensitive data" logging security',
    ),
    "software_supply_chain_failure": (
        '"dependency confusion" security',
        '"malicious dependency" security',
        '"supply chain" dependency security',
        '"malicious package" security',
    ),
}


def _request_json(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-632-v7-missing5",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            raw = response.read(5 * 1024 * 1024)
            return int(response.status), json.loads(raw.decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        return int(exc.code), None, f"HTTP {exc.code}: " + exc.read().decode("utf-8", errors="replace")[:1200]
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _search(query: str, token: str | None) -> tuple[list[dict[str, Any]], str | None]:
    q = f"{query} in:title,body is:pr is:merged archived:false"
    url = "https://api.github.com/search/issues?" + urllib.parse.urlencode({
        "q": q,
        "per_page": 30,
        "sort": "updated",
        "order": "desc",
    })
    status, payload, error = _request_json(url, token)
    if status != 200 or not isinstance(payload, Mapping):
        return [], error or f"HTTP {status}"
    return [dict(item) for item in payload.get("items") or [] if isinstance(item, Mapping)], None


def _project(item: Mapping[str, Any]) -> str:
    url = str(item.get("repository_url") or "")
    return url.split("/repos/", 1)[1].strip("/") if "/repos/" in url else ""


def _candidate(item: Mapping[str, Any]) -> dict[str, Any]:
    project = _project(item)
    number = int(item.get("number") or 0)
    html = str(item.get("html_url") or "").strip()
    title = str(item.get("title") or "").strip()
    body = str(item.get("body") or "").strip()
    owner, repo = project.split("/", 1)
    return {
        "source_root": f"GITHUB-PR-{owner}-{repo}-{number}",
        "source_project": project,
        "source_kind": "github_merged_security_pr_missing5_supplement",
        "summary": title,
        "description": "\n".join(part for part in (title, body) if part),
        "canonical_advisory_url": html,
        "repository_advisory_url": "",
        "source_code_location": html,
        "references": [html],
        "published_at": str(item.get("created_at") or ""),
        "updated_at": str(item.get("updated_at") or ""),
        "advisory_source_type": "upstream_pr",
        "pr_number": number,
        "upstream_repository_reference": html,
        "selection_uses_v6_score": False,
        "selection_uses_v6_case_errors": False,
        "scoring_executed": False,
        "active_target_validation_performed": False,
    }


def _patch_files(project: str, number: int, token: str | None) -> tuple[int, list[dict[str, Any]], str | None, str]:
    url = f"https://api.github.com/repos/{project}/pulls/{number}/files?per_page=100"
    status, payload, error = _request_json(url, token)
    if status == 403 and token:
        status, payload, error = _request_json(url, None)
    rows = [dict(row) for row in payload or [] if isinstance(row, Mapping)] if isinstance(payload, list) else []
    return status, rows, error, url


def _patch_parts(files: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str], str]:
    added: list[str] = []
    removed: list[str] = []
    context: list[str] = []
    chunks: list[str] = []
    for row in files[:100]:
        filename = str(row.get("filename") or "")
        patch = str(row.get("patch") or "")
        if filename or patch:
            chunks.append(f"FILE {filename}\n{patch}"[:10000])
        for line in patch.splitlines():
            if line.startswith(("+++", "---", "@@")):
                continue
            if line.startswith("+") and line[1:].strip():
                added.append(line[1:].strip())
            elif line.startswith("-") and line[1:].strip():
                removed.append(line[1:].strip())
            elif line.startswith(" ") and line[1:].strip():
                context.append(line[1:].strip())
    return added[:400], removed[:400], context[:400], "\n".join(chunks)[:120000]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def discover(token: str | None = None) -> dict[str, Any]:
    prior = exposure_index()
    pools: dict[str, list[dict[str, Any]]] = {}
    diagnostics: dict[str, Any] = {}
    search_calls = 0
    patch_calls = 0

    for family in sorted(QUERIES):
        accepted: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        reasons: dict[str, int] = {}
        query_rows: list[dict[str, Any]] = []

        for query in QUERIES[family]:
            items, error = _search(query, token)
            search_calls += 1
            query_rows.append({"query": query, "result_count": len(items), "error": error})
            time.sleep(2.1)
            for item in items:
                project = _project(item)
                number = int(item.get("number") or 0)
                key = (project.casefold(), number)
                if not project or not number or key in seen:
                    continue
                seen.add(key)
                row = _candidate(item)
                firewall = check_candidate(row, index=prior)
                if not firewall["allowed"]:
                    reasons["firewall"] = reasons.get("firewall", 0) + 1
                    continue
                status, files, patch_error, patch_api = _patch_files(project, number, token)
                patch_calls += 1
                if status != 200 or not files:
                    reasons["patch_fetch"] = reasons.get("patch_fetch", 0) + 1
                    continue
                added, removed, context, patch_text = _patch_parts(files)
                if not added or not patch_text:
                    reasons["patch_has_no_added_fix"] = reasons.get("patch_has_no_added_fix", 0) + 1
                    continue
                enriched = dict(row)
                enriched["patch_text"] = patch_text
                enriched["description"] = (row["description"] + "\n\nUPSTREAM PATCH\n" + patch_text).strip()
                family_passed, family_hits, family_score = audit_row(family, enriched)
                condition_signals, condition_hits = audit_conditions(family, enriched)
                if not family_passed:
                    reasons["family_semantic"] = reasons.get("family_semantic", 0) + 1
                    continue
                if not condition_signals:
                    reasons["condition_semantic"] = reasons.get("condition_semantic", 0) + 1
                    continue
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
                })
                accepted.append(enriched)
                if len(accepted) >= 4:
                    break
            if accepted:
                break

        pools[family] = accepted
        diagnostics[family] = {
            "queries": query_rows,
            "patchable_count": len(accepted),
            "rejections": reasons,
        }

    missing = sorted(family for family, rows in pools.items() if not rows)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_missing5_patchable_supplement_unscored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(QUERIES),
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "families_without_candidates": missing,
        "diagnostics": diagnostics,
        "search_api_call_count": search_calls,
        "patch_api_call_count": patch_calls,
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
    report = discover(os.environ.get("GITHUB_TOKEN"))
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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

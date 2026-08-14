from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import audit_row
from raw_recon_v7_source_firewall import check_candidate, exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.4"
OUT = ROOT / "benchmarks/raw/sources/v7_pr_supplement.json"

QUERIES: dict[str, tuple[str, ...]] = {
    "account_enumeration": ('"user enumeration" security', '"account enumeration" security'),
    "authentication_session": ('"authentication bypass" security', '"session fixation" security'),
    "broken_function_authorization": ('"authorization bypass" admin security', '"function level authorization" security'),
    "broken_object_authorization": ('IDOR security', '"object level authorization" security'),
    "business_logic": ('"business logic" security', '"workflow bypass" security'),
    "command_injection": ('"command injection" security', '"OS command injection" security'),
    "cors_misconfiguration": ('CORS credentials security', '"cross-origin" security fix'),
    "cryptographic_failure": ('"weak cryptography" security', '"predictable random" security'),
    "dom_xss": ('"DOM XSS" security', '"DOM-based XSS" security'),
    "exceptional_condition_mishandling": ('"unhandled exception" security', '"fail open" exception security'),
    "file_upload": ('"arbitrary file upload" security', '"unrestricted upload" security'),
    "graphql_authorization": ('"GraphQL authorization" security', 'GraphQL unauthorized resolver'),
    "graphql_data_exposure": ('GraphQL "data exposure" security', 'GraphQL "information disclosure"'),
    "improper_inventory_management": ('"deprecated endpoint" security', '"legacy endpoint" unauthenticated'),
    "information_disclosure": ('"information disclosure" security', '"sensitive information" exposure security'),
    "ldap_injection": ('"LDAP injection" security', 'LDAP filter injection security'),
    "mass_assignment": ('"mass assignment" security', 'overposting privilege security'),
    "nosql_injection": ('"NoSQL injection" security', '"MongoDB injection" security'),
    "open_redirect": ('"open redirect" security', '"unvalidated redirect" security'),
    "path_traversal": ('"path traversal" security', '"directory traversal" security'),
    "postmessage_trust": ('postMessage origin security', '"message event" origin validation'),
    "race_condition": ('"race condition" security', 'TOCTOU security fix'),
    "secret_exposure": ('"hardcoded secret" security', 'credential exposure security'),
    "security_logging_alerting_failure": ('"sensitive" logging password security', '"missing log" security alert'),
    "security_misconfiguration": ('"security misconfiguration" fix', 'debug exposed security'),
    "sensitive_business_flow_abuse": ('"rate limit" abuse security', '"password reset" flood security'),
    "sensitive_caching": ('"Cache-Control" authenticated security', '"sensitive" caching security'),
    "server_side_template_injection": ('"server side template injection" security', 'SSTI security fix'),
    "software_data_integrity_failure": ('"signature verification" security update', '"unsigned update" security'),
    "software_supply_chain_failure": ('"supply chain" dependency security', 'malicious dependency security'),
    "source_map_exposure": ('"source map" exposure security', 'sourcemap sensitive security'),
    "sql_injection": ('"SQL injection" security', 'SQLi security fix'),
    "ssrf": ('SSRF security', '"server-side request forgery" security'),
    "unrestricted_resource_consumption": ('"resource exhaustion" security', '"denial of service" unbounded security'),
    "unsafe_api_consumption": ('"certificate validation" "http client" security', '"upstream validation" security'),
    "websocket_authorization": ('WebSocket authorization security', 'WebSocket unauthorized security'),
}


def _request_json(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-632-v7-pr-supplement",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            raw = response.read(3 * 1024 * 1024)
            return int(response.status), json.loads(raw.decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1500]
        return int(exc.code), None, f"HTTP {exc.code}: {body}"
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _project(item: Mapping[str, Any]) -> str:
    url = str(item.get("repository_url") or "")
    marker = "/repos/"
    if marker not in url:
        return ""
    return url.split(marker, 1)[1].strip("/")


def _row(item: Mapping[str, Any], *, patch_text: str = "") -> dict[str, Any]:
    project = _project(item)
    number = int(item.get("number") or 0)
    title = str(item.get("title") or "").strip()
    body = str(item.get("body") or "").strip()
    html = str(item.get("html_url") or "").strip()
    description = "\n".join(part for part in (title, body, patch_text) if part).strip()
    owner, repo = (project.split("/", 1) + [""])[:2] if "/" in project else ("", "")
    return {
        "source_root": f"GITHUB-PR-{owner}-{repo}-{number}",
        "source_project": project,
        "source_kind": "github_merged_security_pr_supplement",
        "summary": title,
        "description": description,
        "canonical_advisory_url": html,
        "repository_advisory_url": "",
        "source_code_location": html,
        "references": [html] if html else [],
        "published_at": str(item.get("created_at") or ""),
        "updated_at": str(item.get("updated_at") or ""),
        "advisory_source_type": "upstream_pr",
        "pr_number": number,
        "pull_request_api_url": str((item.get("pull_request") or {}).get("url") or "") if isinstance(item.get("pull_request"), Mapping) else "",
        "scoring_executed": False,
        "active_target_validation_performed": False,
    }


def _patch_text(project: str, number: int, token: str | None) -> str:
    if not project or not number:
        return ""
    url = f"https://api.github.com/repos/{project}/pulls/{number}/files?per_page=100"
    status, payload, error = _request_json(url, token)
    if status != 200 or not isinstance(payload, list):
        return ""
    chunks: list[str] = []
    for file in payload[:30]:
        if not isinstance(file, Mapping):
            continue
        filename = str(file.get("filename") or "")
        patch = str(file.get("patch") or "")[:3500]
        if filename or patch:
            chunks.append(f"FILE {filename}\n{patch}")
    return "\n".join(chunks)[:50000]


def _search(query: str, token: str | None) -> tuple[list[dict[str, Any]], str | None]:
    q = f"{query} is:pr is:merged archived:false"
    url = "https://api.github.com/search/issues?" + urllib.parse.urlencode({
        "q": q,
        "per_page": 20,
        "sort": "updated",
        "order": "desc",
    })
    status, payload, error = _request_json(url, token)
    if status != 200 or not isinstance(payload, Mapping):
        return [], error or f"HTTP {status}"
    rows = [dict(item) for item in payload.get("items") or [] if isinstance(item, Mapping)]
    return rows, None


def discover(token: str | None = None) -> dict[str, Any]:
    prior = exposure_index()
    candidates_by_family: dict[str, list[dict[str, Any]]] = {}
    diagnostics: dict[str, Any] = {}
    search_calls = 0
    patch_calls = 0

    for family in sorted(QUERIES):
        kept: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        query_diag: list[dict[str, Any]] = []
        for query in QUERIES[family]:
            items, error = _search(query, token)
            search_calls += 1
            query_diag.append({"query": query, "result_count": len(items), "error": error})
            # GitHub search has a stricter rate bucket than the core API.
            time.sleep(2.1)
            for item in items:
                project = _project(item)
                number = int(item.get("number") or 0)
                key = (project.casefold(), number)
                if not project or not number or key in seen:
                    continue
                seen.add(key)
                row = _row(item)
                check = check_candidate(row, index=prior)
                if not check["allowed"]:
                    continue
                passed, hits, score = audit_row(family, row)
                if not passed:
                    patch = _patch_text(project, number, token)
                    patch_calls += 1
                    if patch:
                        row = _row(item, patch_text=patch)
                        passed, hits, score = audit_row(family, row)
                if not passed:
                    continue
                row.update({
                    "family": family,
                    "freshness_validated": True,
                    "v7_firewall_allowed": True,
                    "source_family_audit_passed": True,
                    "source_family_audit_group_hits": hits,
                    "source_family_audit_score": score,
                    "upstream_repository_reference": row["source_code_location"],
                    "selection_uses_v6_score": False,
                    "selection_uses_v6_case_errors": False,
                })
                kept.append(row)
                if len(kept) >= 12:
                    break
            if kept:
                # One source-grounded semantic pool is enough; selector handles global uniqueness.
                break
        candidates_by_family[family] = kept
        diagnostics[family] = {"queries": query_diag, "kept_count": len(kept)}

    missing = sorted(family for family, rows in candidates_by_family.items() if not rows)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_passive_merged_pr_source_supplement_unscored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(QUERIES),
        "candidates_by_family": candidates_by_family,
        "family_candidate_counts": {family: len(rows) for family, rows in candidates_by_family.items()},
        "families_without_candidates": missing,
        "diagnostics": diagnostics,
        "search_api_call_count": search_calls,
        "pull_files_api_call_count": patch_calls,
        "source_firewall_scope": "all_exposed_sources_and_provenance_v1_through_consumed_v6",
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
        "pull_files_api_call_count": report["pull_files_api_call_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

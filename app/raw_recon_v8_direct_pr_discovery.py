from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v8_source_firewall import check_candidate, exposure_index
from researcher_logic import researcher_logic_for_family
from v8_source_semantic_audit import audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v8.pr.1"
CANDIDATES = ROOT / "benchmarks/raw/sources/v8_candidates.json"
PATCHABLE = ROOT / "benchmarks/raw/sources/v8_candidates_patchable.json"
OUT = CANDIDATES
SEARCH_API = "https://api.github.com/search/issues"

# Search terms are fixed before any v8 scoring. They are derived from the source
# semantic/condition contracts and source-free researcher logic, not from any
# First Blind result or case-level error.
QUERY_TERMS: dict[str, tuple[str, ...]] = {
    "account_enumeration": (
        '"user enumeration"',
        '"account enumeration"',
        '"account existence"',
        '"registered email" "different response"',
    ),
    "authentication_session": (
        '"session fixation"',
        '"authentication bypass"',
        '"login bypass"',
        '"token forgery"',
    ),
    "broken_function_authorization": (
        '"authorization bypass" admin',
        '"access control bypass" admin',
        '"missing permission" admin',
        '"low privilege" admin',
    ),
    "business_logic": (
        '"workflow bypass"',
        '"invalid state transition"',
        '"without payment"',
        '"double spend"',
    ),
    "cors_misconfiguration": (
        'CORS credentials security',
        '"Access-Control-Allow-Credentials"',
        '"allow-credentials" CORS',
        '"cross-origin" credentials CORS',
    ),
    "exceptional_condition_mishandling": (
        '"fail open" security',
        '"unhandled exception" security',
        '"uncaught exception" security',
        'panic security bypass',
    ),
    "file_upload": (
        '"arbitrary file upload"',
        '"unrestricted upload"',
        '"mime validation" upload',
        '"extension validation" upload security',
    ),
    "graphql_authorization": (
        '"graphql authorization"',
        '"unauthorized mutation" graphql',
        '"unauthorized query" graphql',
        '"resolver access control" graphql',
    ),
    "graphql_data_exposure": (
        '"graphql data exposure"',
        '"graphql information disclosure"',
        '"sensitive graphql data"',
        'graphql "private data" exposure',
    ),
    "improper_inventory_management": (
        '"deprecated endpoint" unauthenticated',
        '"legacy endpoint" unauthenticated',
        '"deprecated api" "still reachable"',
        '"old api version" security endpoint',
    ),
    "information_disclosure": (
        '"information disclosure" security',
        '"sensitive information exposed"',
        '"data exposure" unauthorized',
        '"sensitive response" unauthorized',
    ),
    "mass_assignment": (
        '"mass assignment"',
        'overposting security',
        '"over-posting" security',
        '"privileged field" role security',
    ),
    "nosql_injection": (
        '"NoSQL injection"',
        '"MongoDB injection"',
        '"mongo injection"',
        '"mongo operator" "authentication bypass"',
    ),
    "open_redirect": (
        '"open redirect" security',
        '"unvalidated redirect"',
        '"external redirect" security',
        '"arbitrary redirect" security',
    ),
    "postmessage_trust": (
        'postMessage "origin validation"',
        'postMessage "origin check" security',
        '"event.source" security iframe',
        '"message origin" iframe security',
    ),
    "race_condition": (
        '"race condition" security',
        'TOCTOU security',
        '"time-of-check" security',
        '"double spend" race',
    ),
    "security_logging_alerting_failure": (
        '"sensitive data logged"',
        '"password logged" security',
        '"token logged" security',
        '"missing audit event" security',
    ),
    "security_misconfiguration": (
        '"debug mode" exposed security',
        '"insecure default" security',
        '"unsafe default" security',
        '"directory listing" security fix',
    ),
    "sensitive_business_flow_abuse": (
        '"missing rate limit" "password reset"',
        '"no rate limit" signup',
        '"rate limit" coupon abuse',
        '"rate limit" booking abuse',
    ),
    "sensitive_caching": (
        '"authenticated cache" security',
        '"shared cache" authentication security',
        '"cache-control" sensitive authentication',
        '"public cache" authenticated',
    ),
    "software_supply_chain_failure": (
        '"supply chain" "malicious package"',
        '"malicious dependency"',
        '"compromised dependency"',
        '"compromised package" security',
    ),
    "ssrf": (
        'SSRF security fix',
        '"server-side request forgery"',
        '"server side request forgery"',
        '"internal url" fetch security',
    ),
    "unrestricted_resource_consumption": (
        '"resource exhaustion" security',
        '"memory exhaustion" security',
        '"denial of service" unbounded',
        '"unbounded" "denial of service"',
    ),
}

_DEP_NOISE = (
    "dependabot",
    "renovate",
    "mend renovate",
    "update dependency",
    "update dependencies",
    "bump dependency",
    "bump dependencies",
    "chore(deps)",
    "fix(deps)",
    "npm audit",
    "lockfile",
    "package-lock",
    "pnpm-lock",
    "yarn.lock",
)
_RESEARCH_REPO_TOKENS = (
    "proof-of-concept",
    "proof_of_concept",
    "-poc",
    "_poc",
    "vulnerability-research",
    "vuln-research",
    "security-pocs",
    "exploit-db",
)


def _headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-633-v8-direct-pr-discovery",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request_json(url: str, token: str | None) -> tuple[int, Any, str | None]:
    try:
        request = urllib.request.Request(url, headers=_headers(token))
        with urllib.request.urlopen(request, timeout=45) as response:
            return int(response.status), json.load(response), None
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")[:1200]
        return int(exc.code), None, f"HTTP {exc.code}: {payload}"
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _project_from_repository_api(value: str) -> str:
    match = re.search(r"/repos/([^/]+/[^/]+)$", str(value or "").strip())
    return match.group(1) if match else ""


def _is_noise(project: str, title: str, body: str, author: str) -> bool:
    blob = f"{title}\n{body[:6000]}\n{author}".casefold()
    project_fold = project.casefold()
    if any(token in blob for token in _DEP_NOISE):
        return True
    if author.casefold().endswith("[bot]") or author.casefold() in {"dependabot", "renovate", "renovate-bot"}:
        return True
    compact = re.sub(r"[^a-z0-9_-]+", "-", project_fold)
    return any(token in compact for token in _RESEARCH_REPO_TOKENS)


def _search(term: str, token: str | None, per_page: int) -> tuple[list[dict[str, Any]], str | None]:
    # Keep the search bounded to merged implementation PRs. Freshness is enforced
    # independently by the v1-v7 firewall, so date is only a noise/performance bound.
    q = f"{term} is:pr is:merged updated:>=2025-01-01"
    url = SEARCH_API + "?" + urllib.parse.urlencode({"q": q, "sort": "updated", "order": "desc", "per_page": per_page})
    status, payload, error = _request_json(url, token)
    if status != 200 or not isinstance(payload, Mapping):
        return [], error or f"search status {status}"
    return [dict(row) for row in payload.get("items") or [] if isinstance(row, Mapping)], None


def discover(*, per_query: int = 30, max_candidates_per_family: int = 80, sleep_seconds: float = 2.1) -> dict[str, Any]:
    source = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    patchable = json.loads(PATCHABLE.read_text(encoding="utf-8"))
    for artifact_name, artifact in (("candidates", source), ("patchable", patchable)):
        if artifact.get("scoring_executed") is not False:
            raise RuntimeError(f"v8 direct PR discovery requires unscored {artifact_name}")
        for key in (
            "candidate_selection_uses_v7_first_blind_score",
            "candidate_selection_uses_v7_first_blind_case_errors",
            "candidate_selection_uses_v7_first_blind_error",
        ):
            if artifact.get(key) is not False:
                raise RuntimeError(f"v8 direct PR discovery refuses contaminated {artifact_name}: {key}")

    missing = [str(value) for value in patchable.get("families_without_candidates") or []]
    unknown = sorted(set(missing) - set(QUERY_TERMS))
    if unknown:
        raise RuntimeError(f"direct PR discovery has no preregistered query set for: {unknown}")

    pools_raw = source.get("candidates_by_family") if isinstance(source.get("candidates_by_family"), Mapping) else {}
    pools: dict[str, list[dict[str, Any]]] = {
        str(family): [dict(row) for row in rows or [] if isinstance(row, Mapping)]
        for family, rows in pools_raw.items()
    }
    if len(pools) != 36:
        raise RuntimeError(f"v8 direct PR discovery expects 36 family buckets, got {len(pools)}")

    prior = exposure_index()
    token = os.environ.get("GITHUB_TOKEN")
    search_calls = 0
    search_errors: list[dict[str, str]] = []
    rejected_noise = 0
    rejected_firewall = 0
    duplicate_roots = 0
    added_counts: dict[str, int] = {}
    query_diagnostics: dict[str, list[dict[str, Any]]] = {}

    for family in missing:
        existing_roots = {str(row.get("source_root") or "") for row in pools[family]}
        added = 0
        family_logs: list[dict[str, Any]] = []
        logic = researcher_logic_for_family(family)
        grounding = {
            "role": logic["role"],
            "security_principle": logic["security_principle"],
            "testing_concepts": logic["standards_logic"]["testing_concepts"],
            "risk_concepts": logic["standards_logic"]["risk_concepts"],
            "weakness_concepts": logic["standards_logic"]["weakness_concepts"],
            "writeup_logic": logic["writeup_logic"],
            "counts_as_target_evidence": False,
        }
        for term in QUERY_TERMS[family]:
            rows, error = _search(term, token, per_query)
            search_calls += 1
            if error:
                search_errors.append({"family": family, "query": term, "error": error})
            before = added
            for item in rows:
                if len(pools[family]) >= max_candidates_per_family:
                    break
                project = _project_from_repository_api(str(item.get("repository_url") or ""))
                number = item.get("number")
                html_url = str(item.get("html_url") or "").strip()
                title = str(item.get("title") or "").strip()
                body = str(item.get("body") or "").strip()
                author_obj = item.get("user") if isinstance(item.get("user"), Mapping) else {}
                author = str(author_obj.get("login") or "")
                if not project or not isinstance(number, int) or not html_url:
                    continue
                if _is_noise(project, title, body, author):
                    rejected_noise += 1
                    continue
                root = f"GITHUB-PR-{project.replace('/', '-')}-{number}"
                if root in existing_roots:
                    duplicate_roots += 1
                    continue
                row = {
                    "source_root": root,
                    "source_project": project,
                    "family": family,
                    "matched_cwes": [],
                    "published_at": str(item.get("created_at") or ""),
                    "updated_at": str(item.get("updated_at") or ""),
                    "severity": "",
                    "summary": title,
                    "description": body,
                    "repository_advisory_url": "",
                    "source_code_location": html_url,
                    "canonical_advisory_url": "",
                    "references": [html_url],
                    "upstream_repository_reference": html_url,
                    "source_kind": "github_merged_security_pr_direct_discovery",
                    "selection_basis": "family-specific merged security PR search grounded in preregistered semantic/security contracts before scoring",
                    "freshness_validated": True,
                    "advisory_source_type": "direct_merged_pr",
                    "direct_pr_search_term": term,
                    "source_selection_reasoning_grounding": grounding,
                    "grounding_counts_as_target_evidence": False,
                    "selection_uses_v6_score": False,
                    "selection_uses_v6_case_errors": False,
                    "selection_uses_v7_score": False,
                    "selection_uses_v7_case_errors": False,
                    "selection_uses_v7_execution_error": False,
                    "scoring_executed": False,
                    "active_target_validation_performed": False,
                }
                check = check_candidate(row, index=prior)
                if not check["allowed"]:
                    rejected_firewall += 1
                    continue
                # Prefer rows whose title/body already satisfy the strict family
                # semantics, but retain search-grounded rows because the real diff
                # may supply the decisive source-grounded phrase during patch probe.
                passed, hits, score = audit_row(family, row)
                row["pre_patch_family_semantic_passed"] = bool(passed)
                row["pre_patch_family_semantic_group_hits"] = hits
                row["pre_patch_family_semantic_score"] = score
                pools[family].append(row)
                existing_roots.add(root)
                added += 1
            family_logs.append({
                "query": term,
                "search_result_count": len(rows),
                "added_candidate_count": added - before,
                "error": error,
            })
            if len(pools[family]) >= max_candidates_per_family:
                break
            time.sleep(max(0.0, sleep_seconds))
        added_counts[family] = added
        query_diagnostics[family] = family_logs

    report = dict(source)
    report.update({
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v8_direct_merged_pr_source_discovery_unscored",
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "direct_pr_target_families": missing,
        "direct_pr_added_counts": added_counts,
        "direct_pr_query_diagnostics": query_diagnostics,
        "direct_pr_search_api_call_count": search_calls,
        "direct_pr_search_errors": search_errors,
        "direct_pr_rejected_noise_count": rejected_noise,
        "direct_pr_rejected_firewall_count": rejected_firewall,
        "direct_pr_duplicate_root_count": duplicate_roots,
        "source_selection_grounding": "WSTG/CWE/OWASP concepts and write-up lessons guide query wording only; candidate acceptance still requires fresh upstream PR source text plus real patch feasibility/condition audit",
        "grounding_counts_as_target_evidence": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_score": False,
        "candidate_selection_uses_v7_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_error": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    })
    report["families_without_candidates"] = sorted(family for family, rows in pools.items() if not rows)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-query", type=int, default=30)
    parser.add_argument("--max-candidates-per-family", type=int, default=80)
    parser.add_argument("--sleep-seconds", type=float, default=2.1)
    args = parser.parse_args()
    report = discover(
        per_query=args.per_query,
        max_candidates_per_family=args.max_candidates_per_family,
        sleep_seconds=args.sleep_seconds,
    )
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_family_count": len(report["direct_pr_target_families"]),
        "direct_pr_added_counts": report["direct_pr_added_counts"],
        "search_api_call_count": report["direct_pr_search_api_call_count"],
        "search_error_count": len(report["direct_pr_search_errors"]),
        "rejected_noise_count": report["direct_pr_rejected_noise_count"],
        "rejected_firewall_count": report["direct_pr_rejected_firewall_count"],
        "families_without_candidates": report["families_without_candidates"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

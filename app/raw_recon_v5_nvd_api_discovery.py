from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v4_source_discovery as v4
from raw_recon_v5_nvd_discovery import (
    _candidate,
    _cwes,
    prior_cve_exposure,
)
from raw_recon_v5_source_audit import audit_row
from raw_recon_v5_source_discovery import exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT = ROOT / "benchmarks/raw/sources/v5_candidates.json"
EXACT_FAMILIES = frozenset({
    "dom_xss",
    "graphql_authorization",
    "graphql_data_exposure",
    "improper_inventory_management",
    "postmessage_trust",
    "sensitive_business_flow_abuse",
    "software_supply_chain_failure",
    "source_map_exposure",
    "unsafe_api_consumption",
    "websocket_authorization",
})


def _fetch_cwe(cwe: str, *, cache: dict[str, list[dict[str, Any]]], counters: dict[str, int]) -> list[dict[str, Any]]:
    if cwe in cache:
        counters["cache_hits"] += 1
        return cache[cwe]
    params = urllib.parse.urlencode({"cweId": cwe, "resultsPerPage": 2000})
    request = urllib.request.Request(
        f"{NVD_CVE_API}?{params}",
        headers={
            "User-Agent": "Recon-Monitor-Analysis-6.29-Fresh-Blind-v5/1.0",
            "Accept": "application/json",
        },
    )
    if counters["api_requests"]:
        time.sleep(6.2)
    response = None
    for attempt in range(3):
        try:
            response = urllib.request.urlopen(request, timeout=90)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in {403, 429} or attempt == 2:
                raise
            time.sleep(6.5 * (attempt + 1))
    if response is None:
        raise RuntimeError(f"unable to fetch NVD CWE query: {cwe}")
    with response:
        payload = json.load(response)
    counters["api_requests"] += 1
    counters["records"] += int(payload.get("resultsPerPage") or 0)
    wrappers = payload.get("vulnerabilities") if isinstance(payload, Mapping) else []
    rows = [
        dict(wrapper.get("cve"))
        for wrapper in wrappers or []
        if isinstance(wrapper, Mapping) and isinstance(wrapper.get("cve"), Mapping)
    ]
    cache[cwe] = rows
    return rows


def discover(target_semantic_per_family: int = 8) -> dict[str, Any]:
    prior = exposure_index()
    prior_cves = prior_cve_exposure()
    grounding = v4._grounding_writeup_urls()
    family_cwes = v4._family_cwes()
    generic_families = sorted(set(family_cwes) - set(EXACT_FAMILIES))
    cache: dict[str, list[dict[str, Any]]] = {}
    counters = {"api_requests": 0, "cache_hits": 0, "records": 0}
    pools: dict[str, list[dict[str, Any]]] = {family: [] for family in family_cwes}
    query_plan: dict[str, list[str]] = {}

    # Prefer the rarer/specific CWE IDs first by counting how many current families share each CWE.
    frequency: dict[str, int] = defaultdict(int)
    for cwes in family_cwes.values():
        for cwe in cwes:
            frequency[cwe] += 1

    for family in generic_families:
        cwes = sorted(family_cwes[family], key=lambda value: (frequency[value], value))
        query_plan[family] = []
        by_root: dict[str, dict[str, Any]] = {}
        semantic_count = 0
        for cwe in cwes:
            query_plan[family].append(cwe)
            for cve in _fetch_cwe(cwe, cache=cache, counters=counters):
                row_cwes = _cwes(cve)
                matched = row_cwes & set(family_cwes[family])
                if not matched:
                    continue
                row = _candidate(
                    cve,
                    family=family,
                    matched_cwes=matched,
                    prior=prior,
                    prior_cves=prior_cves,
                    grounding_urls=grounding,
                )
                if row is None:
                    continue
                root = str(row["source_root"])
                if root not in by_root:
                    by_root[root] = row
                else:
                    by_root[root]["matched_cwes"] = sorted(set(by_root[root]["matched_cwes"]) | set(row["matched_cwes"]))
            semantic_count = sum(1 for row in by_root.values() if audit_row(family, row)[0])
            if semantic_count >= target_semantic_per_family:
                break
        rows = list(by_root.values())
        rows.sort(
            key=lambda row: (
                1 if audit_row(family, row)[0] else 0,
                audit_row(family, row)[2],
                row.get("published_at") or "",
                row.get("source_root") or "",
            ),
            reverse=True,
        )
        pools[family] = rows

    candidate_counts = {family: len(rows) for family, rows in pools.items()}
    semantic_counts = {family: sum(1 for row in rows if audit_row(family, row)[0]) for family, rows in pools.items()}
    unresolved = sorted(family for family in generic_families if candidate_counts[family] == 0)
    unresolved_semantic = sorted(family for family in generic_families if semantic_counts[family] == 0)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "source_universe": "NVD CVE API 2.0 CWE-bounded queries plus exact niche CVE supplement",
        "family_count": len(family_cwes),
        "generic_family_count": len(generic_families),
        "exact_family_count": len(EXACT_FAMILIES),
        "exact_families": sorted(EXACT_FAMILIES),
        "unique_cwe_queries": len(cache),
        "api_request_count": counters["api_requests"],
        "query_cache_hit_count": counters["cache_hits"],
        "returned_record_count": counters["records"],
        "query_plan_by_family": query_plan,
        "family_candidate_counts": candidate_counts,
        "family_semantic_candidate_counts": semantic_counts,
        "families_without_candidates": unresolved,
        "families_without_semantic_candidates": unresolved_semantic,
        "excluded_prior_cve_count": len(prior_cves),
        "excluded_prior_root_count": len(prior["roots"]),
        "excluded_prior_project_count": len(prior["projects"]),
        "excluded_prior_url_count": len(prior["urls"]),
        "excluded_grounding_url_count": len(grounding),
        "scoring_executed": False,
        "candidate_selection_uses_source_semantic_audit": True,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_prior_v4_results": False,
        "candidates_by_family": pools,
    }


def main() -> int:
    report = discover()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        key: report[key]
        for key in (
            "source_universe",
            "generic_family_count",
            "exact_family_count",
            "unique_cwe_queries",
            "api_request_count",
            "query_cache_hit_count",
            "families_without_candidates",
            "families_without_semantic_candidates",
            "excluded_prior_cve_count",
        )
    }, indent=2, sort_keys=True))
    return 2 if report["families_without_candidates"] or report["families_without_semantic_candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

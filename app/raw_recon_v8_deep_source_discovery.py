from __future__ import annotations

import argparse
import json
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v5_source_discovery as v5
from raw_recon_v5_source_audit import audit_row
from raw_recon_v8_source_firewall import check_candidate, exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v8.deep.1"
CANDIDATES = ROOT / "benchmarks/raw/sources/v8_candidates.json"
PATCHABLE = ROOT / "benchmarks/raw/sources/v8_candidates_patchable.json"
OUT = CANDIDATES


def _semantic_count(family: str, rows: list[dict[str, Any]]) -> int:
    return sum(1 for row in rows if audit_row(family, row)[0])


def deepen(*, reviewed_pages: int = 8, unreviewed_pages: int = 16, target_semantic: int = 16) -> dict[str, Any]:
    source = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    patchable = json.loads(PATCHABLE.read_text(encoding="utf-8"))

    for key in (
        "candidate_selection_uses_v7_first_blind_score",
        "candidate_selection_uses_v7_first_blind_case_errors",
        "candidate_selection_uses_v7_first_blind_error",
    ):
        if source.get(key) is not False or patchable.get(key) is not False:
            raise RuntimeError(f"v8 deep discovery refuses contaminated input: {key}")
    if source.get("scoring_executed") is not False or patchable.get("scoring_executed") is not False:
        raise RuntimeError("v8 deep discovery requires unscored source artifacts")

    missing = [str(x) for x in patchable.get("families_without_candidates") or []]
    family_cwes = v5.v4._family_cwes()
    unknown = sorted(set(missing) - set(family_cwes))
    if unknown:
        raise RuntimeError(f"unknown v8 families in patchable gap list: {unknown}")

    excluded = exposure_index()
    grounding_urls = v5.v4._grounding_writeup_urls()
    prior_index = excluded
    pools = source.get("candidates_by_family") if isinstance(source.get("candidates_by_family"), Mapping) else {}
    by_family: dict[str, dict[str, dict[str, Any]]] = {}
    for family in family_cwes:
        rows: dict[str, dict[str, Any]] = {}
        for raw in pools.get(family) or []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            root = str(row.get("source_root") or "").strip()
            if root and check_candidate(row, index=prior_index)["allowed"]:
                rows[root] = row
        by_family[family] = rows

    cache: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    counters = {"api_requests": 0, "cache_hits": 0, "reviewed_rows": 0, "unreviewed_rows": 0}
    family_queries: dict[str, list[dict[str, Any]]] = {}

    for family in missing:
        query_log: list[dict[str, Any]] = []
        for cwe in family_cwes[family]:
            for advisory_type, page_limit in (("reviewed", reviewed_pages), ("unreviewed", unreviewed_pages)):
                before = _semantic_count(family, list(by_family[family].values()))
                rows = v5._fetch_query_rows(
                    cwe,
                    advisory_type,
                    max_pages=page_limit,
                    cache=cache,
                    counters=counters,
                )
                for raw in rows:
                    v5._add_candidate(
                        by_family[family],
                        raw,
                        advisory_type=advisory_type,
                        family=family,
                        cwe=cwe,
                        excluded=excluded,
                        grounding=grounding_urls,
                    )
                    if _semantic_count(family, list(by_family[family].values())) >= target_semantic:
                        break
                after = _semantic_count(family, list(by_family[family].values()))
                query_log.append({
                    "cwe": cwe,
                    "advisory_type": advisory_type,
                    "page_limit": page_limit,
                    "semantic_before": before,
                    "semantic_after": after,
                })
                if after >= target_semantic:
                    break
            if _semantic_count(family, list(by_family[family].values())) >= target_semantic:
                break
        family_queries[family] = query_log

    filtered: dict[str, list[dict[str, Any]]] = {}
    firewall_rejections = 0
    for family in family_cwes:
        rows = []
        for row in by_family[family].values():
            check = check_candidate(row, index=prior_index)
            if not check["allowed"]:
                firewall_rejections += 1
                continue
            clean = dict(row)
            clean["v8_firewall_allowed"] = True
            clean["v8_deep_discovery"] = family in missing
            clean["v8_selection_uses_v7_score"] = False
            clean["v8_selection_uses_v7_case_errors"] = False
            clean["v8_selection_uses_v7_execution_error"] = False
            rows.append(clean)
        rows.sort(
            key=lambda x: (
                1 if x.get("advisory_source_type") == "reviewed" else 0,
                int(audit_row(family, x)[2]) if audit_row(family, x)[0] else 0,
                x.get("published_at") or "",
                x.get("source_root") or "",
            ),
            reverse=True,
        )
        filtered[family] = rows

    semantic_counts = {family: _semantic_count(family, rows) for family, rows in filtered.items()}
    counts = {family: len(rows) for family, rows in filtered.items()}
    report = dict(source)
    report.update({
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v8_deep_source_discovery_unscored",
        "candidates_by_family": filtered,
        "family_candidate_counts": counts,
        "family_semantic_candidate_counts": semantic_counts,
        "families_without_candidates": sorted(family for family, rows in filtered.items() if not rows),
        "families_without_semantic_candidates": sorted(family for family, count in semantic_counts.items() if count == 0),
        "deepened_families": missing,
        "deep_reviewed_page_limit": reviewed_pages,
        "deep_unreviewed_page_limit": unreviewed_pages,
        "deep_target_semantic_per_family": target_semantic,
        "deep_query_log": family_queries,
        "deep_api_request_count": counters["api_requests"],
        "deep_query_cache_hit_count": counters["cache_hits"],
        "deep_firewall_rejection_count": firewall_rejections,
        "source_selection_grounding": "external CWE taxonomy plus preregistered semantic audit; WSTG/CWE/OWASP/write-up knowledge is reasoning grounding only and never target evidence",
        "grounding_counts_as_target_evidence": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v7_first_blind_score": False,
        "candidate_selection_uses_v7_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_error": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    })
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewed-pages", type=int, default=8)
    parser.add_argument("--unreviewed-pages", type=int, default=16)
    parser.add_argument("--target-semantic", type=int, default=16)
    args = parser.parse_args()
    report = deepen(
        reviewed_pages=args.reviewed_pages,
        unreviewed_pages=args.unreviewed_pages,
        target_semantic=args.target_semantic,
    )
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "deepened_family_count": len(report["deepened_families"]),
        "deep_api_request_count": report["deep_api_request_count"],
        "families_without_candidates": report["families_without_candidates"],
        "families_without_semantic_candidates": report["families_without_semantic_candidates"],
        "family_semantic_candidate_counts": report["family_semantic_candidate_counts"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

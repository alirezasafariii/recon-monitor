from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v4_source_discovery import (
    _canonical_url,
    _fetch_pages,
    _grounding_writeup_urls,
    _prior_exposure_index,
    _project_from_url,
)

SOURCE_MAP_DISCOVERY_VERSION = "1.0.0"
SOURCE_MAP_DISCOVERY_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_source_map_discovery.json"

# Priority is intentionally fixed before searching. CWE-219 is the narrowest
# web-root exposure bucket, then CWE-200, then path/file-related CWE-22.
SEARCH_CWES = ("CWE-219", "CWE-200", "CWE-22")
REQUIRED_GROUPS = (
    ("source map", "sourcemap", "source-map", ".js.map", ".mjs.map", "sourcescontent"),
    ("public", "unauthenticated", "unauthorized", "expos", "disclos", "retrieve", "read", "browser", "accessible"),
    ("source code", "original source", "server source", "internal source", "sourcescontent", "arbitrary .map", "reconstruct"),
)


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def _semantic_hits(row: Mapping[str, Any]) -> list[list[str]] | None:
    text = _text(row)
    result: list[list[str]] = []
    for group in REQUIRED_GROUPS:
        hits = sorted({term for term in group if term.lower() in text})
        if not hits:
            return None
        result.append(hits)
    return result


def _project(row: Mapping[str, Any], references: list[str]) -> str:
    for value in (
        str(row.get("source_code_location") or ""),
        str(row.get("repository_advisory_url") or ""),
        *references,
    ):
        project = _project_from_url(value)
        if project and not project.startswith("advisories/"):
            return project
    return ""


def _primary_url(row: Mapping[str, Any], references: list[str]) -> str:
    for value in references:
        if value.startswith("https://github.com/") and "/security/advisories/" in value:
            return value
    repo = str(row.get("repository_advisory_url") or "").strip()
    if repo:
        return repo
    return str(row.get("source_code_location") or "").strip()


def discover(*, max_pages_per_cwe: int = 60) -> dict[str, Any]:
    excluded = _prior_exposure_index()
    grounding = _grounding_writeup_urls()
    reviewed = 0
    semantic_matches = 0
    novelty_rejections: list[dict[str, Any]] = []

    for cwe in SEARCH_CWES:
        for page_number, page in enumerate(_fetch_pages(cwe, max_pages=max_pages_per_cwe), start=1):
            reviewed += len(page)
            eligible: list[dict[str, Any]] = []
            for row in page:
                hits = _semantic_hits(row)
                if hits is None:
                    continue
                semantic_matches += 1
                root = str(row.get("ghsa_id") or "").strip()
                references = [str(v).strip() for v in row.get("references") or [] if str(v).strip()]
                project = _project(row, references)
                primary = _primary_url(row, references)
                urls = {
                    _canonical_url(v)
                    for v in (
                        primary,
                        str(row.get("repository_advisory_url") or ""),
                        str(row.get("source_code_location") or ""),
                        *references,
                    )
                    if _canonical_url(v)
                }
                reasons: list[str] = []
                if not root:
                    reasons.append("missing_root")
                if not project:
                    reasons.append("missing_project")
                if not primary:
                    reasons.append("missing_primary_url")
                if root in excluded["roots"]:
                    reasons.append("prior_root")
                if project in excluded["projects"] or project.lower() in {p.lower() for p in excluded["projects"]}:
                    reasons.append("prior_project")
                if urls & excluded["urls"]:
                    reasons.append("prior_url")
                if urls & grounding:
                    reasons.append("grounding_overlap")
                if row.get("withdrawn_at"):
                    reasons.append("withdrawn")
                if reasons:
                    novelty_rejections.append({
                        "cwe": cwe,
                        "page": page_number,
                        "root": root,
                        "project": project,
                        "summary": str(row.get("summary") or ""),
                        "reasons": reasons,
                    })
                    continue
                row_cwes = sorted({
                    str(item.get("cwe_id") or "").strip()
                    for item in row.get("cwes") or []
                    if isinstance(item, Mapping) and str(item.get("cwe_id") or "").strip()
                })
                eligible.append({
                    "source_root": root,
                    "source_project": project,
                    "family": "source_map_exposure",
                    "matched_cwes": row_cwes,
                    "published_at": str(row.get("published_at") or ""),
                    "updated_at": str(row.get("updated_at") or ""),
                    "severity": str(row.get("severity") or ""),
                    "summary": str(row.get("summary") or ""),
                    "description": str(row.get("description") or ""),
                    "repository_advisory_url": str(row.get("repository_advisory_url") or ""),
                    "source_code_location": str(row.get("source_code_location") or ""),
                    "canonical_advisory_url": primary,
                    "references": references,
                    "source_map_semantic_hits": hits,
                    "selection_basis": "reviewed_advisory_exact_source_map_semantics_plus_complete_v4_novelty_firewall_pre_scoring",
                    "freshness_validated": True,
                    "discovered_from_cwe": cwe,
                    "discovered_page": page_number,
                })
            if eligible:
                # First qualifying page in pre-registered CWE/page order wins;
                # strongest semantic richness then recency breaks ties.
                eligible.sort(
                    key=lambda item: (
                        sum(len(group) for group in item["source_map_semantic_hits"]),
                        item["published_at"],
                        item["source_root"],
                    ),
                    reverse=True,
                )
                selected = eligible[0]
                return {
                    "source_map_discovery_version": SOURCE_MAP_DISCOVERY_VERSION,
                    "source_map_discovery_rule_version": SOURCE_MAP_DISCOVERY_RULE_VERSION,
                    "search_cwes": list(SEARCH_CWES),
                    "max_pages_per_cwe": max_pages_per_cwe,
                    "reviewed_advisory_rows": reviewed,
                    "semantic_match_count_before_novelty": semantic_matches,
                    "novelty_rejection_count": len(novelty_rejections),
                    "novelty_rejections": novelty_rejections,
                    "selected": selected,
                    "selection_executes_analysis_engine": False,
                    "selection_uses_detector_scores": False,
                    "selection_uses_admission_results": False,
                    "selection_uses_benchmark_results": False,
                }
    return {
        "source_map_discovery_version": SOURCE_MAP_DISCOVERY_VERSION,
        "source_map_discovery_rule_version": SOURCE_MAP_DISCOVERY_RULE_VERSION,
        "search_cwes": list(SEARCH_CWES),
        "max_pages_per_cwe": max_pages_per_cwe,
        "reviewed_advisory_rows": reviewed,
        "semantic_match_count_before_novelty": semantic_matches,
        "novelty_rejection_count": len(novelty_rejections),
        "novelty_rejections": novelty_rejections,
        "selected": None,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover an exact fresh source-map case for Analysis 6.26 raw v4")
    parser.add_argument("--max-pages-per-cwe", type=int, default=60)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    report = discover(max_pages_per_cwe=max(1, args.max_pages_per_cwe))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "reviewed_advisory_rows": report["reviewed_advisory_rows"],
        "semantic_match_count_before_novelty": report["semantic_match_count_before_novelty"],
        "novelty_rejection_count": report["novelty_rejection_count"],
        "selected": report["selected"],
    }, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if report["selected"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

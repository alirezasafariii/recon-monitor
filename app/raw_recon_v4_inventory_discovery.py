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

INVENTORY_DISCOVERY_VERSION = "1.0.0"
INVENTORY_DISCOVERY_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_inventory_discovery.json"

# External-taxonomy discovery only. The order is pre-registered before search:
# exposed information/public resources first, then missing authorization/auth,
# generic access control, and finally unbounded public legacy operations.
SEARCH_CWES = ("CWE-200", "CWE-306", "CWE-862", "CWE-284", "CWE-400")

LIFECYCLE_MARKERS = (
    "deprecated endpoint", "deprecated api", "deprecated route", "deprecated version",
    "legacy endpoint", "legacy api", "legacy route", "old api", "old endpoint",
    "obsolete endpoint", "obsolete api", "end-of-life api", "end of life api",
    "staging endpoint", "staging api", "development endpoint", "development api",
    "test endpoint", "test api", "beta endpoint", "beta api", "alpha endpoint", "alpha api",
    "deprecated=true", "deprecated = true", "marked deprecated", "is deprecated",
)
API_SURFACE_MARKERS = (
    " endpoint", "endpoint ", " api ", "/api/", "/api/v1", "/api/v2", " route", "handler",
)
REACHABILITY_MARKERS = (
    "unauthenticated", "without authentication", "no authentication", "publicly accessible",
    "publicly reachable", "still reachable", "still accessible", "remains accessible",
    "remains reachable", "can access", "any user", "remote attacker", "without authorization",
    "missing authorization", "no authorization", "exposed", "internet-accessible",
)
WEAKER_CONTROL_MARKERS = (
    "without authentication", "no authentication", "unauthenticated", "without authorization",
    "missing authorization", "no authorization", "no ownership", "no rate limit", "without rate limit",
    "bypass", "weaker", "unrestricted", "any user", "arbitrary", "does not check",
)


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def _hits(text: str, markers: tuple[str, ...]) -> list[str]:
    return sorted({marker for marker in markers if marker in text})


def _semantic(row: Mapping[str, Any]) -> tuple[bool, dict[str, list[str]], int]:
    text = _text(row)
    lifecycle = _hits(text, LIFECYCLE_MARKERS)
    surface = _hits(text, API_SURFACE_MARKERS)
    reachable = _hits(text, REACHABILITY_MARKERS)
    weaker = _hits(text, WEAKER_CONTROL_MARKERS)
    groups = {
        "lifecycle": lifecycle,
        "api_surface": surface,
        "reachable_or_exposed": reachable,
        "weaker_control": weaker,
    }
    if not all(groups.values()):
        return False, groups, 0
    score = sum(len(values) * 3 for values in groups.values())
    if "proof of concept" in text or "## poc" in text or "### poc" in text:
        score += 2
    if "curl " in text or "http/1.1" in text:
        score += 2
    return True, groups, score


def _project(row: Mapping[str, Any], refs: list[str]) -> str:
    for value in (
        str(row.get("source_code_location") or ""),
        str(row.get("repository_advisory_url") or ""),
        *refs,
    ):
        project = _project_from_url(value)
        if project and not project.startswith("advisories/"):
            return project
    return ""


def _primary_url(row: Mapping[str, Any], refs: list[str]) -> str:
    for value in refs:
        if value.startswith("https://github.com/") and "/security/advisories/" in value:
            return value
    repo = str(row.get("repository_advisory_url") or "").strip()
    if repo:
        return repo
    return str(row.get("source_code_location") or "").strip()


def _candidate(
    row: Mapping[str, Any],
    *,
    cwe: str,
    page_number: int,
    excluded: Mapping[str, set[str]],
    grounding: set[str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    semantic_ok, groups, semantic_score = _semantic(row)
    if not semantic_ok:
        return None, None

    root = str(row.get("ghsa_id") or "").strip()
    refs = [str(value).strip() for value in row.get("references") or [] if str(value).strip()]
    project = _project(row, refs)
    primary = _primary_url(row, refs)
    urls = {
        _canonical_url(value)
        for value in (
            primary,
            str(row.get("repository_advisory_url") or ""),
            str(row.get("source_code_location") or ""),
            *refs,
        )
        if _canonical_url(value)
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
    if project in excluded["projects"] or project.lower() in {value.lower() for value in excluded["projects"]}:
        reasons.append("prior_project")
    if urls & excluded["urls"]:
        reasons.append("prior_url")
    if urls & grounding:
        reasons.append("grounding_overlap")
    if row.get("withdrawn_at"):
        reasons.append("withdrawn")
    if reasons:
        return None, {
            "cwe": cwe,
            "page": page_number,
            "root": root,
            "project": project,
            "summary": str(row.get("summary") or ""),
            "semantic_groups": groups,
            "reasons": reasons,
        }

    row_cwes = sorted({
        str(item.get("cwe_id") or "").strip()
        for item in row.get("cwes") or []
        if isinstance(item, Mapping) and str(item.get("cwe_id") or "").strip()
    })
    return {
        "source_root": root,
        "source_project": project,
        "family": "improper_inventory_management",
        "matched_cwes": row_cwes,
        "published_at": str(row.get("published_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
        "severity": str(row.get("severity") or ""),
        "summary": str(row.get("summary") or ""),
        "description": str(row.get("description") or ""),
        "repository_advisory_url": str(row.get("repository_advisory_url") or ""),
        "source_code_location": str(row.get("source_code_location") or ""),
        "canonical_advisory_url": primary,
        "references": refs,
        "inventory_semantic_groups": groups,
        "inventory_semantic_score": semantic_score,
        "selection_basis": "reviewed_advisory_exact_api_lifecycle_exposure_semantics_plus_complete_v4_novelty_firewall_pre_scoring",
        "freshness_validated": True,
        "discovered_from_cwe": cwe,
        "discovered_page": page_number,
    }, None


def discover(*, max_pages_per_cwe: int = 50) -> dict[str, Any]:
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
                candidate, rejection = _candidate(
                    row,
                    cwe=cwe,
                    page_number=page_number,
                    excluded=excluded,
                    grounding=grounding,
                )
                if candidate is not None:
                    semantic_matches += 1
                    eligible.append(candidate)
                elif rejection is not None:
                    semantic_matches += 1
                    novelty_rejections.append(rejection)
            if eligible:
                # Pre-registered stopping rule: first CWE/page containing any
                # fresh exact lifecycle/API/reachability candidate wins; textual
                # richness + recency only break ties inside that page.
                eligible.sort(
                    key=lambda item: (
                        int(item["inventory_semantic_score"]),
                        item["published_at"],
                        item["source_root"],
                    ),
                    reverse=True,
                )
                selected = eligible[0]
                return {
                    "inventory_discovery_version": INVENTORY_DISCOVERY_VERSION,
                    "inventory_discovery_rule_version": INVENTORY_DISCOVERY_RULE_VERSION,
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
        "inventory_discovery_version": INVENTORY_DISCOVERY_VERSION,
        "inventory_discovery_rule_version": INVENTORY_DISCOVERY_RULE_VERSION,
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
    parser = argparse.ArgumentParser(description="Discover an exact fresh API9 inventory case for Analysis 6.26 raw v4")
    parser.add_argument("--max-pages-per-cwe", type=int, default=50)
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

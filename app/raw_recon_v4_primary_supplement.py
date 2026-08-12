from __future__ import annotations

import argparse
import json
import os
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

SUPPLEMENT_VERSION = "1.1.0"
SUPPLEMENT_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"
DEFAULT_MAX_PAGES = 30

# The general discovery pool uses each family's normal CWE taxonomy. GraphQL and
# WebSocket authorization are specialized protocol families whose generic
# authorization CWEs are too broad to identify the protocol from CWE alone.
# This supplement still runs before scoring: it scans reviewed advisories by
# external CWE taxonomy, then requires explicit protocol/authorization language
# and the same novelty firewall as the general v4 pool.
SUPPLEMENT_SEARCH_SPECS: dict[str, dict[str, Any]] = {
    "graphql_authorization": {
        "cwes": ("CWE-862", "CWE-863"),
        "required_text_groups": (
            ("graphql",),
            ("authorization", "unauthorized", "access control", "permission", "scope"),
            ("resolver", "query", "mutation", "token", "schema", "field"),
        ),
    },
    "websocket_authorization": {
        "cwes": ("CWE-862", "CWE-863", "CWE-352", "CWE-287"),
        "required_text_groups": (
            ("websocket", "web socket", "stomp"),
            ("authorization", "unauthorized", "authentication bypass", "security bypass", "permission", "access control"),
            ("message", "subscription", "channel", "connection", "socket", "stomp"),
        ),
    },
}


def _project(row: Mapping[str, Any]) -> str:
    for value in (
        str(row.get("source_code_location") or "").strip(),
        str(row.get("repository_advisory_url") or "").strip(),
    ):
        project = _project_from_url(value)
        if project:
            return project
    return ""


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def _semantic_hits(row: Mapping[str, Any], spec: Mapping[str, Any]) -> tuple[bool, list[str]]:
    text = _text(row)
    hits: list[str] = []
    for group in spec.get("required_text_groups") or ():
        group_hits = [str(term) for term in group if str(term).lower() in text]
        if not group_hits:
            return False, hits
        hits.extend(group_hits)
    return True, sorted(set(hits))


def _primary_url(row: Mapping[str, Any]) -> str:
    references = [str(value).strip() for value in row.get("references") or [] if str(value).strip()]
    for value in references:
        if value.startswith("https://github.com/") and "/security/advisories/" in value:
            return value
    for value in references:
        if "github.com/advisories/" in value or "nvd.nist.gov/" in value:
            continue
        if value.startswith("https://"):
            return value
    repository_advisory = str(row.get("repository_advisory_url") or "").strip()
    if repository_advisory:
        return repository_advisory
    return str(row.get("source_code_location") or "").strip()


def _fresh_candidate(
    *,
    family: str,
    row: Mapping[str, Any],
    spec: Mapping[str, Any],
    excluded: Mapping[str, set[str]],
    grounding: set[str],
) -> dict[str, Any] | None:
    if row.get("withdrawn_at"):
        return None
    root = str(row.get("ghsa_id") or "").strip()
    project = _project(row)
    if not root or not project or root in excluded["roots"] or project in excluded["projects"]:
        return None

    row_cwes = {
        str(item.get("cwe_id") or "").strip()
        for item in row.get("cwes") or []
        if isinstance(item, Mapping)
    }
    expected_cwes = {str(value) for value in spec.get("cwes") or ()}
    matched_cwes = sorted(row_cwes & expected_cwes)
    if not matched_cwes:
        return None

    semantic_ok, hits = _semantic_hits(row, spec)
    if not semantic_ok:
        return None

    primary_url = _primary_url(row)
    references = [str(value).strip() for value in row.get("references") or [] if str(value).strip()]
    all_urls = {
        _canonical_url(value)
        for value in (
            primary_url,
            str(row.get("repository_advisory_url") or ""),
            str(row.get("source_code_location") or ""),
            *references,
        )
        if _canonical_url(value)
    }
    if not primary_url or all_urls & excluded["urls"] or all_urls & grounding:
        return None

    description = str(row.get("description") or "")
    if len(description.strip()) < 100:
        return None

    return {
        "source_root": root,
        "source_project": project,
        "family": family,
        "matched_cwes": matched_cwes,
        "published_at": str(row.get("published_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
        "severity": str(row.get("severity") or ""),
        "summary": str(row.get("summary") or ""),
        "description": description,
        "repository_advisory_url": str(row.get("repository_advisory_url") or ""),
        "source_code_location": str(row.get("source_code_location") or ""),
        "canonical_advisory_url": primary_url,
        "references": references,
        "supplement_semantic_hits": hits,
        "selection_basis": "reviewed_primary_advisory_specialized_semantic_discovery_pre_scoring",
        "freshness_validated": True,
        "freshness_excluded_prior_roots": len(excluded["roots"]),
        "freshness_excluded_prior_projects": len(excluded["projects"]),
        "freshness_excluded_prior_urls": len(excluded["urls"]),
        "freshness_excluded_grounding_urls": len(grounding),
    }


def _discover_family(
    family: str,
    spec: Mapping[str, Any],
    *,
    max_pages: int,
    excluded: Mapping[str, set[str]],
    grounding: set[str],
    used_projects: set[str],
) -> tuple[dict[str, Any], int]:
    eligible: dict[str, dict[str, Any]] = {}
    reviewed_rows = 0
    for cwe in spec.get("cwes") or ():
        for page in _fetch_pages(str(cwe), max_pages=max_pages):
            reviewed_rows += len(page)
            for raw in page:
                candidate = _fresh_candidate(
                    family=family,
                    row=raw,
                    spec=spec,
                    excluded=excluded,
                    grounding=grounding,
                )
                if candidate is None or candidate["source_project"] in used_projects:
                    continue
                prior = eligible.get(candidate["source_root"])
                if prior is None or len(candidate["supplement_semantic_hits"]) > len(prior["supplement_semantic_hits"]):
                    eligible[candidate["source_root"]] = candidate
    rows = list(eligible.values())
    rows.sort(
        key=lambda item: (
            len(item["supplement_semantic_hits"]),
            str(item.get("published_at") or ""),
            str(item.get("source_root") or ""),
        ),
        reverse=True,
    )
    if not rows:
        raise RuntimeError(f"Analysis 6.26 could not find a fresh specialized primary source for {family}")
    return rows[0], reviewed_rows


def build(*, max_pages: int = DEFAULT_MAX_PAGES) -> dict[str, Any]:
    # GITHUB_TOKEN is consumed by the shared source-discovery request helper.
    _ = os.getenv("GITHUB_TOKEN", "")
    excluded = _prior_exposure_index()
    grounding = _grounding_writeup_urls()
    selected: list[dict[str, Any]] = []
    used_projects: set[str] = set()
    reviewed_rows_by_family: dict[str, int] = {}
    for family, spec in sorted(SUPPLEMENT_SEARCH_SPECS.items()):
        candidate, reviewed_rows = _discover_family(
            family,
            spec,
            max_pages=max_pages,
            excluded=excluded,
            grounding=grounding,
            used_projects=used_projects,
        )
        selected.append(candidate)
        used_projects.add(candidate["source_project"])
        reviewed_rows_by_family[family] = reviewed_rows

    if len({row["source_root"] for row in selected}) != len(selected):
        raise RuntimeError("supplement roots must be unique")
    if len({row["source_project"] for row in selected}) != len(selected):
        raise RuntimeError("supplement projects must be unique")

    return {
        "supplement_version": SUPPLEMENT_VERSION,
        "supplement_rule_version": SUPPLEMENT_RULE_VERSION,
        "reviewed_rows_scanned_by_family": reviewed_rows_by_family,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
        "selected": selected,
        "note": (
            "Specialized GraphQL/WebSocket sources are discovered from reviewed advisories by external CWE plus exact protocol semantics, "
            "then accepted only after the same prior-root, prior-project, prior-URL and detector-grounding exclusions as the general v4 pool."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.26 specialized fresh primary source supplement")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    args = parser.parse_args()
    report = build(max_pages=max(1, args.max_pages))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "selected": [
            {
                "family": row["family"],
                "root": row["source_root"],
                "project": row["source_project"],
                "url": row["canonical_advisory_url"],
                "cwes": row["matched_cwes"],
                "semantic_hits": row["supplement_semantic_hits"],
            }
            for row in report["selected"]
        ],
        "reviewed_rows_scanned_by_family": report["reviewed_rows_scanned_by_family"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

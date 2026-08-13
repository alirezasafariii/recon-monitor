from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v4_source_discovery as v4

VERSION = "1.4.0"
RULE_VERSION = "2026.08.13.6.29"
V4_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v4.jsonl"
V4_FILES = tuple((ROOT / "benchmarks/raw/sources").glob("v4_*.json"))
ADVISORY_TYPES = ("reviewed", "unreviewed")
_RESEARCH_REPO_TOKENS = (
    "poc",
    "proof-of-concept",
    "proof_of_concept",
    "exploit",
    "vulnerability-research",
    "vulnerability_research",
    "vuln-research",
    "vuln_research",
    "web-security-pocs",
    "security-pocs",
    "cve-",
    "cves",
)


def exposure_index() -> dict[str, set[str]]:
    out = {key: set(values) for key, values in v4._prior_exposure_index().items()}
    if V4_CORPUS.exists():
        prior = prior_source_index((V4_CORPUS,))
        out["roots"].update(prior["roots"])
        out["projects"].update(prior["projects"])
        out["urls"].update(v4._canonical_url(x) for x in prior["urls"] if v4._canonical_url(x))
    for path in V4_FILES:
        value = v4._read_json(path)
        if value is None:
            continue
        for row in v4._walk_candidate_rows(value):
            root = str(row.get("source_root") or "").strip()
            project = str(row.get("source_project") or "").strip()
            if root:
                out["roots"].add(root)
            if project:
                out["projects"].add(project)
            for key in ("canonical_advisory_url", "repository_advisory_url", "source_code_location"):
                url = v4._canonical_url(str(row.get(key) or ""))
                if url:
                    out["urls"].add(url)
            provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
            url = v4._canonical_url(str(provenance.get("url") or ""))
            if url:
                out["urls"].add(url)
    return out


def _fetch_query_rows(
    cwe: str,
    advisory_type: str,
    *,
    max_pages: int,
    cache: dict[tuple[str, str, int], list[dict[str, Any]]],
    counters: dict[str, int],
    per_page: int = 100,
) -> list[dict[str, Any]]:
    key = (cwe, advisory_type, max_pages)
    if key in cache:
        counters["cache_hits"] += 1
        return cache[key]

    numeric = cwe.removeprefix("CWE-")
    query = urllib.parse.urlencode({"type": advisory_type, "cwes": numeric, "per_page": per_page})
    url = f"{v4.GITHUB_ADVISORY_API}?{query}"
    rows: list[dict[str, Any]] = []
    for _ in range(max_pages):
        request = urllib.request.Request(url, headers=v4._headers())
        response = None
        for attempt in range(3):
            try:
                response = urllib.request.urlopen(request, timeout=45)
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 403 or attempt == 2:
                    raise
                # Secondary-rate-limit protection only. Query selection and results
                # remain unchanged; this merely avoids concurrent burst pressure.
                time.sleep(1.0 + attempt)
        if response is None:
            raise RuntimeError(f"unable to fetch advisory query for {cwe}/{advisory_type}")
        with response:
            payload = json.load(response)
            link = response.headers.get("Link", "")
        counters["api_requests"] += 1
        page_rows = [dict(row) for row in payload if isinstance(row, Mapping)]
        counters[f"{advisory_type}_rows"] += len(page_rows)
        if not page_rows:
            break
        rows.extend(page_rows)
        url = v4._next_link(link)
        if not url:
            break
        time.sleep(0.05)
    cache[key] = rows
    return rows


def _is_research_project(project: str) -> bool:
    lowered = project.lower()
    compact = re.sub(r"[^a-z0-9_-]+", "-", lowered)
    return any(token in compact for token in _RESEARCH_REPO_TOKENS)


def _eligible_unreviewed_candidate(
    row: Mapping[str, Any],
    *,
    family: str,
    cwe: str,
    excluded: Mapping[str, set[str]],
    grounding_urls: set[str],
) -> dict[str, Any] | None:
    root = str(row.get("ghsa_id") or "").strip()
    if not root or root in excluded["roots"] or row.get("withdrawn_at"):
        return None
    row_cwes = {
        str(item.get("cwe_id") or "").strip()
        for item in row.get("cwes") or []
        if isinstance(item, Mapping)
    }
    if cwe not in row_cwes:
        return None
    description = str(row.get("description") or "").strip()
    if len(description) < 120:
        return None
    references = [str(value).strip() for value in row.get("references") or [] if str(value).strip()]
    reference_urls = {v4._canonical_url(value) for value in references if v4._canonical_url(value)}
    if reference_urls & grounding_urls:
        return None

    advisory_url = str(row.get("html_url") or "").strip()
    canonical_advisory = v4._canonical_url(advisory_url)
    if not canonical_advisory or canonical_advisory in excluded["urls"]:
        return None

    project = ""
    project_reference = ""
    for value in references:
        candidate_project = v4._project_from_url(value)
        if not candidate_project or candidate_project.startswith("advisories/"):
            continue
        if _is_research_project(candidate_project):
            continue
        project = candidate_project
        project_reference = value
        break
    if not project or project in excluded["projects"]:
        return None

    return {
        "source_root": root,
        "source_project": project,
        "family": family,
        "matched_cwes": [cwe],
        "published_at": str(row.get("published_at") or "").strip(),
        "updated_at": str(row.get("updated_at") or "").strip(),
        "severity": str(row.get("severity") or "").strip(),
        "summary": str(row.get("summary") or "").strip(),
        "description": description,
        "repository_advisory_url": "",
        "source_code_location": project_reference,
        "canonical_advisory_url": advisory_url,
        "references": references,
        "source_kind": "github_unreviewed_advisory_with_repository_reference",
        "selection_basis": "github_unreviewed_advisory_matched_by_external_CWE_taxonomy_before_scoring",
    }


def _eligible_candidate(
    row: Mapping[str, Any],
    *,
    advisory_type: str,
    family: str,
    cwe: str,
    excluded: Mapping[str, set[str]],
    grounding_urls: set[str],
) -> dict[str, Any] | None:
    candidate = v4._eligible_candidate(
        row,
        family=family,
        cwe=cwe,
        excluded=excluded,
        grounding_urls=grounding_urls,
    )
    if candidate is not None:
        project = str(candidate.get("source_project") or "")
        if project and _is_research_project(project):
            return None
        candidate["source_kind"] = "github_reviewed_or_repository_advisory"
        return candidate
    if advisory_type != "unreviewed":
        return None
    return _eligible_unreviewed_candidate(
        row,
        family=family,
        cwe=cwe,
        excluded=excluded,
        grounding_urls=grounding_urls,
    )


def discover(
    max_pages_reviewed: int = 3,
    max_pages_unreviewed: int = 6,
    target_per_family: int = 60,
) -> dict[str, Any]:
    excluded = exposure_index()
    grounding = v4._grounding_writeup_urls()
    family_cwes = v4._family_cwes()
    by_family: dict[str, list[dict[str, Any]]] = {}
    cache: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    counters = {"api_requests": 0, "cache_hits": 0, "reviewed_rows": 0, "unreviewed_rows": 0}

    for family, cwes in family_cwes.items():
        by_root: dict[str, dict[str, Any]] = {}
        for cwe in cwes:
            for advisory_type in ADVISORY_TYPES:
                page_limit = max_pages_reviewed if advisory_type == "reviewed" else max_pages_unreviewed
                query_rows = _fetch_query_rows(
                    cwe,
                    advisory_type,
                    max_pages=page_limit,
                    cache=cache,
                    counters=counters,
                )
                for raw in query_rows:
                    row = _eligible_candidate(
                        raw,
                        advisory_type=advisory_type,
                        family=family,
                        cwe=cwe,
                        excluded=excluded,
                        grounding_urls=grounding,
                    )
                    if row is None:
                        continue
                    root = str(row["source_root"])
                    if root not in by_root:
                        row["freshness_validated"] = True
                        row["advisory_source_type"] = advisory_type
                        by_root[root] = row
                    else:
                        by_root[root]["matched_cwes"] = sorted(
                            set(by_root[root]["matched_cwes"]) | set(row["matched_cwes"])
                        )
                        if by_root[root].get("advisory_source_type") != "reviewed" and advisory_type == "reviewed":
                            by_root[root]["advisory_source_type"] = "reviewed"
                    if len(by_root) >= target_per_family:
                        break
                if len(by_root) >= target_per_family:
                    break
            if len(by_root) >= target_per_family:
                break
        rows = list(by_root.values())
        rows.sort(
            key=lambda x: (
                1 if x.get("advisory_source_type") == "reviewed" else 0,
                x.get("published_at") or "",
                x["source_root"],
            ),
            reverse=True,
        )
        by_family[family] = rows

    counts = {family: len(rows) for family, rows in by_family.items()}
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "family_count": len(family_cwes),
        "unique_advisory_queries": len(cache),
        "api_request_count": counters["api_requests"],
        "query_cache_hit_count": counters["cache_hits"],
        "queried_rows_by_advisory_type": {
            "reviewed": counters["reviewed_rows"],
            "unreviewed": counters["unreviewed_rows"],
        },
        "advisory_types": list(ADVISORY_TYPES),
        "family_candidate_counts": counts,
        "families_without_candidates": sorted(k for k, count in counts.items() if not count),
        "excluded_prior_root_count": len(excluded["roots"]),
        "excluded_prior_project_count": len(excluded["projects"]),
        "excluded_prior_url_count": len(excluded["urls"]),
        "excluded_grounding_url_count": len(grounding),
        "research_repository_references_rejected": True,
        "scoring_executed": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_prior_v4_results": False,
        "candidates_by_family": by_family,
    }


def main() -> int:
    report = discover()
    out = ROOT / "benchmarks/raw/sources/v5_candidates.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        key: report[key]
        for key in (
            "family_count",
            "families_without_candidates",
            "excluded_prior_root_count",
            "excluded_prior_project_count",
            "unique_advisory_queries",
            "api_request_count",
            "query_cache_hit_count",
            "queried_rows_by_advisory_type",
        )
    }, indent=2))
    return 2 if report["families_without_candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

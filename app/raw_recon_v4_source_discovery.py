from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_standards import FAMILY_STANDARDS
from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT, prior_source_index

SOURCE_DISCOVERY_VERSION = "1.0.0"
SOURCE_DISCOVERY_RULE_VERSION = "2026.08.12.6.26"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

PRIOR_CORPORA = (
    ROOT / "benchmarks" / "golden" / "analysis_golden_v3.jsonl",
    ROOT / "benchmarks" / "golden" / "analysis_golden_v4.jsonl",
    ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl",
    ROOT / "benchmarks" / "raw" / "analysis_raw_v2.jsonl",
    ROOT / "benchmarks" / "raw" / "analysis_raw_v3.jsonl",
)
PRIOR_DISCOVERY_FILES = (
    ROOT / "benchmarks" / "raw" / "sources" / "v2_candidates.json",
    ROOT / "benchmarks" / "raw" / "sources" / "v2_shortlist.json",
    ROOT / "benchmarks" / "raw" / "sources" / "v3_candidates.json",
    ROOT / "benchmarks" / "raw" / "sources" / "v3_external_primary_candidates.json",
    ROOT / "benchmarks" / "raw" / "sources" / "v3_shortlist.json",
)


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _canonical_url(value: str) -> str:
    raw = _norm(value)
    if not raw:
        return ""
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return raw
    path = parsed.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _project_from_url(value: str) -> str:
    raw = _norm(value)
    patterns = (
        r"https://github\.com/([^/]+/[^/#?]+)",
        r"https://api\.github\.com/repos/([^/]+/[^/#?]+)",
    )
    for pattern in patterns:
        match = re.match(pattern, raw)
        if match:
            project = match.group(1).removesuffix(".git")
            if project.lower() != "advisories/ghsa":
                return project
    return ""


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "recon-monitor-analysis-6.26-raw-v4",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _next_link(header: str) -> str:
    for part in (header or "").split(","):
        if 'rel="next"' not in part:
            continue
        match = re.search(r"<([^>]+)>", part)
        if match:
            return match.group(1)
    return ""


def _fetch_pages(cwe: str, *, max_pages: int, per_page: int = 100) -> Iterable[list[dict[str, Any]]]:
    numeric = cwe.removeprefix("CWE-")
    query = urllib.parse.urlencode({"type": "reviewed", "cwes": numeric, "per_page": per_page})
    url = f"{GITHUB_ADVISORY_API}?{query}"
    for _ in range(max_pages):
        request = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.load(response)
            link = response.headers.get("Link", "")
        rows = [dict(row) for row in payload if isinstance(row, Mapping)]
        if not rows:
            return
        yield rows
        url = _next_link(link)
        if not url:
            return


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _walk_candidate_rows(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if value.get("source_root") or value.get("canonical_advisory_url"):
            yield value
        for child in value.values():
            yield from _walk_candidate_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_candidate_rows(child)


def _prior_exposure_index() -> dict[str, set[str]]:
    prior = prior_source_index(PRIOR_CORPORA)
    roots = set(prior["roots"])
    urls = {_canonical_url(value) for value in prior["urls"] if _canonical_url(value)}
    projects = set(prior["projects"])
    for path in PRIOR_DISCOVERY_FILES:
        for row in _walk_candidate_rows(_read_json(path)):
            root = _norm(row.get("source_root"))
            project = _norm(row.get("source_project"))
            candidates = (
                _norm(row.get("canonical_advisory_url")),
                _norm(row.get("repository_advisory_url")),
                _norm((row.get("provenance") or {}).get("url")) if isinstance(row.get("provenance"), Mapping) else "",
            )
            if root:
                roots.add(root)
            if project:
                projects.add(project)
            urls.update(_canonical_url(url) for url in candidates if _canonical_url(url))
    return {"roots": roots, "urls": urls, "projects": projects}


def _grounding_writeup_urls() -> set[str]:
    urls: set[str] = set()
    for spec in DETECTOR_SPECS.values():
        for ref in spec.writeups:
            url = _canonical_url(ref.url)
            if url:
                urls.add(url)
    return urls


def _family_cwes() -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for family in sorted(FAMILY_STANDARDS):
        cwes = tuple(
            str(item.get("id") or "").strip()
            for item in FAMILY_STANDARDS[family].get("cwe", [])
            if str(item.get("id") or "").strip().startswith("CWE-")
        )
        if not cwes:
            raise RuntimeError(f"Analysis 6.26 source discovery has no CWE taxonomy bucket for {family}")
        result[family] = cwes
    return result


def _candidate_primary_url(row: Mapping[str, Any], references: list[str]) -> str:
    repository_advisory = _norm(row.get("repository_advisory_url"))
    source_location = _norm(row.get("source_code_location"))
    candidates = [
        value for value in references
        if value.startswith("https://github.com/") and "/security/advisories/" in value
    ]
    if candidates:
        return candidates[0]
    if repository_advisory:
        return repository_advisory
    if source_location:
        return source_location
    return ""


def _project_for_candidate(row: Mapping[str, Any], primary_url: str, references: list[str]) -> str:
    for value in (
        _norm(row.get("source_code_location")),
        _norm(row.get("repository_advisory_url")),
        primary_url,
        *references,
    ):
        project = _project_from_url(value)
        if project and not project.startswith("advisories/"):
            return project
    return ""


def _eligible_candidate(
    row: Mapping[str, Any],
    *,
    family: str,
    cwe: str,
    excluded: Mapping[str, set[str]],
    grounding_urls: set[str],
) -> dict[str, Any] | None:
    root = _norm(row.get("ghsa_id"))
    if not root or root in excluded["roots"] or row.get("withdrawn_at"):
        return None
    row_cwes = {
        _norm(item.get("cwe_id"))
        for item in row.get("cwes") or []
        if isinstance(item, Mapping)
    }
    if cwe not in row_cwes:
        return None
    description = _norm(row.get("description"))
    if len(description) < 120:
        return None
    references = [_norm(value) for value in row.get("references") or [] if _norm(value)]
    reference_urls = {_canonical_url(value) for value in references if _canonical_url(value)}
    if reference_urls & grounding_urls:
        return None
    primary_url = _candidate_primary_url(row, references)
    canonical_primary = _canonical_url(primary_url)
    if not canonical_primary or canonical_primary in excluded["urls"]:
        return None
    project = _project_for_candidate(row, primary_url, references)
    if not project or project in excluded["projects"]:
        return None
    return {
        "source_root": root,
        "source_project": project,
        "family": family,
        "matched_cwes": [cwe],
        "published_at": _norm(row.get("published_at")),
        "updated_at": _norm(row.get("updated_at")),
        "severity": _norm(row.get("severity")),
        "summary": _norm(row.get("summary")),
        "description": description,
        "repository_advisory_url": _norm(row.get("repository_advisory_url")),
        "source_code_location": _norm(row.get("source_code_location")),
        "canonical_advisory_url": primary_url,
        "references": references,
        "selection_basis": "reviewed_primary_advisory_matched_only_by_external_CWE_taxonomy",
    }


def discover(*, max_pages: int = 8, target_per_family: int = 120) -> dict[str, Any]:
    excluded = _prior_exposure_index()
    grounding_urls = _grounding_writeup_urls()
    family_cwes = _family_cwes()
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    queried_rows = 0
    queried_pairs = 0

    for family, cwes in family_cwes.items():
        by_root: dict[str, dict[str, Any]] = {}
        for cwe in cwes:
            queried_pairs += 1
            for page in _fetch_pages(cwe, max_pages=max_pages):
                queried_rows += len(page)
                for raw in page:
                    candidate = _eligible_candidate(
                        raw,
                        family=family,
                        cwe=cwe,
                        excluded=excluded,
                        grounding_urls=grounding_urls,
                    )
                    if candidate is None:
                        continue
                    root = candidate["source_root"]
                    if root in by_root:
                        merged = sorted(set(by_root[root]["matched_cwes"]) | set(candidate["matched_cwes"]))
                        by_root[root]["matched_cwes"] = merged
                    else:
                        by_root[root] = candidate
                    if len(by_root) >= target_per_family:
                        break
                if len(by_root) >= target_per_family:
                    break
            if len(by_root) >= target_per_family:
                break
        rows = list(by_root.values())
        rows.sort(key=lambda item: (item.get("published_at") or "", item["source_root"]), reverse=True)
        by_family[family] = rows

    counts = {family: len(by_family.get(family, [])) for family in family_cwes}
    missing = sorted(family for family, count in counts.items() if count == 0)
    total_unique = len({(row["source_root"], family) for family, rows in by_family.items() for row in rows})
    return {
        "source_discovery_version": SOURCE_DISCOVERY_VERSION,
        "source_discovery_rule_version": SOURCE_DISCOVERY_RULE_VERSION,
        "family_count": len(family_cwes),
        "queried_family_cwe_pairs": queried_pairs,
        "queried_reviewed_advisory_rows": queried_rows,
        "eligible_family_root_pairs": total_unique,
        "family_candidate_counts": counts,
        "families_without_candidates": missing,
        "excluded_prior_root_count": len(excluded["roots"]),
        "excluded_prior_url_count": len(excluded["urls"]),
        "excluded_prior_project_count": len(excluded["projects"]),
        "excluded_grounding_writeup_url_count": len(grounding_urls),
        "candidate_selection_executes_analysis_engine": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidates_by_family": {family: by_family.get(family, []) for family in family_cwes},
        "note": (
            "Analysis 6.26 discovery is pre-scoring. It selects reviewed primary advisories only through the external CWE taxonomy, "
            "excluding every prior raw/golden source, prior discovery exposure, prior project, and any advisory referencing a write-up "
            "already used to ground detector intelligence. No target detector/ranker/admission/benchmark scoring is executed."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover knowledge-unseen source candidates for Analysis 6.26 fresh raw holdout v4")
    parser.add_argument("--max-pages", type=int, default=8)
    parser.add_argument("--target-per-family", type=int, default=120)
    parser.add_argument("--output", default=str(ROOT / "benchmarks" / "raw" / "sources" / "v4_candidates.json"))
    parser.add_argument("--require-all-families", action="store_true")
    args = parser.parse_args()
    report = discover(max_pages=max(1, args.max_pages), target_per_family=max(1, args.target_per_family))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        key: report[key]
        for key in (
            "family_count",
            "queried_family_cwe_pairs",
            "queried_reviewed_advisory_rows",
            "eligible_family_root_pairs",
            "family_candidate_counts",
            "families_without_candidates",
            "excluded_prior_root_count",
            "excluded_prior_project_count",
            "excluded_grounding_writeup_url_count",
        )
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.require_all_families and report["families_without_candidates"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

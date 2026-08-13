from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v4_source_discovery as v4

VERSION = "1.2.0"
RULE_VERSION = "2026.08.13.6.29"
V4_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v4.jsonl"
V4_FILES = tuple((ROOT / "benchmarks/raw/sources").glob("v4_*.json"))
ADVISORY_TYPES = ("reviewed", "unreviewed")


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
            prov = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
            url = v4._canonical_url(str(prov.get("url") or ""))
            if url:
                out["urls"].add(url)
    return out


def _fetch_typed_pages(cwe: str, advisory_type: str, *, max_pages: int, per_page: int = 100) -> Iterable[list[dict[str, Any]]]:
    numeric = cwe.removeprefix("CWE-")
    query = urllib.parse.urlencode({"type": advisory_type, "cwes": numeric, "per_page": per_page})
    url = f"{v4.GITHUB_ADVISORY_API}?{query}"
    for _ in range(max_pages):
        request = urllib.request.Request(url, headers=v4._headers())
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.load(response)
            link = response.headers.get("Link", "")
        rows = [dict(row) for row in payload if isinstance(row, Mapping)]
        if not rows:
            return
        yield rows
        url = v4._next_link(link)
        if not url:
            return


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
        if candidate_project and not candidate_project.startswith("advisories/"):
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


def discover(max_pages_reviewed: int = 3, max_pages_unreviewed: int = 6, target_per_family: int = 60) -> dict[str, Any]:
    excluded = exposure_index()
    grounding = v4._grounding_writeup_urls()
    family_cwes = v4._family_cwes()
    by_family: dict[str, list[dict[str, Any]]] = {}
    queried = {"reviewed": 0, "unreviewed": 0}

    for family, cwes in family_cwes.items():
        by_root: dict[str, dict[str, Any]] = {}
        for cwe in cwes:
            for advisory_type in ADVISORY_TYPES:
                page_limit = max_pages_reviewed if advisory_type == "reviewed" else max_pages_unreviewed
                for page in _fetch_typed_pages(cwe, advisory_type, max_pages=page_limit):
                    queried[advisory_type] += len(page)
                    for raw in page:
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
                            by_root[root]["matched_cwes"] = sorted(set(by_root[root]["matched_cwes"]) | set(row["matched_cwes"]))
                            if by_root[root].get("advisory_source_type") != "reviewed" and advisory_type == "reviewed":
                                by_root[root]["advisory_source_type"] = "reviewed"
                        if len(by_root) >= target_per_family:
                            break
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
        "queried_rows_by_advisory_type": queried,
        "advisory_types": list(ADVISORY_TYPES),
        "family_candidate_counts": counts,
        "families_without_candidates": sorted(k for k, count in counts.items() if not count),
        "excluded_prior_root_count": len(excluded["roots"]),
        "excluded_prior_project_count": len(excluded["projects"]),
        "excluded_prior_url_count": len(excluded["urls"]),
        "excluded_grounding_url_count": len(grounding),
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
    print(json.dumps({k: report[k] for k in ("family_count", "families_without_candidates", "excluded_prior_root_count", "excluded_prior_project_count", "queried_rows_by_advisory_type")}, indent=2))
    return 2 if report["families_without_candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

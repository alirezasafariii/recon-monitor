from __future__ import annotations

import gzip
import json
import re
import urllib.request
from collections import defaultdict
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
import raw_recon_v4_source_discovery as v4
from raw_recon_v5_source_audit import audit_row
from raw_recon_v5_source_discovery import _is_research_project, exposure_index

VERSION = "1.1.0"
RULE_VERSION = "2026.08.13.6.29"
# Generic source discovery uses only the current-year NVD feed. Older exact
# niche sources are fetched individually by raw_recon_v5_exact_source_supplement.
YEARS = (2026,)
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
OUTPUT = ROOT / "benchmarks/raw/sources/v5_candidates.json"


def prior_cve_exposure() -> set[str]:
    exposed: set[str] = set()
    bench = ROOT / "benchmarks"
    if bench.exists():
        for path in bench.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".md"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            exposed.update(value.upper() for value in CVE_RE.findall(text))
    for url in v4._grounding_writeup_urls():
        exposed.update(value.upper() for value in CVE_RE.findall(url))
    return exposed


def _load_feed(year: int) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        FEED_URL.format(year=year),
        headers={
            "User-Agent": "Recon-Monitor-Analysis-6.29-Fresh-Blind-v5/1.0",
            "Accept": "application/gzip, application/octet-stream;q=0.9, */*;q=0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        with gzip.GzipFile(fileobj=response) as stream:
            payload = json.load(stream)
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, Mapping) else []
    return [dict(value) for value in vulnerabilities or [] if isinstance(value, Mapping)]


def _description(cve: Mapping[str, Any]) -> str:
    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    for value in descriptions:
        if isinstance(value, Mapping) and str(value.get("lang") or "").lower().startswith("en"):
            return str(value.get("value") or "").strip()
    return ""


def _cwes(cve: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    weaknesses = cve.get("weaknesses") if isinstance(cve.get("weaknesses"), list) else []
    for weakness in weaknesses:
        if not isinstance(weakness, Mapping):
            continue
        descriptions = weakness.get("description") if isinstance(weakness.get("description"), list) else []
        for item in descriptions:
            if not isinstance(item, Mapping):
                continue
            text = str(item.get("value") or "").strip().upper()
            if text.startswith("CWE-"):
                values.add(text)
    return values


def _references(cve: Mapping[str, Any]) -> list[str]:
    rows = cve.get("references") if isinstance(cve.get("references"), list) else []
    return [str(row.get("url") or "").strip() for row in rows if isinstance(row, Mapping) and str(row.get("url") or "").strip()]


def _walk_cpe_criteria(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        criteria = str(value.get("criteria") or "").strip()
        if criteria:
            yield criteria
        for child in value.values():
            yield from _walk_cpe_criteria(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpe_criteria(child)


def _cpe_project(criteria: str) -> str:
    parts = criteria.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return ""
    vendor = parts[3].strip().replace("\\", "")
    product = parts[4].strip().replace("\\", "")
    if not vendor or not product or vendor in {"*", "-"} or product in {"*", "-"}:
        return ""
    return f"cpe:{vendor}/{product}"


def _project_identity(cve: Mapping[str, Any], references: list[str]) -> tuple[str, list[str], str]:
    github_projects: list[str] = []
    for url in references:
        project = v4._project_from_url(url)
        if not project or project.startswith("advisories/") or _is_research_project(project):
            continue
        if project not in github_projects:
            github_projects.append(project)
    cpe_projects = sorted({
        project
        for criteria in _walk_cpe_criteria(cve.get("configurations") or [])
        for project in [_cpe_project(criteria)]
        if project
    })
    aliases = github_projects + [value for value in cpe_projects if value not in github_projects]
    if github_projects:
        return github_projects[0], aliases, "github_reference"
    if cpe_projects:
        return cpe_projects[0], aliases, "nvd_cpe"
    return "", aliases, ""


def _severity(cve: Mapping[str, Any]) -> str:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), Mapping) else {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) if isinstance(metrics.get(key), list) else []
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            data = row.get("cvssData") if isinstance(row.get("cvssData"), Mapping) else {}
            severity = str(data.get("baseSeverity") or row.get("baseSeverity") or "").strip()
            if severity:
                return severity.lower()
    return ""


def _candidate(
    cve: Mapping[str, Any],
    *,
    family: str,
    matched_cwes: set[str],
    prior: Mapping[str, set[str]],
    prior_cves: set[str],
    grounding_urls: set[str],
) -> dict[str, Any] | None:
    cve_id = str(cve.get("id") or "").strip().upper()
    if not CVE_RE.fullmatch(cve_id) or cve_id in prior_cves or cve_id in prior["roots"]:
        return None
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    description = _description(cve)
    if len(description) < 120:
        return None
    references = _references(cve)
    canonical_refs = {v4._canonical_url(url) for url in references if v4._canonical_url(url)}
    if canonical_refs & grounding_urls or canonical_refs & prior["urls"]:
        return None
    source_project, aliases, identity_kind = _project_identity(cve, references)
    if not source_project:
        return None
    if any(alias in prior["projects"] for alias in aliases):
        return None
    canonical_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if v4._canonical_url(canonical_url) in prior["urls"]:
        return None
    repository_advisory = next((url for url in references if "/security/advisories/" in url), "")
    github_location = next((url for url in references if v4._project_from_url(url) == source_project), "")
    summary = description.split(". ", 1)[0].strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip() + "..."
    row = {
        "source_root": cve_id,
        "source_project": source_project,
        "project_aliases": aliases,
        "project_identity_kind": identity_kind,
        "family": family,
        "matched_cwes": sorted(matched_cwes),
        "published_at": str(cve.get("published") or "").strip(),
        "updated_at": str(cve.get("lastModified") or "").strip(),
        "severity": _severity(cve),
        "summary": summary,
        "description": description,
        "repository_advisory_url": repository_advisory,
        "source_code_location": github_location,
        "canonical_advisory_url": canonical_url,
        "references": references,
        "source_kind": "nvd_json_2_0_year_feed",
        "advisory_source_type": "nvd",
        "freshness_validated": True,
        "freshness_scope": "all prior benchmark CVE IDs plus golden/raw roots/projects/URLs and detector grounding writeups",
        "selection_basis": "NVD CVE matched by sealed external CWE taxonomy before scoring",
    }
    return row


def discover(target_per_family: int = 80) -> dict[str, Any]:
    prior = exposure_index()
    prior_cves = prior_cve_exposure()
    grounding = v4._grounding_writeup_urls()
    family_cwes = v4._family_cwes()
    cwe_to_families: dict[str, set[str]] = defaultdict(set)
    for family, cwes in family_cwes.items():
        for cwe in cwes:
            cwe_to_families[cwe].add(family)

    by_family: dict[str, dict[str, dict[str, Any]]] = {family: {} for family in family_cwes}
    feed_counts: dict[str, int] = {}
    for year in YEARS:
        vulnerabilities = _load_feed(year)
        feed_counts[str(year)] = len(vulnerabilities)
        for wrapper in vulnerabilities:
            cve = wrapper.get("cve") if isinstance(wrapper.get("cve"), Mapping) else {}
            if not cve:
                continue
            row_cwes = _cwes(cve)
            if not row_cwes:
                continue
            candidate_families = sorted({family for cwe in row_cwes for family in cwe_to_families.get(cwe, set())})
            for family in candidate_families:
                if len(by_family[family]) >= target_per_family:
                    continue
                matched = row_cwes & set(family_cwes[family])
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
                existing = by_family[family].get(root)
                if existing is None:
                    by_family[family][root] = row
                else:
                    existing["matched_cwes"] = sorted(set(existing["matched_cwes"]) | set(row["matched_cwes"]))

    pools: dict[str, list[dict[str, Any]]] = {}
    semantic_counts: dict[str, int] = {}
    for family, indexed in by_family.items():
        rows = list(indexed.values())
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
        semantic_counts[family] = sum(1 for row in rows if audit_row(family, row)[0])

    counts = {family: len(rows) for family, rows in pools.items()}
    missing = sorted(family for family, count in counts.items() if count == 0)
    missing_semantic = sorted(family for family, count in semantic_counts.items() if count == 0)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "source_universe": "NVD JSON 2.0 current-year annual feed plus exact niche CVE supplement",
        "feed_years_requested": list(YEARS),
        "feed_record_counts": feed_counts,
        "family_count": len(family_cwes),
        "family_candidate_counts": counts,
        "family_semantic_candidate_counts": semantic_counts,
        "families_without_candidates": missing,
        "families_without_semantic_candidates": missing_semantic,
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
            "feed_record_counts",
            "families_without_candidates",
            "families_without_semantic_candidates",
            "excluded_prior_cve_count",
            "excluded_prior_root_count",
            "excluded_prior_project_count",
        )
    }, indent=2, sort_keys=True))
    return 2 if report["families_without_candidates"] or report["families_without_semantic_candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

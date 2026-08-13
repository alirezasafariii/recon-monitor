from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v4_source_discovery as v4

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
V4_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v4.jsonl"
V4_FILES = tuple((ROOT / "benchmarks/raw/sources").glob("v4_*.json"))


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


def discover(max_pages: int = 12, target_per_family: int = 180) -> dict[str, Any]:
    excluded = exposure_index()
    grounding = v4._grounding_writeup_urls()
    family_cwes = v4._family_cwes()
    by_family: dict[str, list[dict[str, Any]]] = {}
    queried = 0
    for family, cwes in family_cwes.items():
        by_root: dict[str, dict[str, Any]] = {}
        for cwe in cwes:
            for page in v4._fetch_pages(cwe, max_pages=max_pages):
                queried += len(page)
                for raw in page:
                    row = v4._eligible_candidate(raw, family=family, cwe=cwe, excluded=excluded, grounding_urls=grounding)
                    if row is None:
                        continue
                    root = str(row["source_root"])
                    if root not in by_root:
                        row["freshness_validated"] = True
                        by_root[root] = row
                    else:
                        by_root[root]["matched_cwes"] = sorted(set(by_root[root]["matched_cwes"]) | set(row["matched_cwes"]))
                    if len(by_root) >= target_per_family:
                        break
                if len(by_root) >= target_per_family:
                    break
            if len(by_root) >= target_per_family:
                break
        rows = list(by_root.values())
        rows.sort(key=lambda x: (x.get("published_at") or "", x["source_root"]), reverse=True)
        by_family[family] = rows
    counts = {family: len(rows) for family, rows in by_family.items()}
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "family_count": len(family_cwes),
        "queried_rows": queried,
        "family_candidate_counts": counts,
        "families_without_candidates": sorted(k for k, v in counts.items() if not v),
        "excluded_prior_root_count": len(excluded["roots"]),
        "excluded_prior_project_count": len(excluded["projects"]),
        "excluded_prior_url_count": len(excluded["urls"]),
        "excluded_grounding_url_count": len(grounding),
        "scoring_executed": False,
        "candidates_by_family": by_family,
    }


def main() -> int:
    report = discover()
    out = ROOT / "benchmarks/raw/sources/v5_candidates.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("family_count", "families_without_candidates", "excluded_prior_root_count", "excluded_prior_project_count")}, indent=2))
    return 2 if report["families_without_candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

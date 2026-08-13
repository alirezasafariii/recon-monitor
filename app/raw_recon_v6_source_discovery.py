from __future__ import annotations

import json
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v5_source_discovery as v5
from raw_recon_v6_source_firewall import RULE_VERSION as FIREWALL_RULE_VERSION
from raw_recon_v6_source_firewall import VERSION as FIREWALL_VERSION
from raw_recon_v6_source_firewall import check_candidate, exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.31"
OUT = ROOT / "benchmarks/raw/sources/v6_candidates.json"


def discover(**kwargs: Any) -> dict[str, Any]:
    original_exposure_index = v5.exposure_index
    try:
        v5.exposure_index = exposure_index
        report = v5.discover(**kwargs)
    finally:
        v5.exposure_index = original_exposure_index

    pools = report.get("candidates_by_family") if isinstance(report.get("candidates_by_family"), Mapping) else {}
    filtered: dict[str, list[dict[str, Any]]] = {}
    rejected: dict[str, list[dict[str, Any]]] = {}
    for family, raw_rows in pools.items():
        kept: list[dict[str, Any]] = []
        denied: list[dict[str, Any]] = []
        for raw in raw_rows or []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            check = check_candidate(row)
            row["v6_firewall_allowed"] = bool(check["allowed"])
            row["v6_firewall_version"] = FIREWALL_VERSION
            row["v6_firewall_rule_version"] = FIREWALL_RULE_VERSION
            if check["allowed"]:
                kept.append(row)
            else:
                denied.append({
                    "source_root": check["source_root"],
                    "source_project": check["source_project"],
                    "root_overlap": check["root_overlap"],
                    "project_overlap": check["project_overlap"],
                    "url_overlap": check["url_overlap"],
                })
        filtered[str(family)] = kept
        if denied:
            rejected[str(family)] = denied

    report = dict(report)
    report.update({
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_unscored_source_discovery",
        "source_firewall_version": FIREWALL_VERSION,
        "source_firewall_rule_version": FIREWALL_RULE_VERSION,
        "candidates_by_family": filtered,
        "family_candidate_counts": {family: len(rows) for family, rows in filtered.items()},
        "source_firewall_rejections": rejected,
        "source_firewall_rejection_count": sum(len(rows) for rows in rejected.values()),
        "scoring_executed": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
    })
    report["families_without_candidates"] = sorted(family for family, rows in filtered.items() if not rows)
    return report


def main() -> int:
    report = discover()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report.get("family_count"),
        "families_without_candidates": report.get("families_without_candidates"),
        "families_without_semantic_candidates": report.get("families_without_semantic_candidates"),
        "source_firewall_rejection_count": report.get("source_firewall_rejection_count"),
        "api_request_count": report.get("api_request_count"),
        "scoring_executed": report.get("scoring_executed"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

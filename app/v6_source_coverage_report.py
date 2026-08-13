from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import audit_row

CANDIDATES = ROOT / "benchmarks/raw/sources/v6_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v6_selection_diagnostic.json"


def build_report() -> dict[str, Any]:
    data = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    pools = data.get("candidates_by_family") if isinstance(data.get("candidates_by_family"), Mapping) else {}
    raw_counts: dict[str, int] = {}
    semantic_counts: dict[str, int] = {}
    for family in sorted(DETECTOR_SPECS):
        rows = [row for row in list(pools.get(family, []) or []) if isinstance(row, Mapping)]
        raw_counts[family] = len(rows)
        semantic_counts[family] = sum(
            1 for row in rows
            if row.get("v6_firewall_allowed") is True and audit_row(family, row)[0]
        )
    missing_raw = sorted(family for family, count in raw_counts.items() if count == 0)
    missing_semantic = sorted(family for family, count in semantic_counts.items() if count == 0)
    report = {
        "rule_version": "2026.08.13.6.31",
        "scoring_executed": False,
        "raw_candidate_counts": raw_counts,
        "semantic_candidate_counts": semantic_counts,
        "families_without_raw_candidates": missing_raw,
        "families_without_semantic_candidates": missing_semantic,
        "raw_coverage_count": 36 - len(missing_raw),
        "semantic_coverage_count": 36 - len(missing_semantic),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = build_report()
    print(json.dumps({
        "raw_coverage_count": report["raw_coverage_count"],
        "semantic_coverage_count": report["semantic_coverage_count"],
        "families_without_semantic_candidates": report["families_without_semantic_candidates"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

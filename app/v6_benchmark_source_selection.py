from __future__ import annotations

import json
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row
from raw_recon_v6_source_firewall import validate_shortlist

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.31"
CANDIDATES = ROOT / "benchmarks/raw/sources/v6_candidates.json"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"


def select_sources() -> dict[str, Any]:
    data = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    if data.get("scoring_executed") is not False:
        raise RuntimeError("v6 discovery must remain unscored")
    pools = data.get("candidates_by_family") if isinstance(data.get("candidates_by_family"), Mapping) else {}

    semantic: dict[str, list[dict[str, Any]]] = {}
    for family in sorted(DETECTOR_SPECS):
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in list(pools.get(family, []) or []):
            if not isinstance(raw, Mapping) or raw.get("v6_firewall_allowed") is not True:
                continue
            root = str(raw.get("source_root") or "").strip()
            project = str(raw.get("source_project") or "").strip()
            if not root or not project or root in seen:
                continue
            seen.add(root)
            passed, hits, score = audit_row(family, raw)
            if not passed:
                continue
            row = dict(raw)
            row["source_family_audit_score"] = int(score)
            row["source_family_audit_group_hits"] = hits
            row["source_family_audit_version"] = AUDIT_VERSION
            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION
            rows.append(row)
        rows.sort(key=lambda row: (int(row.get("source_family_audit_score") or 0), 1 if row.get("advisory_source_type") == "reviewed" else 0, row.get("published_at") or ""), reverse=True)
        semantic[family] = rows

    missing = sorted(family for family, rows in semantic.items() if not rows)
    if missing:
        raise RuntimeError("v6 semantic source coverage missing: " + ", ".join(missing))

    used_roots: set[str] = set()
    used_projects: set[str] = set()
    selected: dict[str, dict[str, Any]] = {}
    for family in sorted(semantic, key=lambda name: (len(semantic[name]), name)):
        for row in semantic[family]:
            root = str(row.get("source_root") or "")
            project = str(row.get("source_project") or "")
            if root in used_roots or project in used_projects:
                continue
            selected[family] = row
            used_roots.add(root)
            used_projects.add(project)
            break
        if family not in selected:
            raise RuntimeError(f"v6 unique source selection failed for {family}")

    rows = [selected[family] for family in sorted(selected)]
    firewall = validate_shortlist(rows, required_count=36)
    if not firewall["passed"]:
        raise RuntimeError("v6 shortlist firewall failed: " + "; ".join(firewall["errors"]))
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_unscored_source_selection",
        "selection_executes_scoring": False,
        "selection_uses_detector_output": False,
        "selection_uses_admission_results": False,
        "selection_uses_ranking_results": False,
        "family_count": len(rows),
        "unique_root_count": len(used_roots),
        "unique_project_count": len(used_projects),
        "semantic_candidate_counts": {family: len(items) for family, items in semantic.items()},
        "firewall": firewall,
        "selected": rows,
    }


def main() -> int:
    result = select_sources()
    SHORTLIST.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("family_count", "unique_root_count", "unique_project_count", "selection_executes_scoring")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

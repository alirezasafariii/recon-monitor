from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
LABELS = ROOT / "benchmarks/raw/sources/v6_literal_label_schema.json"
LINKED = ROOT / "benchmarks/raw/sources/v6_literal_linked_summary.json"
FEASIBILITY = ROOT / "benchmarks/raw/sources/v6_literal_capture_feasibility.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_remaining_capture_manifest.json"
VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}


def build_manifest() -> dict[str, Any]:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    linked = json.loads(LINKED.read_text(encoding="utf-8"))
    feasibility = json.loads(FEASIBILITY.read_text(encoding="utf-8"))

    reqs = [dict(row) for row in plan.get("requirements") or [] if isinstance(row, Mapping)]
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in reqs:
        by_family[str(row.get("family") or "")].append(row)

    feasibility_map = {
        str(row.get("family") or ""): dict(row)
        for row in feasibility.get("families") or []
        if isinstance(row, Mapping)
    }
    linked_map = linked.get("families") if isinstance(linked.get("families"), Mapping) else linked
    if not isinstance(linked_map, Mapping):
        linked_map = {}
    label_map = labels.get("families") if isinstance(labels.get("families"), Mapping) else {}

    rows = []
    for family in sorted(by_family):
        requirements = by_family[family]
        present = {str(row.get("case_kind") or "") for row in requirements if bool(row.get("evidence_present"))}
        if present == VARIANTS:
            continue
        source = feasibility_map.get(family, {})
        linked_row = linked_map.get(family) if isinstance(linked_map.get(family), Mapping) else {}
        vocabulary = label_map.get(family) if isinstance(label_map.get(family), Mapping) else {}
        canonical = str(source.get("canonical_reference") or next((r.get("canonical_source_reference") for r in requirements), ""))
        linked_resources = []
        for resource in linked_row.get("successful_resources") or []:
            if not isinstance(resource, Mapping):
                continue
            linked_resources.append({
                "reference": str(resource.get("reference") or ""),
                "fetch_reference": str(resource.get("fetch_reference") or ""),
                "resource_type": str(resource.get("resource_type") or ""),
                "snapshot_sha256": str(resource.get("snapshot_sha256") or ""),
                "payload_identity": resource.get("payload_identity") if isinstance(resource.get("payload_identity"), Mapping) else {},
            })
        rows.append({
            "family": family,
            "source_root": str(requirements[0].get("source_root") or ""),
            "source_project": str(requirements[0].get("source_project") or ""),
            "canonical_reference": canonical,
            "feasibility_tier": str(source.get("feasibility_tier") or ""),
            "has_change_artifact": bool(source.get("has_change_artifact")),
            "successful_link_snapshot_count": int(source.get("successful_link_snapshot_count") or 0),
            "linked_resources": linked_resources,
            "condition_signals": list(vocabulary.get("condition_signals") or []),
            "blocking_controls": list(vocabulary.get("blocking_controls") or []),
            "missing_variants": sorted(VARIANTS - present),
            "evidence_present_count": len(present),
            "evidence_missing_count": 4 - len(present),
            "scoring_executed": False,
        })

    tier_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        tier_counts[str(row["feasibility_tier"])] += 1
    return {
        "evaluation_kind": "fresh_blind_v6_remaining_capture_acquisition_manifest_unscored",
        "remaining_family_count": len(rows),
        "remaining_evidence_count": sum(int(row["evidence_missing_count"]) for row in rows),
        "tier_counts": dict(sorted(tier_counts.items())),
        "families": rows,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    value = build_manifest()
    OUTPUT.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
SOURCE_RESEARCH = ROOT / "benchmarks/raw/sources/v6_literal_source_research.json"
LINKED_RESEARCH = ROOT / "benchmarks/raw/sources/v6_literal_linked_research.json"
PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_capture_feasibility.json"


def build() -> dict[str, Any]:
    source = json.loads(SOURCE_RESEARCH.read_text(encoding="utf-8"))
    linked = json.loads(LINKED_RESEARCH.read_text(encoding="utf-8"))
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    for doc in (source, linked, plan):
        if doc.get("scoring_executed") is not False:
            raise RuntimeError("feasibility planning requires unscored inputs")
        if doc.get("first_blind_consumed") is not False:
            raise RuntimeError("feasibility planning requires unconsumed First Blind")
    if source.get("successful_snapshot_count") != 36 or source.get("unresolved_snapshot_count") != 0:
        raise RuntimeError("feasibility planning requires complete canonical source research")

    source_by_family = {str(row.get("family") or ""): row for row in source.get("entries") or []}
    linked_by_family = {str(row.get("family") or ""): row for row in linked.get("entries") or []}
    plan_by_family: dict[str, list[Mapping[str, Any]]] = {}
    for row in plan.get("requirements") or []:
        plan_by_family.setdefault(str(row.get("family") or ""), []).append(row)

    families = []
    tier_counts = Counter()
    for family in sorted(source_by_family):
        source_row = source_by_family[family]
        linked_row = linked_by_family.get(family, {})
        successful = [
            row for row in linked_row.get("linked_resources") or []
            if row.get("fetch_status") == 200 and row.get("snapshot_payload") is not None
        ]
        types = Counter(str(row.get("resource_type") or "unknown") for row in successful)
        has_change_artifact = bool(types.get("commit") or types.get("pull_request"))
        has_issue = bool(types.get("issue"))
        has_linked_advisory = bool(types.get("security_advisory"))
        source_has_body = bool(source_row.get("has_body_or_description"))
        if has_change_artifact and source_has_body:
            tier = "A_change_artifact_plus_source_context"
            rationale = "At least one fetched upstream commit/PR plus canonical source context; prioritize for patched-control/regression evidence inspection."
        elif successful and source_has_body:
            tier = "B_linked_context_without_change_artifact"
            rationale = "Fetched linked upstream context exists, but no commit/PR snapshot was captured; inspect issue/advisory/test references before reproduction."
        elif source_has_body:
            tier = "C_canonical_source_only"
            rationale = "Canonical source snapshot has explanatory content but no fetched linked artifact; requires targeted passive repository search or controlled reproduction."
        else:
            tier = "D_source_metadata_only"
            rationale = "Canonical source is available but lacks body/description suitable for direct fixture discovery; requires additional primary-source research."
        tier_counts[tier] += 1
        families.append({
            "family": family,
            "source_root": source_row.get("source_root"),
            "source_project": source_row.get("source_project"),
            "canonical_reference": source_row.get("canonical_reference"),
            "capture_requirements": len(plan_by_family.get(family, [])),
            "canonical_source_has_body_or_description": source_has_body,
            "successful_link_snapshot_count": len(successful),
            "successful_resource_types": dict(sorted(types.items())),
            "has_change_artifact": has_change_artifact,
            "feasibility_tier": tier,
            "rationale": rationale,
            "evidence_present_count": sum(1 for row in plan_by_family.get(family, []) if row.get("evidence_present") is True),
            "evidence_missing_count": sum(1 for row in plan_by_family.get(family, []) if row.get("evidence_present") is not True),
        })

    order = {
        "A_change_artifact_plus_source_context": 0,
        "B_linked_context_without_change_artifact": 1,
        "C_canonical_source_only": 2,
        "D_source_metadata_only": 3,
    }
    families.sort(key=lambda row: (order[row["feasibility_tier"]], -row["successful_link_snapshot_count"], row["family"]))
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_literal_capture_feasibility_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "active_target_validation_performed": False,
        "family_count": len(families),
        "required_capture_count": 144,
        "evidence_present_count": sum(row["evidence_present_count"] for row in families),
        "evidence_missing_count": sum(row["evidence_missing_count"] for row in families),
        "tier_counts": dict(sorted(tier_counts.items())),
        "families": families,
    }


def main() -> int:
    report = build()
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "evidence_present_count": report["evidence_present_count"],
        "evidence_missing_count": report["evidence_missing_count"],
        "tier_counts": report["tier_counts"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

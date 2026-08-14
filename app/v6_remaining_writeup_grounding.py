from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT

PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_writeup_grounding_index.json"


def family_grounding(family: str) -> dict[str, Any]:
    spec = DETECTOR_SPECS[family]
    return {
        "family": family,
        "strategy": spec.strategy,
        "principle": spec.principle,
        "surface_terms": list(spec.surface_terms),
        "surface_fields": list(spec.surface_fields),
        "confounders": list(spec.confounders),
        "wstg_ids": list(spec.wstg_ids),
        "owasp_ids": list(spec.owasp_ids),
        "cwe_ids": list(spec.cwe_ids),
        "condition_signals": sorted(spec.condition_signals),
        "blocking_controls": sorted(spec.blocking_controls),
        "override_signals": sorted(spec.override_signals),
        "writeups": [
            {
                "ref": ref.ref,
                "url": ref.url,
                "relation": ref.relation,
                "source": ref.source,
                "lesson": ref.lesson,
                "counts_as_target_evidence": False,
            }
            for ref in spec.writeups
        ],
        "external_knowledge_counts_as_target_evidence": False,
    }


def build_index(plan_path: Path = PLAN) -> dict[str, Any]:
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    requirements = [row for row in plan.get("requirements") or [] if isinstance(row, Mapping)]
    remaining = sorted({
        str(row.get("family") or "")
        for row in requirements
        if not bool(row.get("evidence_present"))
    })
    completed = sorted(set(DETECTOR_SPECS) - set(remaining))
    families = {family: family_grounding(family) for family in sorted(DETECTOR_SPECS)}
    writeup_count = sum(len(row["writeups"]) for row in families.values())
    if set(families) != set(DETECTOR_SPECS):
        raise RuntimeError("writeup grounding coverage mismatch")
    if any(not row["writeups"] for row in families.values()):
        raise RuntimeError("every family must have at least one related writeup")
    if any(
        writeup.get("counts_as_target_evidence") is not False
        for row in families.values()
        for writeup in row["writeups"]
    ):
        raise RuntimeError("writeup grounding must never count as target evidence")
    return {
        "evaluation_kind": "fresh_blind_v6_writeup_grounding_unscored",
        "family_count": len(families),
        "writeup_reference_count": writeup_count,
        "remaining_family_count": len(remaining),
        "remaining_families": remaining,
        "completed_families": completed,
        "families": families,
        "policy": {
            "purpose": "ground capture planning, confounder analysis, blocking-control selection, and post-blind calibration rationale",
            "external_knowledge_counts_as_target_evidence": False,
            "writeup_text_must_not_be_copied_into_raw_observation": True,
            "writeup_grounding_may_not_satisfy_literal_capture_requirements": True,
            "production_rules_changed_before_first_score": False,
        },
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    value = build_index()
    OUTPUT.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": value["family_count"],
        "writeup_reference_count": value["writeup_reference_count"],
        "remaining_family_count": value["remaining_family_count"],
        "scoring_executed": value["scoring_executed"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

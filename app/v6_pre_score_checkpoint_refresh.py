from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

CHECKPOINT = ROOT / "benchmarks/raw/sources/v6_pre_score_checkpoint.json"
PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
EVIDENCE_ROOT = ROOT / "benchmarks/raw/sources/v6_capture_evidence"
VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}


def refresh_checkpoint(*, checkpoint_path: Path = CHECKPOINT, plan_path: Path = PLAN) -> dict[str, Any]:
    checkpoint_path = Path(checkpoint_path)
    plan_path = Path(plan_path)
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    requirements = [dict(row) for row in plan.get("requirements") or [] if isinstance(row, Mapping)]
    if len(requirements) != 144:
        raise RuntimeError(f"v6 capture plan must contain 144 requirements: {len(requirements)}")

    present = [row for row in requirements if bool(row.get("evidence_present"))]
    variants: dict[str, set[str]] = defaultdict(set)
    for row in present:
        variants[str(row.get("family") or "")].add(str(row.get("case_kind") or ""))
    complete = sorted(family for family, kinds in variants.items() if kinds == VARIANTS)
    family_count = len({str(row.get("family") or "") for row in requirements})
    if family_count != 36:
        raise RuntimeError(f"v6 plan family count must be 36: {family_count}")

    progress = checkpoint.setdefault("literal_capture_progress", {})
    progress.update({
        "required_capture_count": 144,
        "evidence_present_count": len(present),
        "evidence_missing_count": 144 - len(present),
        "complete_family_count": len(complete),
        "remaining_family_count": 36 - len(complete),
        "variants_per_complete_family": 4,
        "complete_families": complete,
        "variant_contract": ["positive", "near_miss", "secure_negative", "sparse_noisy"],
        "capture_plan_status": f"{len(present)}_of_144_evidence_present",
        "synthetic_fixture_generation_forbidden": True,
        "cross_variant_mutation_forbidden": True,
    })
    if len(present) < 144:
        progress["materialization_status"] = "blocked_until_144_of_144"
        progress["corpus_validation_status"] = "not_run_on_complete_literal_corpus"
        progress["corpus_freeze_status"] = "not_run"
        progress["evaluator_freeze_status"] = "not_run"
        checkpoint["checkpoint_status"] = f"{len(complete)}_literal_families_complete_{len(present)}_of_144_pending_remaining_evidence"
        checkpoint["next_required_transition"] = (
            f"Continue controlled evidence collection for the remaining {36-len(complete)} families / {144-len(present)} artifacts. "
            "Each family requires four independent source-grounded observations. After 144/144, run evidence-only ingest, strict verifier, "
            "materialize 276 cases, validate, freeze corpus and all evidence, freeze evaluator, then stop before the one-time First Blind score pending explicit approval."
        )
    else:
        progress["materialization_status"] = "ready_after_complete_evidence_ingest"
        checkpoint["checkpoint_status"] = "36_literal_families_complete_144_of_144_ready_for_materialization_and_freeze"
        checkpoint["next_required_transition"] = (
            "Run strict evidence-only ingest and verification, materialize the 276-case corpus, validate it, freeze corpus/evidence, "
            "freeze the evaluator, then stop before the one-time First Blind score pending explicit approval."
        )

    collectors = checkpoint.setdefault("completed_real_collectors", {})
    for family in complete:
        if family in collectors:
            continue
        positive_req = next(row for row in requirements if row.get("family") == family and row.get("case_kind") == "positive")
        evidence_path = ROOT / str(positive_req["required_evidence_path"])
        if not evidence_path.exists():
            continue
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        adjudication = evidence.get("adjudication") if isinstance(evidence.get("adjudication"), Mapping) else {}
        collectors[family] = {
            "source": f"{evidence.get('source_root')} / {evidence.get('source_project')}",
            "capture_run_id": None,
            "status": "passed_4_of_4",
            "positive_observation": str(adjudication.get("notes") or "source-grounded positive observation"),
        }

    checkpoint["scoring_executed"] = False
    checkpoint["first_blind_consumed"] = False
    checkpoint_path.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "evidence_present_count": len(present),
        "evidence_missing_count": 144 - len(present),
        "complete_family_count": len(complete),
        "remaining_family_count": 36 - len(complete),
        "complete_families": complete,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    result = refresh_checkpoint()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

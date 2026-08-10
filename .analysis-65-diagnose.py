from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import benchmark_file, family_compatibility, load_golden_cases, REAL_WORLD_CORPUS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission

cases = load_golden_cases(REAL_WORLD_CORPUS)
report = benchmark_file(REAL_WORLD_CORPUS)


def compatibility_no_block_penalty(family, support, contradict):
    assessment = assess_admission(family, support, contradict)
    policy = FAMILY_ADMISSION_POLICIES[family]
    required_count = max(1, len(policy.get("required", [])))
    satisfied_count = len(assessment.get("required_satisfied") or [])
    coverage = satisfied_count / required_count
    required_sources = max(1, int(policy.get("min_independent_sources", 1)))
    source_ratio = min(1.0, int(assessment.get("independent_sources") or 0) / required_sources)
    score = 0.68 * coverage + 0.14 * source_ratio
    if assessment.get("admitted"):
        score += 0.18
    score = max(0.0, min(1.0, score))
    return {
        "family": family,
        "score": round(score, 6),
        "assessment": assessment,
    }


def evaluate_partition(split):
    subset = [c for c in cases if str(c.get("split") or "development") == split]
    baseline_wrong = []
    simulated_wrong = []
    baseline_confusion = defaultdict(Counter)
    simulated_confusion = defaultdict(Counter)
    changed = []
    for case in subset:
        if not bool(case.get("rank_required", True)):
            continue
        family = str(case["family"])
        acceptable = {str(x) for x in case.get("acceptable_top_families", []) if str(x)} or {family}
        support = case.get("support", [])
        contradict = case.get("contradict", [])
        baseline = [family_compatibility(f, support, contradict) for f in FAMILY_ADMISSION_POLICIES]
        baseline.sort(key=lambda item: (float(item["score"]), bool(item["assessment"].get("admitted")), str(item["family"])), reverse=True)
        simulated = [compatibility_no_block_penalty(f, support, contradict) for f in FAMILY_ADMISSION_POLICIES]
        simulated.sort(key=lambda item: (float(item["score"]), bool(item["assessment"].get("admitted")), str(item["family"])), reverse=True)
        btop = baseline[0]["family"]
        stop = simulated[0]["family"]
        if btop not in acceptable:
            baseline_wrong.append(case["id"])
            baseline_confusion[family][btop] += 1
        if stop not in acceptable:
            simulated_wrong.append(case["id"])
            simulated_confusion[family][stop] += 1
        if btop != stop:
            changed.append({
                "id": case["id"],
                "kind": case["case_kind"],
                "family": family,
                "baseline": btop,
                "simulated": stop,
                "baseline_top3": [(x["family"], x["score"], x["assessment"].get("state")) for x in baseline[:3]],
                "simulated_top3": [(x["family"], x["score"], x["assessment"].get("state")) for x in simulated[:3]],
                "contradict": [str(x.get("type")) for x in contradict],
            })
    total = sum(1 for c in subset if bool(c.get("rank_required", True)))
    return {
        "case_count": len(subset),
        "ranked_count": total,
        "baseline_wrong_count": len(baseline_wrong),
        "simulated_wrong_count": len(simulated_wrong),
        "baseline_top1": round((total - len(baseline_wrong)) / total, 6) if total else 0.0,
        "simulated_top1": round((total - len(simulated_wrong)) / total, 6) if total else 0.0,
        "baseline_confusion": {k: dict(v) for k, v in sorted(baseline_confusion.items())},
        "simulated_confusion": {k: dict(v) for k, v in sorted(simulated_confusion.items())},
        "baseline_wrong_ids": baseline_wrong,
        "simulated_wrong_ids": simulated_wrong,
        "changed_top1": changed,
    }

print(json.dumps({
    "development": evaluate_partition("development"),
    "held_out_audit_only": {
        "published_top1": report["metrics"]["heldout_top1_accuracy"],
        "case_count": report["held_out_case_count"],
    },
}, indent=2, sort_keys=True))

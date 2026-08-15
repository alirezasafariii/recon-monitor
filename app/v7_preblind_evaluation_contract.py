from __future__ import annotations

"""Freeze the descriptive Fresh Blind V7 evaluation contract before scoring.

This module does not score V7. It freezes metric semantics, integrity/lifecycle gates,
and lineage to the historical V6 scorer contract so metrics cannot be changed after
First Blind results are observed.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.preblind-evaluator.1"
V6_RESULT = ROOT / "benchmarks/raw/results/analysis_raw_v6_first_blind.json"
LEDGER = ROOT / "benchmarks/raw/sources/v7_candidate_coverage_ledger.json"
PACKET = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2.json"
HUMAN_TEMPLATE = ROOT / "benchmarks/raw/sources/v7_human_review_template.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_preblind_evaluation_contract.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_preblind_evaluation_contract_report.json"

EXPECTED_V6_SCORER_VERSION = "1.0.0"
EXPECTED_V6_SCORER_RULE = "2026.08.14.6.31.v6.scorer.1"
EXPECTED_V6_EVALUATED_METRICS = (
    "top_hit_recall",
    "condition_recall",
    "admission_precision",
    "admission_recall",
)
EXPECTED_V6_REPORT_ONLY_METRICS = (
    "top_hit_precision",
    "condition_precision",
)
V7_EVALUATED_METRICS = (
    "top_hit_recall",
    "condition_recall",
    "admission_precision",
    "admission_recall",
    "admission_false_positive_rate",
    "admission_false_negative_rate",
    "abstention_rate",
    "top1_family_accuracy",
)
V7_REPORT_ONLY_METRICS = (
    "top_hit_precision",
    "condition_precision",
    "per_family_admission_precision",
    "per_family_admission_recall",
    "per_family_admission_false_positive_rate",
    "per_family_abstention_rate",
)


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def admission_confusion_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | None]:
    for name, value in {"tp": tp, "fp": fp, "tn": tn, "fn": fn}.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    return {
        "precision": safe_ratio(tp, tp + fp),
        "recall": safe_ratio(tp, tp + fn),
        "false_positive_rate": safe_ratio(fp, fp + tn),
        "false_negative_rate": safe_ratio(fn, fn + tp),
    }


def abstention_metrics(abstained: int, total: int) -> dict[str, float | None]:
    if not isinstance(abstained, int) or isinstance(abstained, bool) or abstained < 0:
        raise ValueError("abstained must be a non-negative integer")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise ValueError("total must be a non-negative integer")
    if abstained > total:
        raise ValueError("abstained cannot exceed total")
    return {"abstention_rate": safe_ratio(abstained, total)}


def build_contract() -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    v6 = load(V6_RESULT)
    ledger = load(LEDGER)
    packet = load(PACKET)
    human = load(HUMAN_TEMPLATE)

    if v6.get("first_blind_consumed") is not True:
        raise RuntimeError("historical V6 scorer lineage must come from the consumed first-blind result")
    scorer = v6.get("scorer_freeze") if isinstance(v6.get("scorer_freeze"), Mapping) else {}
    if scorer.get("version") != EXPECTED_V6_SCORER_VERSION or scorer.get("rule_version") != EXPECTED_V6_SCORER_RULE:
        raise RuntimeError("historical V6 scorer lineage version/rule drift")
    if tuple(scorer.get("evaluated_metrics") or ()) != EXPECTED_V6_EVALUATED_METRICS:
        raise RuntimeError("historical V6 evaluated metric lineage drift")
    if tuple(scorer.get("report_only_metrics") or ()) != EXPECTED_V6_REPORT_ONLY_METRICS:
        raise RuntimeError("historical V6 report-only metric lineage drift")
    if scorer.get("engine_output_allowed_as_ground_truth") is not False:
        raise RuntimeError("historical V6 scorer unexpectedly allowed engine output as ground truth")

    for doc, name in ((ledger, "ledger"), (packet, "packet"), (human, "human_template")):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError(f"V7 preblind evaluator {name} source assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError(f"V7 preblind evaluator requires unconsumed {name}")
    if ledger.get("candidate_material_coverage_count") != 66 or ledger.get("unresolved_candidate_material_count") != 0:
        raise RuntimeError("V7 candidate coverage ledger is incomplete")
    if packet.get("review_material_available_count") != 144 or packet.get("review_material_missing_count") != 0:
        raise RuntimeError("V7 semantic review material is incomplete")
    if human.get("family_count") != 36 or human.get("variant_count") != 144:
        raise RuntimeError("V7 human review template coverage drift")
    if human.get("human_review_complete") is not False or human.get("human_verified_record_count") != 0:
        raise RuntimeError("V7 preblind evaluator must freeze before human review completion")

    metric_definitions = {
        "top_hit_recall": {
            "formula": "top_hit_tp / (top_hit_tp + top_hit_fn)",
            "zero_denominator": None,
            "lineage": "V6 scorer evaluated metric",
        },
        "top_hit_precision": {
            "formula": "top_hit_tp / (top_hit_tp + top_hit_fp)",
            "zero_denominator": None,
            "lineage": "V6 scorer report-only metric",
        },
        "condition_recall": {
            "formula": "condition_tp / (condition_tp + condition_fn)",
            "zero_denominator": None,
            "lineage": "V6 scorer evaluated metric",
        },
        "condition_precision": {
            "formula": "condition_tp / (condition_tp + condition_fp)",
            "zero_denominator": None,
            "lineage": "V6 scorer report-only metric",
        },
        "admission_precision": {
            "formula": "admission_tp / (admission_tp + admission_fp)",
            "zero_denominator": None,
            "lineage": "V6 scorer evaluated metric",
        },
        "admission_recall": {
            "formula": "admission_tp / (admission_tp + admission_fn)",
            "zero_denominator": None,
            "lineage": "V6 scorer evaluated metric",
        },
        "admission_false_positive_rate": {
            "formula": "admission_fp / (admission_fp + admission_tn)",
            "zero_denominator": None,
            "lineage": "V7 pre-registered confusion-derived metric",
        },
        "admission_false_negative_rate": {
            "formula": "admission_fn / (admission_fn + admission_tp)",
            "zero_denominator": None,
            "lineage": "V7 pre-registered confusion-derived metric",
        },
        "abstention_rate": {
            "formula": "abstained_case_count / scored_case_count",
            "zero_denominator": None,
            "abstained_case_predicate": "analysis_status == 'abstained' OR vulnerability_analysis_status == 'abstained'",
            "lineage": "engine abstention state supported by existing abstention consistency contract",
        },
        "top1_family_accuracy": {
            "formula": "top1_correct_case_count / top1_evaluable_case_count",
            "zero_denominator": None,
            "evaluable_predicate": "human-reviewed expected_top_hits is non-empty and predicted_top1 is present",
            "correct_predicate": "predicted_top1 is a member of human-reviewed expected_top_hits",
            "lineage": "V7 pre-registered descriptive metric using existing predicted_top1 field",
        },
        "per_family_admission_precision": {
            "formula": "family_admission_tp / (family_admission_tp + family_admission_fp)",
            "zero_denominator": None,
            "lineage": "V7 pre-registered report-only metric",
        },
        "per_family_admission_recall": {
            "formula": "family_admission_tp / (family_admission_tp + family_admission_fn)",
            "zero_denominator": None,
            "lineage": "V7 pre-registered report-only metric",
        },
        "per_family_admission_false_positive_rate": {
            "formula": "family_admission_fp / (family_admission_fp + family_admission_tn)",
            "zero_denominator": None,
            "lineage": "V7 pre-registered report-only metric",
        },
        "per_family_abstention_rate": {
            "formula": "family_abstained_case_count / family_case_count",
            "zero_denominator": None,
            "lineage": "V7 pre-registered report-only metric",
        },
    }

    contract = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_preblind_evaluation_contract",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "descriptive_only": True,
        "performance_thresholds": {
            metric: None for metric in sorted(set(V7_EVALUATED_METRICS + V7_REPORT_ONLY_METRICS))
        },
        "threshold_policy": "No V7 performance threshold may be introduced or changed after First Blind results are observed. Results are reported descriptively; future tuning requires a fresh blind dataset (V8 or later).",
        "v6_scorer_lineage": {
            "result_artifact": "benchmarks/raw/results/analysis_raw_v6_first_blind.json",
            "version": scorer.get("version"),
            "rule_version": scorer.get("rule_version"),
            "duplicate_policy": scorer.get("duplicate_policy"),
            "admitted_family_predicate": scorer.get("admitted_family_predicate"),
            "condition_predicate": scorer.get("condition_predicate"),
            "admission_direct_sources": scorer.get("admission_direct_sources"),
            "evaluated_metrics": list(EXPECTED_V6_EVALUATED_METRICS),
            "report_only_metrics": list(EXPECTED_V6_REPORT_ONLY_METRICS),
            "engine_output_allowed_as_ground_truth": False,
        },
        "v7_metric_contract": {
            "evaluated_metrics": list(V7_EVALUATED_METRICS),
            "report_only_metrics": list(V7_REPORT_ONLY_METRICS),
            "metric_definitions": metric_definitions,
            "no_top3_metric": True,
            "reason_top3_omitted": "Current historical blind schema exposes predicted_top1; no stable pre-existing ranked top-3 output contract was found and none is invented for V7.",
        },
        "ground_truth_contract": {
            "source": "completed_and_validated_v7_human_review_only",
            "engine_output_allowed_as_ground_truth": False,
            "minimum_distinct_human_reviewers": 3,
            "required_variant_count": 144,
            "required_family_count": 36,
            "expected_admission_by_case_kind": {
                "positive": True,
                "near_miss": False,
                "secure_negative": False,
                "sparse_noisy": False,
            },
            "expected_top_hits_and_conditions": "must be materialized only from accepted human-reviewed source evidence and frozen family/condition schema; never inferred from engine predictions",
        },
        "admission_confusion_contract": {
            "positive_class": "human-accepted positive variant",
            "negative_classes": ["human-accepted near_miss", "human-accepted secure_negative", "human-accepted sparse_noisy"],
            "predicted_positive": "family is admitted under the frozen V6 lineage admitted_family_predicate and allowed direct source policy",
            "predicted_negative": "family is not admitted",
            "counts": ["admission_tp", "admission_fp", "admission_tn", "admission_fn"],
        },
        "integrity_gates": {
            "engine_baseline_commit_exact": freeze["engine_baseline_commit"],
            "source_assignment_commit_exact": freeze["source_assignment_commit"],
            "candidate_material_coverage_required": 66,
            "review_material_coverage_required": 144,
            "human_review_complete_required_before_scoring": True,
            "human_review_validation_required_before_scoring": True,
            "human_verified_variant_count_required_before_scoring": 144,
            "family_adjudication_required_count": 11,
            "engine_output_ground_truth_leakage_allowed": False,
            "source_replacement_allowed": False,
            "synthetic_fixture_allowed": False,
            "scorer_contract_mutation_after_results_allowed": False,
        },
        "first_blind_lifecycle": {
            "one_shot": True,
            "first_blind_consumed_before_run": False,
            "mark_consumed_on_scoring_start": True,
            "v7_tuning_after_first_blind_allowed": True,
            "v7_reblind_after_tuning_allowed": False,
            "fresh_blind_required_after_tuning": "V8_or_later",
            "production_accuracy_claim_allowed_from_unreviewed_or_unscored_v7": False,
        },
        "bound_artifacts": {
            "candidate_coverage_ledger": {
                "path": "benchmarks/raw/sources/v7_candidate_coverage_ledger.json",
                "ledger_sha256": ledger.get("ledger_sha256"),
            },
            "semantic_review_packet_v2": {
                "path": "benchmarks/raw/sources/v7_semantic_review_packet_v2.json",
                "packet_set_sha256": packet.get("packet_set_sha256"),
            },
            "human_review_template": {
                "path": "benchmarks/raw/sources/v7_human_review_template.json",
                "template_sha256": human.get("template_sha256"),
            },
        },
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    contract["contract_sha256"] = sha_json({k: v for k, v in contract.items() if k != "contract_sha256"})
    return contract


def main() -> int:
    contract = build_contract()
    OUTPUT.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    report = {
        "version": contract["version"],
        "rule_version": contract["rule_version"],
        "descriptive_only": contract["descriptive_only"],
        "evaluated_metrics": contract["v7_metric_contract"]["evaluated_metrics"],
        "report_only_metrics": contract["v7_metric_contract"]["report_only_metrics"],
        "performance_threshold_count": sum(v is not None for v in contract["performance_thresholds"].values()),
        "human_review_complete_required_before_scoring": True,
        "human_verified_variant_count_required_before_scoring": 144,
        "one_shot_first_blind": True,
        "v7_reblind_after_tuning_allowed": False,
        "fresh_blind_required_after_tuning": "V8_or_later",
        "contract_sha256": contract["contract_sha256"],
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": contract["engine_baseline_commit"],
        "source_assignment_commit": contract["source_assignment_commit"],
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

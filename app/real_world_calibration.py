from __future__ import annotations

"""Human-verified real-world calibration and shadow feedback learning.

This module is deliberately outside the vulnerability evidence boundary. It
accepts only records that satisfy the verified replay contract, applies a
quality gate, creates a label-blind deterministic train/holdout split by case
origin, learns threshold proposals from train only, measures them out-of-sample
on holdout data, and mines recurring error patterns into review suggestions.

Nothing in this module can alter target evidence, Family Reasoning admission,
confirmation, Candidate creation, ranking weights, or production activation.
Even a fully healthy corpus can only become "ready for manual policy review".
"""

import hashlib
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from calibration_engine import DEFAULT_THRESHOLD, confusion_metrics, select_threshold
from family_reasoning import FAMILY_ORDER
from verified_replay_contract import validate_verified_replay_collection


REAL_WORLD_CALIBRATION_VERSION = "1.1.0"
REAL_WORLD_CALIBRATION_RULE_VERSION = "2026.08.14.2"
DEFAULT_HOLDOUT_PERCENT = 20
DEFAULT_MIN_EVIDENCE_QUALITY = 60
FORCED_TRAIN_EVALUATION_ROLES = frozenset({"consumed_benchmark", "development_only"})
FRESH_EVALUATION_ROLE = "fresh_candidate"

QUALITY_WEIGHTS = {
    "reliability": 0.25,
    "specificity": 0.20,
    "directness": 0.20,
    "freshness": 0.10,
    "independence": 0.15,
    "reproducibility": 0.10,
}


def _label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {
        "1", "true", "yes", "positive", "confirmed", "vulnerable"
    }


def _score(value: Any) -> int:
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        numeric = 0
    return max(0, min(100, numeric))


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return round(float(numerator) / float(denominator), 6) if denominator else 0.0


def _record_score(record: Mapping[str, Any]) -> int:
    value = record.get("decision_readiness_score")
    if value is None:
        value = record.get("score")
    return _score(value)


def _quality_score(record: Mapping[str, Any]) -> int:
    raw = record.get("evidence_quality")
    quality = raw if isinstance(raw, Mapping) else {}
    total = 0.0
    weight_total = 0.0
    for name, weight in QUALITY_WEIGHTS.items():
        try:
            value = float(quality.get(name))
        except (TypeError, ValueError):
            return 0
        if value > 1.0 and value <= 100.0:
            value /= 100.0
        if value < 0.0 or value > 1.0:
            return 0
        total += value * weight
        weight_total += weight
    try:
        uncertainty = float(quality.get("uncertainty"))
    except (TypeError, ValueError):
        return 0
    if uncertainty > 1.0 and uncertainty <= 100.0:
        uncertainty /= 100.0
    if uncertainty < 0.0 or uncertainty > 1.0:
        return 0
    base = total / weight_total if weight_total else 0.0
    certainty_factor = 1.0 - (0.50 * uncertainty)
    return max(0, min(100, int(round(base * certainty_factor * 100.0))))


def _origin_key(record: Mapping[str, Any]) -> str:
    return (
        str(record.get("case_origin_id") or "").strip()
        or str(record.get("record_fingerprint") or "").strip()
        or str(record.get("id") or "").strip()
    )


def _stable_bucket(origin: str) -> int:
    digest = hashlib.sha256(str(origin).encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def _with_quality(record: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(record)
    row["evidence_quality_score"] = _quality_score(row)
    row["decision_readiness_score"] = _record_score(row)
    row["score"] = row["decision_readiness_score"]
    return row


def deterministic_holdout_split(
    records: Iterable[Mapping[str, Any]],
    *,
    holdout_percent: int = DEFAULT_HOLDOUT_PERCENT,
    min_evidence_quality: int = DEFAULT_MIN_EVIDENCE_QUALITY,
) -> dict[str, Any]:
    """Validate, quality-gate and split records without using labels.

    All snapshots sharing the same case origin are assigned to the same side.
    The split key never includes the human label, score, family, or reviewer.

    Lifecycle is enforced before hashing: any origin containing a
    ``consumed_benchmark`` or ``development_only`` snapshot is forced wholly to
    train. Only origins made entirely of ``fresh_candidate`` records are eligible
    for holdout hashing. ``reserved_blind`` is rejected by the replay contract.
    """

    holdout_percent = max(5, min(50, int(holdout_percent)))
    min_evidence_quality = max(0, min(100, int(min_evidence_quality)))
    validation = validate_verified_replay_collection(records)
    accepted = [_with_quality(row) for row in validation["records"]]
    eligible = [row for row in accepted if int(row["evidence_quality_score"]) >= min_evidence_quality]
    excluded_quality = [row for row in accepted if int(row["evidence_quality_score"]) < min_evidence_quality]

    by_origin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        origin = _origin_key(row)
        if origin:
            by_origin[origin].append(row)

    forced_train_origins: set[str] = set()
    fresh_origins: set[str] = set()
    for origin, origin_rows in by_origin.items():
        roles = {str(row.get("evaluation_role") or FRESH_EVALUATION_ROLE) for row in origin_rows}
        if roles & FORCED_TRAIN_EVALUATION_ROLES:
            forced_train_origins.add(origin)
        else:
            fresh_origins.add(origin)

    train_origins: set[str] = set(forced_train_origins)
    holdout_origins: set[str] = set()
    ranked_fresh_origins = sorted(fresh_origins, key=lambda origin: (_stable_bucket(origin), origin))
    for origin in ranked_fresh_origins:
        if _stable_bucket(origin) < holdout_percent:
            holdout_origins.add(origin)
        else:
            train_origins.add(origin)

    # For a small but non-trivial *fresh* corpus, preserve a usable split without
    # looking at labels. Forced historical origins never participate in fallback
    # selection and can never be moved to holdout.
    if len(ranked_fresh_origins) >= 2 and not holdout_origins:
        chosen = ranked_fresh_origins[0]
        train_origins.discard(chosen)
        holdout_origins.add(chosen)
    fresh_train_origins = set(train_origins) - forced_train_origins
    if len(ranked_fresh_origins) >= 2 and not fresh_train_origins:
        chosen = ranked_fresh_origins[-1]
        holdout_origins.discard(chosen)
        train_origins.add(chosen)

    train = [row for origin in sorted(train_origins) for row in by_origin[origin]]
    holdout = [row for origin in sorted(holdout_origins) for row in by_origin[origin]]
    leakage = sorted(train_origins & holdout_origins)
    role_counts = Counter(str(row.get("evaluation_role") or FRESH_EVALUATION_ROLE) for row in eligible)
    forced_train = [row for origin in sorted(forced_train_origins) for row in by_origin[origin]]

    return {
        "version": REAL_WORLD_CALIBRATION_VERSION,
        "rule_version": REAL_WORLD_CALIBRATION_RULE_VERSION,
        "holdout_percent": holdout_percent,
        "min_evidence_quality": min_evidence_quality,
        "accepted_count": len(accepted),
        "rejected_count": int(validation["rejected_count"]),
        "duplicate_count": int(validation["duplicate_count"]),
        "quality_excluded_count": len(excluded_quality),
        "evaluation_eligible_count": len(eligible),
        "evaluation_role_counts": dict(sorted(role_counts.items())),
        "forced_train_count": len(forced_train),
        "forced_train_origin_count": len(forced_train_origins),
        "fresh_origin_count": len(fresh_origins),
        "train_count": len(train),
        "holdout_count": len(holdout),
        "train_origin_count": len(train_origins),
        "holdout_origin_count": len(holdout_origins),
        "origin_leakage_count": len(leakage),
        "origin_leakage": leakage,
        "train": train,
        "holdout": holdout,
        "quality_excluded": excluded_quality,
        "rejected": list(validation["rejected"]),
        "safety": {
            "partition_is_label_blind": True,
            "partition_excludes_scores": True,
            "partition_excludes_family": True,
            "partition_excludes_reviewer": True,
            "same_case_origin_never_crosses_train_holdout": True,
            "quality_gate_is_evaluation_only": True,
            "consumed_benchmark_is_train_only": True,
            "development_only_is_train_only": True,
            "reserved_blind_is_contract_rejected": True,
            "mixed_fresh_consumed_origin_is_train_only": True,
        },
    }


def extended_confusion_metrics(
    records: Iterable[Mapping[str, Any]],
    *,
    threshold: int,
) -> dict[str, Any]:
    rows = [dict(row) for row in records]
    metrics = confusion_metrics(
        rows,
        threshold=threshold,
        score_key="decision_readiness_score",
        label_key="label",
    )
    tn = int(metrics["tn"])
    fn = int(metrics["fn"])
    tp = int(metrics["tp"])
    fp = int(metrics["fp"])
    metrics["false_negative_rate"] = _ratio(fn, fn + tp)
    metrics["negative_predictive_value"] = _ratio(tn, tn + fn)
    metrics["balanced_accuracy"] = round(
        (float(metrics["recall"]) + float(metrics["specificity"])) / 2.0,
        6,
    )
    metrics["predicted_positive"] = tp + fp
    metrics["predicted_negative"] = tn + fn
    return metrics


def _has_both_labels(rows: Iterable[Mapping[str, Any]]) -> bool:
    labels = {_label(row.get("label")) for row in rows}
    return labels == {False, True}


def _threshold_evaluation(
    train: list[dict[str, Any]],
    holdout: list[dict[str, Any]],
    *,
    default_threshold: int,
    min_train: int,
    min_holdout: int,
    min_train_positive: int,
    min_train_negative: int,
) -> dict[str, Any]:
    train_positive = sum(1 for row in train if _label(row.get("label")))
    train_negative = len(train) - train_positive
    train_ready = (
        len(train) >= int(min_train)
        and train_positive >= int(min_train_positive)
        and train_negative >= int(min_train_negative)
    )
    selection = (
        select_threshold(
            train,
            score_key="decision_readiness_score",
            label_key="label",
            default_threshold=default_threshold,
        )
        if train_ready
        else {
            "threshold": int(default_threshold),
            "metrics": extended_confusion_metrics(train, threshold=default_threshold),
            "learned": False,
        }
    )
    candidate_threshold = int(selection["threshold"])
    current_metrics = extended_confusion_metrics(holdout, threshold=default_threshold)
    candidate_metrics = extended_confusion_metrics(holdout, threshold=candidate_threshold)
    holdout_ready = len(holdout) >= int(min_holdout) and _has_both_labels(holdout)
    stable = bool(
        holdout_ready
        and float(candidate_metrics["f1"]) >= float(current_metrics["f1"]) - 0.02
        and float(candidate_metrics["precision"]) >= float(current_metrics["precision"]) - 0.02
        and float(candidate_metrics["recall"]) >= float(current_metrics["recall"]) - 0.02
        and float(candidate_metrics["false_positive_rate"]) <= float(current_metrics["false_positive_rate"]) + 0.02
    )
    return {
        "current_threshold": int(default_threshold),
        "candidate_threshold": candidate_threshold,
        "candidate_learned_from_train": bool(selection.get("learned")),
        "train_ready": bool(train_ready),
        "train_support": len(train),
        "train_positive": train_positive,
        "train_negative": train_negative,
        "holdout_ready": bool(holdout_ready),
        "holdout_support": len(holdout),
        "current_holdout_metrics": current_metrics,
        "candidate_holdout_metrics": candidate_metrics,
        "candidate_generalizes_without_material_regression": stable,
        "threshold_delta": candidate_threshold - int(default_threshold),
        "shadow_recommendation": (
            "review_candidate_threshold"
            if bool(selection.get("learned")) and stable and candidate_threshold != int(default_threshold)
            else "retain_current_threshold_for_now"
        ),
    }


def _reviewer_health(rows: list[dict[str, Any]]) -> dict[str, Any]:
    reviewers = Counter(str(row.get("reviewer_id") or "") for row in rows if str(row.get("reviewer_id") or ""))
    total = sum(reviewers.values())
    top_reviewer = reviewers.most_common(1)[0] if reviewers else ("", 0)
    return {
        "reviewer_count": len(reviewers),
        "reviewer_counts": dict(sorted(reviewers.items())),
        "top_reviewer_id": str(top_reviewer[0]),
        "top_reviewer_share": _ratio(int(top_reviewer[1]), total),
    }


def _error_rows(rows: list[dict[str, Any]], threshold: int) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        predicted = _record_score(row) >= int(threshold)
        actual = _label(row.get("label"))
        key = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
        groups[key].append(row)
    return {key: list(groups.get(key, [])) for key in ("tp", "fp", "tn", "fn")}


def _token_counts(rows: Iterable[Mapping[str, Any]], key: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        values = row.get(key)
        if not isinstance(values, (list, tuple, set)):
            continue
        for value in set(str(item) for item in values if str(item).strip()):
            counts[value] += 1
    return counts


def mine_shadow_feedback(
    holdout: Iterable[Mapping[str, Any]],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    min_error_support: int = 2,
    max_recommendations: int = 100,
) -> dict[str, Any]:
    """Mine recurring holdout errors into review suggestions, never weight edits."""

    rows = [dict(row) for row in holdout]
    recommendations: list[dict[str, Any]] = []
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        family = str(row.get("family") or "").strip()
        if family:
            by_family[family].append(row)

    for family, family_rows in sorted(by_family.items()):
        errors = _error_rows(family_rows, threshold)
        fp_signals = _token_counts(errors["fp"], "signals")
        tp_signals = _token_counts(errors["tp"], "signals")
        fn_signals = _token_counts(errors["fn"], "signals")
        fp_contradictions = _token_counts(errors["fp"], "contradictions")

        for signal, support in fp_signals.most_common():
            if support < int(min_error_support):
                continue
            if support <= int(tp_signals.get(signal, 0)):
                continue
            recommendations.append({
                "family": family,
                "kind": "precision_noise_signal_review",
                "token": signal,
                "error_support": support,
                "counter_support": int(tp_signals.get(signal, 0)),
                "suggested_human_action": "review whether this signal is overweighted or missing a required companion signal",
            })

        for signal, support in fn_signals.most_common():
            if support < int(min_error_support):
                continue
            recommendations.append({
                "family": family,
                "kind": "recall_gap_signal_review",
                "token": signal,
                "error_support": support,
                "suggested_human_action": "review whether this repeated verified signal is underrepresented in family reasoning or ranking",
            })

        for contradiction, support in fp_contradictions.most_common():
            if support < int(min_error_support):
                continue
            recommendations.append({
                "family": family,
                "kind": "contradiction_suppression_review",
                "token": contradiction,
                "error_support": support,
                "suggested_human_action": "review whether this contradiction should suppress ranking more strongly after independent validation",
            })

    recommendations = sorted(
        recommendations,
        key=lambda item: (-int(item.get("error_support") or 0), str(item.get("family") or ""), str(item.get("kind") or ""), str(item.get("token") or "")),
    )[: max(1, int(max_recommendations))]
    return {
        "threshold": int(threshold),
        "holdout_support": len(rows),
        "recommendation_count": len(recommendations),
        "recommendations": recommendations,
        "safety": {
            "shadow_only": True,
            "recommendations_do_not_edit_weights": True,
            "recommendations_do_not_edit_family_reasoning": True,
            "recommendations_do_not_change_admission": True,
            "recommendations_require_human_review": True,
        },
    }


def build_real_world_calibration_report(
    records: Iterable[Mapping[str, Any]],
    *,
    default_threshold: int = DEFAULT_THRESHOLD,
    holdout_percent: int = DEFAULT_HOLDOUT_PERCENT,
    min_evidence_quality: int = DEFAULT_MIN_EVIDENCE_QUALITY,
    min_train: int = 20,
    min_holdout: int = 10,
    min_train_positive: int = 5,
    min_train_negative: int = 5,
    min_global_verified: int = 400,
    min_verified_families: int = 40,
    min_reviewers: int = 3,
    min_global_holdout: int = 80,
    min_holdout_precision: float = 0.80,
    min_holdout_recall: float = 0.70,
    max_holdout_fpr: float = 0.10,
) -> dict[str, Any]:
    """Build an out-of-sample real-world evaluation and shadow-learning report."""

    split = deterministic_holdout_split(
        records,
        holdout_percent=holdout_percent,
        min_evidence_quality=min_evidence_quality,
    )
    train = list(split["train"])
    holdout = list(split["holdout"])
    evaluation = _threshold_evaluation(
        train,
        holdout,
        default_threshold=int(default_threshold),
        min_train=int(min_train),
        min_holdout=int(min_holdout),
        min_train_positive=int(min_train_positive),
        min_train_negative=int(min_train_negative),
    )

    by_family_train: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_family_holdout: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in train:
        by_family_train[str(row.get("family") or "")].append(row)
    for row in holdout:
        by_family_holdout[str(row.get("family") or "")].append(row)

    family_metrics: dict[str, Any] = {}
    for family in sorted(set(by_family_train) | set(by_family_holdout)):
        if not family:
            continue
        family_metrics[family] = _threshold_evaluation(
            by_family_train.get(family, []),
            by_family_holdout.get(family, []),
            default_threshold=int(default_threshold),
            min_train=max(6, int(min_train) // 2),
            min_holdout=max(4, int(min_holdout) // 2),
            min_train_positive=max(2, int(min_train_positive) // 2),
            min_train_negative=max(2, int(min_train_negative) // 2),
        )

    eligible = [*train, *holdout]
    positives = sum(1 for row in eligible if _label(row.get("label")))
    negatives = len(eligible) - positives
    families = {str(row.get("family") or "") for row in eligible if str(row.get("family") or "")}
    reviewer_health = _reviewer_health(eligible)
    quality_scores = [int(row.get("evidence_quality_score") or 0) for row in eligible]
    holdout_metrics = evaluation["candidate_holdout_metrics"]

    manual_policy_review_ready = bool(
        len(eligible) >= int(min_global_verified)
        and len(families) >= int(min_verified_families)
        and positives > 0
        and negatives > 0
        and int(reviewer_health["reviewer_count"]) >= int(min_reviewers)
        and float(reviewer_health["top_reviewer_share"]) <= 0.70
        and len(holdout) >= int(min_global_holdout)
        and bool(evaluation["candidate_generalizes_without_material_regression"])
        and float(holdout_metrics["precision"]) >= float(min_holdout_precision)
        and float(holdout_metrics["recall"]) >= float(min_holdout_recall)
        and float(holdout_metrics["false_positive_rate"]) <= float(max_holdout_fpr)
        and int(split["origin_leakage_count"]) == 0
    )

    feedback = mine_shadow_feedback(
        holdout,
        threshold=int(default_threshold),
    )

    return {
        "version": REAL_WORLD_CALIBRATION_VERSION,
        "rule_version": REAL_WORLD_CALIBRATION_RULE_VERSION,
        "status": "ready_for_manual_policy_review" if manual_policy_review_ready else "shadow_only_collect_more_verified_data",
        "activation": "shadow_only",
        "automatic_activation": False,
        "split": {
            key: value
            for key, value in split.items()
            if key not in {"train", "holdout", "quality_excluded", "rejected"}
        },
        "corpus_health": {
            "trusted_evaluation_records": len(eligible),
            "positive": positives,
            "negative": negatives,
            "family_count": len(families),
            "canonical_family_count": len(FAMILY_ORDER),
            "mean_evidence_quality": round(sum(quality_scores) / len(quality_scores), 2) if quality_scores else 0.0,
            "minimum_evidence_quality": int(min_evidence_quality),
            **reviewer_health,
        },
        "global_evaluation": evaluation,
        "family_evaluation": family_metrics,
        "shadow_feedback": feedback,
        "deployment_review": {
            "ready": manual_policy_review_ready,
            "automatic_activation": False,
            "required_manual_policy_change": True,
            "minimums": {
                "verified_records": int(min_global_verified),
                "verified_families": int(min_verified_families),
                "reviewers": int(min_reviewers),
                "global_holdout": int(min_global_holdout),
                "holdout_precision": float(min_holdout_precision),
                "holdout_recall": float(min_holdout_recall),
                "maximum_holdout_false_positive_rate": float(max_holdout_fpr),
                "maximum_top_reviewer_share": 0.70,
            },
        },
        "safety": {
            "human_verified_contract_required": True,
            "low_quality_records_excluded_from_evaluation": True,
            "threshold_selection_uses_train_only": True,
            "holdout_never_selects_threshold": True,
            "same_case_origin_never_crosses_train_holdout": True,
            "consumed_benchmark_origins_are_train_only": True,
            "development_only_origins_are_train_only": True,
            "reserved_blind_records_are_contract_rejected": True,
            "synthetic_or_golden_records_cannot_enter_through_contract": True,
            "feedback_is_shadow_only": True,
            "feedback_cannot_change_weights": True,
            "feedback_cannot_change_family_reasoning": True,
            "feedback_cannot_change_admission": True,
            "feedback_cannot_confirm_vulnerability": True,
            "production_activation_is_never_automatic": True,
            "network_requests": False,
        },
    }


__all__ = [
    "REAL_WORLD_CALIBRATION_VERSION",
    "REAL_WORLD_CALIBRATION_RULE_VERSION",
    "DEFAULT_HOLDOUT_PERCENT",
    "DEFAULT_MIN_EVIDENCE_QUALITY",
    "FORCED_TRAIN_EVALUATION_ROLES",
    "FRESH_EVALUATION_ROLE",
    "deterministic_holdout_split",
    "extended_confusion_metrics",
    "mine_shadow_feedback",
    "build_real_world_calibration_report",
]

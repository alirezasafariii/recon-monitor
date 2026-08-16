from __future__ import annotations

"""Deterministic calibration utilities for Analysis ranking.

Calibration is intentionally advisory. It may measure ranking quality and propose
thresholds, but it never changes target evidence, admission, or confirmation.
Production activation must be an explicit policy decision after sufficient
labeled observations exist.
"""

from collections import defaultdict
from typing import Any, Iterable, Mapping

CALIBRATION_ENGINE_VERSION = "1.0.0"
CALIBRATION_RULE_VERSION = "2026.08.13.1"
DEFAULT_THRESHOLD = 70
DEFAULT_BIN_COUNT = 10


def _score(value: Any) -> int:
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        numeric = 0
    return max(0, min(100, numeric))


def _label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "positive", "confirmed", "vulnerable"}


def _ratio(numerator: int, denominator: int) -> float:
    return round(float(numerator) / float(denominator), 6) if denominator else 0.0


def confusion_metrics(
    records: Iterable[Mapping[str, Any]],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    score_key: str = "score",
    label_key: str = "label",
) -> dict[str, Any]:
    """Return deterministic binary ranking metrics for a decision threshold."""

    threshold = _score(threshold)
    tp = fp = tn = fn = 0
    rows = [dict(record) for record in records]
    for record in rows:
        predicted = _score(record.get(score_key)) >= threshold
        actual = _label(record.get(label_key))
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    fpr = _ratio(fp, fp + tn)
    f1 = round(2.0 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    accuracy = _ratio(tp + tn, len(rows))
    return {
        "threshold": threshold,
        "support": len(rows),
        "positive": tp + fn,
        "negative": tn + fp,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "f1": f1,
        "accuracy": accuracy,
    }


def calibration_bins(
    records: Iterable[Mapping[str, Any]],
    *,
    bins: int = DEFAULT_BIN_COUNT,
    score_key: str = "score",
    label_key: str = "label",
) -> list[dict[str, Any]]:
    """Group raw 0-100 ranking scores into empirical outcome buckets."""

    bins = max(2, min(20, int(bins)))
    grouped: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    rows = [dict(record) for record in records]
    for record in rows:
        score = _score(record.get(score_key))
        index = min(bins - 1, int(score * bins / 101))
        grouped[index].append(record)

    result: list[dict[str, Any]] = []
    for index in range(bins):
        low = int(index * 100 / bins)
        high = 100 if index == bins - 1 else int((index + 1) * 100 / bins) - 1
        bucket = grouped.get(index, [])
        mean_score = round(sum(_score(row.get(score_key)) for row in bucket) / len(bucket), 3) if bucket else None
        observed = round(sum(1 for row in bucket if _label(row.get(label_key))) / len(bucket), 6) if bucket else None
        result.append({
            "index": index,
            "low": low,
            "high": high,
            "support": len(bucket),
            "mean_score": mean_score,
            "observed_positive_rate": observed,
        })
    return result


def calibration_diagnostics(
    records: Iterable[Mapping[str, Any]],
    *,
    bins: int = DEFAULT_BIN_COUNT,
    score_key: str = "score",
    label_key: str = "label",
) -> dict[str, Any]:
    """Return Brier/ECE diagnostics without pretending raw proximity is probability."""

    rows = [dict(record) for record in records]
    if not rows:
        return {"support": 0, "score_brier_diagnostic": None, "expected_calibration_error": None, "bins": []}

    squared = []
    for record in rows:
        probability_like = _score(record.get(score_key)) / 100.0
        actual = 1.0 if _label(record.get(label_key)) else 0.0
        squared.append((probability_like - actual) ** 2)
    brier = round(sum(squared) / len(squared), 6)

    bucket_rows = calibration_bins(rows, bins=bins, score_key=score_key, label_key=label_key)
    ece = 0.0
    for bucket in bucket_rows:
        if not bucket["support"]:
            continue
        mean_score = float(bucket["mean_score"] or 0.0) / 100.0
        observed = float(bucket["observed_positive_rate"] or 0.0)
        ece += (bucket["support"] / len(rows)) * abs(mean_score - observed)
    return {
        "support": len(rows),
        "score_brier_diagnostic": brier,
        "expected_calibration_error": round(ece, 6),
        "bins": bucket_rows,
        "note": "bug_proximity_score is a ranking score, not a vulnerability probability",
    }


def select_threshold(
    records: Iterable[Mapping[str, Any]],
    *,
    score_key: str = "score",
    label_key: str = "label",
    default_threshold: int = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Select a deterministic candidate threshold from labeled ranking records.

    The objective is intentionally conservative: maximize F1, then precision,
    then recall, then minimize FPR, while preferring a threshold near the current
    default when otherwise tied.
    """

    rows = [dict(record) for record in records]
    if not rows:
        return {"threshold": _score(default_threshold), "metrics": confusion_metrics([], threshold=default_threshold), "learned": False}

    candidates = {0, 100, _score(default_threshold)}
    for record in rows:
        value = _score(record.get(score_key))
        candidates.add(value)
        if value < 100:
            candidates.add(value + 1)

    best: tuple[Any, ...] | None = None
    best_metrics: dict[str, Any] | None = None
    for threshold in sorted(candidates):
        metrics = confusion_metrics(rows, threshold=threshold, score_key=score_key, label_key=label_key)
        objective = (
            float(metrics["f1"]),
            float(metrics["precision"]),
            float(metrics["recall"]),
            -float(metrics["false_positive_rate"]),
            -abs(int(threshold) - _score(default_threshold)),
            int(threshold),
        )
        if best is None or objective > best:
            best = objective
            best_metrics = metrics
    assert best_metrics is not None
    return {"threshold": int(best_metrics["threshold"]), "metrics": best_metrics, "learned": True}


def build_calibration_profile(
    records: Iterable[Mapping[str, Any]],
    *,
    source: str = "labeled_replay",
    activation: str = "shadow_only",
    min_global_cases: int = 40,
    min_family_cases: int = 12,
    min_family_positive: int = 3,
    min_family_negative: int = 3,
) -> dict[str, Any]:
    """Build a calibration profile while refusing under-supported family tuning."""

    rows = [dict(record) for record in records]
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in rows:
        family = str(record.get("family") or "").strip()
        if family:
            families[family].append(record)

    global_ready = len(rows) >= int(min_global_cases) and any(_label(row.get("label")) for row in rows) and any(not _label(row.get("label")) for row in rows)
    global_selection = select_threshold(rows) if global_ready else {
        "threshold": DEFAULT_THRESHOLD,
        "metrics": confusion_metrics(rows, threshold=DEFAULT_THRESHOLD),
        "learned": False,
    }
    global_profile = {
        **global_selection,
        "ready": bool(global_ready),
        "diagnostics": calibration_diagnostics(rows),
    }

    family_profiles: dict[str, Any] = {}
    for family, family_rows in sorted(families.items()):
        positives = sum(1 for row in family_rows if _label(row.get("label")))
        negatives = len(family_rows) - positives
        ready = len(family_rows) >= int(min_family_cases) and positives >= int(min_family_positive) and negatives >= int(min_family_negative)
        selection = select_threshold(family_rows) if ready else {
            "threshold": int(global_profile["threshold"]),
            "metrics": confusion_metrics(family_rows, threshold=int(global_profile["threshold"])),
            "learned": False,
        }
        family_profiles[family] = {
            **selection,
            "ready": bool(ready),
            "support": len(family_rows),
            "positive": positives,
            "negative": negatives,
            "threshold_source": "family_labeled_data" if ready else "global_fallback",
            "diagnostics": calibration_diagnostics(family_rows),
        }

    return {
        "engine_version": CALIBRATION_ENGINE_VERSION,
        "rule_version": CALIBRATION_RULE_VERSION,
        "source": str(source),
        "activation": str(activation),
        "global": global_profile,
        "families": family_profiles,
        "minimums": {
            "global_cases": int(min_global_cases),
            "family_cases": int(min_family_cases),
            "family_positive": int(min_family_positive),
            "family_negative": int(min_family_negative),
        },
        "safety": {
            "shadow_only_by_default": True,
            "may_change_target_evidence_confidence": False,
            "may_satisfy_admission": False,
            "may_satisfy_confirmation": False,
            "knowledge_or_llm_can_become_evidence": False,
        },
    }


def calibration_for_score(family: str, score: Any, profile: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return advisory calibration metadata for one ranking score."""

    raw_score = _score(score)
    if not isinstance(profile, Mapping):
        return {
            "available": False,
            "raw_score": raw_score,
            "threshold": DEFAULT_THRESHOLD,
            "threshold_source": "default",
            "activation": "none",
            "above_threshold": raw_score >= DEFAULT_THRESHOLD,
            "empirical_positive_rate": None,
        }

    global_profile = profile.get("global", {}) if isinstance(profile.get("global"), Mapping) else {}
    family_profiles = profile.get("families", {}) if isinstance(profile.get("families"), Mapping) else {}
    family_profile = family_profiles.get(str(family), {}) if isinstance(family_profiles.get(str(family)), Mapping) else {}
    use_family = bool(family_profile.get("ready"))
    selected = family_profile if use_family else global_profile
    threshold = _score(selected.get("threshold", DEFAULT_THRESHOLD))
    bins = selected.get("diagnostics", {}).get("bins", []) if isinstance(selected.get("diagnostics"), Mapping) else []
    empirical = None
    for bucket in bins if isinstance(bins, list) else []:
        if not isinstance(bucket, Mapping) or not bucket.get("support"):
            continue
        if int(bucket.get("low", 0)) <= raw_score <= int(bucket.get("high", 100)):
            empirical = bucket.get("observed_positive_rate")
            break

    return {
        "available": bool(global_profile),
        "raw_score": raw_score,
        "threshold": threshold,
        "threshold_source": "family_labeled_data" if use_family else "global_labeled_data" if global_profile.get("ready") else "default",
        "activation": str(profile.get("activation") or "shadow_only"),
        "above_threshold": raw_score >= threshold,
        "empirical_positive_rate": empirical,
        "family_profile_ready": use_family,
        "advisory_only": True,
    }

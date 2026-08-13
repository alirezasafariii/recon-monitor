from __future__ import annotations

"""Provenance and activation policy for Analysis calibration datasets.

Golden fixtures and generated challenge cases are useful for deterministic
regression and ranking diagnostics, but they are not independent real-world
validation. This module makes that boundary machine-readable so a large synthetic
corpus cannot accidentally make a learned threshold production-ready.
"""

from collections import defaultdict
from typing import Any, Iterable, Mapping

from calibration_engine import build_calibration_profile

CALIBRATION_DATASET_VERSION = "1.0.0"
CALIBRATION_DATASET_RULE_VERSION = "2026.08.13.1"

TRUSTED_ACTIVATION_PROVENANCE = frozenset({
    "human_verified_replay",
    "curated_real_world_replay",
    "confirmed_target_history",
})

NON_ACTIVATING_PROVENANCE = frozenset({
    "golden_seed",
    "synthetic_challenge",
    "generated_hard_negative",
    "generated_partial_evidence",
})


def _label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {
        "1", "true", "yes", "positive", "confirmed", "vulnerable"
    }


def _provenance(record: Mapping[str, Any]) -> str:
    return str(record.get("provenance") or "unclassified").strip().lower()


def is_activation_eligible(record: Mapping[str, Any]) -> bool:
    """Return True only for explicitly human/real-world labeled records."""

    provenance = _provenance(record)
    return (
        provenance in TRUSTED_ACTIVATION_PROVENANCE
        and bool(record.get("human_verified"))
        and bool(record.get("label_source"))
    )


def annotate_record(
    record: Mapping[str, Any],
    *,
    provenance: str,
    case_kind: str,
    human_verified: bool = False,
    label_source: str = "",
) -> dict[str, Any]:
    row = dict(record)
    row["provenance"] = str(provenance).strip().lower()
    row["case_kind"] = str(case_kind).strip().lower()
    row["human_verified"] = bool(human_verified)
    row["label_source"] = str(label_source or "").strip()
    row["activation_eligible"] = is_activation_eligible(row)
    return row


def activation_readiness(
    records: Iterable[Mapping[str, Any]],
    *,
    min_global_verified: int = 400,
    min_verified_families: int = 40,
    min_family_verified: int = 20,
    min_family_positive: int = 5,
    min_family_negative: int = 5,
) -> dict[str, Any]:
    """Evaluate whether labeled evidence is sufficient for threshold activation.

    Readiness intentionally ignores golden and synthetic rows even if there are
    millions of them. Family readiness is independent from global readiness.
    """

    rows = [dict(record) for record in records]
    eligible = [row for row in rows if is_activation_eligible(row)]
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        family = str(row.get("family") or "").strip()
        if family:
            by_family[family].append(row)

    positive = sum(1 for row in eligible if _label(row.get("label")))
    negative = len(eligible) - positive
    represented = sum(1 for family_rows in by_family.values() if family_rows)
    global_ready = (
        len(eligible) >= int(min_global_verified)
        and positive > 0
        and negative > 0
        and represented >= int(min_verified_families)
    )

    family_status: dict[str, Any] = {}
    for family, family_rows in sorted(by_family.items()):
        positives = sum(1 for row in family_rows if _label(row.get("label")))
        negatives = len(family_rows) - positives
        ready = (
            len(family_rows) >= int(min_family_verified)
            and positives >= int(min_family_positive)
            and negatives >= int(min_family_negative)
        )
        family_status[family] = {
            "ready": bool(ready),
            "support": len(family_rows),
            "positive": positives,
            "negative": negatives,
        }

    provenance_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        provenance_counts[_provenance(row)] += 1

    return {
        "global_ready": bool(global_ready),
        "eligible_support": len(eligible),
        "eligible_positive": positive,
        "eligible_negative": negative,
        "eligible_families": represented,
        "family_status": family_status,
        "provenance_counts": dict(sorted(provenance_counts.items())),
        "minimums": {
            "global_verified": int(min_global_verified),
            "verified_families": int(min_verified_families),
            "family_verified": int(min_family_verified),
            "family_positive": int(min_family_positive),
            "family_negative": int(min_family_negative),
        },
    }


def build_guarded_calibration_profile(
    records: Iterable[Mapping[str, Any]],
    *,
    requested_activation: str = "shadow_only",
    source: str = "labeled_replay",
    min_global_cases: int = 40,
    min_family_cases: int = 12,
    min_family_positive: int = 3,
    min_family_negative: int = 3,
    min_global_verified: int = 400,
    min_verified_families: int = 40,
    min_family_verified: int = 20,
    min_verified_family_positive: int = 5,
    min_verified_family_negative: int = 5,
) -> dict[str, Any]:
    """Build advisory calibration plus an independent activation readiness gate."""

    rows = [dict(record) for record in records]
    diagnostic = build_calibration_profile(
        rows,
        source=source,
        activation="shadow_only",
        min_global_cases=min_global_cases,
        min_family_cases=min_family_cases,
        min_family_positive=min_family_positive,
        min_family_negative=min_family_negative,
    )
    readiness = activation_readiness(
        rows,
        min_global_verified=min_global_verified,
        min_verified_families=min_verified_families,
        min_family_verified=min_family_verified,
        min_family_positive=min_verified_family_positive,
        min_family_negative=min_verified_family_negative,
    )

    requested = str(requested_activation or "shadow_only").strip().lower()
    production_requested = requested not in {"", "none", "shadow", "shadow_only", "advisory"}
    effective = requested if production_requested and readiness["global_ready"] else "shadow_only"

    diagnostic["requested_activation"] = requested or "shadow_only"
    diagnostic["activation"] = effective
    diagnostic["activation_readiness"] = readiness
    diagnostic["dataset_policy"] = {
        "version": CALIBRATION_DATASET_VERSION,
        "rule_version": CALIBRATION_DATASET_RULE_VERSION,
        "trusted_activation_provenance": sorted(TRUSTED_ACTIVATION_PROVENANCE),
        "non_activating_provenance": sorted(NON_ACTIVATING_PROVENANCE),
    }
    diagnostic.setdefault("safety", {}).update({
        "golden_or_synthetic_cannot_activate_production": True,
        "human_verified_real_world_labels_required_for_activation": True,
        "requested_production_activation_was_blocked": bool(production_requested and not readiness["global_ready"]),
    })
    return diagnostic

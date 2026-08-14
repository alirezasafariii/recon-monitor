from __future__ import annotations

"""Provenance and activation policy for Analysis calibration datasets.

Golden fixtures and generated challenge cases are useful for deterministic
regression and ranking diagnostics, but they are not independent real-world
validation. Production activation therefore requires not only trusted provenance
and a human label, but also a canonical vulnerability family and an auditable
evidence-snapshot binding.
"""

from collections import defaultdict
from typing import Any, Iterable, Mapping

from calibration_engine import build_calibration_profile
from family_reasoning import FAMILY_ORDER

CALIBRATION_DATASET_VERSION = "1.1.0"
CALIBRATION_DATASET_RULE_VERSION = "2026.08.14.1"

CANONICAL_ACTIVATION_FAMILIES = frozenset(str(family) for family in FAMILY_ORDER)
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

REQUIRED_ACTIVATION_AUDIT_FIELDS = (
    "reviewer_id",
    "reviewed_at",
    "case_origin_id",
    "evidence_snapshot_id",
)


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


def activation_eligibility_reasons(record: Mapping[str, Any]) -> list[str]:
    """Explain why a record cannot contribute to production activation."""

    provenance = _provenance(record)
    if provenance not in TRUSTED_ACTIVATION_PROVENANCE:
        return ["untrusted_provenance"]

    reasons: list[str] = []
    family = str(record.get("family") or "").strip()
    if not family:
        reasons.append("missing_family")
    elif family not in CANONICAL_ACTIVATION_FAMILIES:
        reasons.append("unknown_family")

    if record.get("human_verified") is not True:
        reasons.append("human_verified_true_required")
    if not str(record.get("label_source") or "").strip():
        reasons.append("missing_label_source")

    for field in REQUIRED_ACTIVATION_AUDIT_FIELDS:
        if not str(record.get(field) or "").strip():
            reasons.append(f"missing_{field}")

    quality = record.get("evidence_quality_profile")
    if not isinstance(quality, Mapping) or quality.get("complete") is not True:
        reasons.append("incomplete_evidence_quality")

    return reasons


def is_activation_eligible(record: Mapping[str, Any]) -> bool:
    """Return True only for canonical, audit-ready human/real-world labels."""

    return not activation_eligibility_reasons(record)


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

    Readiness intentionally ignores golden/synthetic rows and trusted rows that
    are non-canonical or lack auditable evidence bindings. Family readiness is
    independent from global readiness.
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
    ineligible_reason_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        provenance_counts[_provenance(row)] += 1
        for reason in activation_eligibility_reasons(row):
            ineligible_reason_counts[reason] += 1

    return {
        "global_ready": bool(global_ready),
        "eligible_support": len(eligible),
        "eligible_positive": positive,
        "eligible_negative": negative,
        "eligible_families": represented,
        "canonical_family_count": len(CANONICAL_ACTIVATION_FAMILIES),
        "family_status": family_status,
        "provenance_counts": dict(sorted(provenance_counts.items())),
        "ineligible_reason_counts": dict(sorted(ineligible_reason_counts.items())),
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
        "canonical_family_count": len(CANONICAL_ACTIVATION_FAMILIES),
        "required_activation_audit_fields": list(REQUIRED_ACTIVATION_AUDIT_FIELDS),
        "trusted_activation_provenance": sorted(TRUSTED_ACTIVATION_PROVENANCE),
        "non_activating_provenance": sorted(NON_ACTIVATING_PROVENANCE),
    }
    diagnostic.setdefault("safety", {}).update({
        "golden_or_synthetic_cannot_activate_production": True,
        "human_verified_real_world_labels_required_for_activation": True,
        "canonical_family_required_for_activation": True,
        "auditable_evidence_snapshot_required_for_activation": True,
        "complete_evidence_quality_required_for_activation": True,
        "requested_production_activation_was_blocked": bool(production_requested and not readiness["global_ready"]),
    })
    return diagnostic

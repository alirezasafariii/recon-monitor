from __future__ import annotations

"""Offline contract for collecting human-verified Analysis replay metadata.

This module validates dataset metadata only. It never contacts a target, creates
vulnerability evidence, changes admission/confirmation, or activates calibration.
Its purpose is to keep future real-world replay labels canonical, auditable and
consistent before they are offered to the calibration pipeline.
"""

import hashlib
from typing import Any, Iterable, Mapping

from calibration_dataset import TRUSTED_ACTIVATION_PROVENANCE
from family_reasoning import FAMILY_ORDER

VERIFIED_REPLAY_CONTRACT_VERSION = "1.0.0"
VERIFIED_REPLAY_CONTRACT_RULE_VERSION = "2026.08.14.1"

CANONICAL_FAMILIES = frozenset(str(family) for family in FAMILY_ORDER)
EVIDENCE_QUALITY_DIMENSIONS = (
    "reliability",
    "specificity",
    "directness",
    "freshness",
    "independence",
    "reproducibility",
    "uncertainty",
)
REQUIRED_AUDIT_FIELDS = (
    "label_source",
    "reviewer_id",
    "reviewed_at",
    "case_origin_id",
    "evidence_snapshot_id",
)
_POSITIVE_LABELS = frozenset({"1", "true", "yes", "positive", "confirmed", "vulnerable"})
_NEGATIVE_LABELS = frozenset({"0", "false", "no", "negative", "rejected", "not_vulnerable", "not-vulnerable"})


def _strict_label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, float) and value in {0.0, 1.0}:
        return bool(int(value))
    token = str(value or "").strip().lower()
    if token in _POSITIVE_LABELS:
        return True
    if token in _NEGATIVE_LABELS:
        return False
    raise ValueError("ambiguous_label")


def _unit_interval(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number > 1.0 and number <= 100.0:
        number /= 100.0
    if number < 0.0 or number > 1.0:
        return None
    return number


def _score_0_100(value: Any) -> int | None:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return None
    if number < 0 or number > 100:
        return None
    return number


def _fingerprint(record: Mapping[str, Any]) -> str:
    material = "|".join((
        str(record.get("family") or "").strip(),
        str(record.get("case_origin_id") or "").strip(),
        str(record.get("evidence_snapshot_id") or "").strip(),
        str(record.get("provenance") or "").strip().lower(),
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def validate_verified_replay_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize one proposed real-world replay label."""

    raw = dict(record)
    errors: list[str] = []

    family = str(raw.get("family") or "").strip()
    if not family:
        errors.append("missing_family")
    elif family not in CANONICAL_FAMILIES:
        errors.append("unknown_family")

    try:
        label = _strict_label(raw.get("label"))
    except ValueError:
        label = False
        errors.append("ambiguous_label")

    provenance = str(raw.get("provenance") or "").strip().lower()
    if provenance not in TRUSTED_ACTIVATION_PROVENANCE:
        errors.append("untrusted_provenance")
    if raw.get("human_verified") is not True:
        errors.append("human_verified_true_required")

    for field in REQUIRED_AUDIT_FIELDS:
        if not str(raw.get(field) or "").strip():
            errors.append(f"missing_{field}")

    quality_raw = raw.get("evidence_quality")
    quality = quality_raw if isinstance(quality_raw, Mapping) else {}
    normalized_quality: dict[str, float] = {}
    for dimension in EVIDENCE_QUALITY_DIMENSIONS:
        if dimension not in quality:
            errors.append(f"missing_quality_{dimension}")
            continue
        parsed = _unit_interval(quality.get(dimension))
        if parsed is None:
            errors.append(f"invalid_quality_{dimension}")
            continue
        normalized_quality[dimension] = parsed

    readiness_raw = raw.get("decision_readiness_score")
    if readiness_raw is None:
        readiness_raw = raw.get("score")
    readiness = _score_0_100(readiness_raw)
    if readiness is None:
        errors.append("invalid_decision_readiness_score")
        readiness = 0

    proximity = _score_0_100(raw.get("bug_proximity_score", 0))
    if proximity is None:
        errors.append("invalid_bug_proximity_score")
        proximity = 0

    evidence_confidence = _score_0_100(raw.get("target_evidence_confidence", 0))
    if evidence_confidence is None:
        errors.append("invalid_target_evidence_confidence")
        evidence_confidence = 0

    normalized = {
        "id": str(raw.get("id") or "").strip(),
        "family": family,
        "label": bool(label),
        "decision_readiness_score": readiness,
        "score": readiness,
        "bug_proximity_score": proximity,
        "target_evidence_confidence": evidence_confidence,
        "signals": [str(value) for value in raw.get("signals", []) if str(value).strip()],
        "contradictions": [str(value) for value in raw.get("contradictions", []) if str(value).strip()],
        "provenance": provenance,
        "human_verified": raw.get("human_verified") is True,
        "label_source": str(raw.get("label_source") or "").strip(),
        "reviewer_id": str(raw.get("reviewer_id") or "").strip(),
        "reviewed_at": str(raw.get("reviewed_at") or "").strip(),
        "case_origin_id": str(raw.get("case_origin_id") or "").strip(),
        "evidence_snapshot_id": str(raw.get("evidence_snapshot_id") or "").strip(),
        "evidence_quality": normalized_quality,
        "contract_version": VERIFIED_REPLAY_CONTRACT_VERSION,
    }
    normalized["record_fingerprint"] = _fingerprint(normalized)
    return {
        "valid": not errors,
        "errors": errors,
        "record": normalized,
    }


def validate_verified_replay_collection(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate a collection and report coverage without changing calibration."""

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_count = 0

    for index, raw in enumerate(records):
        validation = validate_verified_replay_record(raw)
        row = dict(validation["record"])
        if not validation["valid"]:
            rejected.append({
                "index": index,
                "id": str(row.get("id") or ""),
                "family": str(row.get("family") or ""),
                "errors": list(validation["errors"]),
            })
            continue

        fingerprint = str(row.get("record_fingerprint") or "")
        if fingerprint in seen:
            duplicate_count += 1
            rejected.append({
                "index": index,
                "id": str(row.get("id") or ""),
                "family": str(row.get("family") or ""),
                "errors": ["duplicate_verified_replay"],
            })
            continue
        seen.add(fingerprint)
        accepted.append(row)

    positives = sum(1 for row in accepted if bool(row.get("label")))
    families = sorted({str(row.get("family") or "") for row in accepted if str(row.get("family") or "").strip()})
    return {
        "contract_version": VERIFIED_REPLAY_CONTRACT_VERSION,
        "rule_version": VERIFIED_REPLAY_CONTRACT_RULE_VERSION,
        "canonical_family_count": len(CANONICAL_FAMILIES),
        "accepted_count": len(accepted),
        "accepted_positive": positives,
        "accepted_negative": len(accepted) - positives,
        "accepted_family_count": len(families),
        "accepted_families": families,
        "rejected_count": len(rejected),
        "duplicate_count": duplicate_count,
        "records": accepted,
        "rejected": rejected,
        "safety": {
            "offline_metadata_only": True,
            "network_requests": False,
            "changes_analysis_decisions": False,
            "changes_calibration_activation": False,
            "canonical_family_required": True,
            "human_review_required": True,
            "evidence_snapshot_binding_required": True,
            "complete_evidence_quality_required": True,
        },
    }

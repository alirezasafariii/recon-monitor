from __future__ import annotations

"""Validated primary-source coverage for non-code vulnerability families.

Some Recon Monitor families describe deployment, DNS, routing, or operational
security boundaries that are not naturally represented by a package advisory
with an exact parent/fix code revision. This module keeps those primary-source
coverage records separate from exact revision replay.

Primary-source records improve family *coverage visibility* only. They are not
human verification, are not replay labels, do not provide Analysis scores, and
are never production-activation eligible.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_reasoning import FAMILY_ORDER

PRIMARY_SOURCE_COVERAGE_VERSION = "1.0.0"
PRIMARY_SOURCE_COVERAGE_RULE_VERSION = "2026.09.18.1"

ALLOWED_SOURCE_KINDS = frozenset({
    "public_bug_bounty_primary",
    "vendor_security_advisory",
    "official_security_writeup",
})
ALLOWED_COVERAGE_LEVELS = frozenset({
    "primary_source_configuration_boundary",
    "primary_source_behavior_boundary",
})
CANONICAL_FAMILIES = frozenset(str(value) for value in FAMILY_ORDER)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_primary_source_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(raw)
    errors: list[str] = []

    source_id = _text(row.get("source_id"))
    family = _text(row.get("family"))
    source_url = _text(row.get("source_url"))
    source_kind = _text(row.get("source_kind"))
    coverage_level = _text(row.get("coverage_level"))
    title = _text(row.get("title"))
    source_org = _text(row.get("source_org"))
    reported_at = _text(row.get("reported_at"))
    remediation_summary = _text(row.get("remediation_summary"))

    if not source_id:
        errors.append("missing_source_id")
    if family not in CANONICAL_FAMILIES:
        errors.append("family_not_canonical")
    if not source_url.startswith("https://"):
        errors.append("source_url_must_be_https")
    if source_kind not in ALLOWED_SOURCE_KINDS:
        errors.append("source_kind_not_allowed")
    if coverage_level not in ALLOWED_COVERAGE_LEVELS:
        errors.append("coverage_level_not_allowed")
    if not title:
        errors.append("missing_title")
    if not source_org:
        errors.append("missing_source_org")
    if not reported_at:
        errors.append("missing_reported_at")
    if not remediation_summary:
        errors.append("missing_remediation_summary")
    if row.get("human_verified") is True:
        errors.append("primary_source_must_not_be_human_verified")
    if row.get("activation_eligible") is True:
        errors.append("primary_source_must_not_be_activation_eligible")
    if any(
        row.get(name) not in (None, "")
        for name in (
            "decision_readiness_score",
            "bug_proximity_score",
            "target_evidence_confidence",
        )
    ):
        errors.append("primary_source_must_not_contain_analysis_scores")

    record = {
        "source_id": source_id,
        "family": family,
        "source_url": source_url,
        "source_kind": source_kind,
        "coverage_level": coverage_level,
        "title": title,
        "source_org": source_org,
        "reported_at": reported_at,
        "researcher": _text(row.get("researcher")) or None,
        "remediation_summary": remediation_summary,
        "evaluation_role": _text(row.get("evaluation_role")) or "fresh_candidate",
        "human_verified": False,
        "activation_eligible": False,
        "analysis_scoring_executed": False,
        "target_contact_performed": False,
        "label_created": False,
    }
    record["source_snapshot_sha256"] = _canonical_hash(record)
    return {
        "valid": not errors,
        "errors": errors,
        "record": record,
    }


def validate_primary_source_collection(
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()

    for index, raw in enumerate(rows):
        result = validate_primary_source_record(raw)
        record = dict(result["record"])
        errors = list(result["errors"])
        if record["source_id"] in seen_ids:
            errors.append("duplicate_source_id")
        if record["source_url"] in seen_urls:
            errors.append("duplicate_source_url")
        if errors:
            rejected.append({
                "index": index,
                "source_id": record["source_id"],
                "family": record["family"],
                "errors": errors,
            })
            continue
        seen_ids.add(record["source_id"])
        seen_urls.add(record["source_url"])
        accepted.append(record)

    families = sorted({row["family"] for row in accepted})
    return {
        "version": PRIMARY_SOURCE_COVERAGE_VERSION,
        "rule_version": PRIMARY_SOURCE_COVERAGE_RULE_VERSION,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "family_count": len(families),
        "families": families,
        "records": accepted,
        "rejected": rejected,
        "safety": {
            "coverage_only": True,
            "not_human_verified": True,
            "not_replay_labels": True,
            "no_analysis_scores": True,
            "no_production_activation": True,
            "no_target_contact": True,
        },
    }


def load_primary_source_file(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("primary_source_payload_must_be_object")
    rows = payload.get("records")
    if not isinstance(rows, list):
        raise ValueError("primary_source_records_missing")
    return validate_primary_source_collection(
        row for row in rows if isinstance(row, Mapping)
    )


__all__ = [
    "PRIMARY_SOURCE_COVERAGE_VERSION",
    "PRIMARY_SOURCE_COVERAGE_RULE_VERSION",
    "validate_primary_source_record",
    "validate_primary_source_collection",
    "load_primary_source_file",
]

from __future__ import annotations

"""Bridge Real-World Corpus V1 review drafts into the current replay contract.

This module is intentionally fail-closed. Corpus variants, advisory metadata,
CWE hints and historical target-family hints are never converted into labels.
A record becomes calibration-eligible only after an explicit human review and
after scores from the current Recon Monitor engine have been attached.
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from verified_replay_contract import validate_verified_replay_record

CORPUS_V1_BRIDGE_VERSION = "1.0.0"
CORPUS_V1_BRIDGE_RULE_VERSION = "2026.09.18.1"

REVIEW_COMPLETE_STATUSES = frozenset({"accepted", "complete", "reviewed", "verified"})
SCORE_FIELDS = (
    "decision_readiness_score",
    "bug_proximity_score",
    "target_evidence_confidence",
)
QUALITY_FIELDS = (
    "reliability",
    "specificity",
    "directness",
    "freshness",
    "independence",
    "reproducibility",
    "uncertainty",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _load_rows(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, Mapping):
        rows = data.get("drafts")
        if not isinstance(rows, list):
            raise ValueError("review_file_missing_drafts")
    else:
        raise ValueError("review_file_invalid_root")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def load_review_files(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        rows.extend(_load_rows(path))
    return rows


def _score_present(draft: Mapping[str, Any], field: str) -> bool:
    value = draft.get(field)
    if value is None:
        scores = draft.get("analysis_scores")
        if isinstance(scores, Mapping):
            value = scores.get(field)
    if value is None or value == "":
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return 0.0 <= number <= 100.0


def _score_value(draft: Mapping[str, Any], field: str) -> Any:
    value = draft.get(field)
    if value is None:
        scores = draft.get("analysis_scores")
        if isinstance(scores, Mapping):
            value = scores.get(field)
    return value


def review_readiness(drafts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in drafts]
    status_counts: Counter[str] = Counter()
    human_complete = 0
    score_complete = 0
    contract_ready = 0
    variant_counts: Counter[str] = Counter()

    for row in rows:
        variant_counts[_text(row.get("variant")) or "unknown"] += 1
        review_raw = row.get("review")
        review = review_raw if isinstance(review_raw, Mapping) else {}
        status = _text(review.get("review_status")).lower() or "missing"
        status_counts[status] += 1

        quality_raw = review.get("evidence_quality")
        quality = quality_raw if isinstance(quality_raw, Mapping) else {}
        quality_complete = all(quality.get(name) is not None for name in QUALITY_FIELDS)
        reviewer_complete = all(
            _text(review.get(name))
            for name in ("family", "label_source", "reviewer_id", "reviewed_at")
        )
        label_present = "label" in review and review.get("label") is not None
        human_ok = (
            review.get("human_verified") is True
            and status in REVIEW_COMPLETE_STATUSES
            and quality_complete
            and reviewer_complete
            and label_present
        )
        if human_ok:
            human_complete += 1

        scores_ok = all(_score_present(row, field) for field in SCORE_FIELDS)
        if scores_ok:
            score_complete += 1

        finalized = finalize_draft(row)
        if finalized["valid"]:
            contract_ready += 1

    return {
        "version": CORPUS_V1_BRIDGE_VERSION,
        "rule_version": CORPUS_V1_BRIDGE_RULE_VERSION,
        "draft_count": len(rows),
        "human_review_complete_count": human_complete,
        "current_engine_score_complete_count": score_complete,
        "verified_replay_ready_count": contract_ready,
        "status_counts": dict(sorted(status_counts.items())),
        "variant_counts": dict(sorted(variant_counts.items())),
        "human_review_required": contract_ready < len(rows),
    }


def finalize_draft(draft: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one explicitly reviewed draft to current verified-replay schema."""

    raw = dict(draft)
    review_raw = raw.get("review")
    review = review_raw if isinstance(review_raw, Mapping) else {}
    errors: list[str] = []

    status = _text(review.get("review_status")).lower()
    if status not in REVIEW_COMPLETE_STATUSES:
        errors.append("review_not_complete")
    if review.get("human_verified") is not True:
        errors.append("human_verified_true_required")

    if "label" not in review or review.get("label") is None:
        errors.append("missing_human_label")

    for field in ("family", "label_source", "reviewer_id", "reviewed_at"):
        if not _text(review.get(field)):
            errors.append(f"missing_review_{field}")

    quality_raw = review.get("evidence_quality")
    quality = quality_raw if isinstance(quality_raw, Mapping) else {}
    for field in QUALITY_FIELDS:
        if quality.get(field) is None:
            errors.append(f"missing_review_quality_{field}")

    for field in SCORE_FIELDS:
        if not _score_present(raw, field):
            errors.append(f"missing_current_engine_{field}")

    variant = _text(raw.get("variant")).lower()
    binding_raw = raw.get("evidence_binding")
    binding = binding_raw if isinstance(binding_raw, Mapping) else {}
    if variant in {"positive", "secure_negative"} and binding.get(
        "boundary_semantics_human_confirmed"
    ) is not True:
        errors.append("boundary_semantics_human_confirmation_required")

    record = {
        "id": _text(raw.get("draft_id") or raw.get("id")),
        "family": _text(review.get("family")),
        "label": review.get("label"),
        "decision_readiness_score": _score_value(raw, "decision_readiness_score"),
        "bug_proximity_score": _score_value(raw, "bug_proximity_score"),
        "target_evidence_confidence": _score_value(raw, "target_evidence_confidence"),
        "signals": [str(value) for value in raw.get("signals", []) if _text(value)],
        "contradictions": [
            str(value) for value in raw.get("contradictions", []) if _text(value)
        ],
        "provenance": _text(raw.get("proposed_provenance"))
        or "curated_real_world_replay",
        "human_verified": review.get("human_verified") is True,
        "label_source": _text(review.get("label_source")),
        "reviewer_id": _text(review.get("reviewer_id")),
        "reviewed_at": _text(review.get("reviewed_at")),
        "case_origin_id": _text(raw.get("case_origin_id")),
        "evidence_snapshot_id": _text(raw.get("evidence_snapshot_id")),
        "evidence_quality": dict(quality),
    }

    contract = validate_verified_replay_record(record)
    errors.extend(str(value) for value in contract["errors"] if str(value) not in errors)
    return {
        "valid": not errors,
        "errors": errors,
        "record": dict(contract["record"]),
        "draft_id": _text(raw.get("draft_id")),
        "variant": variant,
    }


def finalize_collection(drafts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in drafts]
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for index, raw in enumerate(rows):
        result = finalize_draft(raw)
        record = dict(result["record"])
        fingerprint = _text(record.get("record_fingerprint"))
        errors = list(result["errors"])
        if result["valid"] and fingerprint in seen:
            errors.append("duplicate_verified_replay")
        if errors:
            rejected.append({
                "index": index,
                "draft_id": result["draft_id"],
                "variant": result["variant"],
                "errors": errors,
            })
            continue
        seen.add(fingerprint)
        accepted.append(record)

    return {
        "version": CORPUS_V1_BRIDGE_VERSION,
        "rule_version": CORPUS_V1_BRIDGE_RULE_VERSION,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "records": accepted,
        "rejected": rejected,
        "readiness": review_readiness_shallow(rows),
        "production_activation_performed": False,
    }


def review_readiness_shallow(drafts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in drafts]
    complete = 0
    scored = 0
    for row in rows:
        review_raw = row.get("review")
        review = review_raw if isinstance(review_raw, Mapping) else {}
        quality_raw = review.get("evidence_quality")
        quality = quality_raw if isinstance(quality_raw, Mapping) else {}
        if (
            review.get("human_verified") is True
            and _text(review.get("review_status")).lower() in REVIEW_COMPLETE_STATUSES
            and "label" in review
            and review.get("label") is not None
            and all(_text(review.get(k)) for k in ("family", "label_source", "reviewer_id", "reviewed_at"))
            and all(quality.get(name) is not None for name in QUALITY_FIELDS)
        ):
            complete += 1
        if all(_score_present(row, field) for field in SCORE_FIELDS):
            scored += 1
    return {
        "draft_count": len(rows),
        "human_review_complete_count": complete,
        "current_engine_score_complete_count": scored,
    }


def render_jsonl(records: Iterable[Mapping[str, Any]]) -> str:
    return "".join(
        json.dumps(dict(record), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        + "\n"
        for record in records
    )


def _main() -> int:
    parser = argparse.ArgumentParser(description="Finalize reviewed Real-World Corpus V1 drafts")
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--output")
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()

    rows = load_review_files(args.input)

    if args.status_only:
        print(json.dumps(review_readiness(rows), indent=2, sort_keys=True))
        return 0

    result = finalize_collection(rows)
    if args.output:
        Path(args.output).write_text(render_jsonl(result["records"]), encoding="utf-8")
    print(json.dumps({
        key: value for key, value in result.items() if key != "records"
    }, indent=2, sort_keys=True))
    return 0 if not result["rejected_count"] else 2


if __name__ == "__main__":
    raise SystemExit(_main())

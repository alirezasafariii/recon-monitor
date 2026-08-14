from __future__ import annotations

import json
from typing import Any

import v6_corpus_freeze as freeze

# v6_corpus_freeze.py predates the completed corpus and uses expressions such
# as int(doc.get("zero_count") or -1).  A legitimate integer zero is falsy in
# Python and is therefore misread as -1.  This compatibility entry point fixes
# only that representation bug in-memory.  It does not mutate any source JSON,
# lower any threshold, or alter the protected-file hashes produced by the
# canonical freeze implementation.
_ZERO_SAFE_FIELDS: dict[str, tuple[str, ...]] = {
    "benchmarks/raw/sources/v6_literal_source_research.json": (
        "unresolved_snapshot_count",
    ),
    "benchmarks/raw/sources/v6_literal_capture_feasibility.json": (
        "evidence_missing_count",
    ),
    "benchmarks/raw/sources/v6_literal_capture_plan.json": (
        "evidence_missing_count",
    ),
    "benchmarks/raw/sources/v6_literal_capture_ingest_report.json": (
        "missing_capture_count",
        "error_count",
    ),
    "benchmarks/raw/sources/v6_validation_report.json": (
        "label_leakage_count",
    ),
}

_ORIGINAL_LOAD = freeze._load


def _zero_safe_load(rel: str) -> dict[str, Any]:
    doc = _ORIGINAL_LOAD(rel)
    for field in _ZERO_SAFE_FIELDS.get(rel, ()):
        if field not in doc:
            raise RuntimeError(f"required zero-count field is missing: {rel}:{field}")
        value = doc[field]
        if isinstance(value, bool):
            raise RuntimeError(f"zero-count field must be numeric, not bool: {rel}:{field}")
        try:
            numeric = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"zero-count field is not integer-compatible: {rel}:{field}") from exc
        if numeric != 0:
            # Preserve non-zero values exactly so the canonical fail-closed
            # comparisons continue to reject them.
            continue
        # String "0" remains int-compatible but is truthy, so the canonical
        # `value or -1` expression evaluates to the intended zero.
        doc[field] = "0"
    return doc


def write_freeze() -> dict[str, Any]:
    freeze._load = _zero_safe_load
    try:
        return freeze.write_freeze()
    finally:
        freeze._load = _ORIGINAL_LOAD


def main() -> int:
    report = write_freeze()
    print(json.dumps({
        "evaluation_status": report["evaluation_status"],
        "protected_count": report["protected_count"],
        "literal_evidence_artifact_count": report["literal_evidence_artifact_count"],
        "scoring_executed": report["scoring_executed"],
        "first_blind_consumed": report["first_blind_consumed"],
        "zero_safe_compatibility": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

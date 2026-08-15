from __future__ import annotations

"""Build an auditable ledger for all 66 originally missing Fresh Blind V7 variants.

The ledger proves structural candidate-material coverage only. It does NOT claim that
candidate semantics are correct, does NOT perform human adjudication, does NOT publish
benchmark evidence, and does NOT score or consume First Blind.
"""

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.coverage-ledger.1"
WORKLIST = ROOT / "benchmarks/raw/sources/v7_missing_literal_source_worklist.json"
SECOND = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
THIRD = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue.json"
FOURTH = ROOT / "benchmarks/raw/sources/v7_fourth_pass_resolution_queue.json"
SIXTH = ROOT / "benchmarks/raw/sources/v7_sixth_pass_resolution_queue.json"
FINAL = ROOT / "benchmarks/raw/sources/v7_final_residual_control_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_candidate_coverage_ledger.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_candidate_coverage_ledger_report.json"


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


def collect_ready(doc: Mapping[str, Any], stage: str) -> list[dict[str, Any]]:
    rows = []
    for row in doc.get("items") or []:
        if not isinstance(row, Mapping):
            continue
        if row.get("resolution_status") != "candidate_material_available_for_human_review":
            continue
        rows.append({
            "capture_id": row.get("capture_id"),
            "family": row.get("family"),
            "case_kind": row.get("case_kind"),
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "resolution_stage": stage,
            "candidate_count": int(row.get("candidate_count") or 0),
            "semantic_adjudicated": False,
        })
    return rows


def main() -> int:
    freeze = assert_capture_source_freeze()
    work = load(WORKLIST)
    second = load(SECOND)
    third = load(THIRD)
    fourth = load(FOURTH)
    sixth = load(SIXTH)
    final = load(FINAL)
    docs = (work, second, third, fourth, sixth, final)
    for doc in docs:
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 coverage-ledger input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 coverage ledger requires unconsumed inputs")

    original = [x for x in work.get("items") or [] if isinstance(x, Mapping)]
    if len(original) != 66:
        raise RuntimeError(f"original V7 missing worklist count {len(original)} != 66")
    original_by_id = {text(x.get("capture_id")): x for x in original}
    if len(original_by_id) != 66 or "" in original_by_id:
        raise RuntimeError("original V7 missing worklist capture IDs are not unique/non-empty")

    resolved = []
    resolved.extend(collect_ready(second, "second_pass"))
    resolved.extend(collect_ready(third, "third_pass"))
    resolved.extend(collect_ready(fourth, "fourth_pass"))
    resolved.extend(collect_ready(sixth, "sixth_pass"))
    for candidate in final.get("candidates") or []:
        if not isinstance(candidate, Mapping):
            continue
        resolved.append({
            "capture_id": candidate.get("capture_id"),
            "family": candidate.get("family"),
            "case_kind": candidate.get("case_kind"),
            "source_root": candidate.get("source_root"),
            "source_project": candidate.get("source_project"),
            "resolution_stage": "final_residual_control",
            "candidate_count": 1,
            "semantic_adjudicated": False,
        })

    ids = [text(x.get("capture_id")) for x in resolved]
    counts = Counter(ids)
    duplicates = sorted(capture_id for capture_id, count in counts.items() if count != 1)
    unknown = sorted(set(ids) - set(original_by_id))
    missing = sorted(set(original_by_id) - set(ids))
    if duplicates:
        raise RuntimeError(f"V7 candidate coverage duplicate/non-unique resolutions: {duplicates}")
    if unknown:
        raise RuntimeError(f"V7 candidate coverage contains unknown capture IDs: {unknown}")
    if missing:
        raise RuntimeError(f"V7 candidate coverage still missing capture IDs: {missing}")
    if len(resolved) != 66:
        raise RuntimeError(f"V7 candidate coverage resolved count {len(resolved)} != 66")

    ledger = []
    for row in sorted(resolved, key=lambda x: text(x.get("capture_id"))):
        original_row = original_by_id[text(row.get("capture_id"))]
        for field in ("family", "case_kind", "source_root", "source_project"):
            if text(row.get(field)).casefold() != text(original_row.get(field)).casefold():
                raise RuntimeError(f"{row.get('capture_id')}: {field} drift between worklist and resolution")
        ledger.append(dict(row))

    by_kind = Counter(text(x.get("case_kind")) for x in ledger)
    expected_kinds = {"positive": 20, "near_miss": 26, "secure_negative": 20}
    if dict(by_kind) != expected_kinds:
        raise RuntimeError(f"V7 candidate coverage kind counts drift: {dict(by_kind)} != {expected_kinds}")
    by_stage = Counter(text(x.get("resolution_stage")) for x in ledger)

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_candidate_material_coverage_ledger_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "original_missing_variant_count": 66,
        "candidate_material_coverage_count": 66,
        "unresolved_candidate_material_count": 0,
        "by_case_kind": dict(sorted(by_kind.items())),
        "by_resolution_stage": dict(sorted(by_stage.items())),
        "candidate_material_complete": True,
        "candidate_semantics_adjudicated": False,
        "semantic_adjudication_complete": False,
        "human_adjudication_performed": False,
        "human_review_complete": False,
        "evidence_published": False,
        "publication_authorized": False,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "synthetic_fixture_allowed": False,
        "cross_variant_mutation_allowed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    document = dict(report)
    document["items"] = ledger
    document["ledger_sha256"] = sha_json(ledger)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

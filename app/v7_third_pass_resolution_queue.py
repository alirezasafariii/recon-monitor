from __future__ import annotations

"""Map only the 39 still-unresolved V7 items to third-pass literal candidates.

This queue remains non-adjudicating: structural candidate availability is not a
semantic verdict, original draft statuses are untouched, and no evidence is published.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.third-pass.resolve.1"
SECOND_RESOLUTION = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
THIRD_CAPTURE = ROOT / "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue_report.json"


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


def pair_ref(pair: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "parent_sha": pair.get("parent_sha"),
        "fix_sha": pair.get("fix_sha"),
        "discovery_basis": pair.get("discovery_basis"),
        "pair_candidate_sha256": pair.get("pair_candidate_sha256"),
        "parent_snippet_count": int(pair.get("parent_snippet_count") or 0),
        "fix_snippet_count": int(pair.get("fix_snippet_count") or 0),
        "test_control_candidate_count": int(pair.get("test_control_candidate_count") or 0),
        "semantic_role": pair.get("semantic_role"),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    second = load(SECOND_RESOLUTION)
    third = load(THIRD_CAPTURE)
    for doc in (second, third):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 third-pass resolution input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 third-pass resolution requires unconsumed inputs")
    if second.get("work_item_count") != 66 or second.get("candidate_available_count") != 27 or second.get("still_unresolved_count") != 39:
        raise RuntimeError("V7 second-pass resolution baseline drift")
    if third.get("family_count") != 21 or third.get("candidate_semantics_adjudicated") is not False:
        raise RuntimeError("V7 third-pass source-capture coverage/state drift")
    if third.get("evidence_published") is not False or third.get("source_replacement_used") is not False or third.get("synthetic_fixture_used") is not False:
        raise RuntimeError("V7 third-pass source-capture firewall violated")

    source_by = {
        text(x.get("family")): x
        for x in third.get("families") or []
        if isinstance(x, Mapping)
    }
    unresolved = [
        x for x in second.get("items") or []
        if isinstance(x, Mapping) and x.get("resolution_status") == "still_unresolved_after_second_pass"
    ]
    if len(unresolved) != 39 or len(source_by) != 21:
        raise RuntimeError("V7 third-pass resolution input row coverage drift")

    rows = []
    for item in unresolved:
        family = text(item.get("family"))
        kind = text(item.get("case_kind"))
        source = source_by.get(family)
        if source is None:
            raise RuntimeError(f"{family}: missing third-pass source capture")
        if text(source.get("source_root")) != text(item.get("source_root")):
            raise RuntimeError(f"{family}: frozen source_root drift")
        if text(source.get("source_project")).casefold() != text(item.get("source_project")).casefold():
            raise RuntimeError(f"{family}: frozen source_project drift")

        pairs = [
            x for x in source.get("literal_pair_candidates") or []
            if isinstance(x, Mapping) and not x.get("failure")
        ]
        two_sided = [x for x in pairs if x.get("two_sided_literal_pair") is True]
        controls = [x for x in pairs if int(x.get("test_control_candidate_count") or 0) > 0]
        if kind in {"positive", "secure_negative"}:
            relevant = two_sided
            required_shape = "third_pass_two_sided_literal_revision_pair"
        elif kind == "near_miss":
            relevant = controls
            required_shape = "third_pass_upstream_test_control_candidate"
        else:
            relevant = []
            required_shape = "unsupported_missing_kind_requires_manual_source_review"

        status = "candidate_material_available_for_human_review" if relevant else "still_unresolved_after_third_pass"
        rows.append({
            "family": family,
            "case_kind": kind,
            "capture_id": item.get("capture_id"),
            "source_root": item.get("source_root"),
            "source_project": item.get("source_project"),
            "required_evidence_path": item.get("required_evidence_path"),
            "variant_purpose": item.get("variant_purpose"),
            "required_candidate_shape": required_shape,
            "resolution_status": status,
            "candidate_count": len(relevant),
            "candidate_refs": [pair_ref(x) for x in relevant],
            "human_semantic_decision": None,
            "human_semantic_notes": None,
            "candidate_semantics_adjudicated": False,
            "source_replacement_used": False,
            "synthetic_fixture_used": False,
            "cross_variant_mutation_used": False,
            "evidence_published": False,
            "publication_authorized": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    available = [x for x in rows if x["resolution_status"] == "candidate_material_available_for_human_review"]
    unresolved_after = [x for x in rows if x["resolution_status"] == "still_unresolved_after_third_pass"]
    by_kind = {}
    for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
        subset = [x for x in rows if x["case_kind"] == kind]
        by_kind[kind] = {
            "third_pass_input_count": len(subset),
            "new_candidate_available_count": sum(x["resolution_status"] == "candidate_material_available_for_human_review" for x in subset),
            "still_unresolved_count": sum(x["resolution_status"] == "still_unresolved_after_third_pass" for x in subset),
        }

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_third_pass_resolution_queue_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "third_pass_input_count": len(rows),
        "new_candidate_available_count": len(available),
        "still_unresolved_count": len(unresolved_after),
        "families_with_new_candidate_material": len({x["family"] for x in available}),
        "families_still_unresolved": len({x["family"] for x in unresolved_after}),
        "cumulative_candidate_available_count": 27 + len(available),
        "cumulative_candidate_missing_count": len(unresolved_after),
        "by_case_kind": by_kind,
        "candidate_semantics_adjudicated": False,
        "human_adjudication_performed": False,
        "evidence_published": False,
        "publication_authorized": False,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "source_replacement_used": False,
        "synthetic_fixture_allowed": False,
        "synthetic_fixture_used": False,
        "cross_variant_mutation_allowed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    document = dict(report)
    document["items"] = rows
    document["resolution_queue_sha256"] = sha_json(rows)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""Map the 21 third-pass-unresolved V7 items to fourth-pass candidate material.

This stage is structural only. It does not adjudicate semantics, alter original drafts,
publish evidence, score the engine, or consume First Blind.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.fourth-pass.resolve.1"
THIRD_RESOLUTION = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue.json"
FOURTH = ROOT / "benchmarks/raw/sources/v7_fourth_pass_targeted_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_fourth_pass_resolution_queue.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_fourth_pass_resolution_queue_report.json"


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
        "pair_candidate_sha256": pair.get("pair_candidate_sha256"),
        "parent_snippet_count": int(pair.get("parent_snippet_count") or 0),
        "fix_snippet_count": int(pair.get("fix_snippet_count") or 0),
        "semantic_role": pair.get("semantic_role"),
    }


def control_ref(group: Mapping[str, Any]) -> dict[str, Any]:
    controls = group.get("controls") if isinstance(group.get("controls"), list) else []
    return {
        "path": group.get("path"),
        "commit_sha": group.get("commit_sha"),
        "ref": group.get("ref"),
        "matched_term": group.get("matched_term"),
        "file_sha256": group.get("file_sha256"),
        "control_count": len(controls),
        "discovery_basis": group.get("discovery_basis"),
        "semantic_role": group.get("semantic_role"),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    third = load(THIRD_RESOLUTION)
    fourth = load(FOURTH)
    for doc in (third, fourth):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 fourth-pass resolution input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 fourth-pass resolution requires unconsumed inputs")
    if third.get("still_unresolved_count") != 21 or third.get("cumulative_candidate_available_count") != 45:
        raise RuntimeError("V7 fourth-pass resolution baseline drift")
    if fourth.get("unresolved_input_count") != 21 or fourth.get("family_result_count") != 17:
        raise RuntimeError("V7 fourth-pass candidate coverage drift")
    if fourth.get("candidate_semantics_adjudicated") is not False or fourth.get("evidence_published") is not False:
        raise RuntimeError("V7 fourth-pass candidates unexpectedly adjudicated/published")

    source_by = {
        text(x.get("family")): x
        for x in fourth.get("families") or []
        if isinstance(x, Mapping)
    }
    unresolved = [
        x for x in third.get("items") or []
        if isinstance(x, Mapping) and x.get("resolution_status") == "still_unresolved_after_third_pass"
    ]
    if len(unresolved) != 21 or len(source_by) != 17:
        raise RuntimeError("V7 fourth-pass resolution row coverage drift")

    rows = []
    for item in unresolved:
        family = text(item.get("family"))
        kind = text(item.get("case_kind"))
        source = source_by.get(family)
        if source is None:
            raise RuntimeError(f"{family}: missing fourth-pass candidate row")
        if text(source.get("source_root")) != text(item.get("source_root")):
            raise RuntimeError(f"{family}: source_root drift")
        if text(source.get("source_project")).casefold() != text(item.get("source_project")).casefold():
            raise RuntimeError(f"{family}: source_project drift")

        pairs = [
            x for x in source.get("literal_pair_candidates") or []
            if isinstance(x, Mapping) and not x.get("failure") and x.get("two_sided_literal_pair") is True
        ]
        controls = [
            x for x in source.get("test_control_candidates") or []
            if isinstance(x, Mapping) and x.get("controls")
        ]
        if kind in {"positive", "secure_negative"}:
            relevant_pairs = pairs
            relevant_controls = []
            required_shape = "fourth_pass_two_sided_literal_revision_pair"
        elif kind == "near_miss":
            relevant_pairs = []
            relevant_controls = controls
            required_shape = "fourth_pass_same_source_upstream_test_control"
        else:
            relevant_pairs = []
            relevant_controls = []
            required_shape = "unsupported_missing_kind_requires_manual_source_review"

        candidate_count = len(relevant_pairs) + len(relevant_controls)
        status = "candidate_material_available_for_human_review" if candidate_count else "still_unresolved_after_fourth_pass"
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
            "candidate_count": candidate_count,
            "literal_pair_refs": [pair_ref(x) for x in relevant_pairs],
            "test_control_refs": [control_ref(x) for x in relevant_controls],
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
    unresolved_after = [x for x in rows if x["resolution_status"] == "still_unresolved_after_fourth_pass"]
    by_kind = {}
    for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
        subset = [x for x in rows if x["case_kind"] == kind]
        by_kind[kind] = {
            "fourth_pass_input_count": len(subset),
            "new_candidate_available_count": sum(x["resolution_status"] == "candidate_material_available_for_human_review" for x in subset),
            "still_unresolved_count": sum(x["resolution_status"] == "still_unresolved_after_fourth_pass" for x in subset),
        }

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_fourth_pass_resolution_queue_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fourth_pass_input_count": len(rows),
        "new_candidate_available_count": len(available),
        "still_unresolved_count": len(unresolved_after),
        "families_with_new_candidate_material": len({x["family"] for x in available}),
        "families_still_unresolved": len({x["family"] for x in unresolved_after}),
        "cumulative_candidate_available_count": 45 + len(available),
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

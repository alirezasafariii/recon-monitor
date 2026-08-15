from __future__ import annotations

"""Build a compact worklist for the 18 Fresh Blind V7 items still unresolved.

This is planning metadata only. It does not acquire new evidence, adjudicate semantics,
score the engine, publish evidence, replace sources, or consume First Blind.
"""

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.residual.1"
FOURTH_RESOLUTION = ROOT / "benchmarks/raw/sources/v7_fourth_pass_resolution_queue.json"
THIRD_DEEP = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
THIRD_CAPTURE = ROOT / "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates.json"
FOURTH_CANDIDATES = ROOT / "benchmarks/raw/sources/v7_fourth_pass_targeted_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_residual_unresolved_worklist.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_residual_unresolved_worklist_report.json"


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


def main() -> int:
    freeze = assert_capture_source_freeze()
    resolution = load(FOURTH_RESOLUTION)
    deep = load(THIRD_DEEP)
    capture = load(THIRD_CAPTURE)
    fourth = load(FOURTH_CANDIDATES)
    for doc in (resolution, deep, capture, fourth):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 residual input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 residual worklist requires unconsumed inputs")
    if resolution.get("still_unresolved_count") != 18 or resolution.get("families_still_unresolved") != 14:
        raise RuntimeError("V7 residual unresolved coverage drift")

    unresolved = [
        x for x in resolution.get("items") or []
        if isinstance(x, Mapping) and x.get("resolution_status") == "still_unresolved_after_fourth_pass"
    ]
    if len(unresolved) != 18:
        raise RuntimeError("V7 residual row count drift")
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in unresolved:
        grouped[text(item.get("family"))].append(item)
    if len(grouped) != 14:
        raise RuntimeError("V7 residual family count drift")

    deep_by = {text(x.get("family")): x for x in deep.get("families") or [] if isinstance(x, Mapping)}
    capture_by = {text(x.get("family")): x for x in capture.get("families") or [] if isinstance(x, Mapping)}
    fourth_by = {text(x.get("family")): x for x in fourth.get("families") or [] if isinstance(x, Mapping)}
    families = []
    for family in sorted(grouped):
        items = grouped[family]
        root = text(items[0].get("source_root"))
        project = text(items[0].get("source_project"))
        kinds = sorted({text(x.get("case_kind")) for x in items})
        deep_row = deep_by.get(family, {})
        capture_row = capture_by.get(family, {})
        fourth_row = fourth_by.get(family, {})
        remaining_revision_count = int(fourth_row.get("remaining_revision_candidate_count") or 0)
        prior_two_sided_count = int(capture_row.get("two_sided_literal_pair_count") or 0)
        prior_test_control_count = int(capture_row.get("test_control_candidate_count") or 0)
        fourth_test_control_count = int(fourth_row.get("test_control_candidate_group_count") or 0)

        if any(kind in {"positive", "secure_negative"} for kind in kinds):
            next_route = "manual_non_commit_boundary_or_upstream_release_artifact_review_same_frozen_source"
        else:
            next_route = "manual_same_source_issue_pr_test_example_review_for_independent_near_miss"

        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": kinds,
            "unresolved_item_count": len(items),
            "capture_ids": [x.get("capture_id") for x in items],
            "required_evidence_paths": [x.get("required_evidence_path") for x in items],
            "third_pass_revision_candidate_count": int(deep_row.get("revision_candidate_count") or 0),
            "third_pass_captured_two_sided_pair_count": prior_two_sided_count,
            "third_pass_test_control_candidate_count": prior_test_control_count,
            "fourth_pass_remaining_revision_candidate_count": remaining_revision_count,
            "fourth_pass_test_control_candidate_group_count": fourth_test_control_count,
            "automated_searches_attempted": [
                "identifier_linked_commits_and_prs",
                "version_tag_boundaries",
                "advisory_date_window_commits",
                "release_range_commits",
                "changed_upstream_test_files",
                "lexical_same_project_test_search",
            ],
            "recommended_next_route": next_route,
            "source_replacement_allowed": False,
            "synthetic_fixture_allowed": False,
            "cross_variant_mutation_allowed": False,
            "human_semantic_decision": None,
            "candidate_semantics_adjudicated": False,
            "evidence_published": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_residual_unresolved_worklist_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "unresolved_item_count": len(unresolved),
        "unresolved_family_count": len(families),
        "positive_count": sum(x.get("case_kind") == "positive" for x in unresolved),
        "secure_negative_count": sum(x.get("case_kind") == "secure_negative" for x in unresolved),
        "near_miss_count": sum(x.get("case_kind") == "near_miss" for x in unresolved),
        "cumulative_candidate_available_count": 48,
        "candidate_semantics_adjudicated": False,
        "human_adjudication_performed": False,
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
    document["families"] = families
    document["worklist_sha256"] = sha_json(families)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

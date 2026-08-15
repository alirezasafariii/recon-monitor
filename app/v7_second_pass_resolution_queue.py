from __future__ import annotations

"""Map frozen V7 missing work items to second-pass literal candidates.

This stage is deliberately non-adjudicating. It never changes the original draft status,
never publishes benchmark evidence, and never assigns positive/negative/near-miss semantics
to a candidate. It only determines whether a missing work item now has enough literal
same-source material to be presented to a human reviewer.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.second-pass.resolve.1"
WORKLIST = ROOT / "benchmarks/raw/sources/v7_missing_literal_source_worklist.json"
CAPTURE = ROOT / "benchmarks/raw/sources/v7_second_pass_source_snippet_candidates.json"
PACKETS = ROOT / "benchmarks/raw/sources/v7_semantic_review_packets.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue_report.json"


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def pair_ref(pair: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "parent_sha": pair.get("parent_sha"),
        "fix_sha": pair.get("fix_sha"),
        "basis": pair.get("basis"),
        "pair_candidate_sha256": pair.get("pair_candidate_sha256"),
        "source_code_file_count": int(pair.get("source_code_file_count") or 0),
        "source_code_parent_snippet_count": int(pair.get("source_code_parent_snippet_count") or 0),
        "source_code_fix_snippet_count": int(pair.get("source_code_fix_snippet_count") or 0),
        "test_control_candidate_count": int(pair.get("test_control_candidate_count") or 0),
        "failure": pair.get("failure"),
        "semantic_role": pair.get("semantic_role"),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    work = load(WORKLIST)
    capture = load(CAPTURE)
    packets = load(PACKETS)

    for doc in (work, capture, packets):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 second-pass resolution input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 second-pass resolution requires unconsumed pre-scoring inputs")

    if work.get("work_item_count") != 66 or work.get("families_with_missing_items") != 26:
        raise RuntimeError("V7 missing-source worklist coverage drift")
    if capture.get("family_count") != 26:
        raise RuntimeError("V7 second-pass source capture family coverage drift")
    if capture.get("candidate_semantics_adjudicated") is not False or capture.get("evidence_published") is not False:
        raise RuntimeError("V7 second-pass source candidates unexpectedly adjudicated/published")
    if capture.get("source_replacement_used") is not False or capture.get("synthetic_fixture_used") is not False:
        raise RuntimeError("V7 second-pass source-capture firewall violated")

    packet_by = {
        text(x.get("family")): x
        for x in packets.get("packets") or []
        if isinstance(x, Mapping)
    }
    capture_by = {
        text(x.get("family")): x
        for x in capture.get("families") or []
        if isinstance(x, Mapping)
    }
    if len(packet_by) != 36 or len(capture_by) != 26:
        raise RuntimeError("V7 resolution family map coverage drift")

    rows = []
    for item in work.get("items") or []:
        if not isinstance(item, Mapping):
            continue
        family = text(item.get("family"))
        kind = text(item.get("case_kind"))
        source = capture_by.get(family)
        if source is None:
            raise RuntimeError(f"{family}: missing second-pass source capture")
        if text(source.get("source_root")) != text(item.get("source_root")):
            raise RuntimeError(f"{family}: source_root drift in second-pass resolution")
        if text(source.get("source_project")).casefold() != text(item.get("source_project")).casefold():
            raise RuntimeError(f"{family}: source_project drift in second-pass resolution")

        all_pairs = [
            x for x in (list(source.get("revision_pair_candidates") or []) + list(source.get("version_pair_candidates") or []))
            if isinstance(x, Mapping) and not x.get("failure")
        ]
        two_sided_code = [
            x for x in all_pairs
            if int(x.get("source_code_file_count") or 0) > 0
            and int(x.get("source_code_parent_snippet_count") or 0) > 0
            and int(x.get("source_code_fix_snippet_count") or 0) > 0
        ]
        control_pairs = [
            x for x in all_pairs
            if int(x.get("test_control_candidate_count") or 0) > 0
        ]

        # Availability is intentionally structural only. No candidate is declared to
        # *mean* positive/fixed/near-miss until a human reviews the literal snippets.
        if kind in {"positive", "secure_negative"}:
            relevant = two_sided_code
            required_shape = "two_sided_source_code_before_after_pair"
        elif kind == "near_miss":
            relevant = control_pairs
            required_shape = "upstream_test_control_candidate"
        else:
            relevant = []
            required_shape = "unsupported_missing_kind_requires_manual_source_review"

        status = "candidate_material_available_for_human_review" if relevant else "still_unresolved_after_second_pass"
        packet = packet_by.get(family, {})
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
            "all_two_sided_code_pair_count": len(two_sided_code),
            "all_test_control_pair_count": len(control_pairs),
            "literal_family_adjudication_required": bool(packet.get("literal_family_adjudication_required")),
            "human_semantic_decision": None,
            "human_semantic_notes": None,
            "candidate_semantics_adjudicated": False,
            "source_replacement_used": False,
            "synthetic_fixture_used": False,
            "evidence_published": False,
            "publication_authorized": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    if len(rows) != 66:
        raise RuntimeError(f"V7 resolution queue coverage {len(rows)} != 66")

    available = [x for x in rows if x["resolution_status"] == "candidate_material_available_for_human_review"]
    unresolved = [x for x in rows if x["resolution_status"] == "still_unresolved_after_second_pass"]
    by_kind = {}
    for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
        subset = [x for x in rows if x["case_kind"] == kind]
        by_kind[kind] = {
            "missing_input_count": len(subset),
            "candidate_available_count": sum(x["resolution_status"] == "candidate_material_available_for_human_review" for x in subset),
            "still_unresolved_count": sum(x["resolution_status"] == "still_unresolved_after_second_pass" for x in subset),
        }

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_second_pass_resolution_queue_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "work_item_count": len(rows),
        "candidate_available_count": len(available),
        "still_unresolved_count": len(unresolved),
        "families_with_candidate_material": len({x["family"] for x in available}),
        "families_still_unresolved": len({x["family"] for x in unresolved}),
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

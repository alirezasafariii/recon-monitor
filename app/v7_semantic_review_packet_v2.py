from __future__ import annotations

"""Build the consolidated Fresh Blind V7 semantic review packet for all 144 variants.

This packet combines the 78 original source-grounded drafts with the 66 newly acquired
candidate-material bindings. It is a review surface, not ground truth: no semantic or
family decision is made here, no evidence is published, and no scoring is executed.
"""

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "2.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.semantic-review-packet.2"
OLD_PACKETS = ROOT / "benchmarks/raw/sources/v7_semantic_review_packets.json"
LEDGER = ROOT / "benchmarks/raw/sources/v7_candidate_coverage_ledger.json"
SECOND = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
THIRD = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue.json"
FOURTH = ROOT / "benchmarks/raw/sources/v7_fourth_pass_resolution_queue.json"
SIXTH = ROOT / "benchmarks/raw/sources/v7_sixth_pass_resolution_queue.json"
FINAL = ROOT / "benchmarks/raw/sources/v7_final_residual_control_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2_report.json"

STAGE_ARTIFACTS = {
    "second_pass": {
        "resolution": "benchmarks/raw/sources/v7_second_pass_resolution_queue.json",
        "literal_material": "benchmarks/raw/sources/v7_second_pass_source_snippet_candidates.json",
    },
    "third_pass": {
        "resolution": "benchmarks/raw/sources/v7_third_pass_resolution_queue.json",
        "literal_material": "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates.json",
    },
    "fourth_pass": {
        "resolution": "benchmarks/raw/sources/v7_fourth_pass_resolution_queue.json",
        "literal_material": "benchmarks/raw/sources/v7_fourth_pass_targeted_candidates.json",
    },
    "sixth_pass": {
        "resolution": "benchmarks/raw/sources/v7_sixth_pass_resolution_queue.json",
        "literal_material": "benchmarks/raw/sources/v7_sixth_pass_reference_tree_candidates.json",
    },
    "final_residual_control": {
        "resolution": "benchmarks/raw/sources/v7_final_residual_control_candidates.json",
        "literal_material": "benchmarks/raw/sources/v7_final_residual_control_candidates.json",
    },
}
KINDS = ("positive", "near_miss", "secure_negative", "sparse_noisy")
ALLOWED_VARIANT_DECISIONS = (
    "accept_candidate_as_variant",
    "reject_candidate",
    "needs_additional_source_material",
)
ALLOWED_FAMILY_DECISIONS = (
    "confirm_family_mapping",
    "reject_family_mapping",
    "needs_additional_source_material",
)


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


def item_map(doc: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        text(row.get("capture_id")): row
        for row in doc.get("items") or []
        if isinstance(row, Mapping) and text(row.get("capture_id"))
    }


def final_map(doc: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        text(row.get("capture_id")): row
        for row in doc.get("candidates") or []
        if isinstance(row, Mapping) and text(row.get("capture_id"))
    }


def candidate_binding(stage: str, capture_id: str, sources: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if stage not in STAGE_ARTIFACTS:
        raise RuntimeError(f"{capture_id}: unsupported resolution stage {stage!r}")
    row = sources.get(stage, {}).get(capture_id)
    if not isinstance(row, Mapping):
        raise RuntimeError(f"{capture_id}: missing resolution row for stage {stage}")

    if stage in {"second_pass", "third_pass"}:
        refs = list(row.get("candidate_refs") or [])
    elif stage == "fourth_pass":
        refs = list(row.get("literal_pair_refs") or []) + list(row.get("test_control_refs") or [])
    elif stage == "sixth_pass":
        refs = list(row.get("release_boundary_refs") or []) + list(row.get("tree_test_refs") or [])
    else:
        refs = [{
            "source_commit": row.get("source_commit"),
            "source_file": row.get("source_file"),
            "candidate_role": row.get("candidate_role"),
            "candidate_sha256": row.get("candidate_sha256"),
            "source_snapshot": row.get("source_snapshot"),
            "semantic_role": row.get("semantic_role"),
        }]

    if not refs:
        raise RuntimeError(f"{capture_id}: candidate-ready stage {stage} has no review refs")
    return {
        "material_kind": "acquired_literal_candidate_material",
        "resolution_stage": stage,
        "resolution_artifact": STAGE_ARTIFACTS[stage]["resolution"],
        "literal_material_artifact": STAGE_ARTIFACTS[stage]["literal_material"],
        "candidate_refs": refs,
        "candidate_ref_count": len(refs),
        "semantic_adjudicated": False,
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    old = load(OLD_PACKETS)
    ledger = load(LEDGER)
    second = load(SECOND)
    third = load(THIRD)
    fourth = load(FOURTH)
    sixth = load(SIXTH)
    final = load(FINAL)

    for doc in (old, ledger, second, third, fourth, sixth, final):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 semantic review packet v2 input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 semantic review packet v2 requires unconsumed inputs")
    if old.get("family_count") != 36 or old.get("variant_count") != 144 or old.get("packet_count") != 36:
        raise RuntimeError("V7 original semantic review packet coverage drift")
    if ledger.get("candidate_material_coverage_count") != 66 or ledger.get("unresolved_candidate_material_count") != 0:
        raise RuntimeError("V7 candidate material ledger is not complete")
    if ledger.get("candidate_semantics_adjudicated") is not False or ledger.get("human_review_complete") is not False:
        raise RuntimeError("V7 candidate ledger unexpectedly claims semantic/human completion")

    ledger_by = {
        text(row.get("capture_id")): row
        for row in ledger.get("items") or []
        if isinstance(row, Mapping) and text(row.get("capture_id"))
    }
    if len(ledger_by) != 66:
        raise RuntimeError("V7 candidate ledger capture ID coverage drift")
    sources = {
        "second_pass": item_map(second),
        "third_pass": item_map(third),
        "fourth_pass": item_map(fourth),
        "sixth_pass": item_map(sixth),
        "final_residual_control": final_map(final),
    }

    packets = []
    seen_ids = set()
    original_draft_count = 0
    acquired_candidate_count = 0
    family_adjudication_required_count = 0
    variant_prior_status_counts: Counter[str] = Counter()

    for packet in old.get("packets") or []:
        if not isinstance(packet, Mapping):
            continue
        family = text(packet.get("family"))
        variants = []
        if packet.get("literal_family_adjudication_required") is True:
            family_adjudication_required_count += 1
        for variant in packet.get("variants") or []:
            if not isinstance(variant, Mapping):
                continue
            capture_id = text(variant.get("capture_id"))
            if not capture_id or capture_id in seen_ids:
                raise RuntimeError(f"duplicate/empty V7 packet capture id: {capture_id!r}")
            seen_ids.add(capture_id)
            kind = text(variant.get("case_kind"))
            if kind not in KINDS:
                raise RuntimeError(f"{capture_id}: unexpected case kind {kind!r}")
            variant_prior_status_counts[text(variant.get("status"))] += 1

            if variant.get("draft_path"):
                original_draft_count += 1
                review_material = {
                    "material_kind": "original_source_grounded_draft",
                    "draft_path": variant.get("draft_path"),
                    "draft_sha256": variant.get("draft_sha256"),
                    "capture_reference": variant.get("capture_reference"),
                    "snapshot_role": variant.get("snapshot_role"),
                    "observation_kind": variant.get("observation_kind"),
                    "semantic_adjudicated": False,
                }
            else:
                ledger_row = ledger_by.get(capture_id)
                if not isinstance(ledger_row, Mapping):
                    raise RuntimeError(f"{capture_id}: missing candidate ledger row")
                stage = text(ledger_row.get("resolution_stage"))
                review_material = candidate_binding(stage, capture_id, sources)
                acquired_candidate_count += 1

            variants.append({
                "capture_id": capture_id,
                "case_kind": kind,
                "required_evidence_path": variant.get("required_evidence_path"),
                "variant_purpose": variant.get("variant_purpose"),
                "prior_packet_status": variant.get("status"),
                "prior_block_reason": variant.get("block_reason"),
                "review_material": review_material,
                "review_status": "awaiting_human_semantic_review",
                "allowed_human_decisions": list(ALLOWED_VARIANT_DECISIONS),
                "human_semantic_decision": None,
                "human_semantic_notes": None,
                "reviewer_id": None,
                "reviewed_at": None,
                "semantic_adjudicated": False,
                "human_verified": False,
                "publication_authorized": False,
                "evidence_published": False,
                "scoring_executed": False,
                "first_blind_consumed": False,
            })

        if len(variants) != 4 or {x["case_kind"] for x in variants} != set(KINDS):
            raise RuntimeError(f"{family}: consolidated packet does not contain exactly four variant kinds")
        packets.append({
            "family": family,
            "source_root": packet.get("source_root"),
            "source_project": packet.get("source_project"),
            "literal_family_adjudication_required": bool(packet.get("literal_family_adjudication_required")),
            "condition_signals_vocabulary": list(packet.get("condition_signals_vocabulary") or []),
            "blocking_controls_vocabulary": list(packet.get("blocking_controls_vocabulary") or []),
            "override_signals_vocabulary": list(packet.get("override_signals_vocabulary") or []),
            "schema_role": packet.get("schema_role"),
            "review_instruction": (
                "Review only frozen public-source material. Do not use Analysis/engine output as evidence. "
                "For positive, confirm the decisive condition is literally present; for secure_negative, confirm "
                "the blocking/fixed condition is literally present; for near_miss, confirm the observation is "
                "independent/similar yet does not satisfy the decisive promotion condition; for sparse_noisy, "
                "confirm the partial observation is insufficient for positive admission. Reject rather than infer."
            ),
            "family_review_status": "awaiting_human_family_adjudication" if packet.get("literal_family_adjudication_required") is True else "family_mapping_preexisting_pending_variant_review",
            "allowed_family_decisions": list(ALLOWED_FAMILY_DECISIONS),
            "family_adjudication_decision": None,
            "family_adjudication_notes": None,
            "family_reviewer_id": None,
            "family_reviewed_at": None,
            "human_verified": False,
            "variants": variants,
        })

    if len(packets) != 36 or len(seen_ids) != 144:
        raise RuntimeError(f"V7 consolidated packet coverage families={len(packets)} variants={len(seen_ids)}")
    if original_draft_count != 78 or acquired_candidate_count != 66:
        raise RuntimeError(
            f"V7 consolidated material partition drift drafts={original_draft_count} acquired={acquired_candidate_count}"
        )
    case_counts = Counter(v["case_kind"] for p in packets for v in p["variants"])
    if dict(case_counts) != {"positive": 36, "near_miss": 36, "secure_negative": 36, "sparse_noisy": 36}:
        raise RuntimeError(f"V7 consolidated case-kind coverage drift: {dict(case_counts)}")

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_consolidated_semantic_review_packet_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": 36,
        "variant_count": 144,
        "original_source_grounded_draft_count": original_draft_count,
        "acquired_candidate_material_count": acquired_candidate_count,
        "review_material_available_count": original_draft_count + acquired_candidate_count,
        "review_material_missing_count": 0,
        "by_case_kind": dict(sorted(case_counts.items())),
        "prior_packet_status_counts": dict(sorted(variant_prior_status_counts.items())),
        "family_adjudication_required_count": family_adjudication_required_count,
        "all_variants_awaiting_human_review": True,
        "candidate_semantics_adjudicated": False,
        "semantic_adjudication_complete": False,
        "human_adjudication_performed": False,
        "human_review_complete": False,
        "human_verified_record_count": 0,
        "evidence_published": False,
        "publication_authorized": False,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "synthetic_fixture_allowed": False,
        "cross_variant_mutation_allowed": False,
        "engine_output_allowed_as_evidence": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "candidate_coverage_ledger_sha256": ledger.get("ledger_sha256"),
    }
    document = dict(report)
    document["packets"] = packets
    document["packet_set_sha256"] = sha_json(packets)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""Build reviewer-isolated packets for Fresh Blind V7 human semantic review.

This module operationalizes the already-frozen human review contract. It does not
make semantic decisions, does not fill reviewer identities, does not expose engine
predictions, does not publish benchmark evidence, and does not score/consume First Blind.

Each reviewer receives only their own primary assignments plus a separately marked
locked tie-break queue. Other reviewers' votes/identities are never copied into a packet.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.reviewer-packets.1"
TEMPLATE = ROOT / "benchmarks/raw/sources/v7_human_review_template.json"
SEMANTIC_PACKET = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2.json"
OUTPUT_DIR = ROOT / "benchmarks/raw/sources/v7_human_reviewer_packets"
REPORT = ROOT / "benchmarks/raw/sources/v7_human_reviewer_packets_report.json"
SLOTS = ("reviewer_a", "reviewer_b", "reviewer_c")
VARIANT_DECISIONS = (
    "accept_candidate_as_variant",
    "reject_candidate",
    "needs_additional_source_material",
)
FAMILY_DECISIONS = (
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


def blank_decision() -> dict[str, Any]:
    return {
        "reviewer_id": None,
        "reviewed_at": None,
        "decision": None,
        "notes": None,
        "source_material_checked": False,
        "engine_output_used": False,
    }


def variant_material(variant: Mapping[str, Any]) -> dict[str, Any]:
    material = variant.get("review_material")
    if not isinstance(material, Mapping):
        raise RuntimeError(f"{variant.get('capture_id')}: review_material missing")
    return {
        "capture_id": variant.get("capture_id"),
        "case_kind": variant.get("case_kind"),
        "required_evidence_path": variant.get("required_evidence_path"),
        "review_material": material,
        "allowed_decisions": list(VARIANT_DECISIONS),
        "review_decision": blank_decision(),
    }


def family_record(assignment: Mapping[str, Any], semantic_by_family: Mapping[str, Mapping[str, Any]], *, mode: str) -> dict[str, Any]:
    family = text(assignment.get("family"))
    semantic = semantic_by_family.get(family)
    if semantic is None:
        raise RuntimeError(f"{family}: semantic packet missing")
    variants = [variant_material(v) for v in semantic.get("variants") or [] if isinstance(v, Mapping)]
    if len(variants) != 4:
        raise RuntimeError(f"{family}: reviewer packet variant count {len(variants)} != 4")
    family_review = None
    if bool(assignment.get("literal_family_adjudication_required")):
        family_review = {
            "required": True,
            "allowed_decisions": list(FAMILY_DECISIONS),
            "review_decision": blank_decision(),
        }
    return {
        "family": family,
        "source_root": assignment.get("source_root"),
        "source_project": assignment.get("source_project"),
        "assignment_mode": mode,
        "literal_family_adjudication_required": bool(assignment.get("literal_family_adjudication_required")),
        "family_review": family_review,
        "variants": variants,
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    template = load(TEMPLATE)
    semantic = load(SEMANTIC_PACKET)
    for doc, name in ((template, "human_template"), (semantic, "semantic_packet")):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError(f"V7 reviewer packet {name} source assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError(f"V7 reviewer packet requires unconsumed {name}")
    if template.get("human_review_started") is not False or template.get("human_review_complete") is not False:
        raise RuntimeError("V7 reviewer packets must be built before review starts")
    if template.get("human_verified_record_count") != 0:
        raise RuntimeError("V7 reviewer packet template unexpectedly contains verified records")
    if semantic.get("review_material_available_count") != 144 or semantic.get("review_material_missing_count") != 0:
        raise RuntimeError("V7 reviewer packets require 144/144 review material")
    if semantic.get("engine_output_allowed_as_evidence") is not False:
        raise RuntimeError("V7 semantic packet unexpectedly allows engine output")

    semantic_by_family = {
        text(x.get("family")): x
        for x in semantic.get("packets") or []
        if isinstance(x, Mapping)
    }
    assignments = [x for x in template.get("assignments") or [] if isinstance(x, Mapping)]
    if len(semantic_by_family) != 36 or len(assignments) != 36:
        raise RuntimeError("V7 reviewer packet family coverage drift")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    reports: dict[str, Any] = {}
    packet_hashes: dict[str, str] = {}
    for slot in SLOTS:
        primary = []
        tie_break = []
        for assignment in assignments:
            primary_slots = [text(x) for x in assignment.get("primary_reviewer_slots") or []]
            tie_slot = text(assignment.get("tie_breaker_slot"))
            if slot in primary_slots:
                primary.append(family_record(assignment, semantic_by_family, mode="primary"))
            if slot == tie_slot:
                tie_break.append(family_record(assignment, semantic_by_family, mode="tie_break_locked"))

        primary_variant_count = sum(len(x["variants"]) for x in primary)
        tie_variant_count = sum(len(x["variants"]) for x in tie_break)
        if len(primary) != 24 or primary_variant_count != 96:
            raise RuntimeError(f"{slot}: primary assignment imbalance")
        if len(tie_break) != 12 or tie_variant_count != 48:
            raise RuntimeError(f"{slot}: tie-break assignment imbalance")

        packet = {
            "version": VERSION,
            "rule_version": RULE_VERSION,
            "evaluation_kind": "fresh_blind_v7_independent_human_reviewer_packet_unscored",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reviewer_slot": slot,
            "reviewer_identity": {
                "actual_reviewer_id": None,
                "reviewer_display_name": None,
                "reviewer_attestation": None,
                "attested_at": None,
            },
            "instructions": {
                "engine_output_allowed_as_evidence": False,
                "other_reviewer_votes_visible": False,
                "primary_assignments_must_be_reviewed_independently": True,
                "tie_break_assignments_locked_until_primary_disagreement": True,
                "source_material_must_be_checked": True,
            },
            "primary_family_count": len(primary),
            "primary_variant_count": primary_variant_count,
            "primary_assignments": primary,
            "tie_break_family_count": len(tie_break),
            "tie_break_variant_count": tie_variant_count,
            "tie_break_assignments": tie_break,
            "human_review_started": False,
            "human_review_complete": False,
            "human_verified_record_count": 0,
            "candidate_semantics_adjudicated": False,
            "evidence_published": False,
            "publication_authorized": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
            "engine_baseline_commit": freeze["engine_baseline_commit"],
            "source_assignment_commit": freeze["source_assignment_commit"],
            "human_review_template_sha256": template.get("template_sha256"),
            "semantic_review_packet_sha256": semantic.get("packet_set_sha256"),
        }
        packet["packet_sha256"] = sha_json({k: v for k, v in packet.items() if k != "packet_sha256"})
        path = OUTPUT_DIR / f"{slot}.json"
        path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
        packet_hashes[slot] = packet["packet_sha256"]
        reports[slot] = {
            "primary_family_count": len(primary),
            "primary_variant_count": primary_variant_count,
            "tie_break_family_count": len(tie_break),
            "tie_break_variant_count": tie_variant_count,
            "primary_family_adjudication_count": sum(bool(x["literal_family_adjudication_required"]) for x in primary),
            "tie_break_family_adjudication_count": sum(bool(x["literal_family_adjudication_required"]) for x in tie_break),
            "packet_sha256": packet["packet_sha256"],
        }

    # Across primary packets every family/variant must appear exactly twice.
    primary_family_occurrences: dict[str, int] = {}
    primary_capture_occurrences: dict[str, int] = {}
    for slot in SLOTS:
        packet = load(OUTPUT_DIR / f"{slot}.json")
        for family in packet["primary_assignments"]:
            name = text(family.get("family"))
            primary_family_occurrences[name] = primary_family_occurrences.get(name, 0) + 1
            for variant in family.get("variants") or []:
                capture_id = text(variant.get("capture_id"))
                primary_capture_occurrences[capture_id] = primary_capture_occurrences.get(capture_id, 0) + 1
    if len(primary_family_occurrences) != 36 or set(primary_family_occurrences.values()) != {2}:
        raise RuntimeError("V7 reviewer primary family independence coverage drift")
    if len(primary_capture_occurrences) != 144 or set(primary_capture_occurrences.values()) != {2}:
        raise RuntimeError("V7 reviewer primary variant independence coverage drift")

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_independent_human_reviewer_packet_report_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reviewer_packet_count": 3,
        "family_count": 36,
        "variant_count": 144,
        "primary_reviews_per_family": 2,
        "primary_reviews_per_variant": 2,
        "reviewer_packets": reports,
        "packet_hashes": packet_hashes,
        "engine_output_allowed_as_evidence": False,
        "other_reviewer_votes_visible": False,
        "human_adjudication_performed": False,
        "human_review_complete": False,
        "human_verified_record_count": 0,
        "evidence_published": False,
        "publication_authorized": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

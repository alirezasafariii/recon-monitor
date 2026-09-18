from __future__ import annotations

"""Build human/source review drafts from captured Real-World Corpus V1 evidence.

This stage creates *pending review records*, never verified replay records. It
binds every draft to an exact public-source evidence snapshot while leaving
``family``, ``label``, reviewer metadata and all evidence-quality dimensions
unset. Nothing here may set ``human_verified=true``.

The queue contains three actually captured evidence classes per source:

- positive candidate boundary: exact vulnerable-parent revision where available,
  otherwise the advisory's vulnerable-version boundary;
- secure-negative candidate boundary: exact fix revision where available,
  otherwise candidate fix revision or patched-version boundary;
- sparse/noisy: exact public advisory snapshot.

Near-miss controls are intentionally excluded until their independent control
observation is actually captured.
"""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_reasoning import FAMILY_ORDER
from real_world_corpus_v1_targeted import canonical_family_cwes

REVIEW_QUEUE_VERSION = "1.0.0"
REVIEW_QUEUE_RULE_VERSION = "2026.08.14.11"
EXPECTED_SOURCE_COUNT = 100
EXPECTED_REVIEW_DRAFTS = 300
REVIEW_VARIANTS = ("positive", "secure_negative", "sparse_noisy")
QUALITY_DIMENSIONS = (
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


def _canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _reverse_cwes() -> dict[str, list[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for family, cwes in canonical_family_cwes().items():
        for cwe in cwes:
            result[_text(cwe).upper()].add(str(family))
    return {cwe: sorted(values) for cwe, values in result.items()}


def _family_candidates(source_pack: Mapping[str, Any]) -> list[str]:
    target = _text(source_pack.get("family_target"))
    if target in set(str(item) for item in FAMILY_ORDER):
        return [target]
    reverse = _reverse_cwes()
    advisory = source_pack.get("advisory_snapshot") if isinstance(source_pack.get("advisory_snapshot"), Mapping) else {}
    candidates: set[str] = set()
    for item in advisory.get("cwes", []) or []:
        if not isinstance(item, Mapping):
            continue
        candidates.update(reverse.get(_text(item.get("cwe_id")).upper(), []))
    return sorted(candidates)


def _version_boundary(source_pack: Mapping[str, Any], *, patched: bool) -> dict[str, Any]:
    advisory = source_pack.get("advisory_snapshot") if isinstance(source_pack.get("advisory_snapshot"), Mapping) else {}
    rows: list[dict[str, Any]] = []
    for item in advisory.get("vulnerabilities", []) or []:
        if not isinstance(item, Mapping):
            continue
        row = {
            "ecosystem": _text(item.get("ecosystem")),
            "package": _text(item.get("package")),
            "vulnerable_version_range": _text(item.get("vulnerable_version_range")),
            "first_patched_version": _text(item.get("first_patched_version")),
        }
        if patched and row["first_patched_version"]:
            rows.append(row)
        elif not patched and row["vulnerable_version_range"]:
            rows.append(row)
    return {
        "kind": "patched_version_boundary" if patched else "vulnerable_version_boundary",
        "boundaries": sorted(rows, key=lambda row: (row["ecosystem"], row["package"], row["vulnerable_version_range"], row["first_patched_version"])),
        "advisory_snapshot_sha256": _text(source_pack.get("advisory_snapshot_sha256")),
    }


def _exact_pair_map(revision_pairs: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        _text(row.get("source_root")).upper(): dict(row)
        for row in revision_pairs
        if _text(row.get("source_root"))
    }


def _positive_binding(source_pack: Mapping[str, Any], pair: Mapping[str, Any] | None) -> dict[str, Any]:
    if pair:
        payload = {
            "kind": "exact_parent_revision_boundary",
            "revision_pair_sha256": _text(pair.get("revision_pair_sha256")),
            "parent_commit_sha": _text(pair.get("candidate_vulnerable_parent_sha")),
            "parent_tree_sha": _text(pair.get("parent_tree_sha")),
            "changed_file_pairs": [
                {
                    "filename": item.get("filename"),
                    "parent_blob_sha": item.get("parent_blob_sha"),
                    "parent_present": item.get("parent_present"),
                    "file_pair_sha256": item.get("file_pair_sha256"),
                }
                for item in pair.get("file_pairs", []) or []
                if isinstance(item, Mapping)
            ],
            "boundary_semantics_human_confirmed": False,
        }
        payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
        return payload
    payload = _version_boundary(source_pack, patched=False)
    payload["boundary_semantics_human_confirmed"] = False
    payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
    return payload


def _negative_binding(source_pack: Mapping[str, Any], pair: Mapping[str, Any] | None) -> dict[str, Any]:
    if pair:
        payload = {
            "kind": "exact_fix_revision_boundary",
            "revision_pair_sha256": _text(pair.get("revision_pair_sha256")),
            "fix_commit_sha": _text(pair.get("candidate_fix_commit_sha")),
            "fix_tree_sha": _text(pair.get("fix_tree_sha")),
            "changed_file_pairs": [
                {
                    "filename": item.get("filename"),
                    "fix_blob_sha": item.get("fix_blob_sha"),
                    "fix_present": item.get("fix_present"),
                    "file_pair_sha256": item.get("file_pair_sha256"),
                }
                for item in pair.get("file_pairs", []) or []
                if isinstance(item, Mapping)
            ],
            "boundary_semantics_human_confirmed": False,
        }
        payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
        return payload
    fix_sha = _text(source_pack.get("candidate_fix_commit_sha"))
    if fix_sha:
        payload = {
            "kind": "candidate_fix_revision_boundary",
            "fix_commit_sha": fix_sha,
            "candidate_fix_patch_set_sha256": _text(source_pack.get("candidate_fix_patch_set_sha256")),
            "advisory_snapshot_sha256": _text(source_pack.get("advisory_snapshot_sha256")),
            "boundary_semantics_human_confirmed": False,
        }
        payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
        return payload
    payload = _version_boundary(source_pack, patched=True)
    payload["boundary_semantics_human_confirmed"] = False
    payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
    return payload


def _sparse_binding(source_pack: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "kind": "literal_public_advisory_snapshot",
        "advisory_snapshot_sha256": _text(source_pack.get("advisory_snapshot_sha256")),
        "source_pack_sha256": _text(source_pack.get("source_pack_sha256")),
        "boundary_semantics_human_confirmed": False,
    }
    payload["evidence_snapshot_sha256"] = _canonical_hash(payload)
    return payload


def _review_template() -> dict[str, Any]:
    return {
        "family": None,
        "label": None,
        "label_source": None,
        "reviewer_id": None,
        "reviewed_at": None,
        "human_verified": False,
        "evidence_quality": {dimension: None for dimension in QUALITY_DIMENSIONS},
        "review_status": "pending_human_source_adjudication",
    }


def draft_for(
    source_pack: Mapping[str, Any],
    variant: str,
    pair: Mapping[str, Any] | None,
) -> dict[str, Any]:
    root = _text(source_pack.get("source_root")).upper()
    project = _text(source_pack.get("source_project")).lower()
    if variant == "positive":
        binding = _positive_binding(source_pack, pair)
        proposed_outcome = "positive_candidate_requires_human_boundary_review"
    elif variant == "secure_negative":
        binding = _negative_binding(source_pack, pair)
        proposed_outcome = "secure_negative_candidate_requires_human_boundary_review"
    elif variant == "sparse_noisy":
        binding = _sparse_binding(source_pack)
        proposed_outcome = "sparse_noisy_source_observation_requires_human_review"
    else:
        raise ValueError(f"unsupported_review_variant:{variant}")

    snapshot = _text(binding.get("evidence_snapshot_sha256"))
    candidates = _family_candidates(source_pack)
    return {
        "draft_id": f"rwv1-review:{root}:{variant}",
        "case_origin_id": f"rwv1:{root}",
        "source_corpus_id": "real-world-corpus-v1",
        "evaluation_role": "fresh_candidate",
        "source_root": root,
        "source_project": project,
        "variant": variant,
        "family_target": source_pack.get("family_target"),
        "target_cwe": source_pack.get("target_cwe"),
        "family_candidates": candidates,
        "family_candidates_are_final": False,
        "proposed_outcome": proposed_outcome,
        "proposed_outcome_is_label": False,
        "evidence_snapshot_id": f"sha256:{snapshot}",
        "evidence_binding": binding,
        "proposed_provenance": "curated_real_world_replay",
        "review": _review_template(),
        "decision_readiness_score": None,
        "bug_proximity_score": None,
        "target_evidence_confidence": None,
        "signals": [],
        "contradictions": [],
        "scoring_executed": False,
        "target_contact_performed": False,
        "verified_replay_eligible": False,
    }


def build_review_queue(
    source_packs: Iterable[Mapping[str, Any]],
    revision_pairs: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    packs = [dict(row) for row in source_packs]
    if len(packs) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"source_pack_count:{len(packs)}!=100")
    pair_map = _exact_pair_map(revision_pairs)
    drafts: list[dict[str, Any]] = []
    binding_kinds: Counter[str] = Counter()
    family_candidate_counts: Counter[str] = Counter()

    for pack in sorted(packs, key=lambda row: (_text(row.get("source_root")), _text(row.get("source_project")))):
        root = _text(pack.get("source_root")).upper()
        pair = pair_map.get(root)
        for variant in REVIEW_VARIANTS:
            draft = draft_for(pack, variant, pair)
            drafts.append(draft)
            binding_kinds[_text(draft["evidence_binding"].get("kind"))] += 1
            for family in draft["family_candidates"]:
                family_candidate_counts[family] += 1

    origins: dict[str, set[str]] = defaultdict(set)
    snapshot_ids: set[str] = set()
    errors: list[str] = []
    for row in drafts:
        origins[_text(row.get("case_origin_id"))].add(_text(row.get("variant")))
        snapshot = _text(row.get("evidence_snapshot_id"))
        if not snapshot:
            errors.append(f"missing_snapshot:{row.get('draft_id')}")
        snapshot_ids.add(snapshot)
        review = row.get("review") if isinstance(row.get("review"), Mapping) else {}
        if review.get("family") is not None or review.get("label") is not None:
            errors.append(f"pre_review_family_or_label_present:{row.get('draft_id')}")
        if bool(review.get("human_verified")):
            errors.append(f"pre_review_human_verified:{row.get('draft_id')}")
        if bool(row.get("verified_replay_eligible")):
            errors.append(f"pre_review_marked_eligible:{row.get('draft_id')}")
        if bool(row.get("scoring_executed")) or bool(row.get("target_contact_performed")):
            errors.append(f"forbidden_action_flag:{row.get('draft_id')}")

    if len(drafts) != EXPECTED_REVIEW_DRAFTS:
        errors.append(f"draft_count:{len(drafts)}!=300")
    if len(origins) != EXPECTED_SOURCE_COUNT:
        errors.append(f"origin_count:{len(origins)}!=100")
    if any(variants != set(REVIEW_VARIANTS) for variants in origins.values()):
        errors.append("every_origin_must_have_positive_secure_negative_sparse_noisy")
    if len(snapshot_ids) != EXPECTED_REVIEW_DRAFTS:
        errors.append(f"evidence_snapshot_uniqueness:{len(snapshot_ids)}!=300")

    canonical = json.dumps(drafts, sort_keys=True, separators=(",", ":")).encode("utf-8")
    result = {
        "version": REVIEW_QUEUE_VERSION,
        "rule_version": REVIEW_QUEUE_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_pending_human_review_queue",
        "status": "pending_human_review_queue_ready" if not errors else "review_queue_invalid",
        "draft_count": len(drafts),
        "source_origin_count": len(origins),
        "unique_evidence_snapshot_count": len(snapshot_ids),
        "variant_counts": dict(sorted(Counter(_text(row.get("variant")) for row in drafts).items())),
        "evidence_binding_kind_counts": dict(sorted(binding_kinds.items())),
        "family_candidate_counts": dict(sorted(family_candidate_counts.items())),
        "human_verified_record_count": 0,
        "verified_replay_eligible_count": 0,
        "near_miss_review_draft_count": 0,
        "queue_sha256": hashlib.sha256(canonical).hexdigest(),
        "errors": errors,
        "passed": not errors,
        "human_labels_created": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "drafts": drafts,
        "next_transition": "human_source_boundary_review_plus_independent_near_miss_capture",
    }
    return result


def _load(path: Path, key: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"missing_list:{key}:{path}")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Corpus V1 pending human review queue")
    parser.add_argument("--public-evidence", default="benchmarks/real_world/v1/public_source_evidence.json")
    parser.add_argument("--revision-evidence", default="benchmarks/real_world/v1/revision_pair_evidence.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/human_review_queue.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/human_review_queue_report.json")
    args = parser.parse_args(argv)

    result = build_review_queue(
        _load(Path(args.public_evidence), "source_packs"),
        _load(Path(args.revision_evidence), "revision_pairs"),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "drafts"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": result["passed"],
        "drafts": result["draft_count"],
        "origins": result["source_origin_count"],
        "snapshots": result["unique_evidence_snapshot_count"],
        "binding_kinds": result["evidence_binding_kind_counts"],
        "human_verified": result["human_verified_record_count"],
    }, sort_keys=True))
    if not result["passed"]:
        raise SystemExit("review_queue_gate_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

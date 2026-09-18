from __future__ import annotations

"""Source-attested evaluation for Real-World Corpus V1.

This module removes the requirement for a security-skilled human reviewer from
*label construction* while preserving an explicit scientific boundary:

- labels come only from reviewed public advisories plus exact parent/fix
  revision pairs and an unambiguous canonical CWE-to-family hint;
- ambiguous or incomplete cases are excluded instead of guessed;
- labels never create target evidence;
- labels are never marked human verified and are never activation eligible;
- Analysis scores must come from a separate current-engine replay artifact.
  This module never fabricates scores from the expected family or label.

The result is useful for automatic regression/evaluation, but it is not a
replacement for an independently human-adjudicated production-accuracy study.
"""

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from calibration_engine import confusion_metrics
from family_reasoning import FAMILY_ORDER
from real_world_corpus_v1_family_match import resolve_source_family

SOURCE_ATTESTED_VERSION = "1.0.0"
SOURCE_ATTESTED_RULE_VERSION = "2026.09.18.1"
DEFAULT_THRESHOLD = 70
DEFAULT_HOLDOUT_PERCENT = 20
SOURCE_ATTESTED_PROVENANCE = "source_attested_replay"

CANONICAL_FAMILIES = frozenset(str(value) for value in FAMILY_ORDER)
_SCORE_FIELDS = (
    "decision_readiness_score",
    "bug_proximity_score",
    "target_evidence_confidence",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _blind_case_id(source_project: str, revision_sha: str) -> str:
    material = f"{_text(source_project).lower()}|{_text(revision_sha).lower()}"
    return "SA-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _score(value: Any) -> int | None:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return None
    if number < 0 or number > 100:
        return None
    return number


def _source_index(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in payload.get("sources", []) or []:
        if not isinstance(raw, Mapping):
            continue
        root = _text(raw.get("source_root")).upper()
        if root:
            result[root] = dict(raw)
    return result


def _source_pack_index(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in payload.get("source_packs", []) or []:
        if not isinstance(raw, Mapping):
            continue
        root = _text(raw.get("source_root")).upper()
        if root:
            result[root] = dict(raw)
    return result


def _pair_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(raw)
        for raw in payload.get("revision_pairs", []) or []
        if isinstance(raw, Mapping)
    ]


def _advisory_fix_reference_present(
    advisory: Mapping[str, Any],
    project: str,
    fix_sha: str,
) -> bool:
    project = _text(project).lower()
    fix_sha = _text(fix_sha).lower()
    if not project or not fix_sha:
        return False
    needle = f"github.com/{project}/commit/{fix_sha}"
    return any(
        needle in _text(value).lower()
        for value in advisory.get("references", []) or []
    )


def _patched_version_present(advisory: Mapping[str, Any]) -> bool:
    for raw in advisory.get("vulnerabilities", []) or []:
        if isinstance(raw, Mapping) and _text(raw.get("first_patched_version")):
            return True
    return False


def _attestation_check(
    feasibility: Mapping[str, Any],
    source_pack: Mapping[str, Any],
    pair: Mapping[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []

    source_root = _text(pair.get("source_root")).upper()
    source_project = _text(pair.get("source_project")).lower()
    if not source_root:
        reasons.append("missing_source_root")
    if not source_project:
        reasons.append("missing_source_project")

    if _text(feasibility.get("source_root")).upper() != source_root:
        reasons.append("feasibility_source_root_mismatch")
    if _text(source_pack.get("source_root")).upper() != source_root:
        reasons.append("source_pack_root_mismatch")
    if _text(feasibility.get("source_project")).lower() != source_project:
        reasons.append("feasibility_source_project_mismatch")
    if _text(source_pack.get("source_project")).lower() != source_project:
        reasons.append("source_pack_project_mismatch")

    if _text(feasibility.get("source_kind")) != "github_reviewed_advisory":
        reasons.append("not_github_reviewed_advisory")
    if _text(feasibility.get("advisory_fetch_status")) != "retrieved":
        reasons.append("advisory_not_retrieved")
    if _text(feasibility.get("evaluation_role")) != "fresh_candidate":
        reasons.append("not_fresh_candidate")
    if _text(feasibility.get("capture_feasibility")) != "strong_revision_boundary":
        reasons.append("not_strong_revision_boundary")

    advisory = source_pack.get("advisory_snapshot")
    advisory = advisory if isinstance(advisory, Mapping) else {}
    family_resolution = resolve_source_family(feasibility, advisory)
    family = _text(family_resolution.get("family"))
    if not family_resolution.get("resolved"):
        reasons.extend(
            str(value)
            for value in family_resolution.get("reasons", []) or []
            if str(value) not in reasons
        )
    if family and family not in CANONICAL_FAMILIES:
        reasons.append("resolved_family_not_canonical")

    if _text(advisory.get("ghsa_id")).upper() != source_root:
        reasons.append("advisory_root_mismatch")
    if advisory.get("withdrawn_at"):
        reasons.append("advisory_withdrawn")
    if not _text(advisory.get("published_at")):
        reasons.append("advisory_missing_publication_time")
    if not _text(advisory.get("repository_advisory_url")):
        reasons.append("missing_repository_advisory_url")
    if not _patched_version_present(advisory):
        reasons.append("missing_patched_version_boundary")

    advisory_cwes = {
        _text(item.get("cwe_id")).upper()
        for item in advisory.get("cwes", []) or []
        if isinstance(item, Mapping) and _text(item.get("cwe_id"))
    }
    feasibility_cwes = {
        _text(value).upper()
        for value in feasibility.get("advisory_cwes", []) or []
        if _text(value)
    }
    if not advisory_cwes:
        reasons.append("missing_advisory_cwe")
    if feasibility_cwes and advisory_cwes != feasibility_cwes:
        reasons.append("advisory_cwe_snapshot_mismatch")

    if pair.get("revision_pair_complete") is not True:
        reasons.append("revision_pair_incomplete")
    if int(pair.get("incomplete_file_count") or 0) != 0:
        reasons.append("revision_pair_has_incomplete_files")
    if bool(pair.get("parent_tree_truncated")) or bool(pair.get("fix_tree_truncated")):
        reasons.append("revision_tree_truncated")
    if int(pair.get("changed_file_count") or 0) <= 0:
        reasons.append("no_changed_files")

    parent_sha = _text(pair.get("candidate_vulnerable_parent_sha")).lower()
    fix_sha = _text(pair.get("candidate_fix_commit_sha")).lower()
    if not parent_sha:
        reasons.append("missing_parent_revision")
    if not fix_sha:
        reasons.append("missing_fix_revision")
    if parent_sha and fix_sha and parent_sha == fix_sha:
        reasons.append("parent_equals_fix")
    if not _text(pair.get("parent_tree_sha")):
        reasons.append("missing_parent_tree")
    if not _text(pair.get("fix_tree_sha")):
        reasons.append("missing_fix_tree")
    if not _text(pair.get("revision_pair_sha256")):
        reasons.append("missing_revision_pair_hash")

    file_pairs = [
        raw
        for raw in pair.get("file_pairs", []) or []
        if isinstance(raw, Mapping)
    ]
    if len(file_pairs) != int(pair.get("changed_file_count") or 0):
        reasons.append("changed_file_count_mismatch")
    if any(raw.get("pair_complete") is not True for raw in file_pairs):
        reasons.append("file_pair_incomplete")
    if any(not _text(raw.get("patch_sha256")) for raw in file_pairs):
        reasons.append("missing_patch_hash")

    if _text(source_pack.get("candidate_fix_commit_sha")).lower() != fix_sha:
        reasons.append("source_pack_fix_mismatch")
    if _text(source_pack.get("candidate_vulnerable_parent_sha")).lower() != parent_sha:
        reasons.append("source_pack_parent_mismatch")
    if not _text(source_pack.get("candidate_fix_patch_set_sha256")):
        reasons.append("missing_patch_set_hash")
    if not _advisory_fix_reference_present(advisory, source_project, fix_sha):
        reasons.append("fix_commit_not_directly_referenced_by_advisory")

    return {
        "eligible": not reasons,
        "reasons": reasons,
        "family": family,
        "source_root": source_root,
        "source_project": source_project,
        "parent_sha": parent_sha,
        "fix_sha": fix_sha,
        "advisory_cwes": sorted(advisory_cwes),
        "family_resolution_basis": _text(family_resolution.get("basis")),
        "family_resolution_semantic_matches": list(
            family_resolution.get("semantic_matches", []) or []
        ),
    }


def build_source_attested_cases(
    feasibility_payload: Mapping[str, Any],
    source_evidence_payload: Mapping[str, Any],
    revision_pair_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build conservative non-human labels from exact public source boundaries."""

    feasibility_by_root = _source_index(feasibility_payload)
    source_pack_by_root = _source_pack_index(source_evidence_payload)

    records: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()
    seen_roots: set[str] = set()

    for pair in _pair_rows(revision_pair_payload):
        root = _text(pair.get("source_root")).upper()
        feasibility = feasibility_by_root.get(root)
        source_pack = source_pack_by_root.get(root)
        if feasibility is None or source_pack is None:
            excluded.append({
                "source_root": root,
                "source_project": _text(pair.get("source_project")),
                "reasons": [
                    "missing_feasibility_record"
                    if feasibility is None
                    else "missing_source_evidence_pack"
                ],
            })
            continue

        check = _attestation_check(feasibility, source_pack, pair)
        if not check["eligible"]:
            excluded.append({
                "source_root": root,
                "source_project": check["source_project"],
                "reasons": list(check["reasons"]),
            })
            continue

        if root in seen_roots:
            excluded.append({
                "source_root": root,
                "source_project": check["source_project"],
                "reasons": ["duplicate_revision_pair_origin"],
            })
            continue
        seen_roots.add(root)

        family = str(check["family"])
        family_counts[family] += 2
        pair_hash = _text(pair.get("revision_pair_sha256"))
        patch_set_hash = _text(source_pack.get("candidate_fix_patch_set_sha256"))
        common = {
            "family": family,
            "case_origin_id": f"rwv1:{root}",
            "source_root": root,
            "source_project": check["source_project"],
            "source_corpus_id": "real-world-corpus-v1",
            "evaluation_role": "fresh_candidate",
            "provenance": SOURCE_ATTESTED_PROVENANCE,
            "human_verified": False,
            "activation_eligible": False,
            "label_source": "github_reviewed_advisory_exact_fix_boundary",
            "advisory_cwes": list(check["advisory_cwes"]),
            "revision_pair_sha256": pair_hash,
            "patch_set_sha256": patch_set_hash,
            "family_resolution_basis": check["family_resolution_basis"],
            "family_resolution_semantic_matches": list(
                check["family_resolution_semantic_matches"]
            ),
            "attestation_basis": [
                "github_reviewed_advisory",
                "published_not_withdrawn",
                "first_patched_version_present",
                "exact_fix_commit_directly_referenced",
                "exact_single_parent_revision_pair_captured",
                "complete_patch_hash_set",
                "conservative_canonical_family_resolution",
            ],
            "score_status": "awaiting_current_engine_replay",
            "decision_readiness_score": None,
            "bug_proximity_score": None,
            "target_evidence_confidence": None,
        }
        positive = {
            **common,
            "id": _blind_case_id(check["source_project"], check["parent_sha"]),
            "variant": "positive",
            "label": True,
            "revision_sha": check["parent_sha"],
            "evidence_snapshot_id": f"revision:{check['parent_sha']}:{pair_hash}",
            "source_attestation": "vulnerable_parent_of_exact_advisory_fix",
        }
        negative = {
            **common,
            "id": _blind_case_id(check["source_project"], check["fix_sha"]),
            "variant": "secure_negative",
            "label": False,
            "revision_sha": check["fix_sha"],
            "evidence_snapshot_id": f"revision:{check['fix_sha']}:{pair_hash}",
            "source_attestation": "exact_advisory_fix_revision",
        }
        positive["attestation_fingerprint"] = _canonical_hash(positive)
        negative["attestation_fingerprint"] = _canonical_hash(negative)
        records.extend((positive, negative))

    exclusion_counts: Counter[str] = Counter()
    for row in excluded:
        for reason in row.get("reasons", []):
            exclusion_counts[str(reason)] += 1

    return {
        "version": SOURCE_ATTESTED_VERSION,
        "rule_version": SOURCE_ATTESTED_RULE_VERSION,
        "status": "ready_for_current_engine_replay" if records else "no_eligible_source_attested_cases",
        "eligible_origin_count": len(records) // 2,
        "attested_record_count": len(records),
        "positive_count": sum(1 for row in records if row["label"] is True),
        "negative_count": sum(1 for row in records if row["label"] is False),
        "family_count": len(family_counts),
        "family_record_counts": dict(sorted(family_counts.items())),
        "excluded_origin_count": len(excluded),
        "exclusion_reason_counts": dict(sorted(exclusion_counts.items())),
        "records": records,
        "excluded": excluded,
        "safety": {
            "human_review_required_for_this_mode": False,
            "source_attestation_is_not_human_verification": True,
            "ambiguous_cases_are_excluded": True,
            "labels_do_not_create_target_evidence": True,
            "labels_are_not_activation_eligible": True,
            "scores_are_not_fabricated_from_labels": True,
            "score_case_ids_do_not_encode_label_or_variant": True,
            "production_activation_is_never_performed": True,
        },
    }


def blind_replay_manifest(
    attested_records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return a scorer-facing manifest with ground-truth fields removed."""

    rows: list[dict[str, Any]] = []
    for raw in attested_records:
        row = dict(raw)
        case_id = _text(row.get("id"))
        project = _text(row.get("source_project"))
        revision = _text(row.get("revision_sha"))
        if not case_id or not project or not revision:
            continue
        rows.append({
            "case_id": case_id,
            "source_project": project,
            "revision_sha": revision,
            "scoring_instruction": "score_all_canonical_families_without_ground_truth",
        })
    return {
        "version": SOURCE_ATTESTED_VERSION,
        "rule_version": SOURCE_ATTESTED_RULE_VERSION,
        "case_count": len(rows),
        "cases": rows,
        "ground_truth_fields_removed": [
            "label",
            "variant",
            "family",
            "source_root",
            "advisory_cwes",
            "source_attestation",
            "revision_pair_sha256",
            "patch_set_sha256",
        ],
        "safety": {
            "label_blind": True,
            "family_blind": True,
            "advisory_blind": True,
            "opaque_case_ids": True,
        },
    }


def write_blind_replay_manifest(
    path: str | Path,
    attested_records: Iterable[Mapping[str, Any]],
) -> None:
    payload = blind_replay_manifest(attested_records)
    Path(path).write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_score_rows(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        text = path.read_text(encoding="utf-8")
        stripped = text.lstrip()
        if not stripped:
            continue
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, list):
                rows.extend(dict(row) for row in payload if isinstance(row, Mapping))
                continue
            if isinstance(payload, Mapping):
                values = payload.get("records")
                if not isinstance(values, list):
                    values = payload.get("scores")
                if isinstance(values, list):
                    rows.extend(dict(row) for row in values if isinstance(row, Mapping))
                    continue
                # A single score object is also accepted.
                if any(key in payload for key in _SCORE_FIELDS):
                    rows.append(dict(payload))
                    continue
        for line in text.splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, Mapping):
                rows.append(dict(value))
    return rows


def attach_current_engine_scores(
    attested_records: Iterable[Mapping[str, Any]],
    score_rows: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Join blind current-engine scores to source-attested labels by case ID."""

    scores_by_id: dict[str, dict[str, Any]] = {}
    rejected_scores: list[dict[str, Any]] = []
    for index, raw in enumerate(score_rows):
        row = dict(raw)
        case_id = (
            _text(row.get("attested_case_id"))
            or _text(row.get("case_id"))
            or _text(row.get("id"))
        )
        if not case_id:
            rejected_scores.append({"index": index, "reason": "missing_case_id"})
            continue
        if "label" in row:
            rejected_scores.append({
                "index": index,
                "case_id": case_id,
                "reason": "score_artifact_must_be_label_blind",
            })
            continue
        parsed = {field: _score(row.get(field)) for field in _SCORE_FIELDS}
        if any(value is None for value in parsed.values()):
            rejected_scores.append({
                "index": index,
                "case_id": case_id,
                "reason": "missing_or_invalid_current_engine_score",
            })
            continue
        if case_id in scores_by_id:
            rejected_scores.append({
                "index": index,
                "case_id": case_id,
                "reason": "duplicate_score_case_id",
            })
            continue
        scores_by_id[case_id] = {
            **parsed,
            "engine_version": _text(row.get("engine_version")),
            "engine_rule_version": _text(row.get("engine_rule_version") or row.get("rule_version")),
            "scored_at": _text(row.get("scored_at")),
            "top_family": _text(row.get("top_family")),
        }

    joined: list[dict[str, Any]] = []
    missing_score_ids: list[str] = []
    for raw in attested_records:
        row = dict(raw)
        case_id = _text(row.get("id"))
        score_row = scores_by_id.get(case_id)
        if score_row is None:
            missing_score_ids.append(case_id)
            joined.append(row)
            continue
        row.update(score_row)
        row["score_status"] = "current_engine_scored"
        joined.append(row)

    known_ids = {_text(row.get("id")) for row in joined}
    unused_score_ids = sorted(set(scores_by_id) - known_ids)

    return {
        "records": joined,
        "scored_count": sum(
            1 for row in joined if row.get("score_status") == "current_engine_scored"
        ),
        "unscored_count": sum(
            1 for row in joined if row.get("score_status") != "current_engine_scored"
        ),
        "missing_score_ids": missing_score_ids,
        "unused_score_ids": unused_score_ids,
        "rejected_score_count": len(rejected_scores),
        "rejected_scores": rejected_scores,
    }


def _stable_bucket(origin: str) -> int:
    digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def _origin_split(
    records: Iterable[Mapping[str, Any]],
    *,
    holdout_percent: int,
) -> dict[str, Any]:
    rows = [dict(row) for row in records]
    holdout_percent = max(5, min(50, int(holdout_percent)))
    by_origin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        origin = _text(row.get("case_origin_id"))
        if origin:
            by_origin[origin].append(row)

    ranked = sorted(by_origin, key=lambda value: (_stable_bucket(value), value))
    train_origins = {
        origin for origin in ranked if _stable_bucket(origin) >= holdout_percent
    }
    holdout_origins = set(ranked) - train_origins

    if len(ranked) >= 2 and not holdout_origins:
        chosen = ranked[0]
        train_origins.discard(chosen)
        holdout_origins.add(chosen)
    if len(ranked) >= 2 and not train_origins:
        chosen = ranked[-1]
        holdout_origins.discard(chosen)
        train_origins.add(chosen)

    train = [
        row for origin in sorted(train_origins) for row in by_origin[origin]
    ]
    holdout = [
        row for origin in sorted(holdout_origins) for row in by_origin[origin]
    ]
    return {
        "train": train,
        "holdout": holdout,
        "train_origin_count": len(train_origins),
        "holdout_origin_count": len(holdout_origins),
        "origin_leakage_count": len(train_origins & holdout_origins),
    }


def source_attested_evaluation_report(
    attestation: Mapping[str, Any],
    *,
    score_rows: Iterable[Mapping[str, Any]] = (),
    threshold: int = DEFAULT_THRESHOLD,
    holdout_percent: int = DEFAULT_HOLDOUT_PERCENT,
) -> dict[str, Any]:
    joined = attach_current_engine_scores(
        attestation.get("records", []) or [],
        score_rows,
    )
    scored = [
        dict(row)
        for row in joined["records"]
        if row.get("score_status") == "current_engine_scored"
    ]
    split = _origin_split(scored, holdout_percent=holdout_percent)
    holdout = split["holdout"]

    family_metrics: dict[str, Any] = {}
    for family in sorted({_text(row.get("family")) for row in holdout if _text(row.get("family"))}):
        subset = [row for row in holdout if _text(row.get("family")) == family]
        family_metrics[family] = confusion_metrics(
            subset,
            threshold=int(threshold),
            score_key="decision_readiness_score",
            label_key="label",
        )

    if not scored:
        status = "awaiting_current_engine_replay"
    elif int(joined["unscored_count"]) > 0:
        status = "partial_current_engine_scores"
    else:
        status = "source_attested_evaluation_ready"

    global_metrics = (
        confusion_metrics(
            holdout,
            threshold=int(threshold),
            score_key="decision_readiness_score",
            label_key="label",
        )
        if holdout
        else None
    )

    return {
        "version": SOURCE_ATTESTED_VERSION,
        "rule_version": SOURCE_ATTESTED_RULE_VERSION,
        "status": status,
        "threshold": int(threshold),
        "holdout_percent": max(5, min(50, int(holdout_percent))),
        "attested_origin_count": int(attestation.get("eligible_origin_count") or 0),
        "attested_record_count": int(attestation.get("attested_record_count") or 0),
        "attested_family_count": int(attestation.get("family_count") or 0),
        "scored_record_count": int(joined["scored_count"]),
        "unscored_record_count": int(joined["unscored_count"]),
        "rejected_score_count": int(joined["rejected_score_count"]),
        "train_origin_count": int(split["train_origin_count"]),
        "holdout_origin_count": int(split["holdout_origin_count"]),
        "origin_leakage_count": int(split["origin_leakage_count"]),
        "global_holdout_metrics": global_metrics,
        "family_holdout_metrics": family_metrics,
        "missing_score_ids": list(joined["missing_score_ids"]),
        "unused_score_ids": list(joined["unused_score_ids"]),
        "rejected_scores": list(joined["rejected_scores"]),
        "records": list(joined["records"]),
        "safety": {
            "labels_are_source_attested_not_human_verified": True,
            "score_artifacts_must_be_label_blind": True,
            "partition_is_label_blind_by_case_origin": True,
            "threshold_is_fixed_not_learned_from_this_corpus": True,
            "no_production_activation": True,
            "no_target_contact": True,
            "no_payload_generation": True,
            "metrics_are_unavailable_without_current_engine_scores": True,
        },
    }


def run_source_attested_evaluation(
    *,
    feasibility_path: str | Path,
    source_evidence_path: str | Path,
    revision_pairs_path: str | Path,
    score_paths: Iterable[str | Path] = (),
    threshold: int = DEFAULT_THRESHOLD,
    holdout_percent: int = DEFAULT_HOLDOUT_PERCENT,
) -> dict[str, Any]:
    feasibility = _load_json(feasibility_path)
    source_evidence = _load_json(source_evidence_path)
    revision_pairs = _load_json(revision_pairs_path)
    if not all(isinstance(value, Mapping) for value in (feasibility, source_evidence, revision_pairs)):
        raise ValueError("corpus_source_artifact_must_be_json_object")
    attestation = build_source_attested_cases(
        feasibility,
        source_evidence,
        revision_pairs,
    )
    scores = load_score_rows(score_paths)
    report = source_attested_evaluation_report(
        attestation,
        score_rows=scores,
        threshold=threshold,
        holdout_percent=holdout_percent,
    )
    return {
        "attestation": attestation,
        "evaluation": report,
    }


def summary_payload(result: Mapping[str, Any]) -> dict[str, Any]:
    attestation = result.get("attestation")
    attestation = attestation if isinstance(attestation, Mapping) else {}
    evaluation = result.get("evaluation")
    evaluation = evaluation if isinstance(evaluation, Mapping) else {}
    return {
        "version": SOURCE_ATTESTED_VERSION,
        "rule_version": SOURCE_ATTESTED_RULE_VERSION,
        "status": _text(evaluation.get("status")),
        "attestation": {
            key: value
            for key, value in attestation.items()
            if key not in {"records", "excluded"}
        },
        "evaluation": {
            key: value
            for key, value in evaluation.items()
            if key not in {"records", "missing_score_ids", "rejected_scores"}
        },
        "next_action": (
            "generate_label_blind_current_engine_scores"
            if _text(evaluation.get("status")) == "awaiting_current_engine_replay"
            else "inspect_source_attested_metrics"
        ),
    }


def write_attested_records(
    path: str | Path,
    records: Iterable[Mapping[str, Any]],
) -> None:
    payload = {
        "version": SOURCE_ATTESTED_VERSION,
        "rule_version": SOURCE_ATTESTED_RULE_VERSION,
        "records": [dict(row) for row in records],
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "SOURCE_ATTESTED_VERSION",
    "SOURCE_ATTESTED_RULE_VERSION",
    "DEFAULT_THRESHOLD",
    "DEFAULT_HOLDOUT_PERCENT",
    "build_source_attested_cases",
    "blind_replay_manifest",
    "write_blind_replay_manifest",
    "load_score_rows",
    "attach_current_engine_scores",
    "source_attested_evaluation_report",
    "run_source_attested_evaluation",
    "summary_payload",
    "write_attested_records",
]

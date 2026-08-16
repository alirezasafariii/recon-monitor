from __future__ import annotations

"""Challenge replay and trusted-corpus ingestion for Analysis calibration.

This layer extends the fixed golden replay with diagnostic-only hard cases and a
strict, offline quality gate for human-verified replay metadata. Generated cases
remain activation-ineligible. Verified replay is accepted only when its label is
bound to an auditable evidence snapshot and explicit evidence-quality dimensions.

Raw ``bug_proximity_score`` is preserved for hunting diagnostics. Challenge
classification/calibration uses ``decision_readiness_score`` so useful attack
surfaces are not incorrectly treated as confirmed-looking findings.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from analysis_benchmark import load_golden_cases, replay_golden_cases
from calibration_dataset import annotate_record, build_guarded_calibration_profile
from calibration_engine import confusion_metrics
from meta_ranker import rank_bug_proximity
from vulnerability_knowledge import BUG_PROFILES, rank_families, retrieve_writeups

ANALYSIS_BENCHMARK_V2_VERSION = "1.2.0"
ANALYSIS_BENCHMARK_V2_RULE_VERSION = "2026.08.13.3"
VERIFIED_REPLAY_SCHEMA_VERSION = "1.0.0"
EVIDENCE_QUALITY_VERSION = "1.0.0"

TRUSTED_REPLAY_PROVENANCE = frozenset({
    "human_verified_replay",
    "curated_real_world_replay",
    "confirmed_target_history",
})

EVIDENCE_QUALITY_DIMENSIONS = (
    "reliability",
    "specificity",
    "directness",
    "freshness",
    "independence",
    "reproducibility",
    "uncertainty",
)

_QUALITY_WEIGHTS = {
    "reliability": 0.25,
    "specificity": 0.20,
    "directness": 0.20,
    "freshness": 0.10,
    "independence": 0.15,
    "reproducibility": 0.10,
}

_POSITIVE_LABELS = frozenset({"1", "true", "yes", "positive", "confirmed", "vulnerable"})
_NEGATIVE_LABELS = frozenset({"0", "false", "no", "negative", "rejected", "not_vulnerable", "not-vulnerable"})


def _items(signals: Sequence[str], *, case_id: str, kind: str) -> list[dict[str, Any]]:
    return [
        {
            "type": str(signal),
            "source": "offline_challenge_replay",
            "source_group": f"{case_id}:{kind}:{index}",
            "weight": 1,
            "text": str(signal).replace("_", " "),
        }
        for index, signal in enumerate(signals)
        if str(signal).strip()
    ]


def replay_diagnostic_case(
    family: str,
    support_signals: Sequence[str],
    *,
    contradict_signals: Sequence[str] = (),
    label: bool = False,
    case_id: str,
    case_kind: str,
) -> dict[str, Any]:
    """Replay a diagnostic record through the real Knowledge + Meta Ranker path."""

    support = _items(support_signals, case_id=case_id, kind="support")
    contradict = _items(contradict_signals, case_id=case_id, kind="contradict")
    family_rankings = rank_families(
        support,
        contradict,
        endpoint="/benchmark/challenge",
        summary="offline diagnostic replay",
        limit=100,
    )
    writeups = retrieve_writeups(
        support,
        contradict,
        endpoint="/benchmark/challenge",
        summary="offline diagnostic replay",
        family=family,
        limit=5,
    )
    ranked = rank_bug_proximity(support, contradict, family_rankings, writeups, limit=100)
    matched = next(
        (item for item in ranked.get("rankings", []) if str(item.get("family")) == family),
        None,
    )
    proximity = int(matched.get("bug_proximity_score", 0)) if isinstance(matched, Mapping) else 0
    evidence = int(matched.get("target_evidence_confidence", 0)) if isinstance(matched, Mapping) else 0
    readiness = int(matched.get("decision_readiness_score", 0)) if isinstance(matched, Mapping) else 0
    row = {
        "id": case_id,
        "family": family,
        "label": bool(label),
        "score": max(0, min(100, readiness)),
        "decision_readiness_score": max(0, min(100, readiness)),
        "bug_proximity_score": max(0, min(100, proximity)),
        "target_evidence_confidence": max(0, min(100, evidence)),
        "signals": list(support_signals),
        "contradictions": list(contradict_signals),
        "top_family": str((ranked.get("primary") or {}).get("family") or ""),
        "decision_readiness_band": str((matched.get("decision_readiness") or {}).get("band") or "") if isinstance(matched, Mapping) else "",
        "ranked": matched is not None,
        "diagnostic_only": True,
    }
    return annotate_record(
        row,
        provenance="synthetic_challenge",
        case_kind=case_kind,
        human_verified=False,
        label_source="generated_from_golden_contract",
    )


def _first_contradiction(family: str) -> str:
    profile = BUG_PROFILES.get(family, {}) if isinstance(BUG_PROFILES, Mapping) else {}
    signals = profile.get("signals", {}) if isinstance(profile, Mapping) else {}
    contradictions = signals.get("contradictions", []) if isinstance(signals, Mapping) else []
    for value in contradictions if isinstance(contradictions, (list, tuple, set)) else []:
        if str(value).strip():
            return str(value)
    return "observed_control_enforced"


def build_challenge_records(cases: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Generate three deterministic diagnostic challenges for every family."""

    normalized = [dict(case) for case in cases if str(case.get("family") or "").strip()]
    result: list[dict[str, Any]] = []
    for index, case in enumerate(normalized):
        family = str(case.get("family") or "").strip()
        positive = [str(v) for v in case.get("positive", []) if str(v).strip()]
        negative = [str(v) for v in case.get("negative", []) if str(v).strip()]
        next_case = normalized[(index + 1) % len(normalized)] if normalized else {}
        next_positive = [str(v) for v in next_case.get("positive", []) if str(v).strip()]
        foreign_direct = next_positive[-1] if next_positive else "unrelated_direct_signal"

        partial = positive[:-1] if len(positive) > 1 else list(negative)
        result.append(replay_diagnostic_case(
            family,
            partial,
            label=False,
            case_id=f"challenge:{family}:partial",
            case_kind="partial_evidence",
        ))
        result.append(replay_diagnostic_case(
            family,
            [*negative, foreign_direct],
            label=False,
            case_id=f"challenge:{family}:cross-family-noise",
            case_kind="cross_family_noise",
        ))
        result.append(replay_diagnostic_case(
            family,
            positive,
            contradict_signals=[_first_contradiction(family)],
            label=False,
            case_id=f"challenge:{family}:contradiction",
            case_kind="contradiction_heavy",
        ))
    return result


def _annotate_seed(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in records:
        kind = "golden_positive" if bool(row.get("label")) else "golden_surface_only"
        result.append(annotate_record(
            row,
            provenance="golden_seed",
            case_kind=kind,
            human_verified=False,
            label_source="fixed_golden_fixture",
        ))
    return result


def _strict_label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, float) and value in {0.0, 1.0}:
        return bool(int(value))
    token = str(value or "").strip().lower()
    if token in _POSITIVE_LABELS:
        return True
    if token in _NEGATIVE_LABELS:
        return False
    raise ValueError("ambiguous_label")


def _quality_value(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number > 1.0 and number <= 100.0:
        number /= 100.0
    if number < 0.0 or number > 1.0:
        return None
    return number


def evidence_quality_profile(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Score replay evidence quality without affecting Analysis decisions."""

    source = raw.get("evidence_quality")
    values = source if isinstance(source, Mapping) else {}
    normalized: dict[str, float] = {}
    missing: list[str] = []
    invalid: list[str] = []
    for name in EVIDENCE_QUALITY_DIMENSIONS:
        if name not in values:
            missing.append(name)
            continue
        parsed = _quality_value(values.get(name))
        if parsed is None:
            invalid.append(name)
            continue
        normalized[name] = parsed

    complete = not missing and not invalid
    weighted = 0.0
    total_weight = 0.0
    for name, weight in _QUALITY_WEIGHTS.items():
        if name in normalized:
            weighted += normalized[name] * weight
            total_weight += weight
    base = weighted / total_weight if total_weight else 0.0
    uncertainty = normalized.get("uncertainty")
    certainty_factor = 1.0 - (0.50 * uncertainty) if uncertainty is not None else 1.0
    score = max(0, min(100, int(round(base * certainty_factor * 100.0)))) if complete else 0
    return {
        "version": EVIDENCE_QUALITY_VERSION,
        "complete": bool(complete),
        "score": score,
        "dimensions": normalized,
        "missing_dimensions": missing,
        "invalid_dimensions": invalid,
        "advisory_only": True,
    }


def _replay_fingerprint(raw: Mapping[str, Any]) -> str:
    material = "|".join([
        str(raw.get("family") or "").strip(),
        str(raw.get("case_origin_id") or "").strip(),
        str(raw.get("evidence_snapshot_id") or "").strip(),
        str(raw.get("provenance") or "").strip().lower(),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_verified_replay(raw: Mapping[str, Any], *, default_id: str) -> dict[str, Any]:
    errors: list[str] = []
    family = str(raw.get("family") or "").strip()
    if not family:
        errors.append("missing_family")
    try:
        label = _strict_label(raw.get("label"))
    except ValueError:
        label = False
        errors.append("ambiguous_label")

    provenance = str(raw.get("provenance") or "").strip().lower()
    if provenance not in TRUSTED_REPLAY_PROVENANCE:
        errors.append("untrusted_provenance")
    if raw.get("human_verified") is not True:
        errors.append("human_verified_true_required")
    for field in ("label_source", "reviewer_id", "reviewed_at", "case_origin_id", "evidence_snapshot_id"):
        if not str(raw.get(field) or "").strip():
            errors.append(f"missing_{field}")

    score_source = raw.get("decision_readiness_score")
    if score_source is None:
        score_source = raw.get("score")
    try:
        decision_score = int(round(float(score_source)))
    except (TypeError, ValueError):
        decision_score = 0
        errors.append("invalid_decision_score")
    if decision_score < 0 or decision_score > 100:
        errors.append("decision_score_out_of_range")

    quality = evidence_quality_profile(raw)
    if not quality["complete"]:
        errors.append("incomplete_evidence_quality")

    row = {
        "id": str(raw.get("id") or default_id),
        "family": family,
        "label": bool(label),
        "score": max(0, min(100, decision_score)),
        "decision_readiness_score": max(0, min(100, decision_score)),
        "bug_proximity_score": max(0, min(100, int(raw.get("bug_proximity_score") or 0))),
        "target_evidence_confidence": max(0, min(100, int(raw.get("target_evidence_confidence") or 0))),
        "signals": [str(v) for v in raw.get("signals", []) if str(v).strip()],
        "contradictions": [str(v) for v in raw.get("contradictions", []) if str(v).strip()],
        "provenance": provenance,
        "case_kind": str(raw.get("case_kind") or "real_world_replay"),
        "human_verified": raw.get("human_verified") is True,
        "label_source": str(raw.get("label_source") or "").strip(),
        "reviewer_id": str(raw.get("reviewer_id") or "").strip(),
        "reviewed_at": str(raw.get("reviewed_at") or "").strip(),
        "case_origin_id": str(raw.get("case_origin_id") or "").strip(),
        "evidence_snapshot_id": str(raw.get("evidence_snapshot_id") or "").strip(),
        "evidence_quality": dict(raw.get("evidence_quality") or {}) if isinstance(raw.get("evidence_quality"), Mapping) else {},
        "evidence_quality_profile": quality,
        "verified_replay_schema_version": VERIFIED_REPLAY_SCHEMA_VERSION,
    }
    row["verified_replay_fingerprint"] = _replay_fingerprint(row)
    return {"valid": not errors, "errors": errors, "record": row}


def load_verified_replay_jsonl_with_diagnostics(paths: Iterable[str | Path]) -> dict[str, Any]:
    """Load only auditable, de-duplicated real-world replay metadata.

    Raw requests, credentials, exploit payloads, and unrelated target data are not
    required. Invalid records are summarized by ID/reason and never enter
    calibration readiness.
    """

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_count = 0
    source_files = 0
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        source_files += 1
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            default_id = f"{path.name}:{line_number}"
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                rejected.append({"id": default_id, "family": "", "errors": ["invalid_json"]})
                continue
            if not isinstance(raw, Mapping):
                rejected.append({"id": default_id, "family": "", "errors": ["record_must_be_object"]})
                continue
            validation = _validate_verified_replay(raw, default_id=default_id)
            row = dict(validation["record"])
            if not validation["valid"]:
                rejected.append({
                    "id": str(row.get("id") or default_id),
                    "family": str(row.get("family") or ""),
                    "errors": list(validation["errors"]),
                })
                continue
            fingerprint = str(row.get("verified_replay_fingerprint") or "")
            if fingerprint in seen:
                duplicate_count += 1
                rejected.append({
                    "id": str(row.get("id") or default_id),
                    "family": str(row.get("family") or ""),
                    "errors": ["duplicate_verified_replay"],
                })
                continue
            seen.add(fingerprint)
            accepted.append(annotate_record(
                row,
                provenance=str(row.get("provenance") or "unclassified"),
                case_kind=str(row.get("case_kind") or "real_world_replay"),
                human_verified=True,
                label_source=str(row.get("label_source") or ""),
            ))
            accepted[-1].update({
                "reviewer_id": row["reviewer_id"],
                "reviewed_at": row["reviewed_at"],
                "case_origin_id": row["case_origin_id"],
                "evidence_snapshot_id": row["evidence_snapshot_id"],
                "evidence_quality": row["evidence_quality"],
                "evidence_quality_profile": row["evidence_quality_profile"],
                "verified_replay_fingerprint": row["verified_replay_fingerprint"],
                "verified_replay_schema_version": VERIFIED_REPLAY_SCHEMA_VERSION,
            })

    quality_scores = [int((row.get("evidence_quality_profile") or {}).get("score") or 0) for row in accepted]
    return {
        "records": accepted,
        "rejected": rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "duplicate_count": duplicate_count,
        "source_files": source_files,
        "mean_evidence_quality": round(sum(quality_scores) / len(quality_scores), 2) if quality_scores else 0.0,
        "schema_version": VERIFIED_REPLAY_SCHEMA_VERSION,
        "evidence_quality_version": EVIDENCE_QUALITY_VERSION,
    }


def load_verified_replay_jsonl(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    return list(load_verified_replay_jsonl_with_diagnostics(paths)["records"])


def quality_report(
    repo_root: str | Path,
    *,
    verified_corpus_paths: Iterable[str | Path] = (),
    requested_activation: str = "shadow_only",
) -> dict[str, Any]:
    root = Path(repo_root)
    cases = load_golden_cases([
        root / "tests" / "fixtures" / "vulnerability_intelligence_golden_v1.json",
        root / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json",
    ])
    seed = _annotate_seed(replay_golden_cases(cases))
    challenges = build_challenge_records(cases)
    verified_ingestion = load_verified_replay_jsonl_with_diagnostics(verified_corpus_paths)
    verified = list(verified_ingestion["records"])
    calibration_rows = [*seed, *verified]
    profile = build_guarded_calibration_profile(
        calibration_rows,
        requested_activation=requested_activation,
        source="analysis_decision_readiness_replay_v2",
    )
    threshold = int(profile.get("global", {}).get("threshold", 70))

    by_kind: dict[str, Any] = {}
    kinds = sorted({str(row.get("case_kind") or "") for row in challenges})
    for kind in kinds:
        subset = [row for row in challenges if str(row.get("case_kind")) == kind]
        by_kind[kind] = confusion_metrics(subset, threshold=threshold)

    seed_positive = {
        str(row.get("family")): int(row.get("decision_readiness_score") or row.get("score") or 0)
        for row in seed if bool(row.get("label"))
    }
    ordering_failures: list[dict[str, Any]] = []
    for row in challenges:
        family = str(row.get("family") or "")
        positive_score = seed_positive.get(family)
        if positive_score is None:
            continue
        challenge_score = int(row.get("decision_readiness_score") or row.get("score") or 0)
        if challenge_score >= positive_score:
            ordering_failures.append({
                "family": family,
                "case_kind": str(row.get("case_kind") or ""),
                "positive_readiness": positive_score,
                "challenge_readiness": challenge_score,
                "challenge_proximity": int(row.get("bug_proximity_score") or 0),
            })

    return {
        "benchmark_version": ANALYSIS_BENCHMARK_V2_VERSION,
        "rule_version": ANALYSIS_BENCHMARK_V2_RULE_VERSION,
        "score_semantics": "decision_readiness_score",
        "coverage": {
            "families": len(cases),
            "golden_records": len(seed),
            "challenge_records": len(challenges),
            "verified_records": len(verified),
            "verified_rejected_records": int(verified_ingestion["rejected_count"]),
            "verified_duplicate_records": int(verified_ingestion["duplicate_count"]),
            "total_diagnostic_records": len(seed) + len(challenges) + len(verified),
        },
        "verified_replay_ingestion": verified_ingestion,
        "calibration_profile": profile,
        "challenge_threshold": threshold,
        "challenge_metrics_by_kind": by_kind,
        "challenge_ordering_failures": ordering_failures,
        "challenge_ordering_failure_count": len(ordering_failures),
        "safety": {
            "offline_only": True,
            "network_requests": False,
            "payload_generation": False,
            "bug_proximity_remains_investigation_oriented": True,
            "decision_readiness_is_advisory_only": True,
            "synthetic_challenges_are_activation_ineligible": True,
            "golden_seed_is_activation_ineligible": True,
            "production_activation_requires_human_verified_real_world_labels": True,
            "verified_replay_requires_snapshot_binding": True,
            "verified_replay_requires_reviewer_audit_fields": True,
            "evidence_quality_is_advisory_only": True,
            "rejected_replay_rows_never_enter_calibration": True,
        },
    }

from __future__ import annotations

"""Challenge replay and trusted-corpus ingestion for Analysis calibration.

This layer extends the fixed golden replay with diagnostic-only hard cases:
partial evidence, cross-family noise, and contradiction-heavy observations.
Generated challenges can expose ranking weaknesses but are never eligible to
activate a production threshold.
"""

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from analysis_benchmark import load_golden_cases, replay_golden_cases
from calibration_dataset import annotate_record, build_guarded_calibration_profile
from calibration_engine import confusion_metrics
from meta_ranker import rank_bug_proximity
from vulnerability_knowledge import BUG_PROFILES, rank_families, retrieve_writeups

ANALYSIS_BENCHMARK_V2_VERSION = "1.0.0"
ANALYSIS_BENCHMARK_V2_RULE_VERSION = "2026.08.13.1"


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
    score = int(matched.get("bug_proximity_score", 0)) if isinstance(matched, Mapping) else 0
    evidence = int(matched.get("target_evidence_confidence", 0)) if isinstance(matched, Mapping) else 0
    row = {
        "id": case_id,
        "family": family,
        "label": bool(label),
        "score": max(0, min(100, score)),
        "target_evidence_confidence": max(0, min(100, evidence)),
        "signals": list(support_signals),
        "contradictions": list(contradict_signals),
        "top_family": str((ranked.get("primary") or {}).get("family") or ""),
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


def load_verified_replay_jsonl(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Load a minimal human-verified replay corpus without raw request payloads.

    Accepted rows contain only family, label, score or evidence signal names,
    optional contradiction signal names, provenance, and a human label source.
    Records without trusted provenance + human_verified are retained for
    diagnostics but remain activation-ineligible.
    """

    rows: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, Mapping):
                continue
            family = str(raw.get("family") or "").strip()
            if not family:
                continue
            row = {
                "id": str(raw.get("id") or f"{path.name}:{line_number}"),
                "family": family,
                "label": bool(raw.get("label")),
                "score": int(raw.get("score") or 0),
                "target_evidence_confidence": int(raw.get("target_evidence_confidence") or 0),
                "signals": [str(v) for v in raw.get("signals", []) if str(v).strip()],
                "contradictions": [str(v) for v in raw.get("contradictions", []) if str(v).strip()],
            }
            rows.append(annotate_record(
                row,
                provenance=str(raw.get("provenance") or "unclassified"),
                case_kind=str(raw.get("case_kind") or "real_world_replay"),
                human_verified=bool(raw.get("human_verified")),
                label_source=str(raw.get("label_source") or ""),
            ))
    return rows


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
    verified = load_verified_replay_jsonl(verified_corpus_paths)
    calibration_rows = [*seed, *verified]
    profile = build_guarded_calibration_profile(
        calibration_rows,
        requested_activation=requested_activation,
        source="analysis_quality_replay_v2",
    )
    threshold = int(profile.get("global", {}).get("threshold", 70))

    by_kind: dict[str, Any] = {}
    kinds = sorted({str(row.get("case_kind") or "") for row in challenges})
    for kind in kinds:
        subset = [row for row in challenges if str(row.get("case_kind")) == kind]
        by_kind[kind] = confusion_metrics(subset, threshold=threshold)

    seed_positive = {
        str(row.get("family")): int(row.get("score") or 0)
        for row in seed if bool(row.get("label"))
    }
    ordering_failures: list[dict[str, Any]] = []
    for row in challenges:
        family = str(row.get("family") or "")
        positive_score = seed_positive.get(family)
        if positive_score is None:
            continue
        challenge_score = int(row.get("score") or 0)
        if challenge_score >= positive_score:
            ordering_failures.append({
                "family": family,
                "case_kind": str(row.get("case_kind") or ""),
                "positive_score": positive_score,
                "challenge_score": challenge_score,
            })

    return {
        "benchmark_version": ANALYSIS_BENCHMARK_V2_VERSION,
        "rule_version": ANALYSIS_BENCHMARK_V2_RULE_VERSION,
        "coverage": {
            "families": len(cases),
            "golden_records": len(seed),
            "challenge_records": len(challenges),
            "verified_records": len(verified),
            "total_diagnostic_records": len(seed) + len(challenges) + len(verified),
        },
        "calibration_profile": profile,
        "challenge_threshold": threshold,
        "challenge_metrics_by_kind": by_kind,
        "challenge_ordering_failures": ordering_failures,
        "challenge_ordering_failure_count": len(ordering_failures),
        "safety": {
            "offline_only": True,
            "network_requests": False,
            "payload_generation": False,
            "synthetic_challenges_are_activation_ineligible": True,
            "golden_seed_is_activation_ineligible": True,
            "production_activation_requires_human_verified_real_world_labels": True,
        },
    }

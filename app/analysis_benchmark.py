from __future__ import annotations

"""Offline replay benchmark for the Analysis ranking stack.

The benchmark consumes evidence-only fixtures and runs the same knowledge + meta
ranking path used by Analysis. It never contacts targets and never converts
knowledge similarity into target evidence.
"""

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from calibration_engine import build_calibration_profile, confusion_metrics
from meta_ranker import rank_bug_proximity
from vulnerability_knowledge import rank_families, retrieve_writeups

ANALYSIS_BENCHMARK_VERSION = "1.0.0"
ANALYSIS_BENCHMARK_RULE_VERSION = "2026.08.13.1"


def load_golden_cases(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        raw_cases = payload.get("cases", []) if isinstance(payload, Mapping) else []
        for raw in raw_cases:
            if not isinstance(raw, Mapping):
                continue
            family = str(raw.get("family") or "").strip()
            if not family:
                continue
            cases.append({
                "family": family,
                "positive": [str(value) for value in raw.get("positive", []) if str(value).strip()],
                "negative": [str(value) for value in raw.get("negative", []) if str(value).strip()],
                "validation": str(raw.get("validation") or ""),
                "reference": str(raw.get("reference") or ""),
                "fixture": path.name,
            })
    return cases


def _support(signals: Sequence[str], *, case_id: str) -> list[dict[str, Any]]:
    return [
        {
            "type": str(signal),
            "source": "offline_replay_fixture",
            "source_group": f"{case_id}:source:{index}",
            "weight": 1,
            "text": str(signal).replace("_", " "),
        }
        for index, signal in enumerate(signals)
    ]


def replay_ranking_case(
    family: str,
    signals: Sequence[str],
    *,
    label: bool,
    case_id: str,
    endpoint: str = "/benchmark/replay",
) -> dict[str, Any]:
    support = _support(signals, case_id=case_id)
    family_rankings = rank_families(support, [], endpoint=endpoint, summary="offline replay", limit=100)
    writeups = retrieve_writeups(support, [], endpoint=endpoint, summary="offline replay", family=family, limit=5)
    ranked = rank_bug_proximity(support, [], family_rankings, writeups, limit=100)
    matched = next((item for item in ranked.get("rankings", []) if str(item.get("family")) == family), None)
    score = int(matched.get("bug_proximity_score", 0)) if isinstance(matched, Mapping) else 0
    evidence = int(matched.get("target_evidence_confidence", 0)) if isinstance(matched, Mapping) else 0
    return {
        "id": case_id,
        "family": family,
        "label": bool(label),
        "score": max(0, min(100, score)),
        "target_evidence_confidence": max(0, min(100, evidence)),
        "signal_count": len(signals),
        "signals": list(signals),
        "ranked": matched is not None,
        "top_family": str((ranked.get("primary") or {}).get("family") or ""),
        "engine_version": str(ranked.get("engine_version") or ""),
        "rule_version": str(ranked.get("rule_version") or ""),
    }


def replay_golden_cases(cases: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, raw in enumerate(cases):
        family = str(raw.get("family") or "").strip()
        if not family:
            continue
        fixture = str(raw.get("fixture") or "fixture")
        positive = [str(value) for value in raw.get("positive", []) if str(value).strip()]
        negative = [str(value) for value in raw.get("negative", []) if str(value).strip()]
        records.append(replay_ranking_case(
            family,
            positive,
            label=True,
            case_id=f"{fixture}:{index}:{family}:positive",
        ))
        records.append(replay_ranking_case(
            family,
            negative,
            label=False,
            case_id=f"{fixture}:{index}:{family}:negative",
        ))
    return records


def benchmark_report(
    records: Iterable[Mapping[str, Any]],
    *,
    threshold: int = 70,
    calibration_activation: str = "shadow_only",
) -> dict[str, Any]:
    rows = [dict(record) for record in records]
    families = sorted({str(row.get("family") or "") for row in rows if str(row.get("family") or "").strip()})
    positives = sum(1 for row in rows if bool(row.get("label")))
    negatives = len(rows) - positives
    profile = build_calibration_profile(
        rows,
        source="analysis_golden_replay",
        activation=calibration_activation,
    )
    family_metrics = {
        family: confusion_metrics([row for row in rows if str(row.get("family")) == family], threshold=threshold)
        for family in families
    }
    return {
        "benchmark_version": ANALYSIS_BENCHMARK_VERSION,
        "rule_version": ANALYSIS_BENCHMARK_RULE_VERSION,
        "coverage": {
            "records": len(rows),
            "families": len(families),
            "positive": positives,
            "negative": negatives,
        },
        "threshold": int(threshold),
        "global_metrics": confusion_metrics(rows, threshold=threshold),
        "family_metrics": family_metrics,
        "calibration_profile": profile,
        "safety": {
            "offline_only": True,
            "network_requests": False,
            "payload_generation": False,
            "knowledge_is_non_evidentiary": True,
            "calibration_is_advisory_only": True,
        },
    }


def run_default_benchmark(repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root)
    cases = load_golden_cases([
        root / "tests" / "fixtures" / "vulnerability_intelligence_golden_v1.json",
        root / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json",
    ])
    records = replay_golden_cases(cases)
    return benchmark_report(records)

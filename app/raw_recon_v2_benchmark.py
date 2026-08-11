from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from raw_recon_benchmark import RAW_QUALITY_GATES, _git_blob_sha, run_raw_benchmark
from raw_recon_v2_corpus import load_raw_cases, validate_v2_corpus

RAW_RECON_V2_BENCHMARK_VERSION = "1.0.0"
RAW_RECON_V2_RULE_VERSION = "2026.08.11.6.13"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v2.jsonl"
DEFAULT_MANIFEST = ROOT / "benchmarks" / "raw" / "splits" / "v2.json"


def _canonical_gates() -> dict[str, dict[str, float | str]]:
    return {
        metric: {"direction": direction, "threshold": threshold}
        for metric, (direction, threshold) in RAW_QUALITY_GATES.items()
    }


def _tree_sha(relative: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def verify_v2_freeze(manifest_path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    protected = manifest.get("protected_files") if isinstance(manifest.get("protected_files"), Mapping) else {}
    for relative, expected in protected.items():
        target = ROOT / str(relative)
        if not target.exists():
            errors.append(f"protected file missing: {relative}")
            continue
        actual = _git_blob_sha(target)
        if actual != str(expected):
            errors.append(f"protected file changed after v2 freeze: {relative} expected={expected} actual={actual}")

    protected_trees = manifest.get("protected_trees") if isinstance(manifest.get("protected_trees"), Mapping) else {}
    for relative, expected in protected_trees.items():
        actual = _tree_sha(str(relative))
        if actual != str(expected):
            errors.append(f"protected tree changed after v2 freeze: {relative} expected={expected} actual={actual}")

    if manifest.get("acceptance_gates") != _canonical_gates():
        errors.append("v2 acceptance gates differ from the pre-registered benchmark gates")

    observability = manifest.get("observability_gates") if isinstance(manifest.get("observability_gates"), Mapping) else {}
    if observability != {
        "positive_control_raw_collision_count": {"direction": "max", "threshold": 0},
        "positive_observable_delta_rate": {"direction": "min", "threshold": 1.0},
    }:
        errors.append("v2 observability gates differ from protocol pre-registration")

    return {
        "passed": not errors,
        "errors": errors,
        "manifest": manifest,
        "protected_file_count": len(protected),
        "protected_tree_count": len(protected_trees),
    }


def benchmark_v2_file(
    corpus_path: str | Path = DEFAULT_CORPUS,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    *,
    allow_consumed: bool = False,
) -> dict[str, Any]:
    freeze = verify_v2_freeze(manifest_path)
    if not freeze["passed"]:
        raise RuntimeError("Analysis 6.13 freeze verification failed: " + "; ".join(freeze["errors"]))
    manifest = freeze["manifest"]
    status = str(manifest.get("evaluation_status") or "")
    if status not in {"sealed_unscored", "evaluated_once_consumed"}:
        raise RuntimeError(f"Raw v2 holdout is not sealed for evaluation: status={status!r}")
    if status == "evaluated_once_consumed" and not allow_consumed:
        raise RuntimeError("Raw v2 holdout has already been consumed; rerun only as an explicitly labeled regression")

    cases = load_raw_cases(corpus_path)
    validation = validate_v2_corpus(cases)
    if not validation["passed"]:
        raise RuntimeError("Raw v2 corpus validation failed: " + "; ".join(validation["errors"]))
    report = run_raw_benchmark(cases, validation=validation)
    report["raw_recon_v2_benchmark_version"] = RAW_RECON_V2_BENCHMARK_VERSION
    report["raw_recon_v2_rule_version"] = RAW_RECON_V2_RULE_VERSION
    report["freeze_validation"] = {key: value for key, value in freeze.items() if key != "manifest"}
    report["evaluation_status_at_start"] = status
    report["corpus"] = str(Path(corpus_path))
    report["manifest"] = str(Path(manifest_path))
    return report


def _summary(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    validation = report["corpus_validation"]
    return (
        f"Analysis 6.13 raw v2: {report['case_count']} cases | "
        f"extractP={metrics['condition_extraction_precision']:.3f} "
        f"extractR={metrics['condition_extraction_recall']:.3f} "
        f"top1={metrics['routing_top1_accuracy']:.3f} "
        f"top3={metrics['routing_top3_accuracy']:.3f} "
        f"admitP={metrics['admission_precision']:.3f} "
        f"admitR={metrics['admission_recall']:.3f} "
        f"abstain={metrics['abstention_accuracy']:.3f} "
        f"FPR={metrics['false_promotion_rate']:.3f} | "
        f"observable={validation['positive_observable_delta_rate']:.3f} "
        f"collisions={validation['positive_control_raw_collision_count']} | "
        f"gate={'PASS' if report['quality_gate']['passed'] else 'FAIL'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Analysis 6.13 fresh raw holdout v2 benchmark")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--allow-consumed", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    report = benchmark_v2_file(args.corpus, args.manifest, allow_consumed=args.allow_consumed)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_summary(report))
    if args.strict and not report["quality_gate"]["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

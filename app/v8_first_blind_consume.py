from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v8_benchmark_evaluate import run_v8_benchmark
from v8_freeze_verify import verify_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v8.9"

CORPUS = ROOT / "benchmarks/raw/analysis_raw_v8.jsonl"
SHORTLIST = ROOT / "benchmarks/raw/sources/v8_shortlist.json"
PROTOCOL = ROOT / "benchmarks/raw/sources/v8_protocol.json"
CORPUS_FREEZE = ROOT / "benchmarks/raw/sources/v8_corpus_freeze.json"
EVALUATOR_FREEZE = ROOT / "benchmarks/raw/sources/v8_evaluator_freeze.json"
EVALUATOR = ROOT / "app/v8_benchmark_evaluate.py"
RECEIPT = ROOT / "benchmarks/raw/sources/v8_first_blind_consumption.json"
RESULT = ROOT / "benchmarks/raw/results/analysis_raw_v8_first_blind.json"

CANONICAL_ARTIFACTS = {
    "corpus": CORPUS,
    "shortlist": SHORTLIST,
    "protocol": PROTOCOL,
    "corpus_freeze": CORPUS_FREEZE,
    "evaluator_freeze": EVALUATOR_FREEZE,
    "evaluator": EVALUATOR,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _canonical_artifact_hashes() -> dict[str, str]:
    missing = [name for name, path in CANONICAL_ARTIFACTS.items() if not path.exists()]
    if missing:
        raise RuntimeError("canonical First Blind artifacts are missing: " + ", ".join(sorted(missing)))
    return {name: _sha256(path) for name, path in CANONICAL_ARTIFACTS.items()}


def _validate_run_identity(receipt: Mapping[str, Any], run_id: str, run_attempt: str) -> None:
    expected_run_id = str(receipt.get("github_run_id") or "")
    expected_attempt = str(receipt.get("github_run_attempt") or "")
    if not run_id or not run_attempt:
        raise RuntimeError("GitHub run identity is required for First Blind consumption")
    if run_id != expected_run_id or run_attempt != expected_attempt:
        raise RuntimeError(
            "First Blind authorization belongs to a different GitHub workflow run/attempt; rerun is forbidden"
        )


def _validate_artifact_hashes(receipt: Mapping[str, Any], current: Mapping[str, str]) -> None:
    expected = receipt.get("canonical_artifact_sha256")
    if not isinstance(expected, Mapping) or not expected:
        raise RuntimeError("First Blind authorization is missing canonical artifact hashes")
    normalized_expected = {str(key): str(value) for key, value in expected.items()}
    normalized_current = {str(key): str(value) for key, value in current.items()}
    if normalized_expected != normalized_current:
        changed = sorted(
            set(normalized_expected) | set(normalized_current),
            key=str,
        )
        mismatched = [
            name
            for name in changed
            if normalized_expected.get(name) != normalized_current.get(name)
        ]
        raise RuntimeError(
            "canonical First Blind artifacts changed after authorization: " + ", ".join(mismatched)
        )


def authorize(run_id: str, run_attempt: str) -> dict[str, Any]:
    if RECEIPT.exists():
        raise RuntimeError("First Blind consumption receipt already exists; a second authorization is forbidden")
    if RESULT.exists():
        raise RuntimeError("First Blind result already exists; a second score is forbidden")
    if not run_id or not run_attempt:
        raise RuntimeError("GitHub run id and attempt are required")

    freeze_check = verify_freeze(
        CORPUS_FREEZE,
        require_freeze=True,
        require_evaluator_frozen=True,
    )
    if not freeze_check.get("passed"):
        raise RuntimeError(
            "First Blind authorization requires a valid corpus/evaluator freeze: "
            + "; ".join(str(value) for value in freeze_check.get("errors") or [])
        )

    receipt = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v8_single_consumption",
        "state": "authorized_unscored",
        "github_run_id": str(run_id),
        "github_run_attempt": str(run_attempt),
        "canonical_artifact_sha256": _canonical_artifact_hashes(),
        "authorization_committed_before_scoring": True,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "rerun_allowed": False,
    }
    _write_json(RECEIPT, receipt)
    return receipt


def execute(run_id: str, run_attempt: str) -> dict[str, Any]:
    if not RECEIPT.exists():
        raise RuntimeError("First Blind authorization receipt is missing")
    if RESULT.exists():
        raise RuntimeError("First Blind result already exists; a second score is forbidden")

    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if receipt.get("state") != "authorized_unscored":
        raise RuntimeError(f"First Blind receipt is not executable: state={receipt.get('state')!r}")
    _validate_run_identity(receipt, str(run_id), str(run_attempt))
    _validate_artifact_hashes(receipt, _canonical_artifact_hashes())

    # Mark the local checkout consumed before any detector/admission/ranking code runs.
    # The authorization receipt has already been committed remotely by the workflow,
    # so another run cannot obtain a new authorization even if this process is interrupted.
    receipt["state"] = "consumed_before_scoring"
    receipt["first_blind_consumed"] = True
    receipt["scoring_started"] = True
    _write_json(RECEIPT, receipt)

    try:
        # Intentionally use only the evaluator's canonical defaults. No caller-supplied
        # corpus/shortlist/protocol/freeze path is accepted by the official consumption path.
        report = run_v8_benchmark()
    except Exception as exc:
        failure = {
            "version": VERSION,
            "rule_version": RULE_VERSION,
            "evaluation_kind": "fresh_blind_v8_single_consumption",
            "completed": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "scoring_executed": None,
            "first_blind_consumed": True,
        }
        _write_json(RESULT, failure)
        receipt["state"] = "consumed_execution_error"
        receipt["execution_error_type"] = type(exc).__name__
        receipt["execution_error"] = str(exc)
        receipt["scoring_executed"] = None
        receipt["result_sha256"] = _sha256(RESULT)
        _write_json(RECEIPT, receipt)
        return failure

    _write_json(RESULT, report)
    receipt["state"] = "completed"
    receipt["scoring_executed"] = report.get("scoring_executed") is True
    receipt["first_blind_consumed"] = True
    receipt["quality_gate_passed"] = bool((report.get("quality_gate") or {}).get("passed"))
    receipt["result_sha256"] = _sha256(RESULT)
    _write_json(RECEIPT, receipt)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorize or consume the single Analysis 6.33 v8 First Blind score")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("authorize", "execute"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--run-id", required=True)
        sub.add_argument("--run-attempt", required=True)
    args = parser.parse_args()

    if args.command == "authorize":
        result = authorize(args.run_id, args.run_attempt)
    else:
        result = execute(args.run_id, args.run_attempt)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

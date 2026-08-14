from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from v6_literal_capture_verify import _canonical, _identity, _sha256_json

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
CAPTURES = ROOT / "benchmarks/raw/sources/v6_literal_captures.jsonl"
REPORT = ROOT / "benchmarks/raw/sources/v6_literal_capture_ingest_report.json"
ALLOWED_ADJUDICATION_BASES = {
    "source_observation",
    "upstream_regression",
    "patched_control",
    "source_log_or_trace",
    "repository_test_fixture",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_capture_rows(*, require_complete: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    selected = {
        str(row.get("family") or ""): dict(row)
        for row in shortlist.get("selected") or []
        if isinstance(row, Mapping)
    }
    if plan.get("scoring_executed") is not False or plan.get("first_blind_consumed") is not False:
        raise RuntimeError("literal capture ingest requires an unscored, unconsumed capture plan")
    if len(plan.get("requirements") or []) != 144:
        raise RuntimeError("literal capture ingest requires the sealed 144-entry capture plan")
    if len(selected) != 36 or set(selected) != set(DETECTOR_SPECS):
        raise RuntimeError("literal capture ingest requires the sealed 36-family shortlist")

    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    errors: list[str] = []
    seen_evidence: set[str] = set()

    for requirement in plan.get("requirements") or []:
        family = str(requirement.get("family") or "")
        kind = str(requirement.get("case_kind") or "")
        capture_id = str(requirement.get("capture_id") or f"{family}/{kind}")
        rel = str(requirement.get("required_evidence_path") or "")
        evidence_path = ROOT / rel
        if not evidence_path.exists():
            missing.append(capture_id)
            continue
        digest = _sha256(evidence_path)
        if digest in seen_evidence:
            errors.append(f"{capture_id}: evidence content is reused by another capture")
            continue
        seen_evidence.add(digest)

        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(evidence, Mapping):
            errors.append(f"{capture_id}: evidence must be a JSON object")
            continue
        source = selected.get(family)
        if source is None:
            errors.append(f"{capture_id}: family is not in shortlist")
            continue
        for key, wanted in (
            ("family", family),
            ("case_kind", kind),
            ("source_root", source.get("source_root")),
            ("source_project", source.get("source_project")),
        ):
            if _identity(evidence.get(key)) != _identity(wanted):
                errors.append(f"{capture_id}: evidence.{key} does not match sealed plan/shortlist")

        raw = evidence.get("raw") if isinstance(evidence.get("raw"), Mapping) else None
        if not raw:
            errors.append(f"{capture_id}: evidence raw object is missing")
            continue
        raw_sha = _sha256_json(raw)
        if str(evidence.get("raw_sha256") or "").strip().lower() != raw_sha:
            errors.append(f"{capture_id}: evidence raw hash is invalid")

        adjudication = evidence.get("adjudication") if isinstance(evidence.get("adjudication"), Mapping) else {}
        if adjudication.get("detector_output_used") is not False:
            errors.append(f"{capture_id}: adjudication must not use detector output")
        if adjudication.get("admission_output_used") is not False:
            errors.append(f"{capture_id}: adjudication must not use admission output")
        if adjudication.get("ranking_output_used") is not False:
            errors.append(f"{capture_id}: adjudication must not use ranking output")
        basis = str(adjudication.get("basis") or "").strip()
        if basis not in ALLOWED_ADJUDICATION_BASES:
            errors.append(f"{capture_id}: adjudication basis is missing or unsupported")
        if not str(adjudication.get("notes") or "").strip():
            errors.append(f"{capture_id}: adjudication notes are required")

        signals = [str(value) for value in adjudication.get("expected_condition_signals") or [] if str(value)]
        allowed = set(DETECTOR_SPECS[family].condition_signals)
        if set(signals) - allowed:
            errors.append(f"{capture_id}: adjudication contains non-canonical condition signals")
        if kind == "positive" and not signals:
            errors.append(f"{capture_id}: positive evidence requires at least one pre-score expected condition signal")
        if kind != "positive" and signals:
            errors.append(f"{capture_id}: non-positive evidence cannot carry expected condition signals")

        capture_reference = str(evidence.get("capture_reference") or "").strip()
        captured_at = str(evidence.get("captured_at") or "").strip()
        capture_method = str(evidence.get("capture_method") or "").strip()
        source_snapshot = evidence.get("source_snapshot") if isinstance(evidence.get("source_snapshot"), Mapping) else {}

        rows.append({
            "family": family,
            "case_kind": kind,
            "source_root": source.get("source_root"),
            "source_project": source.get("source_project"),
            "source_date": captured_at,
            "raw": dict(raw),
            "expected_condition_signals": signals,
            "provenance": {
                "literal_capture": True,
                "capture_reference": capture_reference,
                "captured_at": captured_at,
                "capture_method": capture_method,
                "raw_sha256": raw_sha,
                "evidence_path": rel,
                "evidence_sha256": digest,
                "source_snapshot_sha256": str(source_snapshot.get("content_sha256") or "").strip().lower(),
                "adjudication_basis": basis,
                "detector_output_used": False,
                "admission_output_used": False,
                "ranking_output_used": False,
            },
        })

    if require_complete and missing:
        errors.append(f"literal evidence set incomplete: {len(missing)} missing captures")
    if require_complete and len(rows) != 144:
        errors.append(f"literal capture ingest requires 144 valid rows: {len(rows)}")

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_literal_capture_ingest_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "plan_sha256": _sha256(PLAN),
        "shortlist_sha256": _sha256(SHORTLIST),
        "require_complete": require_complete,
        "valid_capture_count": len(rows),
        "missing_capture_count": len(missing),
        "missing_capture_ids": missing,
        "error_count": len(errors),
        "errors": errors,
        "passed": not errors,
    }
    return rows, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.31 literal capture rows from verified evidence artifacts")
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    rows, report = build_capture_rows(require_complete=not args.allow_incomplete)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["passed"]:
        CAPTURES.write_text("\n".join(_canonical(row) for row in rows) + ("\n" if rows else ""), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

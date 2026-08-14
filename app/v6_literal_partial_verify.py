from __future__ import annotations

import json
import tempfile
from pathlib import Path

from raw_recon_corpus import ROOT
from v6_literal_capture_ingest import build_capture_rows
from v6_literal_capture_plan import build_plan
from v6_literal_capture_verify import verify_capture_set

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"


def verify_partial_inventory() -> dict:
    plan = build_plan()
    rows, ingest = build_capture_rows(require_complete=False)
    errors: list[str] = []
    if ingest.get("errors"):
        errors.extend(str(value) for value in ingest["errors"])
    if ingest.get("scoring_executed") is not False or ingest.get("first_blind_consumed") is not False:
        errors.append("partial ingest must remain unscored and unconsumed")
    if int(plan.get("evidence_present_count") or 0) != len(rows):
        errors.append(
            f"plan/ingest evidence count mismatch plan={plan.get('evidence_present_count')} rows={len(rows)}"
        )
    if int(plan.get("evidence_missing_count") or 0) != 144 - len(rows):
        errors.append("plan evidence_missing_count does not match partial ingest")

    verifier: dict = {}
    if rows:
        with tempfile.TemporaryDirectory(prefix="v6_partial_verify_") as tmp:
            capture_path = Path(tmp) / "captures.jsonl"
            capture_path.write_text(
                "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in rows) + "\n",
                encoding="utf-8",
            )
            verifier = verify_capture_set(captures_path=capture_path, require_complete=False)
            if not verifier.get("passed"):
                errors.extend(str(value) for value in verifier.get("errors") or [])
            if int(verifier.get("capture_count") or 0) != len(rows):
                errors.append("partial verifier capture count mismatch")
            if int(verifier.get("evidence_count") or 0) != len(rows):
                errors.append("partial verifier evidence count mismatch")
            if int(verifier.get("unique_evidence_hash_count") or 0) != len(rows):
                errors.append("partial verifier evidence uniqueness mismatch")
    elif plan.get("evidence_present_count") != 0:
        errors.append("plan claims evidence but ingest produced no rows")

    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_partial_literal_evidence_integrity",
        "passed": not errors,
        "errors": errors,
        "evidence_present_count": len(rows),
        "evidence_missing_count": 144 - len(rows),
        "family_with_evidence_count": len({row["family"] for row in rows}),
        "plan_evidence_present_count": plan.get("evidence_present_count"),
        "ingest_error_count": ingest.get("error_count"),
        "strict_partial_verifier": verifier,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
    }


def main() -> int:
    result = verify_partial_inventory()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

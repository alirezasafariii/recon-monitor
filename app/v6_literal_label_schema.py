from __future__ import annotations

import hashlib
import json
from pathlib import Path

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_label_schema.json"


def build() -> dict:
    families = {}
    for family, spec in sorted(DETECTOR_SPECS.items()):
        families[family] = {
            "condition_signals": sorted(spec.condition_signals),
            "blocking_controls": sorted(spec.blocking_controls),
            "override_signals": sorted(spec.override_signals),
            "schema_role": "canonical_vocabulary_only_not_target_adjudication",
        }
    payload = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_pre_score_label_vocabulary",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "family_count": len(families),
        "adjudication_policy": "Source evidence decides whether a condition is present; this file only freezes the canonical signal names accepted by the evaluator and verifier.",
        "families": families,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["schema_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return payload


def main() -> int:
    report = build()
    if report["family_count"] != 36:
        raise RuntimeError(f"label schema family count mismatch: {report['family_count']}")
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "scoring_executed": report["scoring_executed"],
        "first_blind_consumed": report["first_blind_consumed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

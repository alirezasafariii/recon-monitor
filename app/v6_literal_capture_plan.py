from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from v6_literal_capture_verify import ALLOWED_CAPTURE_METHODS, EVIDENCE_ROOT, SINGLE_VARIANTS

VERSION = "1.0.1"
RULE_VERSION = "2026.08.14.6.31.2"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"

VARIANT_PURPOSE = {
    "positive": "Literal vulnerable/positive observation from the selected fresh source, upstream PoC, regression reproduction, HTTP exchange, CLI output, or packet/log capture. No synthesized detector fixture is permitted.",
    "near_miss": "Literal source-grounded observation that is similar/confounding but does not satisfy the target condition. It must come from independently captured upstream evidence, not a mutated positive fixture.",
    "secure_negative": "Literal secure or patched behavior from the selected source, patched regression output, or an upstream secure control. It must demonstrate the target condition is absent without fabricating a response.",
    "sparse_noisy": "Literal partial/noisy observation from the source or its real execution/logging surface with insufficient positive evidence. It must be independently captured rather than field-deleted from another benchmark row.",
}


def _slug(value: Any) -> str:
    raw = str(value or "").strip().casefold()
    return "".join(ch if ch.isalnum() else "-" for ch in raw).strip("-")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_plan() -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    rows = [dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)]
    by_family = {str(row.get("family") or ""): row for row in rows}
    firewall = shortlist.get("firewall") if isinstance(shortlist.get("firewall"), Mapping) else {}
    if shortlist.get("selection_executes_scoring") is not False or firewall.get("scoring_executed") is not False:
        raise RuntimeError("capture planning requires an unscored sealed shortlist")
    if firewall.get("passed") is not True:
        raise RuntimeError("capture planning requires a firewall-passed shortlist")
    if len(rows) != 36 or set(by_family) != set(DETECTOR_SPECS):
        raise RuntimeError("capture planning requires exactly 36 selected families")

    requirements: list[dict[str, Any]] = []
    present = 0
    for family in sorted(by_family):
        source = by_family[family]
        for kind in sorted(SINGLE_VARIANTS):
            filename = f"{_slug(family)}--{_slug(kind)}.json"
            evidence_path = EVIDENCE_ROOT / filename
            evidence_present = evidence_path.exists()
            if evidence_present:
                present += 1
            requirements.append({
                "capture_id": f"v6-{family}-{kind}",
                "family": family,
                "case_kind": kind,
                "source_root": source.get("source_root"),
                "source_project": source.get("source_project"),
                "canonical_source_reference": source.get("canonical_advisory_url") or source.get("source_url") or source.get("repository_advisory_url"),
                "source_selection_track": source.get("source_selection_track"),
                "source_advisory_type": source.get("advisory_source_type"),
                "required_evidence_path": evidence_path.relative_to(ROOT).as_posix(),
                "evidence_present": evidence_present,
                "evidence_sha256": _sha256(evidence_path) if evidence_present else None,
                "variant_purpose": VARIANT_PURPOSE[kind],
                "allowed_capture_methods": sorted(ALLOWED_CAPTURE_METHODS),
                "source_snapshot_required": True,
                "collector_metadata_required": True,
                "raw_sha256_required": True,
                "evidence_sha256_required": True,
                "independent_literal_observation_required": True,
                "synthetic_fixture_generation_forbidden": True,
                "mutation_of_another_variant_to_create_this_variant_forbidden": True,
                "detector_output_may_not_be_used_for_collection_or_selection": True,
                "admission_output_may_not_be_used_for_collection_or_selection": True,
                "ranking_output_may_not_be_used_for_collection_or_selection": True,
            })

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_literal_capture_acquisition_plan_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "source_shortlist_sha256": _sha256(SHORTLIST),
        "family_count": 36,
        "variant_count_per_family": 4,
        "required_capture_count": 144,
        "evidence_present_count": present,
        "evidence_missing_count": 144 - present,
        "all_evidence_present": present == 144,
        "capture_methods_allowed": sorted(ALLOWED_CAPTURE_METHODS),
        "requirements": requirements,
    }
    if len(requirements) != 144:
        raise RuntimeError(f"capture plan cardinality mismatch: {len(requirements)}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the unscored Analysis 6.31 literal capture acquisition plan")
    parser.add_argument("--check", action="store_true", help="verify the committed plan is current instead of rewriting it")
    args = parser.parse_args()
    report = build_plan()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != encoded:
            print("Analysis 6.31 literal capture plan is stale", flush=True)
            return 1
    else:
        OUTPUT.write_text(encoded, encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("family_count", "required_capture_count", "evidence_present_count", "evidence_missing_count", "scoring_executed")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

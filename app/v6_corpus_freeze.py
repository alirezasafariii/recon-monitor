from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT

VERSION = "2.0.0"
RULE_VERSION = "2026.08.14.6.31.13"
SRC = ROOT / "benchmarks/raw/sources"
FREEZE = SRC / "v6_corpus_freeze.json"
MANIFEST = SRC / "v6_freeze_manifest.sha256"

REQUIRED_SOURCE_ARTIFACTS = [
    "benchmarks/raw/sources/v6_protocol.json",
    "benchmarks/raw/sources/v6_candidates.json",
    "benchmarks/raw/sources/v6_complement_overrides.json",
    "benchmarks/raw/sources/v6_owasp_writeup_grounding.json",
    "benchmarks/raw/sources/v6_owasp_writeup_candidates.json",
    "benchmarks/raw/sources/v6_owasp_exact_overrides.json",
    "benchmarks/raw/sources/v6_owasp_extension_grounding.json",
    "benchmarks/raw/sources/v6_owasp_extension_candidates.json",
    "benchmarks/raw/sources/v6_shortlist.json",
    "benchmarks/raw/sources/v6_selection_final_report.json",
    "benchmarks/raw/sources/v6_literal_source_research.json",
    "benchmarks/raw/sources/v6_literal_linked_research.json",
    "benchmarks/raw/sources/v6_literal_linked_summary.json",
    "benchmarks/raw/sources/v6_literal_capture_feasibility.json",
    "benchmarks/raw/sources/v6_literal_label_schema.json",
    "benchmarks/raw/sources/v6_literal_capture_plan.json",
    "benchmarks/raw/sources/v6_literal_captures.jsonl",
    "benchmarks/raw/sources/v6_literal_capture_ingest_report.json",
    "benchmarks/raw/sources/v6_literal_capture_verification.json",
    "benchmarks/raw/sources/v6_materialization_report.json",
    "benchmarks/raw/sources/v6_validation_report.json",
    "benchmarks/raw/analysis_raw_v6.jsonl",
]


def _load(rel: str) -> dict[str, Any]:
    path = ROOT / rel
    if not path.exists():
        raise RuntimeError(f"required freeze input is missing: {rel}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise RuntimeError(f"expected JSON object: {rel}")
    return dict(value)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _identity(value: Any) -> str:
    return str(value or "").strip().casefold()


def _assert_unscored(name: str, doc: Mapping[str, Any]) -> None:
    if doc.get("scoring_executed") is not False:
        raise RuntimeError(f"{name} must remain unscored")
    if "first_blind_consumed" in doc and doc.get("first_blind_consumed") is not False:
        raise RuntimeError(f"{name} cannot consume First Blind before freeze")


def _assert_source_research_matches_shortlist(source_research: Mapping[str, Any], shortlist: Mapping[str, Any]) -> None:
    selected = {
        str(row.get("family") or ""): row
        for row in shortlist.get("selected") or []
        if isinstance(row, Mapping)
    }
    entries = {
        str(row.get("family") or ""): row
        for row in source_research.get("entries") or []
        if isinstance(row, Mapping)
    }
    if set(entries) != set(selected):
        raise RuntimeError("passive source research family coverage does not match shortlist")
    for family, source in selected.items():
        research = entries[family]
        if _identity(research.get("source_root")) != _identity(source.get("source_root")):
            raise RuntimeError(f"{family}: passive research source_root drift")
        if _identity(research.get("source_project")) != _identity(source.get("source_project")):
            raise RuntimeError(f"{family}: passive research source_project drift")
        if int(research.get("fetch_status") or 0) != 200 or research.get("snapshot_payload") is None:
            raise RuntimeError(f"{family}: passive source snapshot is not complete")
        if not str(research.get("snapshot_sha256") or "").strip():
            raise RuntimeError(f"{family}: passive source snapshot hash is missing")


def _assert_label_schema(schema: Mapping[str, Any]) -> None:
    if int(schema.get("family_count") or 0) != 36:
        raise RuntimeError("label schema family count mismatch")
    if schema.get("detector_output_used") is not False or schema.get("admission_output_used") is not False or schema.get("ranking_output_used") is not False:
        raise RuntimeError("label vocabulary must not use engine outputs")
    families = schema.get("families") if isinstance(schema.get("families"), Mapping) else {}
    if len(families) != 36:
        raise RuntimeError("label schema family map mismatch")
    expected = str(schema.get("schema_content_sha256") or "")
    unsigned = dict(schema)
    unsigned.pop("schema_content_sha256", None)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != expected:
        raise RuntimeError("label schema embedded content hash mismatch")


def _protected_paths(evidence_manifest: Mapping[str, Any]) -> list[str]:
    paths: set[str] = set(REQUIRED_SOURCE_ARTIFACTS)

    for pattern in (
        "app/v6_*.py",
        "app/raw_recon_v6_*.py",
        "tests/test_v6_*.py",
        ".github/workflows/analysis-631-*.yml",
    ):
        for path in ROOT.glob(pattern):
            if path.is_file():
                paths.add(_rel(path))

    evidence_dir = SRC / "v6_capture_evidence"
    evidence_files = sorted(path for path in evidence_dir.glob("*.json") if path.is_file())
    if len(evidence_files) != 144:
        raise RuntimeError(f"freeze requires exactly 144 literal evidence files, got {len(evidence_files)}")
    for path in evidence_files:
        rel = _rel(path)
        expected = str(evidence_manifest.get(rel) or "")
        if not expected:
            raise RuntimeError(f"evidence file missing from verifier manifest: {rel}")
        if _sha256(path) != expected:
            raise RuntimeError(f"evidence file hash differs from verifier manifest: {rel}")
        paths.add(rel)

    return sorted(paths)


def build_freeze() -> dict[str, Any]:
    if FREEZE.exists():
        raise RuntimeError("Analysis 6.31 corpus freeze already exists; create a new protocol/version instead of mutating it")

    protocol = _load("benchmarks/raw/sources/v6_protocol.json")
    shortlist = _load("benchmarks/raw/sources/v6_shortlist.json")
    selection = _load("benchmarks/raw/sources/v6_selection_final_report.json")
    source_research = _load("benchmarks/raw/sources/v6_literal_source_research.json")
    linked_research = _load("benchmarks/raw/sources/v6_literal_linked_research.json")
    linked_summary = _load("benchmarks/raw/sources/v6_literal_linked_summary.json")
    feasibility = _load("benchmarks/raw/sources/v6_literal_capture_feasibility.json")
    label_schema = _load("benchmarks/raw/sources/v6_literal_label_schema.json")
    plan = _load("benchmarks/raw/sources/v6_literal_capture_plan.json")
    ingest = _load("benchmarks/raw/sources/v6_literal_capture_ingest_report.json")
    verification = _load("benchmarks/raw/sources/v6_literal_capture_verification.json")
    materialization = _load("benchmarks/raw/sources/v6_materialization_report.json")
    validation = _load("benchmarks/raw/sources/v6_validation_report.json")

    for name, doc in (
        ("selection", selection),
        ("source_research", source_research),
        ("linked_research", linked_research),
        ("linked_summary", linked_summary),
        ("feasibility", feasibility),
        ("label_schema", label_schema),
        ("capture_plan", plan),
        ("capture_ingest", ingest),
        ("capture_verification", verification),
        ("materialization", materialization),
        ("validation", validation),
    ):
        _assert_unscored(name, doc)

    if shortlist.get("selection_executes_scoring") is not False:
        raise RuntimeError("shortlist selection must remain unscored")
    if int(shortlist.get("family_count") or 0) != 36:
        raise RuntimeError("shortlist family count mismatch")
    if int(shortlist.get("unique_root_count") or 0) != 36 or int(shortlist.get("unique_project_count") or 0) != 36:
        raise RuntimeError("shortlist source uniqueness mismatch")
    if int(shortlist.get("owasp_grounded_family_count") or 0) != 14:
        raise RuntimeError("shortlist OWASP-grounded count mismatch")
    if int(shortlist.get("complement_override_family_count") or 0) != 13:
        raise RuntimeError("shortlist complement override count mismatch")
    if int(shortlist.get("legacy_semantic_family_count") or 0) != 9:
        raise RuntimeError("shortlist legacy semantic count mismatch")
    firewall = shortlist.get("firewall") if isinstance(shortlist.get("firewall"), Mapping) else {}
    if firewall.get("passed") is not True or firewall.get("scoring_executed") is not False or firewall.get("rejected") != []:
        raise RuntimeError("shortlist firewall is not a clean unscored pass")

    if int(selection.get("family_count") or 0) != 36:
        raise RuntimeError("selection report family count mismatch")
    if int(selection.get("complement_override_family_count") or 0) != 13 or int(selection.get("legacy_semantic_family_count") or 0) != 9:
        raise RuntimeError("selection report source model mismatch")

    if int(source_research.get("family_count") or 0) != 36 or int(source_research.get("successful_snapshot_count") or 0) != 36 or int(source_research.get("unresolved_snapshot_count") or -1) != 0:
        raise RuntimeError("canonical passive source research is incomplete")
    if source_research.get("active_target_validation_performed") is not False:
        raise RuntimeError("canonical source research must remain passive")
    _assert_source_research_matches_shortlist(source_research, shortlist)

    if int(linked_research.get("family_count") or 0) != 36 or int(linked_research.get("successful_link_snapshot_count") or 0) <= 0:
        raise RuntimeError("linked passive research is incomplete")
    if linked_research.get("active_target_validation_performed") is not False:
        raise RuntimeError("linked research must remain passive")
    if int(linked_summary.get("family_count") or 0) != 36:
        raise RuntimeError("linked research summary family count mismatch")

    if int(feasibility.get("family_count") or 0) != 36 or int(feasibility.get("required_capture_count") or 0) != 144:
        raise RuntimeError("capture feasibility report cardinality mismatch")
    if int(feasibility.get("evidence_present_count") or 0) != 144 or int(feasibility.get("evidence_missing_count") or -1) != 0:
        raise RuntimeError("capture feasibility report must be refreshed to 144/144 before freeze")

    _assert_label_schema(label_schema)

    if int(plan.get("family_count") or 0) != 36 or int(plan.get("required_capture_count") or 0) != 144:
        raise RuntimeError("capture plan cardinality mismatch")
    if plan.get("all_evidence_present") is not True or int(plan.get("evidence_present_count") or 0) != 144 or int(plan.get("evidence_missing_count") or -1) != 0:
        raise RuntimeError("capture plan is not complete")
    if str(plan.get("source_shortlist_sha256") or "") != _sha256(SRC / "v6_shortlist.json"):
        raise RuntimeError("capture plan is not bound to current shortlist")

    if ingest.get("passed") is not True or int(ingest.get("valid_capture_count") or 0) != 144 or int(ingest.get("missing_capture_count") or -1) != 0 or int(ingest.get("error_count") or -1) != 0:
        raise RuntimeError("literal capture ingest is not a clean 144/144 pass")
    if str(ingest.get("plan_sha256") or "") != _sha256(SRC / "v6_literal_capture_plan.json"):
        raise RuntimeError("capture ingest plan hash mismatch")
    if str(ingest.get("shortlist_sha256") or "") != _sha256(SRC / "v6_shortlist.json"):
        raise RuntimeError("capture ingest shortlist hash mismatch")

    if verification.get("passed") is not True or int(verification.get("capture_count") or 0) != 144 or int(verification.get("evidence_count") or 0) != 144 or int(verification.get("unique_evidence_hash_count") or 0) != 144:
        raise RuntimeError("literal capture verification is not a clean 144/144 pass")
    evidence_manifest = verification.get("evidence_manifest") if isinstance(verification.get("evidence_manifest"), Mapping) else {}
    if len(evidence_manifest) != 144:
        raise RuntimeError("literal capture evidence manifest must contain 144 entries")

    if materialization.get("fresh_raw_claim") is not True or materialization.get("raw_capture_mode") != "literal_source_capture":
        raise RuntimeError("materialization is not evidence-backed literal raw")
    expected_counts = {
        "literal_single_capture_count": 144,
        "input_capture_count": 144,
        "single_case_count": 144,
        "pair_case_count": 72,
        "triad_case_count": 60,
        "case_count": 276,
        "family_count": 36,
    }
    for key, expected in expected_counts.items():
        if int(materialization.get(key) or 0) != expected:
            raise RuntimeError(f"materialization count mismatch for {key}")

    if validation.get("passed") is not True or int(validation.get("literal_single_capture_count") or 0) != 144 or int(validation.get("label_leakage_count") or -1) != 0:
        raise RuntimeError("corpus validation is not a clean literal-fresh pass")
    validation_firewall = validation.get("source_firewall") if isinstance(validation.get("source_firewall"), Mapping) else {}
    if validation_firewall.get("passed") is not True:
        raise RuntimeError("validation source firewall did not pass")

    protected_paths = _protected_paths(evidence_manifest)
    protected: dict[str, str] = {}
    for rel in protected_paths:
        path = ROOT / rel
        if not path.exists():
            raise RuntimeError(f"protected path disappeared during freeze: {rel}")
        protected[rel] = _sha256(path)

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_status": "sealed_evidence_backed_literal_fresh_unscored_corpus",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "first_blind_evaluator_frozen": False,
        "case_count": 276,
        "single_case_count": 144,
        "pair_case_count": 72,
        "triad_case_count": 60,
        "literal_single_capture_count": 144,
        "literal_evidence_artifact_count": 144,
        "family_count": 36,
        "source_root_count": shortlist["unique_root_count"],
        "source_project_count": shortlist["unique_project_count"],
        "source_model": {
            "owasp_grounded_family_count": 14,
            "complement_override_family_count": 13,
            "legacy_semantic_family_count": 9,
        },
        "research_model": {
            "canonical_source_snapshot_count": 36,
            "linked_snapshot_count": int(linked_research.get("successful_link_snapshot_count") or 0),
            "active_target_validation_performed": False,
        },
        "pre_registered_gates": {
            "single": protocol["single_quality_gates"],
            "pair": protocol["pair_quality_gates"],
            "triad": protocol["triad_quality_gates"],
        },
        "protected_sha256": protected,
        "protected_count": len(protected),
        "mutation_policy": "all Analysis 6.31 source inputs, passive research, label vocabulary, capture planning and collectors, all 144 evidence artifacts, ingest, corpus, validation, evaluator code, tests and Analysis 6.31 workflows are immutable after this freeze; evaluator authorization is frozen separately before the one-time score",
    }
    return report


def write_freeze() -> dict[str, Any]:
    report = build_freeze()
    FREEZE.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    MANIFEST.write_text(
        "".join(f"{digest}  {rel}\n" for rel, digest in sorted(report["protected_sha256"].items())),
        encoding="utf-8",
    )
    return report


def main() -> int:
    report = write_freeze()
    print(json.dumps({
        "evaluation_status": report["evaluation_status"],
        "protected_count": report["protected_count"],
        "literal_evidence_artifact_count": report["literal_evidence_artifact_count"],
        "scoring_executed": report["scoring_executed"],
        "first_blind_consumed": report["first_blind_consumed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

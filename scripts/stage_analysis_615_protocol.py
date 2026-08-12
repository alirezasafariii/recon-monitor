from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"


def blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def tree_sha(relative: str) -> str:
    result = subprocess.run(["git", "rev-parse", f"HEAD:{relative}"], cwd=ROOT, text=True, capture_output=True, check=True)
    return result.stdout.strip()


v2_corpus = (APP / "raw_recon_v2_corpus.py").read_text(encoding="utf-8")
v3_corpus = (
    v2_corpus
    .replace("RAW_V2", "RAW_V3")
    .replace("V2_", "V3_")
    .replace("validate_v2_corpus", "validate_v3_corpus")
    .replace("raw v2", "raw v3")
    .replace("Raw v2", "Raw v3")
    .replace("v2 prior", "v3 prior")
    .replace("v2 positive", "v3 positive")
    .replace("v2 source", "v3 source")
    .replace("v2_prior_corpus_count", "v3_prior_corpus_count")
)
v3_corpus = v3_corpus.replace(
    'ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl",\n)',
    'ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl",\n    ROOT / "benchmarks" / "raw" / "analysis_raw_v2.jsonl",\n)',
)
v3_corpus = v3_corpus.replace(
    '"""Validate the second raw holdout without executing detector scoring.',
    '"""Validate the third raw holdout without executing detector scoring.',
)
v3_corpus = v3_corpus.replace(
    'Analysis 6.13 fixes the main fixture-design failure found in raw v1:',
    'Analysis 6.15 preserves the collision/observability contract established after raw v1:',
)
(APP / "raw_recon_v3_corpus.py").write_text(v3_corpus, encoding="utf-8")

v2_bench = (APP / "raw_recon_v2_benchmark.py").read_text(encoding="utf-8")
v3_bench = (
    v2_bench
    .replace("raw_recon_v2_corpus", "raw_recon_v3_corpus")
    .replace("validate_v2_corpus", "validate_v3_corpus")
    .replace("RAW_RECON_V2", "RAW_RECON_V3")
    .replace("verify_v2_freeze", "verify_v3_freeze")
    .replace("benchmark_v2_file", "benchmark_v3_file")
    .replace("analysis_raw_v2.jsonl", "analysis_raw_v3.jsonl")
    .replace('"v2.json"', '"v3.json"')
    .replace("v2 freeze", "v3 freeze")
    .replace("v2 acceptance", "v3 acceptance")
    .replace("v2 observability", "v3 observability")
    .replace("Raw v2", "Raw v3")
    .replace("raw v2", "raw v3")
    .replace("v2 holdout", "v3 holdout")
    .replace("Analysis 6.13", "Analysis 6.15")
    .replace("2026.08.11.6.13", "2026.08.12.6.15")
)
(APP / "raw_recon_v3_benchmark.py").write_text(v3_bench, encoding="utf-8")

DOC = ROOT / "docs" / "ANALYSIS_ENGINE_6_15_FRESH_RAW_HOLDOUT_V3.md"
DOC.write_text("""# Analysis Engine 6.15 — Fresh Raw Holdout v3

Analysis 6.15 performs one new blind raw-artifact evaluation of the frozen Analysis 6.14 engine. The benchmark protocol, quality gates, production code hashes, collision rules, and corpus validator are sealed before any new v3 source discovery.

## Scientific contract

- Raw v1 and raw v2 are consumed diagnostics and are never treated as fresh again.
- Source roots and canonical advisory URLs must be absent from Golden v3, Golden v4, raw v1, and raw v2.
- Every root has four variants: positive, near_miss, secure_negative, sparse_noisy.
- A positive raw artifact must differ from near_miss and secure_negative and contain a target-observable delta.
- No engine-native signal names, typed evidence arrays, CWE labels, WSTG labels, or advisory conclusions may be copied into raw detector input.
- No production tuning is permitted after the first v3 score while still calling v3 fresh/blind.
- The first score consumes v3 permanently, regardless of PASS or FAIL.

## Pre-registered quality gates

The same raw gates used by Analysis 6.13 are retained for direct comparability: extraction P/R, routing Top-1/Top-3, admission P/R, abstention, FPR, wrong-family promotion, end-to-end accuracy, source overlap, and label leakage. Positive/control raw collision must be zero and positive observable-delta rate must be 1.0.

A fresh PASS demonstrates generalization only within this curated raw-artifact benchmark boundary; it is not a claim of universal real-world vulnerability-detection accuracy.
""", encoding="utf-8")

TEST = ROOT / "tests" / "test_raw_recon_v3_protocol_v6150.py"
TEST.write_text("""from __future__ import annotations

import json
import unittest
from pathlib import Path

from raw_recon_benchmark import RAW_QUALITY_GATES
from raw_recon_v3_benchmark import RAW_RECON_V3_BENCHMARK_VERSION, RAW_RECON_V3_RULE_VERSION, verify_v3_freeze
from raw_recon_v3_corpus import RAW_V3_CORPUS_VALIDATOR_VERSION, V3_PRIOR_CORPORA

ROOT = Path(__file__).resolve().parents[1]


class RawReconV3Protocol6150Tests(unittest.TestCase):
    def test_protocol_versions(self):
        self.assertEqual(RAW_RECON_V3_BENCHMARK_VERSION, "1.0.0")
        self.assertEqual(RAW_RECON_V3_RULE_VERSION, "2026.08.12.6.15")
        self.assertEqual(RAW_V3_CORPUS_VALIDATOR_VERSION, "1.0.0")

    def test_prior_index_includes_all_consumed_raw_corpora(self):
        names = {path.name for path in V3_PRIOR_CORPORA}
        self.assertIn("analysis_golden_v3.jsonl", names)
        self.assertIn("analysis_golden_v4.jsonl", names)
        self.assertIn("analysis_raw_v1.jsonl", names)
        self.assertIn("analysis_raw_v2.jsonl", names)

    def test_manifest_is_pre_registered_and_unscored(self):
        manifest = json.loads((ROOT / "benchmarks/raw/splits/v3.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["evaluation_status"], "protocol_sealed_collection_open")
        self.assertFalse(manifest["seal"]["scored"])
        self.assertFalse(manifest["corpus"]["scored"])
        expected = {metric: {"direction": direction, "threshold": threshold} for metric, (direction, threshold) in RAW_QUALITY_GATES.items()}
        self.assertEqual(manifest["acceptance_gates"], expected)
        self.assertEqual(manifest["observability_gates"]["positive_control_raw_collision_count"]["threshold"], 0)
        self.assertEqual(manifest["observability_gates"]["positive_observable_delta_rate"]["threshold"], 1.0)

    def test_freeze_verifier_passes(self):
        report = verify_v3_freeze(ROOT / "benchmarks/raw/splits/v3.json")
        self.assertTrue(report["passed"], report["errors"])


if __name__ == "__main__":
    unittest.main()
""", encoding="utf-8")

RAW_GATES = {
    "condition_extraction_precision": {"direction": "min", "threshold": 0.90},
    "condition_extraction_recall": {"direction": "min", "threshold": 0.75},
    "routing_top1_accuracy": {"direction": "min", "threshold": 0.80},
    "routing_top3_accuracy": {"direction": "min", "threshold": 0.95},
    "admission_precision": {"direction": "min", "threshold": 0.93},
    "admission_recall": {"direction": "min", "threshold": 0.75},
    "abstention_accuracy": {"direction": "min", "threshold": 0.90},
    "false_promotion_rate": {"direction": "max", "threshold": 0.07},
    "wrong_family_promotion_rate": {"direction": "max", "threshold": 0.05},
    "end_to_end_accuracy": {"direction": "min", "threshold": 0.80},
    "prior_source_root_overlap_rate": {"direction": "max", "threshold": 0.0},
    "raw_label_leakage_rate": {"direction": "max", "threshold": 0.0},
}
SOURCE_BUCKETS = [
    {"family": "broken_object_authorization", "cwe": 639},
    {"family": "broken_function_authorization", "cwe": 862},
    {"family": "mass_assignment", "cwe": 915},
    {"family": "authentication_session", "cwe": 287},
    {"family": "account_enumeration", "cwe": 203},
    {"family": "open_redirect", "cwe": 601},
    {"family": "ssrf", "cwe": 918},
    {"family": "file_upload", "cwe": 434},
    {"family": "path_traversal", "cwe": 22},
    {"family": "information_disclosure", "cwe": 200},
    {"family": "cors_misconfiguration", "cwe": 942},
    {"family": "race_condition", "cwe": 362},
    {"family": "sql_injection", "cwe": 89},
    {"family": "nosql_injection", "cwe": 943},
    {"family": "command_injection", "cwe": 78},
    {"family": "server_side_template_injection", "cwe": 1336},
    {"family": "ldap_injection", "cwe": 90},
    {"family": "unrestricted_resource_consumption", "cwe": 400},
    {"family": "security_misconfiguration", "cwe": 209},
    {"family": "secret_exposure", "cwe": 798},
]

protected_files = [
    "app/analysis_engine.py",
    "app/bug_candidates.py",
    "app/security_reasoning.py",
    "app/hypothesis_admission.py",
    "app/analysis_standards.py",
    "app/analysis_ranking.py",
    "app/family_reasoners.py",
    "app/security_family_ranker.py",
    "app/family_evidence_extractors.py",
    "app/raw_condition_reconstruction.py",
    "app/raw_recon_v3_benchmark.py",
    "app/raw_recon_v3_corpus.py",
]
protocol_files = [
    "app/raw_recon_v3_benchmark.py",
    "app/raw_recon_v3_corpus.py",
    "docs/ANALYSIS_ENGINE_6_15_FRESH_RAW_HOLDOUT_V3.md",
    "tests/test_raw_recon_v3_protocol_v6150.py",
]
manifest = {
    "schema_version": "1.0",
    "protocol": "analysis-6.15-fresh-raw-holdout-v3",
    "evaluation_status": "protocol_sealed_collection_open",
    "protocol_sealed_at": "2026-08-12",
    "frozen_engine_head_sha": "50b9875c3d358f6a3e38a4946e5d72eb1e3dc50e",
    "frozen_engine": {
        "analysis_engine_version": "6.14.0",
        "detector_execution_engine_version": "1.2.0",
        "detector_execution_rule_version": "2026.08.12.6.14",
        "raw_condition_reconstruction_version": "1.1.0",
        "raw_condition_reconstruction_rule_version": "2026.08.12.6.14",
        "raw_v3_benchmark_version": "1.0.0",
        "raw_v3_benchmark_rule_version": "2026.08.12.6.15",
    },
    "acceptance_gates": RAW_GATES,
    "observability_gates": {
        "positive_control_raw_collision_count": {"direction": "max", "threshold": 0},
        "positive_observable_delta_rate": {"direction": "min", "threshold": 1.0},
    },
    "collection_target": {
        "minimum_cases": 96,
        "minimum_source_roots": 24,
        "minimum_source_projects": 20,
        "minimum_positive_families": 18,
        "variants_per_root": 4,
        "required_case_variants": ["positive", "near_miss", "secure_negative", "sparse_noisy"],
    },
    "corpus": {"path": "benchmarks/raw/analysis_raw_v3.jsonl", "sealed": False, "scored": False},
    "seal": {"corpus_materialized": False, "scored": False, "note": "Production logic, benchmark gates, v3 observability rules, and benchmark harness were frozen before any new v3 advisory source discovery."},
    "pre_freeze_exclusions": {"source_roots": [], "reason": "No new v3 advisory roots were queried or inspected before protocol sealing."},
    "prior_evaluations": {
        "analysis_golden_v3": {"evaluation_status": "consumed_diagnostic_regression_only"},
        "analysis_golden_v4": {"evaluation_status": "consumed_postfreeze_structured_evidence"},
        "analysis_raw_v1": {"evaluation_status": "evaluated_once_consumed"},
        "analysis_raw_v2": {"evaluation_status": "evaluated_once_consumed", "run_id": "31471744115"},
    },
    "source_buckets": SOURCE_BUCKETS,
    "source_policy": {
        "primary_sources_only": True,
        "github_reviewed_advisories_preferred": True,
        "https_required": True,
        "require_repository_advisory_url": True,
        "require_source_code_location": True,
        "minimum_advisory_description_chars": 160,
        "root_is_split_unit": True,
        "root_must_be_absent_from_v3_v4_raw_v1_raw_v2": True,
        "url_must_be_absent_from_v3_v4_raw_v1_raw_v2": True,
        "typed_evidence_arrays_forbidden": True,
        "raw_engine_signal_keys_forbidden": True,
        "positive_raw_must_differ_from_near_miss_and_secure_negative": True,
        "positive_details_must_contain_target_observable_delta": True,
        "retuning_after_first_evaluation": False,
        "selection_rule": "After protocol seal, query declared source buckets. Select reviewed primary advisories whose source roots and canonical advisory URLs are absent from Golden v3, Golden v4, raw v1, and raw v2. Prefer unused projects and facts that translate into target-observable raw artifacts without copying engine labels or advisory conclusions into detector input. No detector scoring is allowed during discovery, selection, materialization, validation, or corpus sealing.",
    },
    "reuse_policy": "After the first fresh evaluation, v3 is consumed. Every later run must be explicitly labeled regression-only and must never be described as fresh or blind.",
    "protected_files": {relative: blob_sha(ROOT / relative) for relative in protected_files},
    "protected_trees": {"app/family_detectors": tree_sha("app/family_detectors")},
    "protocol_files": {relative: blob_sha(ROOT / relative) for relative in protocol_files},
}
manifest_path = ROOT / "benchmarks" / "raw" / "splits" / "v3.json"
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps({"protocol": manifest["protocol"], "protected_file_count": len(manifest["protected_files"]), "source_bucket_count": len(SOURCE_BUCKETS), "status": manifest["evaluation_status"]}, indent=2))

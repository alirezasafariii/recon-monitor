from __future__ import annotations

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

    def test_manifest_preserves_preregistered_gates_across_lifecycle(self):
        manifest = json.loads((ROOT / "benchmarks/raw/splits/v3.json").read_text(encoding="utf-8"))
        self.assertIn(manifest["evaluation_status"], {"protocol_sealed_collection_open", "sealed_unscored", "evaluated_once_consumed"})
        expected = {metric: {"direction": direction, "threshold": threshold} for metric, (direction, threshold) in RAW_QUALITY_GATES.items()}
        self.assertEqual(manifest["acceptance_gates"], expected)
        self.assertEqual(manifest["observability_gates"]["positive_control_raw_collision_count"]["threshold"], 0)
        self.assertEqual(manifest["observability_gates"]["positive_observable_delta_rate"]["threshold"], 1.0)
        if manifest["evaluation_status"] == "evaluated_once_consumed":
            self.assertTrue(manifest["seal"]["scored"])
            self.assertTrue(manifest["corpus"]["scored"])
            self.assertTrue(manifest["evaluation"]["fresh_run_consumed"])
            self.assertEqual(manifest["evaluation"]["first_and_only_fresh_run_id"], "31559204156")
            self.assertEqual(manifest["evaluation"]["result_path"], "benchmarks/raw/results/analysis_raw_v3_first_blind.json")
        else:
            self.assertFalse(manifest["seal"]["scored"])
            self.assertFalse(manifest["corpus"]["scored"])

    def test_consumed_freeze_detects_postfreeze_engine_mutation(self):
        manifest = json.loads((ROOT / "benchmarks/raw/splits/v3.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["evaluation_status"], "evaluated_once_consumed")
        self.assertTrue(manifest["evaluation"]["fresh_run_consumed"])
        report = verify_v3_freeze(ROOT / "benchmarks/raw/splits/v3.json")
        self.assertFalse(report["passed"], report["errors"])
        errors = [str(value) for value in report["errors"]]
        expected_paths = {"app/analysis_engine.py", "app/bug_candidates.py", "app/security_reasoning.py"}
        changed_paths = {
            path
            for path in expected_paths
            if any(f"protected file changed after v3 freeze: {path}" in error for error in errors)
        }
        self.assertEqual(changed_paths, expected_paths, errors)
        self.assertFalse(any("benchmarks/raw/analysis_raw_v3.jsonl" in error for error in errors), errors)
        self.assertFalse(any("app/raw_recon_v3_benchmark.py" in error for error in errors), errors)
        self.assertFalse(any("app/raw_recon_v3_corpus.py" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()

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

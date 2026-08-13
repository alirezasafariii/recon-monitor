from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import analysis_engine
import bug_candidates
import security_reasoning
from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, get_detector_spec, validate_detector_registry
from family_detectors.base import DETECTOR_RULE_VERSION
from family_detectors.execution import EXECUTION_ENGINE_VERSION, EXECUTION_RULE_VERSION
from family_evidence_extractors import FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION, FAMILY_EVIDENCE_EXTRACTOR_VERSION, FAMILY_EVIDENCE_EXTRACTOR_PROFILES
from family_reasoners import FAMILY_REASONER_PROFILES, FAMILY_REASONER_RULE_VERSION, FAMILY_REASONER_VERSION
from hypothesis_admission import ADMISSION_ENGINE_VERSION, ADMISSION_RULE_VERSION, FAMILY_ADMISSION_POLICIES
from raw_condition_reconstruction import RECONSTRUCTION_ENGINE_VERSION, RECONSTRUCTION_RULE_VERSION
from raw_recon_v4_blind import verify_v4_freeze


CORPUS_SHA256 = "fe6936881b7fe0e8c71c9bc76a0f87d02446a3d703ec1dddf84e0b6caa7fb9b6"
SHORTLIST_SHA256 = "d329752e8b6045b433e3d490c0ff438f067577840fb5429a80721a0f79a34f85"
FIRST_BLIND_REPORT_SHA256 = "5c9d241b9da38fb374caa1851b8474aab2580dbafd1dbf25b6e68db267097960"


class Analysis627SealTests(unittest.TestCase):
    def test_analysis_layer_versions_preserve_627_floor(self) -> None:
        self.assertGreaterEqual(tuple(int(x) for x in analysis_engine.ENGINE_VERSION.split(".")), (6, 27, 0))
        self.assertGreaterEqual(tuple(int(x) for x in bug_candidates.CANDIDATE_ENGINE_VERSION.split(".")), (6, 27, 0))
        self.assertGreaterEqual(tuple(int(x) for x in security_reasoning.REASONING_ENGINE_VERSION.split(".")), (6, 27, 0))
        self.assertGreaterEqual(tuple(int(x) for x in analysis_engine.RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))
        self.assertGreaterEqual(tuple(int(x) for x in bug_candidates.CANDIDATE_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))
        self.assertGreaterEqual(tuple(int(x) for x in security_reasoning.REASONING_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))
        self.assertGreaterEqual(tuple(int(x) for x in EXECUTION_ENGINE_VERSION.split(".")), (1, 3, 0))
        self.assertGreaterEqual(tuple(int(x) for x in EXECUTION_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))
        self.assertEqual(RECONSTRUCTION_ENGINE_VERSION, "1.2.0")
        self.assertEqual(RECONSTRUCTION_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.5.0")
        self.assertEqual(ADMISSION_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.2.0")
        self.assertEqual(DETECTOR_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.4.0")
        self.assertEqual(FAMILY_REASONER_VERSION, "1.2.0")
        self.assertEqual(FAMILY_REASONER_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(FAMILY_EVIDENCE_EXTRACTOR_VERSION, "1.1.0")
        self.assertEqual(FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION, "2026.08.13.6.27")

    def test_all_36_families_keep_four_layer_grounding_and_cross_layer_ownership(self) -> None:
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(len(families), 36)
        self.assertEqual(set(FAMILY_REASONER_PROFILES), families)
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), families)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        for family in sorted(families):
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_consumed_v4_holdout_is_still_byte_identical_and_never_reclassified_as_first_blind(self) -> None:
        freeze = verify_v4_freeze()
        self.assertTrue(freeze["passed"], freeze["errors"])
        self.assertEqual(freeze["corpus_sha256"], CORPUS_SHA256)
        self.assertEqual(freeze["shortlist_sha256"], SHORTLIST_SHA256)
        receipt_path = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_receipt.json"
        report_path = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_report.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "first_blind_consumed")
        self.assertEqual(receipt["evaluation_kind"], "first_blind_single_consumption")
        self.assertEqual(receipt["corpus_sha256"], CORPUS_SHA256)
        self.assertEqual(receipt["shortlist_sha256"], SHORTLIST_SHA256)
        self.assertEqual(receipt["report_sha256"], FIRST_BLIND_REPORT_SHA256)
        self.assertEqual(hashlib.sha256(report_path.read_bytes()).hexdigest(), FIRST_BLIND_REPORT_SHA256)
        first = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(first["quality_gate"]["passed"])
        self.assertEqual(first["evaluation_kind"], "first_blind_single_consumption")

    def test_post_blind_regression_passes_every_pre_registered_gate_without_mutating_holdout(self) -> None:
        path = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v4_6_27_regression.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["evaluation_kind"], "post_first_blind_regression")
        self.assertTrue(report["first_blind_consumed"])
        self.assertTrue(report["quality_gate"]["passed"], report["quality_gate"]["failures"])
        self.assertEqual(report["quality_gate"]["failures"], [])
        metrics = report["metrics"]
        exact = {
            "condition_extraction_precision": 1.0,
            "condition_extraction_recall": 1.0,
            "routing_top1_accuracy": 0.861111,
            "routing_top3_accuracy": 0.962963,
            "admission_precision": 1.0,
            "admission_recall": 1.0,
            "abstention_accuracy": 1.0,
            "false_promotion_rate": 0.0,
            "wrong_family_promotion_rate": 0.0,
            "end_to_end_accuracy": 1.0,
            "near_miss_abstention_accuracy": 1.0,
            "secure_negative_rejection_accuracy": 1.0,
            "sparse_noisy_abstention_accuracy": 1.0,
            "positive_end_to_end_accuracy": 1.0,
            "prior_source_root_overlap_rate": 0.0,
            "raw_label_leakage_rate": 0.0,
        }
        for key, value in exact.items():
            self.assertEqual(metrics[key], value, key)
        self.assertEqual(report["frozen_inputs"]["corpus_sha256"], CORPUS_SHA256)
        self.assertEqual(report["frozen_inputs"]["shortlist_sha256"], SHORTLIST_SHA256)

    def test_no_condition_false_positives_or_wrong_promotions_remain_in_627_diagnostic(self) -> None:
        path = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v4_6_27_diagnostic.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["condition_false_positive_family_counts"], {})
        self.assertEqual(report["wrong_promotion_family_counts"], {})
        self.assertEqual(report["ranking_error_count"], 15)
        self.assertFalse(report["diagnostic_executes_analysis_engine"])
        self.assertFalse(report["diagnostic_reruns_holdout"])

    def test_unsafe_api_certificate_validation_is_consistent_across_detector_standards_candidate_and_reasoning_layers(self) -> None:
        condition = "upstream_certificate_validation_failure"
        spec = get_detector_spec("unsafe_api_consumption")
        self.assertIn(condition, spec.condition_signals)
        self.assertIn("CWE-295", set(spec.cwe_ids))
        schema = bug_candidates.FAMILY_EVIDENCE_SCHEMAS["unsafe_api_consumption"]
        self.assertIn(condition, set(schema["required_any"][1]))
        adjustment, missing = bug_candidates._family_schema_gate(
            "unsafe_api_consumption",
            [
                {"type": "third_party_integration", "source": "stored_upstream_observation"},
                {"type": condition, "source": "stored_upstream_observation"},
            ],
            [],
        )
        self.assertEqual(adjustment, 0)
        self.assertEqual(missing, [])
        reasoning = security_reasoning.FAMILY_SCHEMAS["unsafe_api_consumption"]
        self.assertIn(condition, set(reasoning["required"][1]))
        self.assertIn(condition, set(reasoning["support"]))
        grounding_urls = {ref.url for ref in spec.writeups}
        self.assertNotIn("https://github.com/advisories/GHSA-q7xv-cj2x-93j5", grounding_urls)
        self.assertNotIn("https://github.com/esm-dev/esm.sh/security/advisories/GHSA-rg65-45m7-hq57", grounding_urls)

    def test_cors_and_source_map_reasoning_match_627_admission_boundaries(self) -> None:
        cors = security_reasoning.FAMILY_SCHEMAS["cors_misconfiguration"]
        self.assertIn("cors_policy_surface", cors["rank_gate"])
        self.assertEqual(len(cors["required"]), 3)
        self.assertIn("strict_origin_allowlist", cors["contradict"])
        source_map = security_reasoning.FAMILY_SCHEMAS["source_map_exposure"]
        self.assertEqual(len(source_map["required"]), 3)
        self.assertTrue({"public_observation", "direct_reachability"} & set(source_map["required"][2]))


if __name__ == "__main__":
    unittest.main()

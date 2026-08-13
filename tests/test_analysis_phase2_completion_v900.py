from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.base import FamilyAnalyzerContext
from family_analyzers.router import analyzer_for_family, router_status
from family_reasoning import FAMILY_ORDER, confirmation_gaps, validation_level_for_family
from hypothesis_admission import assess_admission
from owasp_phase2_catalog import (
    PHASE2_DIRECT_TYPES,
    PHASE2_FAMILY_ORDER,
    PHASE2_FAMILY_SPECS,
)
from vulnerability_knowledge import knowledge_for_family

FIXTURE = ROOT / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json"


def _support(types):
    return [
        {
            "type": evidence_type,
            "source": f"phase2-golden:{index}",
            "source_group": f"phase2-golden:{index}",
            "text": f"Fixed non-payload phase2 evidence: {evidence_type}",
        }
        for index, evidence_type in enumerate(types, start=1)
    ]


class AnalysisPhase2CompletionV900Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = cls.data["cases"]

    def test_phase2_catalog_is_fixed_unique_and_total_family_count_is_74(self):
        families = [case["family"] for case in self.cases]
        self.assertEqual(self.data["version"], "2.0.0")
        self.assertEqual(self.data["family_count"], 43)
        self.assertEqual(len(families), 43)
        self.assertEqual(len(set(families)), 43)
        self.assertEqual(tuple(families), PHASE2_FAMILY_ORDER)
        self.assertEqual(len(FAMILY_ORDER), 74)
        self.assertEqual(tuple(FAMILY_ORDER[-43:]), PHASE2_FAMILY_ORDER)

    def test_router_has_74_dedicated_analyzers_and_no_generic_fallback(self):
        status = router_status()
        self.assertEqual(status["registered_count"], 74)
        self.assertEqual(status["target_family_count"], 74)
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["pending"], [])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertEqual(tuple(status["registered"]), tuple(FAMILY_ORDER))
        for family in PHASE2_FAMILY_ORDER:
            analyzer = analyzer_for_family(family)
            self.assertIsNotNone(analyzer, family)
            self.assertEqual(analyzer.family, family)

    def test_positive_phase2_golden_cases_admit_and_confirm(self):
        for case in self.cases:
            with self.subTest(family=case["family"]):
                decision = assess_admission(case["family"], _support(case["positive"]), [])
                self.assertTrue(decision["admitted"], decision)
                self.assertEqual(confirmation_gaps(case["family"], case["positive"]), [])

    def test_surface_only_phase2_cases_abstain(self):
        for case in self.cases:
            with self.subTest(family=case["family"]):
                decision = assess_admission(case["family"], _support(case["negative"]), [])
                self.assertFalse(decision["admitted"], decision)
                self.assertIn(decision["state"], {"shadow_signal", "shadow_partial"})

    def test_safety_class_and_curated_reference_are_pinned(self):
        for case in self.cases:
            with self.subTest(family=case["family"]):
                self.assertEqual(validation_level_for_family(case["family"]), case["validation"])
                refs = {item["id"] for item in knowledge_for_family(case["family"])}
                self.assertIn(case["reference"], refs)

    def test_each_phase2_analyzer_promotes_only_from_concrete_stored_evidence(self):
        for family, spec in PHASE2_FAMILY_SPECS.items():
            with self.subTest(family=family):
                analyzer = analyzer_for_family(family)
                details = {
                    spec["context"][0]: True,
                    spec["direct"][0]: True,
                }
                if spec["validation"] == "manual_only":
                    details.update({
                        "controlled_test_context": True,
                        "benign_test_marker": True,
                    })
                context = FamilyAnalyzerContext(
                    db=None,
                    analysis_id="phase2-test",
                    target="example.test",
                    endpoint="https://example.test/test",
                    method="GET",
                    details=details,
                )
                result = analyzer.analyze(context)
                self.assertIsNotNone(result)
                self.assertTrue(result["direct"], result)
                meta = result["family_analyzer"]
                self.assertTrue(meta["promotion_ready_from_stored_target_evidence"], meta)
                self.assertTrue(meta["confirmation_ready_from_stored_target_evidence"], meta)
                self.assertFalse(meta["active_request_performed"])
                self.assertFalse(meta["payload_generated"])
                self.assertFalse(meta["state_changing_action_performed"])
                self.assertFalse(meta["third_party_action_performed"])

    def test_manual_only_direct_flags_are_not_decisive_without_control_markers(self):
        for family, spec in PHASE2_FAMILY_SPECS.items():
            if spec["validation"] != "manual_only":
                continue
            with self.subTest(family=family):
                analyzer = analyzer_for_family(family)
                context = FamilyAnalyzerContext(
                    db=None,
                    analysis_id="phase2-test",
                    target="example.test",
                    endpoint="https://example.test/test",
                    method="GET",
                    details={
                        spec["context"][0]: True,
                        spec["direct"][0]: True,
                    },
                )
                result = analyzer.analyze(context)
                self.assertIsNotNone(result)
                self.assertFalse(result["direct"], result)
                self.assertFalse(
                    result["family_analyzer"]["promotion_ready_from_stored_target_evidence"],
                    result,
                )

    def test_phase2_taxonomy_and_direct_types_have_no_empty_family_contracts(self):
        for family, spec in PHASE2_FAMILY_SPECS.items():
            with self.subTest(family=family):
                self.assertTrue(spec["context"])
                self.assertTrue(spec["direct"])
                self.assertEqual(set(spec["direct"]), set(PHASE2_DIRECT_TYPES[family]))
                self.assertTrue(spec["owasp"] or spec["wstg"] or spec["cwe"])
                for ref in spec["wstg"]:
                    self.assertRegex(ref, r"^WSTG-[A-Z]+-\d{2}$")


if __name__ == "__main__":
    unittest.main()

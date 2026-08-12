from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, FAMILY_OWASP_MAPPINGS, OWASP_REFERENCE_VERSION, validate_family_standards
from family_detectors.registry import DETECTOR_SPECS, detector_rule_ids
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, knowledge_for_family


class Analysis619StandardsGroundingTests(unittest.TestCase):
    def test_all_31_families_have_four_layer_knowledge_grounding(self):
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(families, set(FAMILY_STANDARDS))
        self.assertEqual(families, set(FAMILY_OWASP_MAPPINGS))
        self.assertEqual(families, set(DETECTOR_SPECS))
        self.assertGreaterEqual(len(families), 31)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")
        for family in families:
            standards = FAMILY_STANDARDS[family]; spec = DETECTOR_SPECS[family]
            self.assertTrue(standards["wstg"], family)
            self.assertTrue(standards["owasp"], family)
            self.assertTrue(standards["cwe"], family)
            self.assertTrue(spec.writeups, family)
            self.assertEqual(spec.owasp_ids, tuple(item["id"] for item in standards["owasp"]), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_knowledge_output_contains_owasp_without_turning_it_into_evidence(self):
        for family in FAMILY_ADMISSION_POLICIES:
            refs = knowledge_for_family(family)
            self.assertTrue(any(str(item.get("source") or "").startswith("OWASP") for item in refs), family)
            self.assertTrue(any(str(item.get("source") or "") == "MITRE CWE" for item in refs), family)
            spec = DETECTOR_SPECS[family]
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)


if __name__ == "__main__":
    unittest.main()

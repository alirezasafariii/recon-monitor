from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# Seal the three public analysis layers on the same lineage.
for relative, pairs in {
    "app/analysis_engine.py": [
        ('ENGINE_VERSION = "6.19.0"', 'ENGINE_VERSION = "6.20.0"'),
        ('RULE_VERSION = "2026.08.12.6.19"', 'RULE_VERSION = "2026.08.12.6.20"'),
    ],
    "app/bug_candidates.py": [
        ('CANDIDATE_ENGINE_VERSION = "6.19.0"', 'CANDIDATE_ENGINE_VERSION = "6.20.0"'),
        ('CANDIDATE_RULE_VERSION = "2026.08.12.6.19"', 'CANDIDATE_RULE_VERSION = "2026.08.12.6.20"'),
    ],
    "app/security_reasoning.py": [
        ('REASONING_ENGINE_VERSION = "6.19.0"', 'REASONING_ENGINE_VERSION = "6.20.0"'),
        ('REASONING_RULE_VERSION = "2026.08.12.6.19"', 'REASONING_RULE_VERSION = "2026.08.12.6.20"'),
    ],
}.items():
    path = ROOT / relative
    for old, new in pairs:
        replace_once(path, old, new)

# Historical 6.19 seal remains a minimum/lineage regression after later seals,
# while its client-side collector rule stays pinned to 6.19.
old_test = ROOT / "tests" / "test_analysis_619_seal.py"
replace_once(
    old_test,
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.19.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.19.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.19.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.19")
''',
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 19, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
        self.assertTrue(analysis_engine.RULE_VERSION.startswith("2026.08.12.6."))
''',
)

seal_test = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import API_CONFIGURATION_COLLECTOR_RULE_VERSION, API_CONFIGURATION_FAMILIES


class Analysis620SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_620(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.20.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.20.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.20.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(API_CONFIGURATION_COLLECTOR_RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_31_families_keep_four_layer_grounding(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 31)
        for family in FAMILY_ADMISSION_POLICIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_api_configuration_taxonomy_and_writeup_lineage(self) -> None:
        self.assertEqual(set(API_CONFIGURATION_FAMILIES), {
            "unrestricted_resource_consumption", "sensitive_business_flow_abuse",
            "security_misconfiguration", "improper_inventory_management", "unsafe_api_consumption",
        })
        expected_api = {
            "unrestricted_resource_consumption": "API4:2023",
            "sensitive_business_flow_abuse": "API6:2023",
            "security_misconfiguration": "API8:2023",
            "improper_inventory_management": "API9:2023",
            "unsafe_api_consumption": "API10:2023",
        }
        for family, api_id in expected_api.items():
            spec = get_detector_spec(family)
            self.assertIn(api_id, set(spec.owasp_ids), family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
        resource_urls = {ref.url for ref in get_detector_spec("unrestricted_resource_consumption").writeups}
        flow_urls = {ref.url for ref in get_detector_spec("sensitive_business_flow_abuse").writeups}
        self.assertIn("https://securitylab.github.com/advisories/GHSL-2023-225_GHSL-2023-226_Mealie/", resource_urls)
        self.assertIn("https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/", flow_urls)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_620_seal.py").write_text(seal_test, encoding="utf-8")

doc = '''# Analysis Engine 6.20 — Seal

Analysis 6.20 seals the API/configuration physical-collector cutover on a single production lineage:

- Analysis Engine: `6.20.0`
- Candidate Engine: `6.20.0`
- Security Reasoning Engine: `6.20.0`
- Analysis/Candidate/Reasoning rule lineage: `2026.08.12.6.20`
- API/configuration collector rule lineage: `2026.08.12.6.20`

The sealed batch covers OWASP API Security Top 10 API4/API6/API8/API9/API10 families while retaining the global 31-family requirement for WSTG + OWASP + CWE + real write-up grounding.

External standards and write-ups remain knowledge only. They never count as target evidence, satisfy independent-source requirements, or override target-side contradictions. Promotion remains dependent on stored passive target evidence and family-specific admission.

The seal also preserves the earlier raw-routing precision boundary: ordinary API versioning such as `/api/v1` is not, by itself, an inventory-management hypothesis. Inventory routing requires legacy/non-production semantics or explicit target evidence of inventory drift.

Full unit regression, strict Golden analysis benchmark, and integration validation are required before the seal commit can be emitted.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_20_SEAL.md").write_text(doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in ("tests/test_analysis_620_seal.py", "docs/ANALYSIS_ENGINE_6_20_SEAL.md"):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

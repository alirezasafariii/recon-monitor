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


for relative, pairs in {
    "app/analysis_engine.py": [
        ('ENGINE_VERSION = "6.20.0"', 'ENGINE_VERSION = "6.21.0"'),
        ('RULE_VERSION = "2026.08.12.6.20"', 'RULE_VERSION = "2026.08.12.6.21"'),
    ],
    "app/bug_candidates.py": [
        ('CANDIDATE_ENGINE_VERSION = "6.20.0"', 'CANDIDATE_ENGINE_VERSION = "6.21.0"'),
        ('CANDIDATE_RULE_VERSION = "2026.08.12.6.20"', 'CANDIDATE_RULE_VERSION = "2026.08.12.6.21"'),
    ],
    "app/security_reasoning.py": [
        ('REASONING_ENGINE_VERSION = "6.20.0"', 'REASONING_ENGINE_VERSION = "6.21.0"'),
        ('REASONING_RULE_VERSION = "2026.08.12.6.20"', 'REASONING_RULE_VERSION = "2026.08.12.6.21"'),
    ],
}.items():
    path = ROOT / relative
    for old, new in pairs:
        replace_once(path, old, new)

# Turn the prior seal into a historical minimum/lineage regression.
old_test = ROOT / "tests" / "test_analysis_620_seal.py"
replace_once(
    old_test,
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.20.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.20.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.20.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.20")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.20")
''',
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 20, 0))
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
from raw_family_collectors import BUSINESS_LOGIC_COLLECTOR_RULE_VERSION, BUSINESS_LOGIC_FAMILIES


class Analysis621SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_621(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.21.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.21.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.21.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.21")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.21")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.21")
        self.assertEqual(BUSINESS_LOGIC_COLLECTOR_RULE_VERSION, "2026.08.12.6.21")
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

    def test_business_logic_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(BUSINESS_LOGIC_FAMILIES), {"business_logic", "race_condition"})
        expected = {
            "business_logic": ({"WSTG-BUSL-01", "WSTG-BUSL-06"}, {"A06:2025"}, {"CWE-841"}),
            "race_condition": ({"WSTG-BUSL-04"}, {"A06:2025"}, {"CWE-362"}),
        }
        advisory = "https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/"
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url == advisory for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_621_seal.py").write_text(seal_test, encoding="utf-8")

doc = '''# Analysis Engine 6.21 — Seal

Analysis 6.21 seals the Business Logic / Race Condition physical-collector cutover.

- Analysis Engine: `6.21.0`
- Candidate Engine: `6.21.0`
- Security Reasoning Engine: `6.21.0`
- Shared rule lineage: `2026.08.12.6.21`
- Business Logic collector rule lineage: `2026.08.12.6.21`

The two families remain explicitly grounded in WSTG, OWASP Top 10:2025, MITRE CWE, and the exact GHSL-2025-038 Branch Deploy Action primary advisory. External knowledge remains detector knowledge only and cannot become target evidence.

Business Logic requires observed workflow/value/state invariant failure; Race Condition requires observed duplicate/atomicity/concurrency effects. Mere endpoint names, business-flow semantics, or single-use operations remain hidden hypotheses until decisive target evidence exists.

Full unit regression, strict Golden benchmark, and integration validation are required before the seal commit is created.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_21_SEAL.md").write_text(doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in ("tests/test_analysis_621_seal.py", "docs/ANALYSIS_ENGINE_6_21_SEAL.md"):
    if relative not in paths:
        paths.append(relative)
entries = [f"{hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()}  {relative}" for relative in sorted(set(paths))]
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

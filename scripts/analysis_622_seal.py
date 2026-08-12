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


for relative, replacements in {
    "app/analysis_engine.py": [
        ('ENGINE_VERSION = "6.21.0"', 'ENGINE_VERSION = "6.22.0"'),
        ('RULE_VERSION = "2026.08.12.6.21"', 'RULE_VERSION = "2026.08.12.6.22"'),
    ],
    "app/bug_candidates.py": [
        ('CANDIDATE_ENGINE_VERSION = "6.21.0"', 'CANDIDATE_ENGINE_VERSION = "6.22.0"'),
        ('CANDIDATE_RULE_VERSION = "2026.08.12.6.21"', 'CANDIDATE_RULE_VERSION = "2026.08.12.6.22"'),
    ],
    "app/security_reasoning.py": [
        ('REASONING_ENGINE_VERSION = "6.21.0"', 'REASONING_ENGINE_VERSION = "6.22.0"'),
        ('REASONING_RULE_VERSION = "2026.08.12.6.21"', 'REASONING_RULE_VERSION = "2026.08.12.6.22"'),
    ],
}.items():
    path = ROOT / relative
    for old, new in replacements:
        replace_once(path, old, new)

# Historical seal tests remain regression contracts instead of pinning the current version forever.
old_test = ROOT / "tests" / "test_analysis_621_seal.py"
replace_once(
    old_test,
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.21.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.21.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.21.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.21")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.21")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.21")
''',
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 21, 0))
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
from raw_family_collectors import AUTHENTICATION_COLLECTOR_RULE_VERSION, AUTHENTICATION_FAMILIES


class Analysis622SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_622(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.22.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.22.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.22.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(AUTHENTICATION_COLLECTOR_RULE_VERSION, "2026.08.12.6.22")
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

    def test_authentication_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(AUTHENTICATION_FAMILIES), {"authentication_session", "account_enumeration"})
        expected = {
            "authentication_session": ({"WSTG-ATHN-04", "WSTG-SESS-01"}, {"A07:2025", "API2:2023"}, {"CWE-287"}),
            "account_enumeration": ({"WSTG-IDNT-04"}, {"A07:2025", "API2:2023"}, {"CWE-204"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        auth = get_detector_spec("authentication_session")
        self.assertEqual(auth.writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/")
        enum = get_detector_spec("account_enumeration")
        self.assertEqual(enum.writeups[0].url, "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j")
        self.assertEqual(enum.writeups[0].source, "GitHub Advisory Database")
        self.assertEqual(enum.writeups[0].relation, "exact")


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_622_seal.py").write_text(seal_test, encoding="utf-8")

doc = '''# Analysis Engine 6.22 Seal

Analysis 6.22 seals the authentication decomposition after successful physical-collector, raw-reconstruction, full-unit, Golden benchmark, and integration validation.

Sealed production lineage:

- Analysis Engine: `6.22.0`
- Candidate Engine: `6.22.0`
- Security Reasoning Engine: `6.22.0`
- Rule lineage: `2026.08.12.6.22`
- Authentication collector rule lineage: `2026.08.12.6.22`

The seal preserves the mandatory four-layer detector contract for all 31 families: OWASP WSTG, OWASP Top 10 / API Security Top 10, MITRE CWE, and real security write-ups. External standards and write-ups remain knowledge only and never count as target evidence.

For account enumeration, the sealed detector specifically requires a controlled observable discrepancy between present and absent identities; uniform response behavior is retained only as a non-promoted hypothesis surface.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_22_SEAL.md").write_text(doc, encoding="utf-8")

manifest_path = ROOT / "MANIFEST.sha256"
entries: set[str] = set()
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.add(rel.strip())
entries.update({"tests/test_analysis_622_seal.py", "docs/ANALYSIS_ENGINE_6_22_SEAL.md"})
lines = []
for rel in sorted(entries):
    path = ROOT / rel
    if not path.is_file():
        raise RuntimeError(f"manifest path missing after 6.22 seal: {rel}")
    lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}")
manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

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
        ('ENGINE_VERSION = "6.22.0"', 'ENGINE_VERSION = "6.23.0"'),
        ('RULE_VERSION = "2026.08.12.6.22"', 'RULE_VERSION = "2026.08.12.6.23"'),
    ],
    "app/bug_candidates.py": [
        ('CANDIDATE_ENGINE_VERSION = "6.22.0"', 'CANDIDATE_ENGINE_VERSION = "6.23.0"'),
        ('CANDIDATE_RULE_VERSION = "2026.08.12.6.22"', 'CANDIDATE_RULE_VERSION = "2026.08.12.6.23"'),
    ],
    "app/security_reasoning.py": [
        ('REASONING_ENGINE_VERSION = "6.22.0"', 'REASONING_ENGINE_VERSION = "6.23.0"'),
        ('REASONING_RULE_VERSION = "2026.08.12.6.22"', 'REASONING_RULE_VERSION = "2026.08.12.6.23"'),
    ],
}.items():
    path = ROOT / relative
    for old, new in replacements:
        replace_once(path, old, new)

old_test = ROOT / "tests" / "test_analysis_622_seal.py"
replace_once(
    old_test,
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.22.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.22.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.22.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.22")
''',
    '''        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 22, 0))
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
from raw_family_collectors import EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION, EXPOSURE_HEADERS_FAMILIES


class Analysis623SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_623(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.23.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.23.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.23.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION, "2026.08.12.6.23")
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

    def test_exposure_header_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(EXPOSURE_HEADERS_FAMILIES), {"information_disclosure", "cors_misconfiguration", "sensitive_caching"})
        expected = {
            "information_disclosure": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A01:2025"}, {"CWE-200"}),
            "cors_misconfiguration": ({"WSTG-CLNT-07"}, {"A02:2025"}, {"CWE-942"}),
            "sensitive_caching": ({"WSTG-ATHN-06"}, {"A06:2025"}, {"CWE-524", "CWE-525"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("information_disclosure").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2026-037_Wekan/")
        self.assertEqual(get_detector_spec("cors_misconfiguration").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-161_GHSL-2024-162_rembg/")
        cache = get_detector_spec("sensitive_caching")
        self.assertEqual(cache.writeups[0].url, "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p")
        self.assertEqual(cache.writeups[0].source, "GitHub Repository Security Advisory")
        self.assertEqual(cache.writeups[0].relation, "exact")
        self.assertIn("browser_cache_no_store_missing", set(cache.condition_signals))
        self.assertIn("browser_cache_no_store_missing", set().union(*FAMILY_ADMISSION_POLICIES["sensitive_caching"]["required"]))


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_623_seal.py").write_text(seal_test, encoding="utf-8")

doc = '''# Analysis Engine 6.23 Seal

Analysis 6.23 seals the physical decomposition of Information Disclosure, CORS Misconfiguration, and Sensitive Caching after collector, routing-boundary, raw-reconstruction, full-unit, Golden benchmark, and integration validation.

Sealed production lineage:

- Analysis Engine: `6.23.0`
- Candidate Engine: `6.23.0`
- Security Reasoning Engine: `6.23.0`
- Rule lineage: `2026.08.12.6.23`
- Exposure/header collector lineage: `2026.08.12.6.23`

All 31 vulnerability families retain mandatory WSTG + OWASP + CWE + real-write-up grounding. Standards and write-ups remain detector knowledge only and never target evidence.

The seal additionally locks two precision boundaries: route/category words such as `token` do not create Information Disclosure without a stored response/source artifact, and browser-cache promotion requires sensitive/authenticated response context plus an actual cache-isolation weakness such as missing `no-store`; protected `no-store` remains blocking evidence.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_23_SEAL.md").write_text(doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
entries: set[str] = set()
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.add(rel.strip())
entries.update({"tests/test_analysis_623_seal.py", "docs/ANALYSIS_ENGINE_6_23_SEAL.md"})
manifest.write_text(
    "\n".join(f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(entries)) + "\n",
    encoding="utf-8",
)

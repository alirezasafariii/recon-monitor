from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected exactly one seal replacement, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.18.0"\nRULE_VERSION = "2026.08.12.6.18"',
    'ENGINE_VERSION = "6.19.0"\nRULE_VERSION = "2026.08.12.6.19"',
)
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.18.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.18"',
    'CANDIDATE_ENGINE_VERSION = "6.19.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.19"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.18.0"\nREASONING_RULE_VERSION = "2026.08.12.6.18"',
    'REASONING_ENGINE_VERSION = "6.19.0"\nREASONING_RULE_VERSION = "2026.08.12.6.19"',
)

# Historical 6.18 seal remains a minimum-lineage regression rather than pinning
# the current engine forever. The 6.18 collector itself stays pinned to 6.18.
replace_once(
    "tests/test_analysis_618_seal.py",
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.18.0")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.18.0")\n'
    '        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.18.0")\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.18")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.18")\n'
    '        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.18")\n'
    '        self.assertEqual(FILE_REMOTE_COLLECTOR_RULE_VERSION, "2026.08.12.6.18")',
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)\n'
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)\n'
    '        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 18, 0))\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)\n'
    '        self.assertTrue(analysis_engine.RULE_VERSION.startswith("2026.08.12.6."))\n'
    '        self.assertEqual(FILE_REMOTE_COLLECTOR_RULE_VERSION, "2026.08.12.6.18")',
)
replace_once(
    "tests/test_analysis_618_seal.py",
    '            self.assertTrue(spec.wstg_ids, family)\n            self.assertTrue(spec.cwe_ids, family)',
    '            self.assertTrue(spec.wstg_ids, family)\n            self.assertTrue(spec.owasp_ids, family)\n            self.assertTrue(spec.cwe_ids, family)',
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
from raw_family_collectors import CLIENT_SIDE_COLLECTOR_RULE_VERSION, CLIENT_SIDE_FAMILIES


class Analysis619SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_619(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.19.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.19.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.19.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(CLIENT_SIDE_COLLECTOR_RULE_VERSION, "2026.08.12.6.19")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_families_are_four_layer_grounded(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 31)
        for family in FAMILY_ADMISSION_POLICIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.principle.strip(), family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_client_side_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(CLIENT_SIDE_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        expected = {
            "dom_xss": ({"WSTG-CLNT-01"}, {"A05:2025"}, {"CWE-79"}),
            "postmessage_trust": ({"WSTG-CLNT-11"}, {"A07:2025"}, {"CWE-940", "CWE-346"}),
            "open_redirect": ({"WSTG-CLNT-04"}, {"A01:2025"}, {"CWE-601"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_619_seal.py").write_text(seal_test, encoding="utf-8")

seal_doc = '''# Analysis Engine 6.19 — Seal

Analysis 6.19 is sealed after the client-side collector cutover and the four-layer security-knowledge grounding upgrade.

## Sealed version lineage

- Analysis engine: `6.19.0`
- Candidate engine: `6.19.0`
- Security reasoning engine: `6.19.0`
- Analysis rule lineage: `2026.08.12.6.19`
- Client-side collector rule lineage: `2026.08.12.6.19`
- Standards engine: `1.3.0`
- Physical detector engine: `1.1.0`
- OWASP taxonomy reference: `Top10:2025+API-Security:2023`

## Mandatory detector knowledge contract

Every one of the 31 vulnerability families is required to carry four independent knowledge layers:

1. OWASP WSTG testing guidance.
2. OWASP Top 10:2025 and/or OWASP API Security Top 10:2023 taxonomy.
3. MITRE CWE weakness mapping.
4. At least one relevant real-world security write-up with an explicit detector lesson.

The physical detector registry fails closed if WSTG, OWASP, CWE, or write-up grounding is absent. Detector rule lineage exposes `wstg:*`, `owasp:*`, `cwe:*`, and `writeup:*` identifiers.

## Evidence boundary

Standards and write-ups define the detector criteria, family identity, confounders, and required vulnerability condition. They never count as target evidence, never satisfy independent-source requirements, and never override target-side contradictions. Promotion still requires stored target evidence from passive execution/reconstruction and family-specific admission.

## Client-side family boundary

- DOM XSS: WSTG-CLNT-01 + OWASP A05:2025 + CWE-79 + relevant DOM-XSS write-up evidence model.
- postMessage trust: WSTG-CLNT-11 + OWASP A07:2025 + CWE-940/CWE-346 + postMessage/external-message write-ups.
- Open Redirect: WSTG-CLNT-04 + OWASP A01:2025 + CWE-601 + real Open Redirect write-up.

Hidden near-miss hypotheses may coexist with promoted hypotheses in the same family. This is intentional: incomplete client-side surfaces are retained for correlation while only observations carrying decisive family-condition evidence can promote.

## Validation boundary

The seal requires four-layer standards validation, client-side collector regression, the full unit suite, strict Golden benchmark, and integration runner. It is an architecture/regression claim, not a universal real-world accuracy claim.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_19_SEAL.md").write_text(seal_doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in ("docs/ANALYSIS_ENGINE_6_19_SEAL.md", "tests/test_analysis_619_seal.py"):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

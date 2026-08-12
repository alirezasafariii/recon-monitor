from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected one seal replacement, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.17.0"\nRULE_VERSION = "2026.08.12.6.17"',
    'ENGINE_VERSION = "6.18.0"\nRULE_VERSION = "2026.08.12.6.18"',
)
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.17.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.17"',
    'CANDIDATE_ENGINE_VERSION = "6.18.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.18"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.17.0"\nREASONING_RULE_VERSION = "2026.08.12.6.17"',
    'REASONING_ENGINE_VERSION = "6.18.0"\nREASONING_RULE_VERSION = "2026.08.12.6.18"',
)

replace_once(
    "tests/test_analysis_617_seal.py",
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.17.0")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.17.0")\n'
    '        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.17.0")\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.17")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.17")\n'
    '        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.17")',
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)\n'
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)\n'
    '        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 17, 0))\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)\n'
    '        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)\n'
    '        self.assertTrue(analysis_engine.RULE_VERSION.startswith("2026.08.12.6."))',
)

seal_test = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import get_detector_spec
from raw_family_collectors import FILE_REMOTE_COLLECTOR_RULE_VERSION, FILE_REMOTE_FAMILIES


class Analysis618SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_618(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.18.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.18.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.18.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.18")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.18")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.18")
        self.assertEqual(FILE_REMOTE_COLLECTOR_RULE_VERSION, "2026.08.12.6.18")

    def test_file_remote_families_remain_standards_and_writeup_grounded(self) -> None:
        self.assertEqual(set(FILE_REMOTE_FAMILIES), {"ssrf", "file_upload", "path_traversal"})
        for family in FILE_REMOTE_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.principle.strip(), family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_618_seal.py").write_text(seal_test, encoding="utf-8")

seal_doc = '''# Analysis Engine 6.18 — Seal

Analysis 6.18 is sealed after the physical raw-collector cutover for SSRF, File Upload, and Path Traversal.

## Sealed lineage

- Analysis engine: `6.18.0`
- Candidate engine: `6.18.0`
- Security reasoning engine: `6.18.0`
- Analysis rule lineage: `2026.08.12.6.18`
- File/remote-resource collector rule lineage: `2026.08.12.6.18`

## Security-knowledge boundary

The three families remain grounded in their physical detector specifications. Each detector must retain WSTG identifiers, CWE identifiers, a family principle, admission-condition signals, and at least one real-world write-up. External standards and write-ups define the detector model but never count as target evidence.

## Validation boundary

The seal requires the dedicated 6.18 collector contract, recall-preserving surface-hypothesis regressions, the complete unit suite, strict Golden benchmark, and integration runner to pass. This is an architecture/regression seal and does not create a new fresh-holdout accuracy claim.

The next collector batch is client-side analysis. That batch will additionally make explicit OWASP category grounding mandatory alongside WSTG, CWE, and write-up grounding.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_18_SEAL.md").write_text(seal_doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in ("docs/ANALYSIS_ENGINE_6_18_SEAL.md", "tests/test_analysis_618_seal.py"):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

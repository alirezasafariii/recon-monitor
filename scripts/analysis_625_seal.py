from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EPHEMERAL = {
    ".github/workflows/analysis-625-seal-one-shot.yml",
    "scripts/analysis_625_seal.py",
}
NEW_PERSISTENT = {
    "tests/test_analysis_625_seal.py",
    "docs/ANALYSIS_ENGINE_6_25_SEAL.md",
}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if old not in text:
        raise SystemExit(f"anchor not found in {rel}: {old!r}")
    write(rel, text.replace(old, new, 1))


def update_manifest() -> None:
    manifest = ROOT / "MANIFEST.sha256"
    names: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            continue
        _, name = line.split("  ", 1)
        if name and name not in EPHEMERAL:
            names.add(name)
    names.update(NEW_PERSISTENT)
    rows: list[str] = []
    for name in sorted(names):
        path = ROOT / name
        if not path.is_file() or name in EPHEMERAL:
            continue
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")


# Seal all three analysis layers on the same lineage.
replace_once("app/analysis_engine.py", 'ENGINE_VERSION = "6.24.0"\nRULE_VERSION = "2026.08.12.6.24"', 'ENGINE_VERSION = "6.25.0"\nRULE_VERSION = "2026.08.12.6.25"')
replace_once("app/bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "6.24.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.24"', 'CANDIDATE_ENGINE_VERSION = "6.25.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.25"')
replace_once("app/security_reasoning.py", 'REASONING_ENGINE_VERSION = "6.24.0"\nREASONING_RULE_VERSION = "2026.08.12.6.24"', 'REASONING_ENGINE_VERSION = "6.25.0"\nREASONING_RULE_VERSION = "2026.08.12.6.25"')

# Historical 6.24 seal remains a lineage floor rather than pinning the current
# engine forever, while its specialized-static collector rule stays exact 6.24.
old_versions = '''        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.24.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.24.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.24.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.24")
'''
new_versions = '''        self.assertGreaterEqual(tuple(map(int, analysis_engine.ENGINE_VERSION.split("."))), (6, 24, 0))
        self.assertGreaterEqual(tuple(map(int, bug_candidates.CANDIDATE_ENGINE_VERSION.split("."))), (6, 24, 0))
        self.assertGreaterEqual(tuple(map(int, security_reasoning.REASONING_ENGINE_VERSION.split("."))), (6, 24, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
'''
replace_once("tests/test_analysis_624_seal.py", old_versions, new_versions)

write("tests/test_analysis_625_seal.py", r'''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from family_evidence_extractors import FAMILY_EVIDENCE_EXTRACTOR_PROFILES, FAMILY_EXTRACTION_IDENTITY_GATES
from family_reasoners import FAMILY_IDENTITY_GATES, FAMILY_REASONER_PROFILES
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, OWASP_TOP10_2025_FAMILIES, validate_owasp_top10_2025_collectors
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, validate_static_specialized_collectors


NEW_FAMILIES = {
    "software_supply_chain_failure",
    "cryptographic_failure",
    "software_data_integrity_failure",
    "security_logging_alerting_failure",
    "exceptional_condition_mishandling",
}


class Analysis625SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_exactly_sealed_at_625(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.25.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.25.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.25.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_36_families_have_exact_cross_layer_ownership(self) -> None:
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(len(families), 36)
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), families)
        self.assertEqual(set(FAMILY_EXTRACTION_IDENTITY_GATES), families)
        self.assertEqual(set(FAMILY_REASONER_PROFILES), families)
        self.assertEqual(set(FAMILY_IDENTITY_GATES), families)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(validate_owasp_top10_2025_collectors(), [])
        self.assertEqual(validate_static_specialized_collectors(), [])
        self.assertEqual(set(OWASP_TOP10_2025_FAMILIES), NEW_FAMILIES)
        self.assertEqual(len(STATIC_SPECIALIZED_FAMILIES), 5)
        for family in families:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_owasp_top10_2025_and_api_top10_2023_are_both_ten_of_ten(self) -> None:
        top10 = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("A") and str(ref.get("id") or "").endswith(":2025")
        }
        api = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("API") and str(ref.get("id") or "").endswith(":2023")
        }
        self.assertEqual(top10, {f"A{i:02d}:2025" for i in range(1, 11)})
        self.assertEqual(api, {f"API{i}:2023" for i in range(1, 11)})

    def test_new_family_grounding_and_writeups_are_exact(self) -> None:
        expected = {
            "software_supply_chain_failure": ({"WSTG-CONF-01", "WSTG-CONF-02"}, {"A03:2025"}, {"CWE-1104", "CWE-1357", "CWE-1395"}, "https://securitylab.github.com/advisories/GHSL-2024-171_QGIS/"),
            "cryptographic_failure": ({"WSTG-CRYP-01"}, {"A04:2025"}, {"CWE-319", "CWE-327", "CWE-338", "CWE-757"}, "https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/"),
            "software_data_integrity_failure": ({"WSTG-CONF-02"}, {"A08:2025"}, {"CWE-345", "CWE-494", "CWE-502", "CWE-829"}, "https://securitylab.github.com/advisories/GHSL-2024-301_274056675_springboot-openai-chatgpt/"),
            "security_logging_alerting_failure": ({"WSTG-CONF-02", "WSTG-ERRH-01"}, {"A09:2025"}, {"CWE-117", "CWE-532", "CWE-778"}, "https://github.com/advisories/GHSA-vqf5-2xx6-9wfm"),
            "exceptional_condition_mishandling": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A10:2025"}, {"CWE-248", "CWE-636", "CWE-703", "CWE-755"}, "https://securitylab.github.com/advisories/GHSL-2023-116_MySQL/"),
        }
        for family, (wstg, owasp, cwe, url) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertEqual(spec.writeups[0].url, url, family)
            self.assertFalse(spec.writeups[0].counts_as_target_evidence, family)


if __name__ == "__main__":
    unittest.main()
''')

write("docs/ANALYSIS_ENGINE_6_25_SEAL.md", '''# Analysis Engine 6.25 Seal\n\nAnalysis 6.25 seals OWASP Top 10:2025 coverage completion.\n\nSealed lineage:\n- Analysis Engine: `6.25.0`\n- Candidate Engine: `6.25.0`\n- Security Reasoning Engine: `6.25.0`\n- Rule lineage: `2026.08.12.6.25`\n- OWASP Top 10:2025 completion collector lineage: `2026.08.12.6.25`\n\nThe engine now has 36 vulnerability families. The five Analysis 6.25 families add first-class coverage for A03 Software Supply Chain Failures, A04 Cryptographic Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions. Together with the existing families, OWASP Top 10:2025 and OWASP API Security Top 10:2023 are both explicitly mapped 10/10.\n\nAll 36 families retain cross-layer admission, evidence-extractor, reasoner, physical-detector, WSTG, OWASP, CWE, and real-write-up ownership. External standards/write-ups remain detector criteria only and never count as target evidence. Supply-chain/logging absence is not inferred from client visibility, and exceptional/cryptographic/integrity families require concrete stored target conditions before admission.\n''')

update_manifest()

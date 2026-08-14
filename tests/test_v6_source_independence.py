from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from raw_recon_v6_source_firewall import RULE_VERSION, VERSION, canonical_url, check_candidate, exposure_index


class V6SourceIndependenceTests(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(VERSION, "1.1.0")
        self.assertEqual(RULE_VERSION, "2026.08.14.6.31.1")

    def test_prior_v5_source_is_not_fresh(self) -> None:
        result = check_candidate({
            "source_root": "CVE-2026-24468",
            "source_project": "OpenAEV-Platform/openaev",
        })
        self.assertFalse(result["allowed"])
        self.assertTrue(result["root_overlap"])
        self.assertTrue(result["project_overlap"])
        self.assertFalse(result["scoring_executed"])

    def test_case_variants_do_not_bypass_firewall(self) -> None:
        result = check_candidate({
            "source_root": "cve-2026-24468",
            "source_project": "openaev-platform/OPENAEV",
        })
        self.assertFalse(result["allowed"])
        self.assertTrue(result["root_overlap"])
        self.assertTrue(result["project_overlap"])

    def test_identifier_in_url_does_not_bypass_root_identity(self) -> None:
        result = check_candidate({
            "source_root": "unrelated-wrapper-id",
            "source_project": "v6-independence/alias-probe",
            "canonical_advisory_url": "https://example.invalid/security/CVE-2026-24468",
        })
        self.assertFalse(result["allowed"])
        self.assertIn("cve-2026-24468", result["identifier_overlap"])

    def test_project_aliases_are_checked(self) -> None:
        result = check_candidate({
            "source_root": "V6-INDEPENDENCE-ALIAS-ROOT",
            "source_project": "new-owner/new-name",
            "source_project_aliases": ["OpenAEV-Platform/openaev"],
        })
        self.assertFalse(result["allowed"])
        self.assertIn("openaev-platform/openaev", result["project_overlap"])

    def test_prior_calibration_source_is_not_fresh(self) -> None:
        result = check_candidate({
            "source_root": "CVE-2024-53995",
            "source_project": "sickchill/sickchill",
        })
        self.assertFalse(result["allowed"])
        self.assertTrue(result["root_overlap"])
        self.assertTrue(result["project_overlap"])

    def test_new_identity_can_pass_firewall(self) -> None:
        result = check_candidate({
            "source_root": "V6-INDEPENDENCE-TEST-ROOT",
            "source_project": "v6-independence/test-project",
        })
        self.assertTrue(result["allowed"])

    def test_canonical_url(self) -> None:
        self.assertEqual(canonical_url("HTTPS://Example.COM:443/path/#x"), "https://example.com/path")
        self.assertEqual(
            canonical_url("https://WWW.GitHub.com/OpenAEV-Platform/OpenAEV/security/advisories/GHSA-ABCD-EFGH-IJKL/"),
            "https://github.com/openaev-platform/openaev/security/advisories/ghsa-abcd-efgh-ijkl",
        )

    def test_index_contains_v5_and_calibration(self) -> None:
        index = exposure_index()
        self.assertIn("cve-2026-24468", index["roots"])
        self.assertIn("cve-2024-53995", index["roots"])
        self.assertIn("cve-2026-24468", index["identifiers"])


if __name__ == "__main__":
    unittest.main()

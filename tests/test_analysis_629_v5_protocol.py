from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v5_prepare import _multi_cases
from raw_recon_v5_source_audit import HARD_ANCHORS, audit_row
from raw_recon_v5_source_discovery import _is_research_project

ROOT = Path(__file__).resolve().parents[1]


class Analysis629V5ProtocolTests(unittest.TestCase):
    def test_family_taxonomy_is_exactly_current_registry(self):
        self.assertEqual(set(HARD_ANCHORS), set(DETECTOR_SPECS))
        self.assertEqual(len(DETECTOR_SPECS), 36)

    def test_preparation_modules_do_not_import_scoring_or_ranking_runners(self):
        forbidden = {"raw_recon_benchmark", "analysis_ranking"}
        for name in (
            "app/raw_recon_v5_source_discovery.py",
            "app/raw_recon_v5_source_audit.py",
            "app/raw_recon_v5_business_logic_supplement.py",
            "app/raw_recon_v5_prepare.py",
        ):
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])
            self.assertFalse(imports & forbidden, (name, sorted(imports & forbidden)))

    def test_research_only_repository_references_are_not_project_identity(self):
        for project in (
            "meifukun/Web-Security-PoCs",
            "researcher/CVE-2026-1234",
            "lab/exploit-pocs",
        ):
            self.assertTrue(_is_research_project(project), project)
        self.assertFalse(_is_research_project("pretix/pretix"))
        self.assertFalse(_is_research_project("RocketChat/Rocket.Chat"))

    def test_business_logic_fresh_advisory_wording_passes_semantic_gate(self):
        passed, hits, _ = audit_row(
            "business_logic",
            {
                "summary": "Payment integration did not properly validate payment status responses",
                "description": "A successful payment status response from one payment could be supplied for a different payment, gaining multiple tickets with one payment.",
            },
        )
        self.assertTrue(passed, hits)
        self.assertTrue(all(hits), hits)

    def test_multifamily_pairing_is_disjoint_complete_and_independent(self):
        selected = [
            {
                "family": family,
                "source_root": f"ROOT-{index:02d}",
                "source_project": f"org/project-{index:02d}",
                "published_at": "2026-08-13T00:00:00Z",
                "canonical_advisory_url": f"https://fixture.invalid/{index}",
            }
            for index, family in enumerate(sorted(DETECTOR_SPECS), start=1)
        ]
        cases = _multi_cases(selected)
        self.assertEqual(len(cases), 72)
        self.assertTrue(all(len(row["raw_observations"]) == 2 for row in cases))
        self.assertTrue(all("raw" not in row for row in cases))
        dual = [row for row in cases if row["case_kind"] == "dual_positive"]
        self.assertEqual(len(dual), 18)
        seen = []
        for row in dual:
            self.assertEqual(len(row["expected_families"]), 2)
            seen.extend(row["expected_families"])
        self.assertEqual(sorted(seen), sorted(DETECTOR_SPECS))

    def test_frozen_artifacts_when_present_have_pre_score_status(self):
        freeze = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"
        if not freeze.exists():
            self.skipTest("v5 has not been prepared yet")
        data = json.loads(freeze.read_text(encoding="utf-8"))
        self.assertEqual(data["evaluation_status"], "sealed_unscored")
        self.assertFalse(data["scoring_executed"])
        self.assertEqual(data["case_count"], 216)
        self.assertEqual(data["single_case_count"], 144)
        self.assertEqual(data["multi_case_count"], 72)
        self.assertEqual(data["multi_observation_model"], "two_independent_stored_target_observations")
        self.assertEqual(data["family_count"], 36)
        self.assertEqual(data["source_root_count"], 36)
        self.assertEqual(data["source_project_count"], 36)
        self.assertEqual(data["prior_root_overlap_count"], 0)
        self.assertEqual(data["prior_project_overlap_count"], 0)
        self.assertEqual(data["prior_url_overlap_count"], 0)


if __name__ == "__main__":
    unittest.main()

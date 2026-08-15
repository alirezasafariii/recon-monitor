from __future__ import annotations

import json
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import raw_recon_v7_source_firewall as firewall
import raw_recon_v7_duplicate_target_repair as duplicate_repair
import v7_external_exposure as external


def empty_index() -> dict[str, set[str]]:
    return {"roots": set(), "projects": set(), "urls": set(), "identifiers": set()}


class V7StrictUnseenFirewallTests(unittest.TestCase):
    def test_external_registry_is_identity_only_and_exactly_100(self) -> None:
        payload = {
            "sources": [
                {
                    "source_root": f"GHSA-TEST-{i:04d}-ABCD",
                    "source_project": f"owner{i}/repo{i}",
                    "canonical_advisory_url": f"https://github.com/advisories/GHSA-TEST-{i:04d}-ABCD",
                    "references": [f"https://github.com/owner{i}/repo{i}/commit/deadbeef{i:04d}"],
                    "identifiers": [f"CVE-2099-{10000+i}"],
                    "family": "must_not_be_imported",
                    "label": True,
                    "score": 100,
                    "evidence": {"secret": "must_not_be_imported"},
                }
                for i in range(100)
            ]
        }
        registry = external.build_registry(payload)
        self.assertEqual(registry["source_count"], 100)
        self.assertEqual(registry["unique_root_count"], 100)
        self.assertEqual(registry["unique_project_count"], 100)
        self.assertTrue(registry["identity_only"])
        self.assertFalse(registry["labels_imported"])
        self.assertFalse(registry["evidence_imported"])
        self.assertFalse(registry["scores_imported"])
        row = registry["sources"][0]
        self.assertNotIn("family", row)
        self.assertNotIn("label", row)
        self.assertNotIn("score", row)
        self.assertNotIn("evidence", row)

    def test_engine_seen_source_is_hard_rejected(self) -> None:
        hard = empty_index()
        hard["roots"].add("ghsa-engine-seen")
        research = empty_index()
        row = {"source_root": "GHSA-ENGINE-SEEN", "source_project": "new/project"}
        result = firewall.check_candidate(row, index=hard, research_index=research)
        self.assertFalse(result["allowed"])
        self.assertTrue(result["engine_seen"])
        self.assertFalse(result["research_preexposed"])

    def test_research_only_preexposure_is_allowed_but_marked(self) -> None:
        hard = empty_index()
        research = empty_index()
        research["roots"].add("ghsa-research-only")
        row = {"source_root": "GHSA-RESEARCH-ONLY", "source_project": "new/project"}
        result = firewall.check_candidate(row, index=hard, research_index=research)
        self.assertTrue(result["allowed"])
        self.assertFalse(result["engine_seen"])
        self.assertTrue(result["research_preexposed"])

    def test_duplicate_target_repair_promotes_same_root_without_labeling(self) -> None:
        payload = {
            "scoring_executed": False,
            "first_blind_consumed": False,
            "candidates_by_family": {
                "dom_xss": [
                    {
                        "source_root": "GHSA-DOM-TEST",
                        "source_project": "owner/dom-project",
                        "matched_cwes": [],
                        "scoring_executed": False,
                    }
                ]
            },
        }
        targeted = {
            "dom_xss": [
                {
                    "source_root": "GHSA-DOM-TEST",
                    "source_project": "owner/dom-project",
                    "matched_cwes": ["CWE-79"],
                    "v7_targeted_gap_candidate": True,
                    "v7_targeted_exact_cwe": True,
                    "v7_targeted_context_match": True,
                    "v7_targeted_context_tokens": ["dom", "xss"],
                    "v7_target_family_is_candidate_only": True,
                    "v7_target_family_requires_literal_adjudication": True,
                    "selection_uses_detector_scores": False,
                    "selection_uses_admission_results": False,
                    "selection_uses_ranking_results": False,
                    "selection_uses_v6_first_blind_score": False,
                    "selection_uses_v6_first_blind_case_errors": False,
                    "selection_uses_corpus_v1_labels": False,
                    "selection_uses_corpus_v1_evidence": False,
                    "selection_uses_corpus_v1_scores": False,
                    "scoring_executed": False,
                }
            ]
        }
        merged, promoted = duplicate_repair.merge_targeted_rows(payload, targeted)
        self.assertEqual(promoted["dom_xss"], 1)
        rows = merged["candidates_by_family"]["dom_xss"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["matched_cwes"], ["CWE-79"])
        self.assertTrue(rows[0]["v7_targeted_gap_candidate"])
        self.assertTrue(rows[0]["v7_target_family_is_candidate_only"])
        self.assertNotIn("final_family", rows[0])
        self.assertNotIn("label", rows[0])
        self.assertFalse(merged["duplicate_target_repair_scoring_executed"])

    def test_protocol_pins_engine_and_corpus_v1(self) -> None:
        protocol_path = Path(__file__).resolve().parents[1] / "benchmarks/raw/sources/v7_protocol.json"
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
        self.assertEqual(
            protocol["engine_baseline"]["commit_sha"],
            "b8b15261cc4049a1e5e425a83e57b6378a856113",
        )
        self.assertEqual(
            protocol["source_independence"]["real_world_corpus_v1_commit_pin"],
            external.CORPUS_V1_COMMIT,
        )
        self.assertTrue(protocol["source_independence"]["forbid_real_world_corpus_v1_overlap"])
        self.assertTrue(protocol["source_independence"]["forbid_engine_seen_root_overlap"])
        self.assertTrue(protocol["source_independence"]["allow_candidate_only_research_preexposure_if_engine_unseen"])
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_labels_used_for_source_selection"])
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_evidence_used_for_source_selection"])
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_scores_used_for_source_selection"])
        self.assertFalse(protocol["scoring_executed"])
        self.assertFalse(protocol["first_blind_consumed"])
        self.assertFalse(protocol["freeze_contract"]["merge_authorized"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import v7_external_exposure as external


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
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_labels_used_for_source_selection"])
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_evidence_used_for_source_selection"])
        self.assertFalse(protocol["research_contract"]["real_world_corpus_v1_scores_used_for_source_selection"])
        self.assertFalse(protocol["scoring_executed"])
        self.assertFalse(protocol["first_blind_consumed"])
        self.assertFalse(protocol["freeze_contract"]["merge_authorized"])


if __name__ == "__main__":
    unittest.main()

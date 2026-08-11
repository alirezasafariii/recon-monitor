from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v2_corpus import validate_v2_corpus


def case(root: str, kind: str, details: dict, *, project: str = "example/project", family: str = "information_disclosure") -> dict:
    return {
        "id": f"{root}-{kind}",
        "source_root": root,
        "source_project": project,
        "source_date": "2026-08-11",
        "family": family,
        "case_kind": kind,
        "rank_required": kind != "sparse_noisy",
        "split": "postfreeze_holdout",
        "provenance": {
            "primary_source": True,
            "source_kind": "github_reviewed_advisory",
            "url": f"https://github.com/{project}/security/advisories/{root}",
        },
        "raw": {
            "target": "example.fixture.invalid",
            "endpoint": "/api/status",
            "method": "GET",
            "endpoint_schema": {"authentication_hints": [], "body_fields": [], "object_identifiers": [], "path_parameters": [], "query_parameters": []},
            "details": details,
            "business_context": "customer_data",
            "category": "",
        },
        "expected": {
            "family": family,
            "admitted": kind == "positive",
            "condition_signals": ["public_observation"] if kind == "positive" else [],
        },
    }


class RawReconV2Protocol6130Tests(unittest.TestCase):
    def group(self, root: str = "GHSA-v2test-0000-0001") -> list[dict]:
        return [
            case(root, "positive", {"status_code": 200, "response_text": "Stored public response contains sensitive diagnostic material"}),
            case(root, "near_miss", {"status_code": 200}),
            case(root, "secure_negative", {"status_code": 403}),
            case(root, "sparse_noisy", {}),
        ]

    def test_positive_must_not_be_raw_identical_to_near_miss(self):
        rows = self.group()
        rows[1]["raw"] = dict(rows[0]["raw"])
        report = validate_v2_corpus(rows, require_collection_floor=False)
        self.assertFalse(report["passed"])
        self.assertEqual(report["positive_control_raw_collision_count"], 1)

    def test_positive_must_have_distinct_observable_details(self):
        rows = self.group()
        rows[1]["raw"]["details"] = dict(rows[0]["raw"]["details"])
        rows[1]["raw"]["endpoint"] = "/api/other"
        report = validate_v2_corpus(rows, require_collection_floor=False)
        self.assertFalse(report["passed"])
        self.assertEqual(report["positive_observable_delta_rate"], 0.0)

    def test_target_observable_delta_passes_protocol_layer(self):
        report = validate_v2_corpus(self.group(), require_collection_floor=False)
        self.assertTrue(report["passed"], report["errors"])
        self.assertEqual(report["positive_control_raw_collision_count"], 0)
        self.assertEqual(report["positive_observable_delta_rate"], 1.0)

    def test_v1_root_is_rejected_as_prior_overlap(self):
        rows = self.group("GHSA-3pjw-73gf-8qr5")
        report = validate_v2_corpus(rows, require_collection_floor=False)
        self.assertFalse(report["passed"])
        self.assertGreaterEqual(report["prior_source_root_overlap_count"], 1)


if __name__ == "__main__":
    unittest.main()

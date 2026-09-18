from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_review_queue as queue


def source_pack(i: int, *, exact_target: bool = True) -> dict:
    return {
        "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
        "source_project": f"owner/project-{i:04d}",
        "family_target": "ssrf" if exact_target else None,
        "target_cwe": "CWE-918" if exact_target else None,
        "candidate_fix_commit_sha": f"fix{i:04d}" if i < 70 else None,
        "candidate_fix_patch_set_sha256": f"{i+1:064x}"[-64:],
        "advisory_snapshot_sha256": f"{i+1000:064x}"[-64:],
        "source_pack_sha256": f"{i+2000:064x}"[-64:],
        "advisory_snapshot": {
            "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
            "vulnerabilities": [{
                "ecosystem": "pip",
                "package": f"pkg-{i}",
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": "2.0.0",
            }],
        },
    }


def pair(i: int) -> dict:
    return {
        "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
        "source_project": f"owner/project-{i:04d}",
        "revision_pair_sha256": f"{i+3000:064x}"[-64:],
        "candidate_vulnerable_parent_sha": f"parent{i:04d}",
        "candidate_fix_commit_sha": f"fix{i:04d}",
        "parent_tree_sha": f"ptree{i:04d}",
        "fix_tree_sha": f"ftree{i:04d}",
        "file_pairs": [{
            "filename": "app.py",
            "parent_blob_sha": f"pblob{i:04d}",
            "fix_blob_sha": f"fblob{i:04d}",
            "parent_present": True,
            "fix_present": True,
            "file_pair_sha256": f"{i+4000:064x}"[-64:],
        }],
    }


class ReviewQueueTests(unittest.TestCase):
    def test_exact_pair_generates_distinct_positive_negative_bindings(self):
        pack = source_pack(0)
        exact = pair(0)
        positive = queue.draft_for(pack, "positive", exact)
        negative = queue.draft_for(pack, "secure_negative", exact)
        self.assertEqual(positive["evidence_binding"]["kind"], "exact_parent_revision_boundary")
        self.assertEqual(negative["evidence_binding"]["kind"], "exact_fix_revision_boundary")
        self.assertNotEqual(positive["evidence_snapshot_id"], negative["evidence_snapshot_id"])
        self.assertIsNone(positive["review"]["family"])
        self.assertIsNone(positive["review"]["label"])
        self.assertFalse(positive["review"]["human_verified"])
        self.assertFalse(positive["verified_replay_eligible"])

    def test_version_fallback_stays_candidate_only(self):
        pack = source_pack(90)
        positive = queue.draft_for(pack, "positive", None)
        negative = queue.draft_for(pack, "secure_negative", None)
        self.assertEqual(positive["evidence_binding"]["kind"], "vulnerable_version_boundary")
        self.assertEqual(negative["evidence_binding"]["kind"], "patched_version_boundary")
        self.assertFalse(positive["proposed_outcome_is_label"])
        self.assertFalse(negative["proposed_outcome_is_label"])

    def test_candidate_fix_without_exact_parent_is_not_called_exact(self):
        pack = source_pack(68)
        negative = queue.draft_for(pack, "secure_negative", None)
        self.assertEqual(negative["evidence_binding"]["kind"], "candidate_fix_revision_boundary")
        self.assertFalse(negative["evidence_binding"]["boundary_semantics_human_confirmed"])

    def test_builds_exact_300_pending_drafts(self):
        packs = [source_pack(i, exact_target=(i < 60)) for i in range(100)]
        pairs = [pair(i) for i in range(66)]
        result = queue.build_review_queue(packs, pairs)
        self.assertTrue(result["passed"])
        self.assertEqual(result["draft_count"], 300)
        self.assertEqual(result["source_origin_count"], 100)
        self.assertEqual(result["unique_evidence_snapshot_count"], 300)
        self.assertEqual(result["variant_counts"], {
            "positive": 100,
            "secure_negative": 100,
            "sparse_noisy": 100,
        })
        self.assertEqual(result["near_miss_review_draft_count"], 0)
        self.assertEqual(result["human_verified_record_count"], 0)
        self.assertEqual(result["verified_replay_eligible_count"], 0)

    def test_queue_never_prefills_evidence_quality_or_label(self):
        result = queue.build_review_queue(
            [source_pack(i, exact_target=(i < 60)) for i in range(100)],
            [pair(i) for i in range(66)],
        )
        for draft in result["drafts"]:
            review = draft["review"]
            self.assertTrue(all(value is None for value in review["evidence_quality"].values()))
            self.assertIsNone(review["family"])
            self.assertIsNone(review["label"])
            self.assertIsNone(review["reviewer_id"])
            self.assertIsNone(review["reviewed_at"])
            self.assertFalse(review["human_verified"])
            self.assertFalse(draft["scoring_executed"])
            self.assertFalse(draft["target_contact_performed"])


if __name__ == "__main__":
    unittest.main()

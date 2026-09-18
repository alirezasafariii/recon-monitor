from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_source_attested as source_attested


def artifacts(root: str = "GHSA-AAAA-BBBB-CCCC", family: str = "ssrf") -> tuple[dict, dict, dict]:
    project = "owner/project"
    fix = "f" * 40
    parent = "a" * 40
    feasibility = {
        "sources": [{
            "source_root": root,
            "source_project": project,
            "source_kind": "github_reviewed_advisory",
            "advisory_fetch_status": "retrieved",
            "evaluation_role": "fresh_candidate",
            "capture_feasibility": "strong_revision_boundary",
            "family_hints": [family],
            "advisory_cwes": ["CWE-918"],
            "source_taxonomy_match": {
                "family_target": family,
                "target_cwe": "CWE-918",
                "target_cwe_present": True,
            },
        }]
    }
    source_evidence = {
        "source_packs": [{
            "source_root": root,
            "source_project": project,
            "candidate_fix_commit_sha": fix,
            "candidate_vulnerable_parent_sha": parent,
            "candidate_fix_patch_set_sha256": "1" * 64,
            "advisory_snapshot": {
                "ghsa_id": root,
                "published_at": "2026-09-01T00:00:00Z",
                "withdrawn_at": None,
                "repository_advisory_url": f"https://api.github.com/repos/{project}/security-advisories/{root}",
                "references": [
                    f"https://github.com/{project}/commit/{fix}",
                    f"https://github.com/advisories/{root}",
                ],
                "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
                "vulnerabilities": [{
                    "package": "example",
                    "vulnerable_version_range": "< 2.0.0",
                    "first_patched_version": "2.0.0",
                }],
            },
        }]
    }
    revision_pairs = {
        "revision_pairs": [{
            "source_root": root,
            "source_project": project,
            "candidate_fix_commit_sha": fix,
            "candidate_vulnerable_parent_sha": parent,
            "changed_file_count": 1,
            "parent_tree_sha": "b" * 40,
            "fix_tree_sha": "c" * 40,
            "parent_tree_truncated": False,
            "fix_tree_truncated": False,
            "revision_pair_complete": True,
            "revision_pair_sha256": "2" * 64,
            "incomplete_file_count": 0,
            "file_pairs": [{
                "filename": "app.py",
                "pair_complete": True,
                "patch_sha256": "3" * 64,
            }],
        }]
    }
    return feasibility, source_evidence, revision_pairs


class SourceAttestedCorpusV1Tests(unittest.TestCase):
    def test_exact_reviewed_boundary_creates_positive_and_negative_without_human_review(self):
        result = source_attested.build_source_attested_cases(*artifacts())
        self.assertEqual(result["eligible_origin_count"], 1)
        self.assertEqual(result["attested_record_count"], 2)
        self.assertEqual(result["positive_count"], 1)
        self.assertEqual(result["negative_count"], 1)
        self.assertEqual(result["family_count"], 1)
        labels = {row["variant"]: row["label"] for row in result["records"]}
        self.assertEqual(labels, {"positive": True, "secure_negative": False})
        self.assertTrue(all(row["human_verified"] is False for row in result["records"]))
        self.assertTrue(all(row["activation_eligible"] is False for row in result["records"]))
        self.assertTrue(result["safety"]["ambiguous_cases_are_excluded"])

    def test_ambiguous_family_hint_is_excluded_instead_of_guessed(self):
        feasibility, source_evidence, revision_pairs = artifacts()
        feasibility["sources"][0]["family_hints"] = ["ssrf", "open_redirect"]
        result = source_attested.build_source_attested_cases(
            feasibility, source_evidence, revision_pairs
        )
        self.assertEqual(result["attested_record_count"], 0)
        self.assertEqual(result["excluded_origin_count"], 1)
        self.assertIn(
            "family_hint_not_unambiguous",
            result["excluded"][0]["reasons"],
        )

    def test_withdrawn_advisory_is_excluded(self):
        feasibility, source_evidence, revision_pairs = artifacts()
        source_evidence["source_packs"][0]["advisory_snapshot"]["withdrawn_at"] = "2026-09-02T00:00:00Z"
        result = source_attested.build_source_attested_cases(
            feasibility, source_evidence, revision_pairs
        )
        self.assertEqual(result["attested_record_count"], 0)
        self.assertIn("advisory_withdrawn", result["excluded"][0]["reasons"])

    def test_fix_commit_must_be_directly_referenced_by_advisory(self):
        feasibility, source_evidence, revision_pairs = artifacts()
        source_evidence["source_packs"][0]["advisory_snapshot"]["references"] = [
            "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC"
        ]
        result = source_attested.build_source_attested_cases(
            feasibility, source_evidence, revision_pairs
        )
        self.assertEqual(result["attested_record_count"], 0)
        self.assertIn(
            "fix_commit_not_directly_referenced_by_advisory",
            result["excluded"][0]["reasons"],
        )


    def test_blind_replay_manifest_removes_ground_truth_and_uses_opaque_ids(self):
        result = source_attested.build_source_attested_cases(*artifacts())
        manifest = source_attested.blind_replay_manifest(result["records"])
        self.assertEqual(manifest["case_count"], 2)
        self.assertTrue(manifest["safety"]["label_blind"])
        self.assertTrue(manifest["safety"]["family_blind"])
        for row in manifest["cases"]:
            self.assertTrue(row["case_id"].startswith("SA-"))
            self.assertNotIn("positive", row["case_id"])
            self.assertNotIn("negative", row["case_id"])
            self.assertNotIn("label", row)
            self.assertNotIn("family", row)
            self.assertNotIn("variant", row)
            self.assertNotIn("source_root", row)

    def test_no_engine_scores_means_metrics_remain_unavailable(self):
        attestation = source_attested.build_source_attested_cases(*artifacts())
        report = source_attested.source_attested_evaluation_report(attestation)
        self.assertEqual(report["status"], "awaiting_current_engine_replay")
        self.assertEqual(report["scored_record_count"], 0)
        self.assertIsNone(report["global_holdout_metrics"])
        self.assertTrue(report["safety"]["metrics_are_unavailable_without_current_engine_scores"])

    def test_score_artifact_must_not_contain_ground_truth_label(self):
        attestation = source_attested.build_source_attested_cases(*artifacts())
        case_id = attestation["records"][0]["id"]
        joined = source_attested.attach_current_engine_scores(
            attestation["records"],
            [{
                "id": case_id,
                "label": True,
                "decision_readiness_score": 90,
                "bug_proximity_score": 90,
                "target_evidence_confidence": 90,
            }],
        )
        self.assertEqual(joined["scored_count"], 0)
        self.assertEqual(joined["rejected_score_count"], 1)
        self.assertEqual(
            joined["rejected_scores"][0]["reason"],
            "score_artifact_must_be_label_blind",
        )

    def test_complete_blind_scores_produce_holdout_metrics_without_origin_leakage(self):
        first = source_attested.build_source_attested_cases(*artifacts())
        second_artifacts = artifacts(
            root="GHSA-DDDD-EEEE-FFFF",
            family="ssrf",
        )
        # Keep the second source independent.
        second_artifacts[0]["sources"][0]["source_project"] = "owner/second"
        second_artifacts[1]["source_packs"][0]["source_project"] = "owner/second"
        second_artifacts[2]["revision_pairs"][0]["source_project"] = "owner/second"
        second_artifacts[1]["source_packs"][0]["advisory_snapshot"]["repository_advisory_url"] = (
            "https://api.github.com/repos/owner/second/security-advisories/GHSA-DDDD-EEEE-FFFF"
        )
        fix = second_artifacts[2]["revision_pairs"][0]["candidate_fix_commit_sha"]
        second_artifacts[1]["source_packs"][0]["advisory_snapshot"]["references"][0] = (
            f"https://github.com/owner/second/commit/{fix}"
        )
        second = source_attested.build_source_attested_cases(*second_artifacts)

        records = [*first["records"], *second["records"]]
        attestation = {
            "eligible_origin_count": 2,
            "attested_record_count": 4,
            "family_count": 1,
            "records": records,
        }
        scores = []
        for row in records:
            scores.append({
                "id": row["id"],
                "decision_readiness_score": 90 if row["label"] else 10,
                "bug_proximity_score": 90 if row["label"] else 10,
                "target_evidence_confidence": 90 if row["label"] else 10,
                "engine_version": "8.8.0",
            })
        report = source_attested.source_attested_evaluation_report(
            attestation,
            score_rows=scores,
        )
        self.assertEqual(report["status"], "source_attested_evaluation_ready")
        self.assertEqual(report["scored_record_count"], 4)
        self.assertEqual(report["origin_leakage_count"], 0)
        self.assertIsNotNone(report["global_holdout_metrics"])
        self.assertEqual(report["global_holdout_metrics"]["precision"], 1.0)
        self.assertEqual(report["global_holdout_metrics"]["recall"], 1.0)
        self.assertTrue(report["safety"]["no_production_activation"])

    def test_checked_in_corpus_has_conservative_nonzero_auto_attestation_coverage(self):
        feasibility = json.loads(
            (ROOT / "benchmarks/real_world/v1/source_feasibility_final.json").read_text(encoding="utf-8")
        )
        source_evidence = json.loads(
            (ROOT / "benchmarks/real_world/v1/public_source_evidence.json").read_text(encoding="utf-8")
        )
        revision_pairs = json.loads(
            (ROOT / "benchmarks/real_world/v1/revision_pair_evidence.json").read_text(encoding="utf-8")
        )
        result = source_attested.build_source_attested_cases(
            feasibility,
            source_evidence,
            revision_pairs,
        )
        self.assertEqual(result["eligible_origin_count"], 19)
        self.assertEqual(result["attested_record_count"], 38)
        self.assertEqual(result["family_count"], 11)
        self.assertEqual(result["positive_count"], 19)
        self.assertEqual(result["negative_count"], 19)


if __name__ == "__main__":
    unittest.main()

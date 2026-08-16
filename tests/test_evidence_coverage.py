from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from evidence_coverage import snapshot_evidence_coverage
from family_reasoning import FAMILY_REASONING


class FakeDB:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def all(self, sql, params=()):
        if "FROM analysis_hypotheses" in sql:
            analysis_id, target = params
            return [
                row
                for row in self.rows
                if row.get("analysis_id") == analysis_id and row.get("target") == target
            ]
        return []


def evidence(signal, *, source_group="test"):
    return {"type": signal, "source_group": source_group, "text": signal}


def row(family, *, support=(), contradict=(), analysis_id="ANALYSIS-1"):
    return {
        "analysis_id": analysis_id,
        "target": "example.test",
        "bug_family": family,
        "supporting_evidence_json": json.dumps(list(support)),
        "contradicting_evidence_json": json.dumps(list(contradict)),
    }


def quality(*, dns="complete", urls="complete", javascript="complete"):
    return {
        "status": "complete"
        if {dns, urls, javascript} == {"complete"}
        else "degraded",
        "dimensions": {
            "dns": {"status": dns},
            "urls": {"status": urls},
            "javascript": {"status": javascript},
        },
    }


def make_ctx(root: Path, rows=()):
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        db=FakeDB(rows),
        run_id="RUN-1",
        run_dir=run_dir,
        policy=SimpleNamespace(name="example.test"),
    )


def signal_map(group):
    return {item["signal"]: item for item in group["signals"]}


class EvidenceCoverageTests(unittest.TestCase):
    def test_ssrf_uses_canonical_family_reasoning_and_observed_support(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                [
                    row(
                        "ssrf",
                        support=[
                            evidence("url_parameter", source_group="endpoint"),
                            evidence("server_request_function", source_group="javascript"),
                            evidence("server_fetch_observed", source_group="behavioral"),
                        ],
                    )
                ],
            )
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(),
                persist=False,
            )
            ssrf = result["families"]["ssrf"]
            self.assertEqual(ssrf["policy_source"], "family_reasoning")
            self.assertEqual(ssrf["promotion_coverage_status"], "observed")
            self.assertEqual(
                len(ssrf["promotion_required"]),
                len(FAMILY_REASONING["ssrf"]["promotion_required"]),
            )
            self.assertEqual(ssrf["promotion_required"][0]["status"], "observed")
            self.assertEqual(ssrf["promotion_required"][1]["status"], "observed")
            self.assertEqual(ssrf["promotion_required"][2]["status"], "observed")

    def test_complete_passive_collection_can_mean_not_observed_but_not_absent(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(),
                persist=False,
            )
            first_group = result["families"]["ssrf"]["promotion_required"][0]
            signals = signal_map(first_group)
            self.assertEqual(first_group["status"], "not_observed")
            self.assertEqual(signals["url_parameter"]["status"], "not_observed")
            self.assertTrue(signals["url_parameter"]["not_proof_of_absence"])
            self.assertIn("not proof", result["absence_semantics"])

    def test_collection_gap_becomes_not_collected(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(javascript="partial"),
                persist=False,
            )
            second_group = result["families"]["ssrf"]["promotion_required"][1]
            signals = signal_map(second_group)
            self.assertEqual(second_group["status"], "not_collected")
            self.assertEqual(signals["server_request_function"]["status"], "not_collected")
            self.assertEqual(
                signals["server_request_function"]["collection_status"]["javascript"],
                "partial",
            )

    def test_behavioral_confirmation_stays_unknown_without_direct_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(),
                persist=False,
            )
            confirmation = result["families"]["ssrf"]["confirmation_required"][0]
            signals = signal_map(confirmation)
            self.assertEqual(confirmation["status"], "unknown")
            self.assertEqual(
                signals["destination_policy_bypass_observed"]["status"],
                "unknown",
            )
            self.assertEqual(
                signals["restricted_destination_accepted"]["status"],
                "unknown",
            )

    def test_observed_evidence_overrides_collection_gap(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                [
                    row(
                        "ssrf",
                        support=[
                            evidence(
                                "server_request_function",
                                source_group="javascript",
                            )
                        ],
                    )
                ],
            )
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(javascript="partial"),
                persist=False,
            )
            second_group = result["families"]["ssrf"]["promotion_required"][1]
            signals = signal_map(second_group)
            self.assertEqual(second_group["status"], "observed")
            self.assertEqual(signals["server_request_function"]["status"], "observed")
            self.assertEqual(
                signals["server_request_function"]["observation_channel"],
                "support",
            )

    def test_unknown_collection_never_turns_into_not_observed(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(urls="unknown", javascript="unknown"),
                persist=False,
            )
            first_group = result["families"]["ssrf"]["promotion_required"][0]
            self.assertEqual(first_group["status"], "unknown")

    def test_contradicting_signal_is_reported_as_observed_without_satisfying_support_group(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                [
                    row(
                        "ssrf",
                        contradict=[
                            evidence(
                                "destination_validation_observed",
                                source_group="behavioral",
                            )
                        ],
                    )
                ],
            )
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(),
                persist=False,
            )
            blocking = {
                item["signal"]: item
                for item in result["families"]["ssrf"]["blocking_contradictions"]
            }
            self.assertEqual(
                blocking["destination_validation_observed"]["status"],
                "observed",
            )
            self.assertEqual(
                blocking["destination_validation_observed"]["observation_channel"],
                "contradict",
            )
            self.assertNotEqual(
                result["families"]["ssrf"]["promotion_coverage_status"],
                "observed",
            )

    def test_secret_pattern_tracks_javascript_collection_gap(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(javascript="partial"),
                persist=False,
            )
            first_group = result["families"]["secret_exposure"]["promotion_required"][0]
            signals = signal_map(first_group)
            self.assertEqual(first_group["status"], "not_collected")
            self.assertEqual(signals["secret_pattern"]["status"], "not_collected")
            self.assertEqual(
                signals["secret_pattern"]["collection_status"]["javascript"],
                "partial",
            )

    def test_snapshot_is_diagnostic_only_and_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_evidence_coverage(
                ctx,
                analysis_id="ANALYSIS-1",
                collection_quality=quality(),
            )
            self.assertTrue(result["diagnostic_only"])
            self.assertFalse(result["affects_admission"])
            self.assertFalse(result["affects_candidate_promotion"])
            self.assertIsNone(result["numeric_score"])
            self.assertEqual(result["family_count"], len(FAMILY_REASONING))
            output = Path(result["output"])
            self.assertTrue(output.exists())
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(persisted["analysis_id"], "ANALYSIS-1")
            self.assertIn("ssrf", persisted["families"])


if __name__ == "__main__":
    unittest.main()

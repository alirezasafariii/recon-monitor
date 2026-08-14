from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import v6_benchmark_evaluate as evaluator


class V6EvaluatorGuardTests(unittest.TestCase):
    def test_noncanonical_artifact_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alternate = Path(tmp) / "analysis_raw_v6.jsonl"
            alternate.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "override is forbidden"):
                evaluator._require_canonical_path("corpus", alternate, evaluator.DEFAULT_CORPUS)

    def test_canonical_artifact_path_is_accepted(self) -> None:
        self.assertEqual(
            evaluator._require_canonical_path("protocol", evaluator.DEFAULT_PROTOCOL, evaluator.DEFAULT_PROTOCOL),
            evaluator.DEFAULT_PROTOCOL,
        )

    def test_scoring_requires_persisted_consumption_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with mock.patch.object(evaluator, "DEFAULT_CONSUMPTION_RECEIPT", missing):
                with self.assertRaisesRegex(RuntimeError, "consumption receipt is required"):
                    evaluator._require_consumption_authorization()

    def test_scoring_receipt_is_bound_to_github_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipt_path = Path(tmp) / "receipt.json"
            receipt_path.write_text(
                json.dumps(
                    {
                        "state": "consumed_before_scoring",
                        "github_run_id": "12345",
                        "github_run_attempt": "1",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(evaluator, "DEFAULT_CONSUMPTION_RECEIPT", receipt_path):
                with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1"}, clear=False):
                    receipt = evaluator._require_consumption_authorization()
                    self.assertEqual(receipt["state"], "consumed_before_scoring")

                with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"}, clear=False):
                    with self.assertRaisesRegex(RuntimeError, "workflow identity does not match"):
                        evaluator._require_consumption_authorization()


if __name__ == "__main__":
    unittest.main()

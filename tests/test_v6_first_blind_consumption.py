from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from v6_first_blind_consume import _validate_artifact_hashes, _validate_run_identity


class V6FirstBlindConsumptionTests(unittest.TestCase):
    def test_authorization_is_bound_to_exact_workflow_run_and_attempt(self) -> None:
        receipt = {
            "github_run_id": "12345",
            "github_run_attempt": "1",
        }
        _validate_run_identity(receipt, "12345", "1")
        with self.assertRaisesRegex(RuntimeError, "different GitHub workflow run/attempt"):
            _validate_run_identity(receipt, "12345", "2")
        with self.assertRaisesRegex(RuntimeError, "different GitHub workflow run/attempt"):
            _validate_run_identity(receipt, "99999", "1")

    def test_authorization_rejects_missing_workflow_identity(self) -> None:
        receipt = {
            "github_run_id": "12345",
            "github_run_attempt": "1",
        }
        with self.assertRaisesRegex(RuntimeError, "run identity is required"):
            _validate_run_identity(receipt, "", "1")

    def test_authorization_is_bound_to_exact_canonical_artifact_hashes(self) -> None:
        receipt = {
            "canonical_artifact_sha256": {
                "corpus": "a" * 64,
                "shortlist": "b" * 64,
                "protocol": "c" * 64,
            }
        }
        current = {
            "corpus": "a" * 64,
            "shortlist": "b" * 64,
            "protocol": "c" * 64,
        }
        _validate_artifact_hashes(receipt, current)

        changed = dict(current)
        changed["protocol"] = "d" * 64
        with self.assertRaisesRegex(RuntimeError, "protocol"):
            _validate_artifact_hashes(receipt, changed)

    def test_authorization_rejects_missing_canonical_hash_manifest(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "missing canonical artifact hashes"):
            _validate_artifact_hashes({}, {"corpus": "a" * 64})


if __name__ == "__main__":
    unittest.main()

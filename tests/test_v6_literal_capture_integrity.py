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

from v6_literal_capture_verify import _canonical, _sha256_bytes, _sha256_json, verify_capture_set


class V6LiteralCaptureIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shortlist_path = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
        shortlist = json.loads(cls.shortlist_path.read_text(encoding="utf-8"))
        cls.source = dict(shortlist["selected"][0])

    def _base(self, evidence_root: Path) -> tuple[dict, dict, Path]:
        raw = {
            "target": "capture.example.invalid",
            "endpoint": "/observed",
            "method": "GET",
            "endpoint_schema": {"path_parameters": [], "query_parameters": []},
            "details": {"status_code": 200, "observed_header": "x-v6-test"},
        }
        captured_at = "2026-08-14T09:00:00+03:30"
        reference = "https://github.com/example/project/issues/1"
        snapshot_payload = {"status": 200, "body": "literal upstream observation"}
        evidence = {
            "schema_version": "1.0",
            "family": self.source["family"],
            "case_kind": "positive",
            "source_root": self.source["source_root"],
            "source_project": self.source["source_project"],
            "captured_at": captured_at,
            "capture_reference": reference,
            "capture_method": "http_exchange",
            "collector": {"tool": "curl", "request": "GET /observed"},
            "source_snapshot": {
                "reference": reference,
                "retrieved_at": captured_at,
                "payload": snapshot_payload,
                "content_sha256": _sha256_json(snapshot_payload),
            },
            "raw": raw,
            "raw_sha256": _sha256_json(raw),
        }
        evidence_path = evidence_root / "capture.json"
        evidence_path.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
        row = {
            "family": self.source["family"],
            "case_kind": "positive",
            "source_root": self.source["source_root"],
            "source_project": self.source["source_project"],
            "raw": raw,
            "provenance": {
                "literal_capture": True,
                "capture_reference": reference,
                "captured_at": captured_at,
                "capture_method": "http_exchange",
                "raw_sha256": _sha256_json(raw),
                "evidence_path": evidence_path.relative_to(ROOT).as_posix(),
                "evidence_sha256": _sha256_bytes(evidence_path.read_bytes()),
            },
        }
        return row, evidence, evidence_path

    def _run(self, row: dict, evidence_root: Path) -> dict:
        captures_path = evidence_root.parent / "captures.jsonl"
        captures_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        return verify_capture_set(
            captures_path=captures_path,
            shortlist_path=self.shortlist_path,
            evidence_root=evidence_root,
            require_complete=False,
        )

    def test_valid_partial_capture_requires_real_evidence_artifact(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "benchmarks/raw/sources", prefix="v6_capture_test_") as tmp:
            evidence_root = Path(tmp) / "evidence"
            evidence_root.mkdir()
            row, _, _ = self._base(evidence_root)
            result = self._run(row, evidence_root)
            self.assertTrue(result["passed"], result["errors"])
            self.assertEqual(result["evidence_count"], 1)

    def test_literal_true_without_evidence_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "benchmarks/raw/sources", prefix="v6_capture_test_") as tmp:
            evidence_root = Path(tmp) / "evidence"
            evidence_root.mkdir()
            row, _, evidence_path = self._base(evidence_root)
            evidence_path.unlink()
            result = self._run(row, evidence_root)
            self.assertFalse(result["passed"])
            self.assertTrue(any("evidence artifact is missing" in error for error in result["errors"]))

    def test_raw_tampering_after_evidence_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "benchmarks/raw/sources", prefix="v6_capture_test_") as tmp:
            evidence_root = Path(tmp) / "evidence"
            evidence_root.mkdir()
            row, _, _ = self._base(evidence_root)
            row["raw"]["details"]["status_code"] = 418
            row["provenance"]["raw_sha256"] = _sha256_json(row["raw"])
            result = self._run(row, evidence_root)
            self.assertFalse(result["passed"])
            self.assertTrue(any("benchmark raw does not exactly match evidence raw" in error for error in result["errors"]))

    def test_evidence_path_cannot_escape_capture_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "benchmarks/raw/sources", prefix="v6_capture_test_") as tmp:
            evidence_root = Path(tmp) / "evidence"
            evidence_root.mkdir()
            row, _, _ = self._base(evidence_root)
            row["provenance"]["evidence_path"] = "benchmarks/raw/sources/v6_shortlist.json"
            result = self._run(row, evidence_root)
            self.assertFalse(result["passed"])
            self.assertTrue(any("evidence_path must point" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(TOOLS))
from katana_completion import CONTRACT, read_completion


class CompletionContractTests(unittest.TestCase):
    def event(self, **changes):
        row = dict(contract=CONTRACT, origin="https://example.test/",
                   stop_reason="queue_exhausted", attempted_requests=3,
                   failed_requests=0, limited_requests=0, pending_items=0, active_items=0)
        row.update(changes)
        return row

    def read(self, content, origins=("https://example.test",), **flags):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "completion.jsonl"
            path.write_bytes(content.encode() if isinstance(content, str) else content)
            return read_completion(path, origins, returncode=flags.get("returncode", 0),
                                   timed_out=flags.get("timed_out", False))

    def test_explicit_quiescent_origin_is_completed_but_missing_sibling_is_unknown(self):
        result = self.read(json.dumps(self.event()), origins=("https://example.test", "https://other.test"))
        self.assertEqual(result["https://example.test"]["status"], "completed")
        self.assertEqual(result["https://other.test"]["status"], "unknown")

    def test_errors_deadline_cancellation_and_page_limit_stay_partial_even_with_rc_zero(self):
        for changes in (dict(stop_reason="deadline"), dict(stop_reason="cancelled"),
                        dict(stop_reason="request_errors", failed_requests=1),
                        dict(stop_reason="page_limit", limited_requests=1), dict(stop_reason="unknown")):
            with self.subTest(changes=changes):
                result = self.read(json.dumps(self.event(**changes)))
                self.assertEqual(result["https://example.test"]["status"], "partial")

    def test_invalid_or_ambiguous_artifacts_never_complete_an_origin(self):
        valid = json.dumps(self.event())
        cases = ["", "not JSON", b"\xff", valid + "\n" + valid,
                 valid[:-1] + ', "contract": "other"}', "[]",
                 json.dumps(self.event(contract="future.v2")),
                 json.dumps(self.event(origin="https://outside.test")),
                 json.dumps(self.event(origin="https://example.test/private")),
                 json.dumps(self.event(origin="https://user:secret@example.test")),
                 json.dumps(self.event(active_items=1)),
                 json.dumps(self.event(pending_items=1)),
                 json.dumps(self.event(failed_requests=1)),
                 json.dumps(self.event(attempted_requests=0)),
                 json.dumps(self.event(attempted_requests=True)),
                 json.dumps(self.event(failed_requests=-1)),
                 json.dumps(self.event(stop_reason="request_errors")),
                 " " * (1024 * 1024 + 1)]
        for content in cases:
            with self.subTest(size=len(content)):
                result = self.read(content)
                self.assertEqual(result["https://example.test"]["status"], "unknown")

    def test_failed_process_overrides_a_claimed_complete_event(self):
        for flags in (dict(returncode=124), dict(returncode=1), dict(timed_out=True)):
            result = self.read(json.dumps(self.event()), **flags)
            self.assertEqual(result["https://example.test"]["status"], "unknown")

    def test_empty_error_log_is_not_completion_evidence(self):
        result = self.read("\n")
        self.assertEqual(result["https://example.test"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

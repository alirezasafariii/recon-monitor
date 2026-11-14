from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from family_analyzers.dom_xss import analyze_dom_xss_signal
from family_analyzers.phase2_expansion import PHASE2_ANALYZER_TYPES, analyze_phase2_family
from family_analyzers.xss_observations import normalize_xss_observations


class XssObservationTests(unittest.TestCase):
    endpoint = "https://example.test/search"
    marker = "RECON_MARKER_123456"

    def capture(self, **changes):
        item = dict(marker=self.marker, input_marker=self.marker, input_name="q",
                    request_id="read-1", request_url=self.endpoint, response_url=self.endpoint,
                    content_type="text/html; charset=utf-8",
                    response_text="<p>" + self.marker + "</p>")
        item.update(changes)
        return item

    def normalize(self, family="reflected_xss", **changes):
        return normalize_xss_observations(family, self.endpoint,
                                         {family + "_observations": [self.capture(**changes)]})

    def test_reflection_is_context_and_never_execution(self):
        details, meta = self.normalize()
        self.assertTrue(details["reflected_input_surface"])
        self.assertEqual(meta["xss_capture_summaries"][0]["contexts"], ["html_text"])
        self.assertNotIn("reflected_script_execution_observed", details["reflected_xss_observations"][0])

    def test_each_html_context_is_classified_without_execution_claims(self):
        for body, expected in ((f'<div title="{self.marker}">', "html_attribute"),
                               (f'<script>const x="{self.marker}"</script>', "script"),
                               (f'<!--{self.marker}-->', "html_comment"),
                               (f'<textarea>{self.marker}</textarea>', "textarea")):
            with self.subTest(expected=expected):
                _, meta = self.normalize(response_text=body)
                self.assertEqual(meta["xss_capture_summaries"][0]["contexts"], [expected])
                self.assertFalse(meta["xss_capture_summaries"][0]["execution_established"])

    def test_json_plain_text_and_missing_marker_do_not_create_reflection_context(self):
        for changes in ({"content_type": "application/json"}, {"content_type": "text/plain"},
                        {"response_text": "<p>nothing</p>"}):
            details, _ = self.normalize(**changes)
            self.assertNotIn("reflected_input_surface", details)

    def test_unbound_foreign_or_oversized_captures_do_not_support_execution(self):
        for changes in ({"input_marker": "other"}, {"request_id": ""},
                        {"response_url": "https://other.test/"},
                        {"request_url": "https://example.test/other"},
                        {"response_text": "x" * 1_048_577}):
            details, meta = self.normalize(reflected_script_execution_observed=True, **changes)
            self.assertFalse(meta["xss_capture_summaries"][0]["capture_valid"])
            self.assertNotIn("reflected_script_execution_observed", details["reflected_xss_observations"][0])

    def test_stored_requires_separate_write_and_marker_free_read(self):
        for changes in ({}, {"write_request_id": "read-1", "write_marker": self.marker,
                             "read_request_contains_marker": False},
                        {"write_request_id": "write-1", "write_marker": self.marker,
                         "read_request_contains_marker": True}):
            details, _ = self.normalize("stored_xss", **changes)
            self.assertNotIn("persistent_user_content_surface", details)
        details, meta = self.normalize("stored_xss", write_request_id="write-1",
                                       write_marker=self.marker, read_request_contains_marker=False)
        self.assertTrue(details["persistent_user_content_surface"])
        self.assertTrue(meta["xss_capture_summaries"][0]["persistence_established"])

    def test_execution_must_be_bound_to_browser_marker_and_origin(self):
        for changes in ({}, {"execution_marker": "other"},
                        {"execution_url": "https://other.test/"}):
            item = dict(reflected_script_execution_observed=True, execution_marker=self.marker,
                        execution_url=self.endpoint, browser_capture_id="browser-1")
            item.update(changes)
            if not changes:
                item.pop("browser_capture_id")
            details, _ = self.normalize(**item)
            self.assertNotIn("reflected_script_execution_observed", details["reflected_xss_observations"][0])

    def test_real_analyzer_accepts_bound_controlled_execution(self):
        family = "reflected_xss"
        analyzer = PHASE2_ANALYZER_TYPES[family]()
        result = analyze_phase2_family(analyzer=analyzer, family=family, endpoint=self.endpoint,
            method="GET", details={family + "_observations": [self.capture(
                reflected_script_execution_observed=True, execution_marker=self.marker,
                execution_url=self.endpoint, browser_capture_id="browser-1",
                controlled_test_context=True, benign_test_marker=True)]})
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertNotIn(self.marker, str(result))

    def test_controls_block_conflicting_execution_claim_in_same_observation(self):
        for family, control in (("reflected_xss", "contextual_output_encoding_observed"),
                                ("stored_xss", "stored_sanitization_observed")):
            direct = family.replace("_xss", "_script_execution_observed")
            data, _ = normalize_xss_observations(family, self.endpoint, {
                family + "_observations": [{direct: True, control: True,
                    "controlled_test_context": True, "benign_test_marker": True}]})
            self.assertNotIn(direct, data[family + "_observations"][0])

    def test_dom_conflicting_sanitization_is_not_direct(self):
        result = analyze_dom_xss_signal(None, analysis_id="a", target="example.test",
            source_kind="location.hash", sink_kind="eval", details={
                "dom_runtime_observations": [{"runtime_dom_sink_reached": True,
                    "sanitized": True, "unsanitized_dom_flow": True}]})
        self.assertFalse(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_dom_missing_source_cannot_establish_user_control(self):
        result = analyze_dom_xss_signal(None, analysis_id="a", target="example.test",
            sink_kind="eval", details={"dom_runtime_observations": [
                {"runtime_dom_sink_reached": True, "sanitized": False}]})
        self.assertFalse(result["direct"])


if __name__ == "__main__":
    unittest.main()

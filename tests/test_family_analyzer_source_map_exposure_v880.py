from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates
from core import APP_VERSION, Database, utc_now
from family_analyzers.router import analyzer_for_family, router_status
from family_analyzers.source_map_exposure import (
    SOURCE_MAP_FAMILY_ANALYZER_VERSION,
    SOURCE_MAP_METHOD,
    analyze_source_map_exposure_signal,
)
from family_reasoning import confirmation_gaps


class SourceMapExposureFamilyAnalyzerV880Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-SMAP-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-SMAP-FAMILY','RUN-SMAP-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, *, source_count=0, internal_count=0, details=None):
        return analyze_source_map_exposure_signal(
            self.db,
            analysis_id="AN-SMAP-FAMILY",
            target="example.com",
            source_map_url="https://example.com/assets/app.js.map",
            js_url="https://example.com/assets/app.js",
            source_count=source_count,
            internal_source_count=internal_count,
            details=dict(details or {}),
            business_context="general",
        )

    def _insert_source_map_row(self, *, source_count: int, internal_count: int) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO source_map_intelligence(
            analysis_id,target,run_id,js_url,source_map_url,source_count,internal_source_count,evidence_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-SMAP-FAMILY", "example.com", "RUN-SMAP-FAMILY",
                "https://example.com/assets/app.js", "https://example.com/assets/app.js.map",
                source_count, internal_count,
                json.dumps(["redacted-internal-source"] if internal_count else []), utc_now(),
            ),
        )

    def test_router_registers_all_twenty_one_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 21)
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["registered"], [
  "broken_object_authorization", "broken_function_authorization", "mass_assignment",
  "authentication_session", "account_enumeration", "dom_xss", "postmessage_trust",
  "open_redirect", "ssrf", "file_upload", "path_traversal", "information_disclosure",
  "source_map_exposure", "secret_exposure", "graphql_authorization", "graphql_data_exposure",
  "business_logic", "race_condition", "websocket_authorization", "cors_misconfiguration",
  "sensitive_caching",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("source_map_exposure"))
        self.assertIsNotNone(analyzer_for_family("secret_exposure"))
        self.assertIsNotNone(analyzer_for_family("graphql_authorization"))

    def test_methodology_is_non_evidentiary_and_read_only(self):
        result = self.analyze()
        meta = result["family_analyzer"]
        self.assertEqual(SOURCE_MAP_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-200", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-INFO-05", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-INFO-05", {x for step in SOURCE_MAP_METHOD for x in step["basis"]})
        self.assertTrue(all(item["non_evidentiary"] for item in meta["writeup_patterns"]))
        self.assertFalse(meta["active_request_performed"])
        self.assertFalse(meta["credentialed_request_performed"])
        self.assertFalse(meta["source_content_copied_to_output"])

    def test_reference_only_is_hidden_surface(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        self.assertEqual(observed, {"source_map"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_internal_paths_without_public_reachability_do_not_promote(self):
        result = self.analyze(source_count=5, internal_count=3)
        observed = {row["type"] for row in result["support"]}
        self.assertIn("internal_sources", observed)
        self.assertNotIn("source_map_publicly_reachable", observed)
        self.assertFalse(result["direct"])

    def test_passive_collector_public_map_with_internal_sources_is_direct(self):
        result = self.analyze(
            source_count=5,
            internal_count=3,
            details={"collector_download_succeeded": True},
        )
        observed = {row["type"] for row in result["support"]}
        self.assertIn("source_map", observed)
        self.assertIn("internal_sources", observed)
        self.assertIn("source_map_publicly_reachable", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(confirmation_gaps("source_map_exposure", observed), [])

    def test_public_map_without_internal_sources_does_not_bypass_promotion(self):
        result = self.analyze(source_count=2, internal_count=0, details={"collector_download_succeeded": True})
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("source_map_publicly_reachable", observed)
        self.assertFalse(result["direct"])

    def test_sensitive_content_without_public_reachability_promotes_but_does_not_confirm(self):
        result = self.analyze(details={"sensitive_source_content_observed": True})
        observed = {row["type"] for row in result["support"]}
        self.assertIn("sensitive_source_content_observed", observed)
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_not_public_is_contradiction(self):
        result = self.analyze(internal_count=2, details={"publicly_reachable": False})
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("source_map_not_public", contradictions)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_output_never_echoes_raw_source_or_secret_values(self):
        secret = "SUPER-SECRET-VALUE-DO-NOT-ECHO"
        result = self.analyze(
            source_count=4,
            internal_count=2,
            details={
                "collector_download_succeeded": True,
                "sensitive_source_content_observed": True,
                "raw_source_content": secret,
                "secret_value": secret,
            },
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, rendered)

    def test_static_source_map_reference_is_migrated_to_hidden_hypothesis(self):
        self._insert_source_map_row(source_count=0, internal_count=0)
        bug_candidates._static_candidates(self.db, "AN-SMAP-FAMILY", "RUN-SMAP-FAMILY", "example.com")
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='source_map_exposure'",
            ("AN-SMAP-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='source_map_exposure'",
            ("AN-SMAP-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_static_passively_downloaded_internal_map_promotes_candidate(self):
        self._insert_source_map_row(source_count=4, internal_count=2)
        bug_candidates._static_candidates(self.db, "AN-SMAP-FAMILY", "RUN-SMAP-FAMILY", "example.com")
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='source_map_exposure'",
            ("AN-SMAP-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {x["type"] for x in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("source_map_publicly_reachable", support)
        self.assertTrue(json.loads(hypothesis["admission_json"])["admitted"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='source_map_exposure'",
            ("AN-SMAP-FAMILY",),
        )
        self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main()

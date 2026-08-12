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
from family_analyzers.secret_exposure import (
    SECRET_EXPOSURE_FAMILY_ANALYZER_VERSION,
    SECRET_EXPOSURE_METHOD,
    analyze_secret_exposure_signal,
    detect_redacted_secret_material,
)
from family_reasoning import confirmation_gaps


class SecretExposureFamilyAnalyzerV881Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-SECRET-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-SECRET-FAMILY','RUN-SECRET-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, *, observations=None, markers=None, details=None):
        return analyze_secret_exposure_signal(
            self.db,
            analysis_id="AN-SECRET-FAMILY",
            target="example.com",
            js_url="https://example.com/assets/app.js",
            observations=list(observations or []),
            marker_classes=list(markers or []),
            details=dict(details or {}),
            business_context="general",
        )

    def _insert_secret_row(self, *, kind: str, fingerprint: str, confidence: int, assessment: str) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO secret_intelligence(
            analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                "AN-SECRET-FAMILY", "example.com", "RUN-SECRET-FAMILY",
                "https://example.com/assets/app.js", kind, fingerprint,
                confidence, assessment, json.dumps(["redacted regression observation"]), utc_now(),
            ),
        )

    def _insert_marker(self, marker: str) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO js_indicators(
            target,js_url,kind,value,redacted,first_seen,last_seen,last_run_id
            ) VALUES(?,?,?,?,1,?,?,?)""",
            (
                "example.com", "https://example.com/assets/app.js", "sensitive_marker",
                f"{marker}:count=1", utc_now(), utc_now(), "RUN-SECRET-FAMILY",
            ),
        )

    def test_router_registers_fourteen_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 14)
        self.assertEqual(status["pending_count"], 7)
        self.assertEqual(status["registered"], [
            "broken_object_authorization", "broken_function_authorization", "mass_assignment",
            "authentication_session", "account_enumeration", "dom_xss", "postmessage_trust",
            "open_redirect", "ssrf", "file_upload", "path_traversal", "information_disclosure",
            "source_map_exposure", "secret_exposure",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("secret_exposure"))
        self.assertIsNone(analyzer_for_family("graphql_authorization"))

    def test_methodology_is_non_evidentiary_and_never_validates_credentials(self):
        result = self.analyze(markers=["aws_access_key_pattern"])
        meta = result["family_analyzer"]
        self.assertEqual(SECRET_EXPOSURE_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-798", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-INFO-05", meta["taxonomy"]["wstg"])
        self.assertIn("CWE-798", {x for step in SECRET_EXPOSURE_METHOD for x in step["basis"]})
        self.assertTrue(all(item["non_evidentiary"] for item in meta["writeup_patterns"]))
        self.assertFalse(meta["active_request_performed"])
        self.assertFalse(meta["credential_validation_performed"])
        self.assertFalse(meta["provider_request_performed"])
        self.assertFalse(meta["credential_material_copied_to_output"])

    def test_sensitive_assignment_name_is_surface_only(self):
        result = self.analyze(markers=["sensitive_assignment"])
        observed = {row["type"] for row in result["support"]}
        self.assertEqual(observed, {"secret_pattern"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertIn("assignment_name_only", {row["type"] for row in result["contradict"]})

    def test_aws_access_key_id_marker_is_candidate_not_confirmation(self):
        result = self.analyze(markers=["aws_access_key_pattern"])
        observed = {row["type"] for row in result["support"]}
        self.assertIn("secret_pattern", observed)
        self.assertIn("context", observed)
        self.assertNotIn("credential_material_confirmed", observed)
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_complete_private_key_block_is_confirmed_offline_and_redacted(self):
        body = "MII" + ("Ab9+/" * 40)
        raw = f"const k = `-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----`;"
        observations = detect_redacted_secret_material(raw)
        private = next(row for row in observations if row["secret_kind"] == "private_key_block")
        self.assertEqual(private["assessment"], "credential_material_confirmed")
        self.assertGreaterEqual(private["confidence"], 95)
        rendered = json.dumps(observations, sort_keys=True)
        self.assertNotIn(body, rendered)
        result = self.analyze(observations=observations)
        observed = {row["type"] for row in result["support"]}
        self.assertIn("credential_material_confirmed", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(confirmation_gaps("secret_exposure", observed), [])

    def test_paired_aws_credential_is_confirmed_without_provider_request(self):
        access = "AKIA" + "A" * 16
        secret = "B" * 40
        raw = f'const cfg={{accessKeyId:"{access}", secretAccessKey:"{secret}"}};'
        observations = detect_redacted_secret_material(raw)
        pair = next(row for row in observations if row["secret_kind"] == "aws_credential_pair")
        self.assertEqual(pair["assessment"], "credential_material_confirmed")
        rendered = json.dumps(observations, sort_keys=True)
        self.assertNotIn(access, rendered)
        self.assertNotIn(secret, rendered)

    def test_generic_placeholder_assignment_is_not_direct(self):
        observations = detect_redacted_secret_material('const client_secret="YOUR_CLIENT_SECRET";')
        row = next(row for row in observations if row["secret_kind"] == "client_secret_assignment")
        self.assertEqual(row["assessment"], "likely_placeholder")
        result = self.analyze(observations=observations)
        self.assertIn("placeholder", {row["type"] for row in result["contradict"]})
        self.assertFalse(result["direct"])

    def test_stripe_test_key_is_not_treated_as_live_secret(self):
        observations = detect_redacted_secret_material('const key="sk_test_1234567890ABCDEFGH";')
        row = next(row for row in observations if row["secret_kind"] == "stripe_secret_key_material")
        self.assertEqual(row["assessment"], "likely_placeholder")
        self.assertFalse(self.analyze(observations=observations)["direct"])

    def test_jwt_shape_is_candidate_not_live(self):
        token = "eyJ" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20
        observations = detect_redacted_secret_material(f'const access_token="{token}";')
        jwt = next(row for row in observations if row["secret_kind"] == "jwt_token_material")
        self.assertEqual(jwt["assessment"], "candidate")
        result = self.analyze(observations=observations)
        self.assertFalse(result["direct"])
        self.assertNotIn("live_secret_context", {row["type"] for row in result["support"]})

    def test_live_status_requires_authorized_stored_lifecycle_evidence(self):
        observation = {
            "secret_kind": "token_material",
            "value_fingerprint": "abc",
            "confidence": 90,
            "assessment": "candidate",
            "reasons": [],
        }
        result = self.analyze(observations=[observation], details={"live_secret_context": True})
        self.assertNotIn("live_secret_context", {row["type"] for row in result["support"]})
        result = self.analyze(
            observations=[observation],
            details={"live_secret_context": True, "authorized_lifecycle_evidence": True},
        )
        self.assertIn("live_secret_context", {row["type"] for row in result["support"]})
        self.assertTrue(result["direct"])

    def test_public_client_identifier_is_not_promoted(self):
        observation = {
            "secret_kind": "api_key_assignment",
            "value_fingerprint": "public",
            "confidence": 35,
            "assessment": "intended_public_client_identifier",
            "reasons": [],
        }
        result = self.analyze(observations=[observation])
        self.assertNotIn("context", {row["type"] for row in result["support"]})
        self.assertIn("intended_public_client_identifier", {row["type"] for row in result["contradict"]})
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])

    def test_static_assignment_surface_is_migrated_to_hidden_hypothesis(self):
        self._insert_secret_row(kind="sensitive_marker", fingerprint="surface", confidence=55, assessment="candidate")
        self._insert_marker("sensitive_assignment")
        bug_candidates._static_candidates(self.db, "AN-SECRET-FAMILY", "RUN-SECRET-FAMILY", "example.com")
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='secret_exposure'",
            ("AN-SECRET-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        self.assertFalse(json.loads(hypothesis["admission_json"])["admitted"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='secret_exposure'",
            ("AN-SECRET-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_static_confirmed_material_promotes_candidate(self):
        self._insert_secret_row(kind="private_key_block", fingerprint="private-key-fp", confidence=98, assessment="credential_material_confirmed")
        bug_candidates._static_candidates(self.db, "AN-SECRET-FAMILY", "RUN-SECRET-FAMILY", "example.com")
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='secret_exposure'",
            ("AN-SECRET-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {x["type"] for x in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("credential_material_confirmed", support)
        self.assertTrue(json.loads(hypothesis["admission_json"])["admitted"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='secret_exposure'",
            ("AN-SECRET-FAMILY",),
        )
        self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main()

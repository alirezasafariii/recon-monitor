from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from family_detectors import evaluate_family_detector, execute_detector_intelligence, get_detector_spec
from hypothesis_admission import assess_admission
from raw_family_collectors import AUTHENTICATION_FAMILIES, AUTHENTICATION_OBSERVATIONS, collect_authentication_observations, validate_authentication_collectors


class PhysicalRawCollectorAuthentication6220Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(AUTHENTICATION_FAMILIES), {"authentication_session", "account_enumeration"})
        self.assertEqual(validate_authentication_collectors(), [])
        auth = get_detector_spec("authentication_session")
        self.assertEqual(set(auth.wstg_ids), {"WSTG-ATHN-04", "WSTG-SESS-01"})
        self.assertEqual(set(auth.owasp_ids), {"A07:2025", "API2:2023"})
        self.assertEqual(set(auth.cwe_ids), {"CWE-287"})
        self.assertTrue(auth.writeups)
        self.assertTrue(all(ref.url == "https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/" for ref in auth.writeups))
        enum = get_detector_spec("account_enumeration")
        self.assertEqual(set(enum.wstg_ids), {"WSTG-IDNT-04"})
        self.assertEqual(set(enum.owasp_ids), {"A07:2025", "API2:2023"})
        self.assertEqual(set(enum.cwe_ids), {"CWE-204"})
        self.assertEqual(len(enum.writeups), 1)
        self.assertEqual(enum.writeups[0].url, "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j")
        self.assertEqual(enum.writeups[0].source, "GitHub Advisory Database")
        self.assertEqual(enum.writeups[0].relation, "exact")
        for family in AUTHENTICATION_FAMILIES:
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in get_detector_spec(family).writeups), family)

    def test_positive_execution_contracts_admit_both_families(self):
        auth_raw = dict(
            target="fixture.invalid", endpoint="/api/session/refresh", method="POST",
            endpoint_schema={"authentication_hints": ["session"]},
            details={"context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}]},
            category="authentication", business_context="identity",
        )
        enum_raw = dict(
            target="fixture.invalid", endpoint="/forgot-password", method="POST",
            endpoint_schema={"body_fields": ["email"]},
            details={"context_observations": [
                {"context": "existing_identity", "status_code": 200, "response_text": "reset sent"},
                {"context": "absent_identity", "status_code": 404, "response_text": "unknown user"},
            ]},
            category="authentication", business_context="identity",
        )
        execution_map = {}
        for family, raw in (("authentication_session", auth_raw), ("account_enumeration", enum_raw)):
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_authentication_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(AUTHENTICATION_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "authentication_session": dict(
                target="fixture.invalid", endpoint="/login", method="POST",
                endpoint_schema={"authentication_hints": ["session"]}, details={}, category="authentication", business_context="identity",
            ),
            "account_enumeration": dict(
                target="fixture.invalid", endpoint="/forgot-password", method="POST",
                endpoint_schema={"body_fields": ["email"]}, details={}, category="authentication", business_context="identity",
            ),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_uniform_existing_absent_observations_do_not_promote_enumeration(self):
        raw = dict(
            target="fixture.invalid", endpoint="/forgot-password", method="POST",
            endpoint_schema={"body_fields": ["email"]},
            details={"context_observations": [
                {"context": "existing_identity", "status_code": 200, "response_text": "If the account exists, mail will be sent"},
                {"context": "absent_identity", "status_code": 200, "response_text": "If the account exists, mail will be sent"},
            ]},
            category="authentication", business_context="identity",
        )
        execution, assessment = self._assessment("account_enumeration", raw)
        signals = {str(row.get("type") or "") for row in execution.get("account_enumeration", {}).get("support", [])}
        self.assertNotIn("response_difference", signals)
        self.assertFalse(assessment["admitted"], (assessment, execution.get("account_enumeration")))

    def test_collector_is_metadata_only(self):
        for family, observation in AUTHENTICATION_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_authentication_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("validate_family_ownership()", source)
        self.assertNotIn('collect_authentication_observations(execution_map)', source)
        self.assertNotIn("detector-execution-fallback", source)

    def test_run_analysis_routes_both_through_authentication_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-622-auth"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.21.0", "success", now, now, target))
                alerts = [
                    ("Authentication boundary regression", "/api/session/refresh", {
                        "method": "POST",
                        "context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}],
                    }),
                    ("Account existence differential", "/forgot-password", {
                        "method": "POST", "body_fields": ["email"],
                        "context_observations": [
                            {"context": "existing_identity", "status_code": 200, "response_text": "reset sent"},
                            {"context": "absent_identity", "status_code": 404, "response_text": "unknown user"},
                        ],
                    }),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"622:{title}", "authentication", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(AUTHENTICATION_FAMILIES) and "raw-collector-authentication-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(AUTHENTICATION_FAMILIES), hypotheses)
                for family, expected in AUTHENTICATION_OBSERVATIONS.items():
                    rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(rows, (family, routed[family]))
                    promoted = [row for row in rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted, (family, [dict(row) for row in rows]))
                    conditions = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(any(
                        {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & conditions
                        for row in promoted
                    ), (family, conditions, [dict(row) for row in promoted]))
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-authentication-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(AUTHENTICATION_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

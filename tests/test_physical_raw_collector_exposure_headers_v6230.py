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
from raw_family_collectors import EXPOSURE_HEADERS_FAMILIES, EXPOSURE_HEADERS_OBSERVATIONS, collect_exposure_headers_observations, validate_exposure_headers_collectors


class PhysicalRawCollectorExposureHeaders6230Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(EXPOSURE_HEADERS_FAMILIES), {"information_disclosure", "cors_misconfiguration", "sensitive_caching"})
        self.assertEqual(validate_exposure_headers_collectors(), [])
        expected = {
            "information_disclosure": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A01:2025"}, {"CWE-200"}),
            "cors_misconfiguration": ({"WSTG-CLNT-07"}, {"A02:2025"}, {"CWE-942"}),
            "sensitive_caching": ({"WSTG-ATHN-06"}, {"A06:2025"}, {"CWE-524", "CWE-525"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("information_disclosure").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2026-037_Wekan/")
        self.assertEqual(get_detector_spec("cors_misconfiguration").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-161_GHSL-2024-162_rembg/")
        cache_ref = get_detector_spec("sensitive_caching").writeups[0]
        self.assertEqual(cache_ref.url, "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p")
        self.assertEqual(cache_ref.relation, "exact")
        self.assertEqual(cache_ref.source, "GitHub Repository Security Advisory")

    def test_positive_execution_contracts_admit_all_three(self):
        fixtures = {
            "information_disclosure": dict(target="fixture.invalid", endpoint="/status", method="GET", endpoint_schema={}, details={"status_code": 200, "response_text": "Traceback: File '/srv/app.py', line 42, internal exception"}, category="debug", business_context="general"),
            "cors_misconfiguration": dict(target="fixture.invalid", endpoint="/api/profile", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"response_headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}, category="api", business_context="identity"),
            "sensitive_caching": dict(target="fixture.invalid", endpoint="/account", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"status_code": 200, "request_headers": {"Cookie": "session=fixture"}, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "email=user@example.invalid"}, category="account", business_context="identity"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_exposure_headers_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(EXPOSURE_HEADERS_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "information_disclosure": dict(target="fixture.invalid", endpoint="/support", method="GET", endpoint_schema={}, details={"response_text": "internal debug reference"}, category="support", business_context="general"),
            "cors_misconfiguration": dict(target="fixture.invalid", endpoint="/public", method="GET", endpoint_schema={}, details={"response_headers": {"Access-Control-Allow-Origin": "*"}}, category="api", business_context="general"),
            "sensitive_caching": dict(target="fixture.invalid", endpoint="/catalog", method="GET", endpoint_schema={}, details={"status_code": 200, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "public catalog"}, category="api", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_browser_cache_no_store_condition_is_evidence_gated(self):
        vulnerable = dict(target="fixture.invalid", endpoint="/account", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"status_code": 200, "request_headers": {"Cookie": "session=fixture"}, "response_headers": {"Cache-Control": "max-age=300"}, "response_text": "email=user@example.invalid"}, category="account", business_context="identity")
        execution, assessment = self._assessment("sensitive_caching", vulnerable)
        signals = {str(row.get("type") or "") for row in execution["sensitive_caching"]["support"]}
        self.assertIn("browser_cache_no_store_missing", signals)
        self.assertTrue(assessment["admitted"], (assessment, execution["sensitive_caching"]))
        protected = dict(vulnerable)
        protected["details"] = {"status_code": 200, "response_headers": {"Cache-Control": "private, no-store"}, "response_text": "email=user@example.invalid"}
        execution2, assessment2 = self._assessment("sensitive_caching", protected)
        protected_packet = execution2.get("sensitive_caching", {"support": [], "contradict": []})
        support2 = {str(row.get("type") or "") for row in protected_packet["support"]}
        contradict2 = {str(row.get("type") or "") for row in protected_packet["contradict"]}
        self.assertNotIn("browser_cache_no_store_missing", support2)
        if protected_packet["support"] or protected_packet["contradict"]:
            self.assertIn("no_store", contradict2)
        self.assertFalse(assessment2["admitted"], (assessment2, protected_packet))

    def test_cors_business_label_without_auth_or_credentials_does_not_promote(self):
        raw = dict(target="fixture.invalid", endpoint="/api/profile", method="GET", endpoint_schema={}, details={"response_headers": {"Access-Control-Allow-Origin": "*"}}, category="api", business_context="customer_data")
        execution, assessment = self._assessment("cors_misconfiguration", raw)
        signals = {str(row.get("type") or "") for row in execution["cors_misconfiguration"]["support"]}
        self.assertNotIn("authenticated_context", signals)
        self.assertFalse(assessment["admitted"], (assessment, execution["cors_misconfiguration"]))

    def test_collector_is_metadata_only(self):
        for family, observation in EXPOSURE_HEADERS_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_exposure_header_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("validate_family_ownership()", source)
        self.assertNotIn('collect_exposure_headers_observations(execution_map)', source)
        self.assertNotIn("detector-execution-fallback", source)

    def test_run_analysis_routes_all_three_through_exposure_headers_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-623-exposure"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.22.0", "success", now, now, target))
                alerts = [
                    ("Public stack trace", "/status", {"method": "GET", "status_code": 200, "response_text": "Traceback: File '/srv/app.py', line 42, internal exception"}, "debug"),
                    ("Credentialed CORS", "/api/profile", {"method": "GET", "request_headers": {"Authorization": "Bearer <redacted>"}, "response_headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}, "api"),
                    ("Sensitive browser cache", "/account", {"method": "GET", "status_code": 200, "request_headers": {"Authorization": "Bearer <redacted>"}, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "email=user@example.invalid"}, "account"),
                ]
                for title, endpoint, details, category in alerts:
                    db.upsert_alert(target, f"623:{title}", category, "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(EXPOSURE_HEADERS_FAMILIES) and "raw-collector-exposure-headers-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(EXPOSURE_HEADERS_FAMILIES), hypotheses)
                for family, expected in EXPOSURE_HEADERS_OBSERVATIONS.items():
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
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-exposure-headers-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(EXPOSURE_HEADERS_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

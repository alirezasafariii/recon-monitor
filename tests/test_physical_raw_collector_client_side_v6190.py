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
from raw_family_collectors import (
    AUTHORIZATION_FAMILIES,
    CLIENT_SIDE_COLLECTOR_RULE_VERSION,
    CLIENT_SIDE_COLLECTOR_VERSION,
    CLIENT_SIDE_FAMILIES,
    CLIENT_SIDE_OBSERVATIONS,
    FILE_REMOTE_FAMILIES,
    INJECTION_FAMILIES,
    collect_client_side_observations,
    validate_client_side_collectors,
)


class PhysicalRawCollectorClientSide6190Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        scoped = evaluate_family_detector(family, packet.get("support") or [], packet.get("contradict") or [], channel="analysis_619_test")
        return execution, assess_admission(family, scoped["support"], scoped["contradict"])

    def test_registry_owns_exactly_client_side_batch(self):
        self.assertEqual(set(CLIENT_SIDE_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        self.assertEqual(set(CLIENT_SIDE_OBSERVATIONS), set(CLIENT_SIDE_FAMILIES))
        self.assertEqual(validate_client_side_collectors(), [])
        self.assertEqual(CLIENT_SIDE_COLLECTOR_VERSION, "1.0.0")
        self.assertEqual(CLIENT_SIDE_COLLECTOR_RULE_VERSION, "2026.08.12.6.19")
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(INJECTION_FAMILIES)))
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(AUTHORIZATION_FAMILIES)))
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(FILE_REMOTE_FAMILIES)))

    def test_client_specs_have_exact_standards_and_real_writeup_grounding(self):
        expected = {
            "dom_xss": ({"WSTG-CLNT-01"}, {"A05:2025"}, {"CWE-79"}),
            "postmessage_trust": ({"WSTG-CLNT-11"}, {"A07:2025"}, {"CWE-940", "CWE-346"}),
            "open_redirect": ({"WSTG-CLNT-04"}, {"A01:2025"}, {"CWE-601"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_all_three_families(self):
        fixtures = {
            "dom_xss": dict(
                target="fixture.invalid", endpoint="/app.js", method="GET",
                endpoint_schema={},
                details={"source_code": "const x=location.hash; node.innerHTML=x;", "runtime_reachable_flow": True, "status_code": 200},
                category="javascript", business_context="general",
            ),
            "postmessage_trust": dict(
                target="fixture.invalid", endpoint="/frame.js", method="GET",
                endpoint_schema={},
                details={"source_code": "window.addEventListener('message', e => { location.href = e.data; });", "missing_origin_check": True, "status_code": 200},
                category="javascript", business_context="general",
            ),
            "open_redirect": dict(
                target="fixture.invalid", endpoint="/login?redirect=/home", method="GET",
                endpoint_schema={"query_parameters": ["redirect"]},
                details={"status_code": 302, "response_headers": {"Location": "https://external.invalid/landing"}},
                category="navigation", business_context="general",
            ),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_client_side_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(CLIENT_SIDE_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "dom_xss": dict(target="fixture.invalid", endpoint="/app.js", method="GET", endpoint_schema={}, details={"source_code": "const x=location.hash; node.innerHTML=x;"}, category="javascript", business_context="general"),
            "postmessage_trust": dict(target="fixture.invalid", endpoint="/frame.js", method="GET", endpoint_schema={}, details={"source_code": "window.addEventListener('message', e => { location.href=e.data; });"}, category="javascript", business_context="general"),
            "open_redirect": dict(target="fixture.invalid", endpoint="/login?redirect=/home", method="GET", endpoint_schema={"query_parameters": ["redirect"]}, details={"status_code": 302, "response_headers": {"Location": "/home"}}, category="navigation", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_external_knowledge_cannot_become_target_evidence(self):
        execution = execute_detector_intelligence(
            target="fixture.invalid", endpoint="/app.js", method="GET", endpoint_schema={}, details={}, category="javascript",
            evidence_for=[
                {"type": "runtime_reachable_flow", "source": "OWASP WSTG", "url": "https://owasp.org/"},
                {"type": "runtime_reachable_flow", "source": "stored_behavior", "source_group": "runtime_behavior"},
            ],
        )
        rows = execution.get("dom_xss", {}).get("support", [])
        self.assertTrue(any(row.get("source") == "stored_behavior" for row in rows))
        self.assertFalse(any("owasp" in str(row.get("source") or "").lower() for row in rows))

    def test_collector_is_metadata_only(self):
        for family, observation in CLIENT_SIDE_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_redirect_emission(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_client_side_observations(execution_map)", source)
        self.assertIn("Analysis 6.19: legacy Open Redirect alert emission was physically removed", source)
        self.assertNotIn('emit("open_redirect", "unvalidated_destination"', source)

    def test_run_analysis_routes_all_three_through_client_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-619-client"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.18.0", "success", now, now, target))
                alerts = [
                    ("DOM flow", "/app.js", {"method": "GET", "source_code": "const x=location.hash; node.innerHTML=x;", "runtime_reachable_flow": True, "status_code": 200, "category": "javascript"}),
                    ("Message trust", "/frame.js", {"method": "GET", "source_code": "window.addEventListener('message', e => { location.href=e.data; });", "missing_origin_check": True, "status_code": 200, "category": "javascript"}),
                    ("External redirect", "/login?redirect=/home", {"method": "GET", "query_parameters": ["redirect"], "status_code": 302, "response_headers": {"Location": "https://external.invalid/landing"}, "category": "navigation"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"619:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(CLIENT_SIDE_FAMILIES), hypotheses)
                for family, expected in CLIENT_SIDE_OBSERVATIONS.items():
                    family_rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(family_rows, (family, routed[family]))
                    promoted_rows = [row for row in family_rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted_rows, (family, [dict(row) for row in family_rows]))
                    condition_signals = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(
                        any(
                            {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & condition_signals
                            for row in promoted_rows
                        ),
                        (family, condition_signals, [dict(row) for row in promoted_rows]),
                    )
                # A postMessage handler using location.href may legitimately retain a separate
                # non-promoted Open Redirect hypothesis. The real redirect observation must
                # still promote independently with external-destination evidence.
                redirect_promoted = [row for row in routed["open_redirect"] if str(row["state"]) == "promoted"]
                self.assertTrue(any("/login?redirect=/home" in str(row["endpoint"]) for row in redirect_promoted), [dict(row) for row in routed["open_redirect"]])
                self.assertTrue(any(
                    "external_destination" in {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")}
                    for row in redirect_promoted
                ), [dict(row) for row in redirect_promoted])
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted = {}
                for row in candidates:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        promoted[family] = row
                self.assertEqual(set(promoted), set(CLIENT_SIDE_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

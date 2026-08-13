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
from raw_family_collectors import BUSINESS_LOGIC_FAMILIES, BUSINESS_LOGIC_OBSERVATIONS, collect_business_logic_observations, validate_business_logic_collectors


class PhysicalRawCollectorBusinessLogic6210Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(BUSINESS_LOGIC_FAMILIES), {"business_logic", "race_condition"})
        self.assertEqual(validate_business_logic_collectors(), [])
        for family in BUSINESS_LOGIC_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url == "https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/" for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_both_families(self):
        fixtures = {
            "business_logic": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={"workflow_invariant_violation": True}, category="api", business_context="commerce"),
            "race_condition": dict(target="fixture.invalid", endpoint="/api/transfer", method="POST", endpoint_schema={}, details={"duplicate_effect_observed": True}, category="api", business_context="payment"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_business_logic_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(BUSINESS_LOGIC_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "business_logic": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={}, category="api", business_context="commerce"),
            "race_condition": dict(target="fixture.invalid", endpoint="/api/transfer", method="POST", endpoint_schema={}, details={}, category="api", business_context="payment"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_collector_is_metadata_only(self):
        for family, observation in BUSINESS_LOGIC_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_business_race_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("validate_family_ownership()", source)
        self.assertNotIn('collect_business_logic_observations(execution_map)', source)
        self.assertNotIn("detector-execution-fallback", source)

    def test_run_analysis_routes_both_through_business_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-621-business"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.20.0", "success", now, now, target))
                alerts = [
                    ("Workflow invariant", "/api/checkout", {"method": "POST", "workflow_invariant_violation": True, "category": "api"}),
                    ("Duplicate transfer", "/api/transfer", {"method": "POST", "duplicate_effect_observed": True, "category": "api"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"621:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(BUSINESS_LOGIC_FAMILIES) and "raw-collector-business-logic-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(BUSINESS_LOGIC_FAMILIES), hypotheses)
                for family, expected in BUSINESS_LOGIC_OBSERVATIONS.items():
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
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-business-logic-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(BUSINESS_LOGIC_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

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
from family_detectors import evaluate_family_detector, execute_detector_intelligence
from hypothesis_admission import assess_admission
from raw_family_collectors import (
    AUTHORIZATION_FAMILIES,
    FILE_REMOTE_COLLECTOR_RULE_VERSION,
    FILE_REMOTE_COLLECTOR_VERSION,
    FILE_REMOTE_FAMILIES,
    FILE_REMOTE_OBSERVATIONS,
    INJECTION_FAMILIES,
    collect_file_remote_resource_observations,
    validate_file_remote_collectors,
)


class PhysicalRawCollectorFileRemote6180Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        scoped = evaluate_family_detector(
            family,
            packet.get("support") or [],
            packet.get("contradict") or [],
            channel="analysis_618_test",
        )
        return execution, assess_admission(family, scoped["support"], scoped["contradict"])

    def test_registry_owns_exactly_file_and_remote_resource_families(self):
        self.assertEqual(set(FILE_REMOTE_FAMILIES), {"ssrf", "file_upload", "path_traversal"})
        self.assertEqual(set(FILE_REMOTE_OBSERVATIONS), set(FILE_REMOTE_FAMILIES))
        self.assertEqual(validate_file_remote_collectors(), [])
        self.assertEqual(FILE_REMOTE_COLLECTOR_VERSION, "1.0.0")
        self.assertEqual(FILE_REMOTE_COLLECTOR_RULE_VERSION, "2026.08.12.6.18")
        self.assertTrue(set(FILE_REMOTE_FAMILIES).isdisjoint(set(INJECTION_FAMILIES)))
        self.assertTrue(set(FILE_REMOTE_FAMILIES).isdisjoint(set(AUTHORIZATION_FAMILIES)))

    def test_collectors_emit_only_for_present_execution_packets(self):
        execution = {
            "ssrf": {"support": [{"type": "remote_destination"}], "contradict": []},
            "cors_misconfiguration": {"support": [{"type": "wildcard_origin"}], "contradict": []},
        }
        observations = collect_file_remote_resource_observations(execution)
        self.assertEqual([item.family for item in observations], ["ssrf"])
        self.assertIn("raw-collector-file-remote-v1", observations[0].rules)

    def test_positive_execution_contracts_admit_all_three_families(self):
        fixtures = {
            "ssrf": dict(
                target="fixture.invalid",
                endpoint="/api/preview",
                method="POST",
                endpoint_schema={"body_fields": ["url"]},
                details={"server_fetch_observed": True, "status_code": 200},
                category="remote url preview",
                business_context="general",
            ),
            "file_upload": dict(
                target="fixture.invalid",
                endpoint="/api/upload",
                method="POST",
                endpoint_schema={"body_fields": ["file"]},
                details={"dangerous_type_accepted": True, "content_type": "multipart/form-data", "status_code": 200},
                category="file upload",
                business_context="general",
            ),
            "path_traversal": dict(
                target="fixture.invalid",
                endpoint="/api/download?path=fixture.txt",
                method="GET",
                endpoint_schema={"query_parameters": ["path"]},
                details={"path_escape_observed": True, "status_code": 200},
                category="file download",
                business_context="general",
            ),
        }
        execution = {}
        for family, raw in fixtures.items():
            packet, assessment = self._assessment(family, raw)
            execution[family] = packet[family]
            self.assertTrue(assessment["admitted"], (family, assessment, packet.get(family)))
        observations = collect_file_remote_resource_observations(execution)
        self.assertEqual({item.family for item in observations}, set(FILE_REMOTE_FAMILIES))

    def test_surface_only_near_misses_do_not_admit(self):
        fixtures = {
            "ssrf": dict(target="fixture.invalid", endpoint="/api/preview", method="POST", endpoint_schema={"body_fields": ["url"]}, details={"status_code": 200}, category="remote url preview", business_context="general"),
            "file_upload": dict(target="fixture.invalid", endpoint="/api/upload", method="POST", endpoint_schema={"body_fields": ["file"]}, details={"content_type": "multipart/form-data", "status_code": 200}, category="file upload", business_context="general"),
            "path_traversal": dict(target="fixture.invalid", endpoint="/api/download?path=fixture.txt", method="GET", endpoint_schema={"query_parameters": ["path"]}, details={"status_code": 200}, category="file download", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_collector_is_metadata_only(self):
        for family, observation in FILE_REMOTE_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_family_emission(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_file_remote_resource_observations(execution_map)", source)
        self.assertIn("Analysis 6.18: SSRF/File Upload/Path Traversal legacy collection was physically", source)
        self.assertNotIn('emit("ssrf", "remote_fetch"', source)
        self.assertNotIn('emit("file_upload", "file_validation"', source)
        self.assertNotIn('emit("path_traversal", "path_construction"', source)
        # Analysis 6.20 removed the API10 inline correlation variables; SSRF itself
        # remains owned by the 6.18 physical file/remote collector.
        self.assertNotIn("ssrf_tokens = _contains_any", source)
        self.assertNotIn("generic_url_fields =", source)
        self.assertNotIn("if ssrf_tokens or generic_url_fields:", source)

    def test_run_analysis_routes_all_three_families_through_physical_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td))
            paths.ensure()
            db = Database(paths.db)
            try:
                now = utc_now()
                run_id = "run-618-file-remote"
                target = "fixture.invalid"
                db.execute(
                    "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
                    (run_id, "6.17.0", "success", now, now, target),
                )
                alerts = [
                    ("Remote URL preview", "/api/preview", {"method": "POST", "body_fields": ["url"], "server_fetch_observed": True, "status_code": 200, "category": "remote url preview"}),
                    ("Unsafe upload", "/api/upload", {"method": "POST", "body_fields": ["file"], "content_type": "multipart/form-data", "dangerous_type_accepted": True, "status_code": 200, "category": "file upload"}),
                    ("Path escape download", "/api/download?path=fixture.txt", {"method": "GET", "path_escape_observed": True, "status_code": 200, "category": "file download"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"618:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)

                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all(
                    "SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(FILE_REMOTE_FAMILIES) and "raw-collector-file-remote-v1" in rules:
                        routed[family] = row
                self.assertEqual(set(routed), set(FILE_REMOTE_FAMILIES), hypotheses)
                for family, expected in FILE_REMOTE_OBSERVATIONS.items():
                    self.assertEqual(str(routed[family]["bug_variant"]), expected.variant)
                    self.assertEqual(str(routed[family]["state"]), "promoted")

                candidates = db.all(
                    "SELECT bug_family,bug_variant,rule_ids_json FROM bug_candidates WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                promoted = {}
                for row in candidates:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(FILE_REMOTE_FAMILIES) and "raw-collector-file-remote-v1" in rules:
                        promoted[family] = row
                self.assertEqual(set(promoted), set(FILE_REMOTE_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

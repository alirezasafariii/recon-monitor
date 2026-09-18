from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from passive_evidence_extractor import extract_passive_family_evidence


class PassiveMisconfigurationInventoryTests(unittest.TestCase):
    def test_debug_api_requires_concrete_successful_diagnostic_response(self):
        route_only = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/debug",
            target="example.test",
            details={"content_type": "application/json"},
        )
        self.assertNotIn("debug_mode_publicly_exposed", route_only)
        self.assertNotIn("debug_api_publicly_reachable", route_only)

        login_catch_all = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/debug",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "text/html",
                "title": "Sign in",
            },
        )
        self.assertNotIn("debug_mode_publicly_exposed", login_catch_all)
        self.assertNotIn("debug_api_publicly_reachable", login_catch_all)

        concrete = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/debug",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "application/json",
            },
        )
        self.assertTrue(concrete["debug_mode_publicly_exposed"])
        self.assertTrue(concrete["debug_api_publicly_reachable"])
        self.assertEqual(
            concrete["passive_condition_details"][
                "debug_api_publicly_reachable"
            ]["status_code"],
            200,
        )

    def test_restricted_debug_api_is_contradiction_not_public_reachability(self):
        details = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/debug",
            target="example.test",
            details={
                "status_code": 403,
                "content_type": "application/json",
            },
        )
        self.assertTrue(details["debug_endpoint_restricted"])
        self.assertNotIn("debug_api_publicly_reachable", details)
        self.assertNotIn("debug_mode_publicly_exposed", details)

    def test_directory_listing_requires_response_derived_index_title(self):
        exposed = extract_passive_family_evidence(
            endpoint="https://example.test/downloads/",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "text/html",
                "title": "Index of /downloads/",
            },
        )
        self.assertTrue(exposed["directory_listing_observed"])

        generic = extract_passive_family_evidence(
            endpoint="https://example.test/directory/",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "text/html",
                "title": "Downloads",
            },
        )
        self.assertNotIn("directory_listing_observed", generic)

    def test_versioned_api_path_alone_never_implies_inventory_drift(self):
        details = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/orders",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "application/json",
                "category": "api",
            },
        )
        self.assertNotIn("inventory_drift_signal", details)
        self.assertNotIn("deprecated_api_publicly_reachable", details)
        self.assertNotIn("undocumented_api_publicly_reachable", details)

    def test_authoritative_lifecycle_metadata_can_establish_inventory_drift(self):
        deprecated = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/orders",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "application/json",
                "category": "api",
                "inventory_baseline": "approved inventory: v2 only",
                "lifecycle_status": "deprecated",
            },
        )
        self.assertTrue(deprecated["inventory_drift_signal"])
        self.assertTrue(deprecated["deprecated_api_publicly_reachable"])

        undocumented = extract_passive_family_evidence(
            endpoint="https://example.test/api/private/orders",
            target="example.test",
            details={
                "status_code": 200,
                "content_type": "application/json",
                "category": "api",
                "authoritative_inventory": "published API inventory",
                "inventory_documented": False,
            },
        )
        self.assertTrue(undocumented["inventory_drift_signal"])
        self.assertTrue(undocumented["undocumented_api_publicly_reachable"])

        decommissioned = extract_passive_family_evidence(
            endpoint="https://example.test/api/v1/orders",
            target="example.test",
            details={
                "status_code": 410,
                "content_type": "application/json",
                "category": "api",
                "inventory_baseline": "approved inventory: v2 only",
                "lifecycle_status": "decommissioned",
            },
        )
        self.assertTrue(decommissioned["version_decommissioned"])
        self.assertNotIn(
            "deprecated_api_publicly_reachable",
            decommissioned,
        )

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-MISINV',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-MISINV','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-MISINV")),
        )
        return temp, paths, db, now

    def _insert_surface(
        self,
        db,
        now,
        *,
        endpoint: str,
        category: str,
        status: int,
        content_type: str,
        title: str,
    ):
        db.execute(
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                endpoint,
                "absolute_url",
                category,
                92,
                json_dumps([{"category": category, "confidence": 92}]),
                json_dumps(["stored Recon surface"]),
                json_dumps(["passive-misconfig-inventory-test"]),
                now,
                now,
                "RUN-MISINV",
            ),
        )
        db.execute(
            "INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                endpoint,
                "fp-" + str(abs(hash(endpoint))),
                status,
                title,
                "test",
                "[]",
                content_type,
                2048,
                now,
                now,
                "RUN-MISINV",
            ),
        )

    def test_raw_analysis_promotes_concrete_debug_and_directory_observations(self):
        temp, paths, db, now = self._project()
        try:
            debug_url = "https://example.test/api/v1/debug"
            directory_url = "https://example.test/downloads/"
            false_debug_url = "https://example.test/debug"

            self._insert_surface(
                db,
                now,
                endpoint=debug_url,
                category="api",
                status=200,
                content_type="application/json",
                title="",
            )
            self._insert_surface(
                db,
                now,
                endpoint=directory_url,
                category="general",
                status=200,
                content_type="text/html",
                title="Index of /downloads/",
            )
            self._insert_surface(
                db,
                now,
                endpoint=false_debug_url,
                category="debug",
                status=200,
                content_type="text/html",
                title="Sign in",
            )

            result = run_analysis(paths, db, "RUN-MISINV", "example.test")
            runtime = result["bug_candidates"]["detection_runtime"]
            families = set(runtime["potential_finding_families"])
            self.assertIn("security_misconfiguration", families)
            self.assertIn("improper_inventory_management", families)

            misconfig_rows = db.all(
                "SELECT endpoint,supporting_evidence_json FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='security_misconfiguration' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )
            inventory_rows = db.all(
                "SELECT endpoint,supporting_evidence_json FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='improper_inventory_management' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )

            misconfig_endpoints = [str(row["endpoint"]) for row in misconfig_rows]
            inventory_endpoints = [str(row["endpoint"]) for row in inventory_rows]
            self.assertIn(debug_url, misconfig_endpoints)
            self.assertIn(directory_url, misconfig_endpoints)
            self.assertNotIn(false_debug_url, misconfig_endpoints)
            self.assertEqual(inventory_endpoints, [debug_url])

            debug_row = next(
                row for row in inventory_rows
                if str(row["endpoint"]) == debug_url
            )
            evidence = json.loads(str(debug_row["supporting_evidence_json"]))
            direct = next(
                item
                for item in evidence
                if item.get("type") == "debug_api_publicly_reachable"
            )
            self.assertEqual(direct["observation"]["status_code"], 200)
            self.assertEqual(
                direct["observation"]["content_type"],
                "application/json",
            )
            self.assertEqual(runtime["active_requests_added"], 0)
            self.assertFalse(runtime["collector_behavior_changed"])
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

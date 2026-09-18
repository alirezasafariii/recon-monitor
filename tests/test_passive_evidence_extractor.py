from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from family_analyzers.base import FamilyAnalyzerContext
from family_analyzers.router import analyzer_for_family
from passive_evidence_extractor import (
    PASSIVE_EVIDENCE_EXTRACTOR_VERSION,
    extract_passive_family_evidence,
)


class PassiveEvidenceExtractorTests(unittest.TestCase):
    def test_backup_requires_successful_non_html_stored_response(self):
        positive = extract_passive_family_evidence(
            endpoint="https://example.test/archive/database.sql",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/plain",
                "content_length": 4096,
            },
        )
        self.assertTrue(positive["backup_file_publicly_reachable_observed"])
        meta = positive["_passive_evidence_extractor"]
        self.assertEqual(meta["version"], PASSIVE_EVIDENCE_EXTRACTOR_VERSION)
        self.assertEqual(meta["network_requests"], 0)
        self.assertFalse(meta["collector_behavior_changed"])
        self.assertFalse(meta["confirmation_signals_synthesized"])

        html_catch_all = extract_passive_family_evidence(
            endpoint="https://example.test/archive/database.sql",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "content_length": 4096,
            },
        )
        self.assertNotIn(
            "backup_file_publicly_reachable_observed",
            html_catch_all,
        )

        route_only = extract_passive_family_evidence(
            endpoint="https://example.test/archive/database.sql",
            details={"content_type": "text/plain"},
        )
        self.assertNotIn(
            "backup_file_publicly_reachable_observed",
            route_only,
        )

    def test_backup_negative_status_becomes_contradiction_not_finding_evidence(self):
        details = extract_passive_family_evidence(
            endpoint="https://example.test/backups/site.zip",
            details={
                "status_code": 404,
                "reachable": True,
                "content_type": "text/html",
            },
        )
        self.assertTrue(details["backup_files_not_publicly_reachable"])
        self.assertNotIn("backup_file_publicly_reachable_observed", details)

    def test_admin_requires_successful_browser_visible_stored_response(self):
        positive = extract_passive_family_evidence(
            endpoint="https://example.test/admin/",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html; charset=utf-8",
                "title": "Administration Console",
            },
        )
        self.assertTrue(positive["admin_interface_publicly_reachable_observed"])

        protected = extract_passive_family_evidence(
            endpoint="https://example.test/admin/",
            details={
                "status_code": 403,
                "reachable": True,
                "content_type": "text/html",
                "title": "Forbidden",
            },
        )
        self.assertTrue(protected["admin_authentication_enforced"])
        self.assertNotIn("admin_interface_publicly_reachable_observed", protected)

        route_only = extract_passive_family_evidence(
            endpoint="https://example.test/admin/",
            details={"content_type": "text/html"},
        )
        self.assertNotIn("admin_interface_publicly_reachable_observed", route_only)

    def test_security_header_evidence_requires_real_header_snapshot(self):
        weak = extract_passive_family_evidence(
            endpoint="https://example.test/account",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {},
            },
        )
        self.assertTrue(
            weak["required_security_header_missing_or_invalid_observed"]
        )
        self.assertTrue(weak["hsts_policy_weak_or_missing_observed"])

        unknown = extract_passive_family_evidence(
            endpoint="https://example.test/account",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers": {},
            },
        )
        self.assertNotIn(
            "required_security_header_missing_or_invalid_observed",
            unknown,
        )
        self.assertNotIn("hsts_policy_weak_or_missing_observed", unknown)

        strong = extract_passive_family_evidence(
            endpoint="https://example.test/account",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin",
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                },
            },
        )
        self.assertTrue(strong["required_security_headers_valid_observed"])
        self.assertTrue(strong["hsts_policy_valid_observed"])
        self.assertNotIn(
            "required_security_header_missing_or_invalid_observed",
            strong,
        )
        self.assertNotIn("hsts_policy_weak_or_missing_observed", strong)

    def test_clickjacking_evidence_is_sensitive_ui_only_and_never_confirmation(self):
        exposed = extract_passive_family_evidence(
            endpoint="https://example.test/account/settings",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {},
                "sensitive_ui_frame_surface": True,
            },
        )
        self.assertTrue(exposed["frame_ancestors_protection_missing_observed"])
        self.assertNotIn("sensitive_page_frameable_observed", exposed)

        protected = extract_passive_family_evidence(
            endpoint="https://example.test/account/settings",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {
                    "x-frame-options": "DENY",
                    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                },
                "sensitive_ui_frame_surface": True,
            },
        )
        self.assertTrue(protected["x_frame_options_enforced"])
        self.assertTrue(protected["csp_frame_ancestors_enforced"])
        self.assertNotIn(
            "frame_ancestors_protection_missing_observed",
            protected,
        )

        public_page = extract_passive_family_evidence(
            endpoint="https://example.test/about",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {},
            },
        )
        self.assertNotIn(
            "frame_ancestors_protection_missing_observed",
            public_page,
        )

    def test_hsts_is_only_evaluated_on_https(self):
        http = extract_passive_family_evidence(
            endpoint="http://example.test/account",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {},
            },
        )
        self.assertNotIn("hsts_policy_weak_or_missing_observed", http)

        short = extract_passive_family_evidence(
            endpoint="https://example.test/account",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "response_headers_observed": True,
                "response_headers": {
                    "strict-transport-security": "max-age=300",
                },
            },
        )
        self.assertTrue(short["hsts_policy_weak_or_missing_observed"])

    def test_context_integration_keeps_confirmation_false(self):
        class EmptyDb:
            def all(self, sql, params=()):
                return []

        context = FamilyAnalyzerContext(
            db=EmptyDb(),
            analysis_id="AN-PASSIVE",
            target="example.test",
            endpoint="https://example.test/backups/site.zip",
            method="GET",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/zip",
                "content_length": 2048,
                "raw_surface_observation": True,
            },
        )
        analyzer = analyzer_for_family("backup_unreferenced_file_exposure")
        self.assertIsNotNone(analyzer)
        result = analyzer.analyze(
            context,
            semantic_text="backup site zip",
        )
        self.assertIsNotNone(result)
        observed = {str(item.get("type") or "") for item in result["support"]}
        self.assertIn("backup_or_unreferenced_file_surface", observed)
        self.assertIn("backup_file_publicly_reachable_observed", observed)
        self.assertTrue(
            result["family_analyzer"]["promotion_ready_from_stored_target_evidence"]
        )
        self.assertFalse(
            result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"]
        )
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["active_request_performed"])

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-PASSIVE',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-PASSIVE','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-PASSIVE")),
        )
        return temp, paths, db, now

    def _insert_surface(
        self,
        db,
        now,
        *,
        endpoint,
        category,
        status,
        content_type,
        title,
        content_length,
        response_headers=None,
        response_headers_observed=False,
    ):
        db.execute(
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                endpoint,
                "absolute_url",
                category,
                88,
                json_dumps([{"category": category, "confidence": 88}]),
                json_dumps(["stored Recon surface"]),
                json_dumps(["passive-evidence-test"]),
                now,
                now,
                "RUN-PASSIVE",
            ),
        )
        db.execute(
            "INSERT INTO endpoint_validations(target,endpoint,resolved_url,method,status_code,content_type,reachable,confidence,checked_at,last_run_id,error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                endpoint,
                endpoint,
                "GET",
                status,
                content_type,
                1,
                90,
                now,
                "RUN-PASSIVE",
                "",
            ),
        )
        db.execute(
            "INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,response_headers_json,response_headers_observed,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                endpoint,
                f"fp-{abs(hash(endpoint))}",
                status,
                title,
                "test",
                "[]",
                content_type,
                content_length,
                json_dumps(response_headers or {}),
                1 if response_headers_observed else 0,
                now,
                now,
                "RUN-PASSIVE",
            ),
        )

    def test_raw_analysis_promotes_only_concrete_passive_observations(self):
        temp, paths, db, now = self._project()
        try:
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/backups/site.zip",
                category="file",
                status=200,
                content_type="application/zip",
                title="",
                content_length=8192,
            )
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/admin/",
                category="administration",
                status=200,
                content_type="text/html",
                title="Administration Console",
                content_length=4096,
            )
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/backup-false-positive.sql",
                category="file",
                status=200,
                content_type="text/html",
                title="Not Found",
                content_length=2048,
            )
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/manage/",
                category="administration",
                status=403,
                content_type="text/html",
                title="Forbidden",
                content_length=512,
            )
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/account/settings",
                category="account",
                status=200,
                content_type="text/html",
                title="Account Settings",
                content_length=2048,
                response_headers={},
                response_headers_observed=True,
            )
            self._insert_surface(
                db,
                now,
                endpoint="https://example.test/account/protected",
                category="account",
                status=200,
                content_type="text/html",
                title="Protected Account",
                content_length=2048,
                response_headers={
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin",
                    "x-frame-options": "DENY",
                    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                },
                response_headers_observed=True,
            )

            result = run_analysis(paths, db, "RUN-PASSIVE", "example.test")
            runtime = result["bug_candidates"]["detection_runtime"]
            families = set(runtime["potential_finding_families"])
            self.assertIn("backup_unreferenced_file_exposure", families)
            self.assertIn("admin_interface_exposure", families)
            self.assertIn("security_headers", families)
            self.assertIn("clickjacking", families)
            self.assertIn("tls_hsts_weakness", families)

            backup_candidates = db.all(
                "SELECT endpoint FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='backup_unreferenced_file_exposure' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )
            admin_candidates = db.all(
                "SELECT endpoint FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='admin_interface_exposure' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )
            self.assertEqual(
                [str(row["endpoint"]) for row in backup_candidates],
                ["https://example.test/backups/site.zip"],
            )
            self.assertEqual(
                [str(row["endpoint"]) for row in admin_candidates],
                ["https://example.test/admin/"],
            )
            for family in (
                "security_headers",
                "clickjacking",
                "tls_hsts_weakness",
            ):
                rows = db.all(
                    "SELECT endpoint FROM bug_candidates "
                    "WHERE analysis_id=? AND bug_family=? ORDER BY endpoint",
                    (result["analysis_id"], family),
                )
                endpoints = [str(row["endpoint"]) for row in rows]
                self.assertIn("https://example.test/account/settings", endpoints)
                self.assertNotIn(
                    "https://example.test/account/protected",
                    endpoints,
                )
            self.assertEqual(runtime["active_requests_added"], 0)
            self.assertFalse(runtime["collector_behavior_changed"])
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

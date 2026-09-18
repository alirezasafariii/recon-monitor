from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from candidate_intelligence import _extract_semantic_units
from core import APP_VERSION, AppPaths, Database, sha256_text, utc_now
from passive_evidence_extractor import extract_passive_family_evidence


class SemanticJsPassiveEvidenceTests(unittest.TestCase):
    def test_semantic_extraction_keeps_storage_values_redacted(self):
        units = _extract_semantic_units(
            """
            const accessToken = getToken();
            localStorage.setItem("access_token", accessToken);
            sessionStorage.setItem("theme", "dark");
            localStorage.setItem("refresh_token", "SUPERSECRET-LITERAL");
            """
        )
        writes = [
            unit for unit in units
            if unit.get("unit_type") == "browser_storage_write"
        ]
        self.assertEqual(len(writes), 3)

        sensitive = [
            dict(unit["value"])
            for unit in writes
            if dict(unit["value"]).get("sensitive_hint")
        ]
        self.assertEqual(
            {item["key"] for item in sensitive},
            {"access_token", "refresh_token"},
        )
        serialized = repr(writes)
        self.assertNotIn("SUPERSECRET-LITERAL", serialized)
        self.assertNotIn("accessToken", serialized)

        safe = next(
            dict(unit["value"])
            for unit in writes
            if dict(unit["value"]).get("key") == "theme"
        )
        self.assertFalse(safe["sensitive_hint"])

    def test_new_tab_extraction_normalizes_only_static_protection(self):
        units = _extract_semantic_units(
            """
            window.open("https://outside.example.net/help", "_blank");
            window.open("https://docs.example.net/", "_blank", "noopener,width=500");
            window.open("https://dynamic.example.net/", "_blank", features);
            """
        )
        opens = [
            dict(unit["value"])
            for unit in units
            if unit.get("unit_type") == "new_tab_open"
        ]
        self.assertEqual(len(opens), 2)

        exposed = next(
            item for item in opens
            if item["destination"].startswith("https://outside.")
        )
        self.assertFalse(exposed["noopener"])
        self.assertFalse(exposed["noreferrer"])
        self.assertTrue(exposed["features_static"])

        protected = next(
            item for item in opens
            if item["destination"].startswith("https://docs.")
        )
        self.assertTrue(protected["noopener"])
        self.assertFalse(protected["noreferrer"])
        self.assertNotIn("width=500", repr(protected))

    def test_passive_storage_requires_sensitive_static_write(self):
        sensitive = extract_passive_family_evidence(
            endpoint="https://example.test/app.js",
            target="example.test",
            details={
                "semantic_js_unit_type": "browser_storage_write",
                "semantic_js_static_observation": True,
                "semantic_js_observation": {
                    "storage": "localStorage",
                    "key": "access_token",
                    "sensitive_hint": True,
                    "operation": "setItem",
                },
            },
        )
        self.assertTrue(
            sensitive["sensitive_data_in_browser_storage_observed"]
        )
        self.assertNotIn(
            "sensitive_token_persisted_in_web_storage_observed",
            sensitive,
        )

        harmless = extract_passive_family_evidence(
            endpoint="https://example.test/app.js",
            target="example.test",
            details={
                "semantic_js_unit_type": "browser_storage_write",
                "semantic_js_static_observation": True,
                "semantic_js_observation": {
                    "storage": "sessionStorage",
                    "key": "theme",
                    "sensitive_hint": False,
                    "operation": "setItem",
                },
            },
        )
        self.assertNotIn(
            "sensitive_data_in_browser_storage_observed",
            harmless,
        )

    def test_reverse_tabnabbing_requires_external_static_window_open(self):
        exposed = extract_passive_family_evidence(
            endpoint="https://example.test/app.js",
            target="example.test",
            details={
                "semantic_js_unit_type": "new_tab_open",
                "semantic_js_static_observation": True,
                "semantic_js_observation": {
                    "destination": "https://outside.example.net/help",
                    "target": "_blank",
                    "mechanism": "window.open",
                    "features_static": True,
                    "noopener": False,
                    "noreferrer": False,
                },
            },
        )
        self.assertTrue(exposed["opener_reference_exposed_observed"])
        self.assertNotIn("external_tab_can_control_opener_observed", exposed)

        protected = extract_passive_family_evidence(
            endpoint="https://example.test/app.js",
            target="example.test",
            details={
                "semantic_js_unit_type": "new_tab_open",
                "semantic_js_static_observation": True,
                "semantic_js_observation": {
                    "destination": "https://outside.example.net/help",
                    "target": "_blank",
                    "mechanism": "window.open",
                    "features_static": True,
                    "noopener": True,
                    "noreferrer": False,
                },
            },
        )
        self.assertTrue(protected["noopener_enforced"])
        self.assertNotIn("opener_reference_exposed_observed", protected)

        same_site = extract_passive_family_evidence(
            endpoint="https://example.test/app.js",
            target="example.test",
            details={
                "semantic_js_unit_type": "new_tab_open",
                "semantic_js_static_observation": True,
                "semantic_js_observation": {
                    "destination": "https://app.example.test/help",
                    "target": "_blank",
                    "mechanism": "window.open",
                    "features_static": True,
                    "noopener": False,
                    "noreferrer": False,
                },
            },
        )
        self.assertNotIn("opener_reference_exposed_observed", same_site)

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-JS',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-JS','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-JS")),
        )
        return temp, paths, db, now

    def _insert_js(self, db, now, paths, *, name: str, body: str):
        js_dir = paths.blobs / "js"
        js_dir.mkdir(parents=True, exist_ok=True)
        blob = js_dir / name
        blob.write_text(body, encoding="utf-8")
        url = f"https://example.test/static/{name}"
        digest = sha256_text(body)
        db.execute(
            "INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                url,
                digest,
                digest,
                str(blob),
                len(body.encode("utf-8")),
                now,
                now,
                "RUN-JS",
            ),
        )
        return url

    def test_raw_analysis_promotes_only_concrete_semantic_js_evidence(self):
        temp, paths, db, now = self._project()
        try:
            vulnerable_url = self._insert_js(
                db,
                now,
                paths,
                name="app.js",
                body="""
                    const token = getAccessToken();
                    localStorage.setItem("access_token", token);
                    window.open("https://outside.example.net/help", "_blank");
                """,
            )
            safe_url = self._insert_js(
                db,
                now,
                paths,
                name="safe.js",
                body="""
                    sessionStorage.setItem("theme", "dark");
                    window.open(
                        "https://docs.example.net/",
                        "_blank",
                        "noopener,width=500"
                    );
                """,
            )

            result = run_analysis(paths, db, "RUN-JS", "example.test")
            runtime = result["bug_candidates"]["detection_runtime"]
            families = set(runtime["potential_finding_families"])
            self.assertIn("browser_storage_exposure", families)
            self.assertIn("reverse_tabnabbing", families)

            for family in (
                "browser_storage_exposure",
                "reverse_tabnabbing",
            ):
                rows = db.all(
                    "SELECT endpoint FROM bug_candidates "
                    "WHERE analysis_id=? AND bug_family=? ORDER BY endpoint",
                    (result["analysis_id"], family),
                )
                endpoints = [str(row["endpoint"]) for row in rows]
                self.assertIn(vulnerable_url, endpoints)
                self.assertNotIn(safe_url, endpoints)

            units = db.all(
                "SELECT unit_type,value_json FROM semantic_js_units "
                "WHERE analysis_id=? AND unit_type IN "
                "('browser_storage_write','new_tab_open') "
                "ORDER BY unit_type,unit_key",
                (result["analysis_id"],),
            )
            self.assertGreaterEqual(len(units), 4)
            persisted = "\n".join(str(row["value_json"]) for row in units)
            self.assertNotIn("getAccessToken", persisted)
            self.assertEqual(runtime["active_requests_added"], 0)
            self.assertFalse(runtime["collector_behavior_changed"])
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

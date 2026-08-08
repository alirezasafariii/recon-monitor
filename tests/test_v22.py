from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import Database  # noqa: E402
from dashboard_auth import hash_password, verify_password  # noqa: E402
from evidence import build_evidence_export  # noqa: E402
from intelligence import build_js_diff, classify_endpoint, technology_confidence  # noqa: E402


class Version22Tests(unittest.TestCase):
    def test_endpoint_classification(self) -> None:
        result = classify_endpoint("/api/v3/admin/export")
        self.assertEqual(result["primary_category"], "admin")
        self.assertGreaterEqual(result["confidence"], 90)
        self.assertTrue(result["reasons"])

    def test_detailed_js_diff_and_redaction(self) -> None:
        old = 'const apiKey="old-secret"; const endpoint="/api/v1/profile";'
        new = 'const apiKey="new-secret"; const endpoint="/api/v2/admin/export";'
        diff, summary = build_js_diff(old, new)
        self.assertIn("[REDACTED]", diff)
        self.assertNotIn("new-secret", diff)
        self.assertTrue(summary["added_endpoints"])
        self.assertEqual(summary["added_endpoints"][0]["primary_category"], "admin")

    def test_technology_confidence(self) -> None:
        result = technology_confidence(
            "nginx",
            {"webserver": "nginx", "title": "Example", "body_hash": "abc", "favicon_hash": "def"},
        )
        self.assertGreaterEqual(result["confidence"], 90)
        self.assertEqual(result["confidence_label"], "high")

    def test_workflow_tags_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "recon.db")
            try:
                alert_id, is_new, _ = db.upsert_alert(
                    "example.com", "key", "new_url", "HIGH", 75, "New admin URL", "/admin", {}, "run1"
                )
                self.assertTrue(is_new)
                db.set_alert_status(alert_id, "investigating", "Initial review")
                db.update_alert_workflow(alert_id, priority="high", assignee="alireza", note="Review auth flow")
                db.add_tag("example.com", "alert", str(alert_id), "Auth Review")
                alert = db.one("SELECT status,priority,assignee,workflow_note FROM alerts WHERE id=?", (alert_id,))
                self.assertEqual(alert["status"], "investigating")
                self.assertEqual(alert["priority"], "high")
                self.assertEqual(alert["assignee"], "alireza")
                self.assertGreaterEqual(int(db.one("SELECT COUNT(*) FROM alert_history WHERE alert_id=?", (alert_id,))[0]), 3)
                self.assertEqual(db.one("SELECT tag FROM entity_tags WHERE target='example.com'")[0], "auth-review")
            finally:
                db.close()

    def test_evidence_export(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "recon.db")
            try:
                alert_id, _, _ = db.upsert_alert(
                    "example.com", "evidence-key", "new_url", "HIGH", 75, "New endpoint", "/api/admin", {}, "run1"
                )
                db.add_note("example.com", "alert", str(alert_id), "Needs manual verification")
                filename, data = build_evidence_export(db, alert_id=alert_id)
                self.assertTrue(filename.endswith(".zip"))
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    self.assertIn("evidence.json", archive.namelist())
                    payload = json.loads(archive.read("evidence.json"))
                    self.assertEqual(payload["target"], "example.com")
                    self.assertEqual(payload["alert"]["id"], alert_id)
            finally:
                db.close()

    def test_dashboard_password_hash(self) -> None:
        salt, digest, iterations = hash_password("correct-horse-battery-staple")
        self.assertTrue(verify_password("correct-horse-battery-staple", salt, digest, iterations))
        self.assertFalse(verify_password("wrong-password", salt, digest, iterations))

    def test_schema_version_four(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "recon.db")
            try:
                self.assertEqual(db.meta_get("schema_version"), "17")
                tables = {row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertTrue({"js_diffs", "endpoint_intelligence", "technology_observations", "entity_tags", "alert_history"}.issubset(tables))
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

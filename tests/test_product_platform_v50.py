from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Database, utc_now
from dashboard import DashboardHandler
from evidence import build_evidence_export
from plugins import PluginManager, validate_manifest
from product_platform import (
    build_report_draft,
    build_validation_package,
    engine_quality,
    learn_target_profile,
    list_cases,
    noise_budget_status,
    operations_center,
    platform_sync,
    run_completeness,
    scope_center,
    set_case_state,
    storage_health,
)


class ProductPlatformV50Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\n', encoding="utf-8")
        paths.policy.write_text(json.dumps({
            "schema": 1,
            "defaults": {"limits": {"max_http_requests": 1000, "max_runtime_minutes": 60}},
            "targets": [{"name": "example.com", "roots": ["example.com"], "include": ["*.example.com"], "exclude": ["status.example.com"], "modules": {"ports": False, "nuclei": False}}],
        }), encoding="utf-8")
        return temp, paths, Database(paths.db)

    def analyzed_project(self):
        temp, paths, db = self.project(); now = utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", ("run50", APP_VERSION, "success", now, now, "example.com"))
        db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,?,0)", ("run50", "example.com", "hash", "success", "report", now, now, str(paths.output / "run50")))
        for stage in ("subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "report"):
            db.execute("INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,finished_at,heartbeat_at,metrics_json) VALUES(?,?,?,?,1,?,?,?,?)", ("run50", "example.com", stage, "success", now, now, now, json.dumps({"records": 1})))
        details = {
            "status_code": 200, "method": "PATCH", "authentication": "bearer",
            "body_fields": ["displayName", "role", "isAdmin", "tenantId", "userId"],
            "path_parameters": ["tenantId", "userId"],
            "endpoint_classification": {"primary_category": "admin", "confidence": 96},
            "response_json": {"user": {"email": "redacted", "role": "admin"}, "tenantId": "t1"},
            "context_observations": {"anonymous": {"status_code": 200, "auth_state": "anonymous", "confidence": 82}},
        }
        alert_id, _, _ = db.upsert_alert("example.com", "v50-alert", "new_endpoint", "HIGH", 91, "Tenant administration endpoint", "/api/tenants/{tenantId}/users/{userId}", details, "run50")
        js = paths.state / "v50.js"; js.write_text("const enableTenantAdmin=true; fetch('/api/tenants/'+tenantId+'/users/'+userId);", encoding="utf-8")
        db.execute("INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)", ("example.com", "https://example.com/app.js", "raw50", "sem50", str(js), js.stat().st_size, now, now, now, "run50"))
        result = run_analysis(paths, db, "run50", "example.com")
        return temp, paths, db, alert_id, result

    def test_version_schema_and_platform_tables(self):
        temp, paths, db = self.project()
        try:
            self.assertEqual(APP_VERSION, "8.4.0"); self.assertEqual(SCHEMA_VERSION, 17); self.assertEqual(db.meta_get("schema_version"), "17")
            names = {row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in ("engine_quality_snapshots", "rule_governance", "rule_noise_budgets", "target_learning_profiles", "security_cases", "security_case_events", "security_stories", "validation_packages", "report_drafts", "run_completeness", "scope_snapshots", "schedule_policies", "notification_policies", "storage_snapshots", "incremental_checkpoints", "incremental_reasoning_cache", "plugin_health_history"):
                self.assertIn(name, names)
        finally: db.close(); temp.cleanup()

    def test_platform_sync_builds_case_quality_learning_and_budget(self):
        temp, paths, db, _, result = self.analyzed_project()
        try:
            sync = platform_sync(paths, db, result["analysis_id"])
            self.assertEqual(sync["version"], "6.0.4")
            self.assertGreaterEqual(sync["cases"]["cases"], 1)
            self.assertGreater(sync["quality"]["candidates"], 0)
            self.assertEqual(sync["target_learning"]["target"], "example.com")
            self.assertEqual(sync["noise_budget"]["profile"], "balanced")
            self.assertTrue(list_cases(db))
        finally: db.close(); temp.cleanup()

    def test_case_lifecycle_validation_and_report_are_safe(self):
        temp, paths, db, _, result = self.analyzed_project()
        try:
            platform_sync(paths, db, result["analysis_id"]); case = list_cases(db)[0]
            changed = set_case_state(db, case["case_id"], "reviewing", assigned_to="analyst-a", note="triaged")
            self.assertEqual(changed["state"], "reviewing")
            package = build_validation_package(db, case["case_id"], actor="test")
            self.assertIn("safe_stop_conditions", package); self.assertNotIn("payload", package)
            draft = build_report_draft(db, case["case_id"], actor="test")
            self.assertIn("Draft only", draft["disclaimer"]); self.assertLessEqual(draft["report_readiness"], 100)
        finally: db.close(); temp.cleanup()

    def test_quality_learning_and_noise_budget_are_explainable(self):
        temp, paths, db, _, result = self.analyzed_project()
        try:
            quality = engine_quality(db, result["analysis_id"], target="example.com", persist=True)
            self.assertIn("families", quality); self.assertIn("noise_budget", quality); self.assertIn("target_learning", quality)
            learned = learn_target_profile(db, "example.com", result["analysis_id"])
            self.assertIn("common_families", learned["baseline"])
            budget = noise_budget_status(db, result["analysis_id"], profile="quiet", target="example.com")
            self.assertEqual(budget["maximum_candidates"], 10); self.assertIn("no evidence is deleted", budget["routing"])
        finally: db.close(); temp.cleanup()

    def test_scope_completeness_storage_and_operations(self):
        temp, paths, db, _, _ = self.analyzed_project()
        try:
            scope = scope_center(paths, db); self.assertEqual(scope["targets"][0]["authorization_status"], "confirmed")
            completeness = run_completeness(db, "run50"); self.assertGreaterEqual(completeness["score"], 90)
            storage = storage_health(paths, db, persist=True); self.assertIn("retention_preview", storage)
            operations = operations_center(paths, db); self.assertIn("program_health_score", operations); self.assertIn("plugins", operations)
        finally: db.close(); temp.cleanup()

    def test_plugin_manifest_contract_and_health_history(self):
        temp, paths, db = self.project()
        try:
            plug = paths.plugins / "demo"; plug.mkdir(parents=True); (plug / "plugin.py").write_text("plugin=None\n", encoding="utf-8")
            manifest = {"name": "demo-plugin", "version": "1.0", "category": "analysis", "entrypoint": "plugin.py", "timeout_seconds": 30, "resource_limits": {"memory_mb": 128}, "output_evidence_types": ["demo"]}
            (plug / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            ok, errors, normalized = validate_manifest(manifest, plug); self.assertTrue(ok); self.assertFalse(errors); self.assertEqual(normalized["timeout_seconds"], 30)
            PluginManager(paths, db).health()
            self.assertGreater(db.one("SELECT COUNT(*) count FROM plugin_health_history WHERE plugin_name='demo-plugin'")["count"], 0)
        finally: db.close(); temp.cleanup()

    def test_dashboard_is_case_first_and_routes_render(self):
        temp, paths, db, _, result = self.analyzed_project(); platform_sync(paths, db, result["analysis_id"]); db.close()
        try:
            handler = object.__new__(DashboardHandler); handler.paths = paths; handler.db_path = paths.db; handler.path = "/"; handler.query = lambda: {}
            captured = {}; handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.overview(); self.assertIn("Decision inbox", captured["body"]); self.assertIn("Security stories", captured["body"]); self.assertIn("Coverage snapshot", captured["body"])
            for method, title in (("cases_page", "Security cases"), ("engine_quality_platform_page", "Engine quality"), ("operations_center_page", "Operations center"), ("scope_center_page", "Scope center")):
                captured.clear(); getattr(handler, method)(); self.assertEqual(captured["title"], title)
        finally: temp.cleanup()

    def test_evidence_export_includes_product_platform_records(self):
        temp, paths, db, alert_id, result = self.analyzed_project()
        try:
            platform_sync(paths, db, result["analysis_id"]); case = list_cases(db)[0]; build_validation_package(db, case["case_id"]); build_report_draft(db, case["case_id"])
            _, data = build_evidence_export(db, alert_id=alert_id)
            with zipfile.ZipFile(io.BytesIO(data)) as archive: payload = json.loads(archive.read("evidence.json"))
            for key in ("engine_quality_snapshots", "security_cases", "security_case_members", "security_case_events", "validation_packages", "report_drafts", "security_stories", "incremental_checkpoints", "target_learning_profiles", "scope_snapshots"):
                self.assertIn(key, payload)
            self.assertGreater(len(payload["security_cases"]), 0)
        finally: db.close(); temp.cleanup()

    def test_incremental_reasoning_cache_is_populated_and_reusable(self):
        temp, paths, db, _, result = self.analyzed_project()
        try:
            first = db.one("SELECT COUNT(*) count FROM incremental_reasoning_cache")["count"]
            self.assertGreater(first, 0)
            from security_reasoning import apply_security_reasoning
            apply_security_reasoning(db, result["analysis_id"])
            traces = [json.loads(r[0]) for r in db.all("SELECT trace_json FROM candidate_reasoning_traces WHERE analysis_id=?", (result["analysis_id"],))]
            self.assertTrue(any(trace.get("cache", {}).get("reused") for trace in traces))
        finally: db.close(); temp.cleanup()


if __name__ == "__main__":
    unittest.main()

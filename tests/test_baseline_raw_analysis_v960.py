from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import ENGINE_VERSION, run_analysis
from core import (
    APP_VERSION,
    AppPaths,
    Config,
    Database,
    Logger,
    TargetPolicy,
    json_dumps,
    utc_now,
)
from reporting import create_alerts_and_notify


class BaselineRawAnalysisV960Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-BASELINE',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-BASELINE','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-BASELINE")),
        )
        policy = TargetPolicy.from_dict(
            {
                "name": "example.test",
                "roots": ["example.test"],
                "alert": {"minimum_score": 0},
            }
        )
        run_dir = paths.output / "RUN-BASELINE" / "example.test"
        run_dir.mkdir(parents=True, exist_ok=True)
        ctx = SimpleNamespace(
            events_path=run_dir / "changes" / "events.jsonl",
            policy=policy,
            config=Config(paths),
            db=db,
            run_id="RUN-BASELINE",
            logger=Logger(paths, verbose=False),
        )
        ctx.events_path.parent.mkdir(parents=True, exist_ok=True)
        return temp, paths, db, ctx

    def test_first_scan_records_events_but_creates_no_alerts(self):
        temp, _paths, db, ctx = self.project()
        try:
            event = {
                "target": "example.test",
                "dedup_key": "baseline-event",
                "category": "new_url",
                "severity": "HIGH",
                "risk_score": 90,
                "title": "Baseline URL",
                "item": "https://example.test/admin/export.csv",
                "details": {},
                "confirmation_state": "confirmed",
            }
            ctx.events_path.write_text(json_dumps(event) + "\n", encoding="utf-8")
            # Legacy configuration must not be able to re-enable first-scan
            # Alerts; baseline silence is now a product invariant.
            ctx.config.values["ALERT_ON_BASELINE"] = "true"

            baseline = create_alerts_and_notify(ctx, baseline=True)
            self.assertEqual(baseline["events"], 1)
            self.assertEqual(baseline["new_alerts"], 0)
            self.assertFalse(baseline["alerting_active"])
            self.assertFalse(baseline["baseline_alerts_created"])
            self.assertEqual(db.one("SELECT COUNT(*) count FROM alerts")["count"], 0)

            later = create_alerts_and_notify(ctx, baseline=False)
            self.assertEqual(later["new_alerts"], 1)
            self.assertTrue(later["alerting_active"])
            self.assertEqual(db.one("SELECT COUNT(*) count FROM alerts")["count"], 1)
        finally:
            db.close()
            temp.cleanup()

    def test_failed_partial_data_does_not_activate_alerting(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
                "VALUES('RUN-FAILED',?,'partial',?,?,?,1)",
                (APP_VERSION, now, now, "failed.test"),
            )
            db.execute(
                "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
                "VALUES('RUN-FAILED','failed.test','policy','failed',NULL,?,?,?,1)",
                (now, now, str(paths.output / "RUN-FAILED")),
            )
            db.upsert_asset(
                "failed.test",
                "api.failed.test",
                ["failed-partial-run"],
                "RUN-FAILED",
            )

            self.assertFalse(db.target_has_history("failed.test"))
            db.execute(
                "UPDATE run_targets SET status='success' "
                "WHERE run_id='RUN-FAILED' AND target='failed.test'"
            )
            self.assertTrue(db.target_has_history("failed.test"))
        finally:
            db.close()
            temp.cleanup()

    def test_stored_raw_finding_can_create_potential_without_an_alert(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            endpoint = "https://example.test/"
            db.execute(
                "INSERT INTO findings(target,dedup_key,template_id,name,severity,matched_at,details_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "missing-security-header",
                    "missing-security-header",
                    "Required browser security header missing",
                    "medium",
                    endpoint,
                    json_dumps(
                        {
                            "browser_security_header_surface": True,
                            "required_security_header_missing_or_invalid_observed": True,
                            "status_code": 200,
                        }
                    ),
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )

            result = run_analysis(paths, db, "RUN-BASELINE", "example.test")

            candidate = db.one(
                "SELECT alert_id,bug_family,candidate_state,source_ref FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='security_headers'",
                (result["analysis_id"],),
            )
            self.assertIsNotNone(candidate)
            self.assertIsNone(candidate["alert_id"])
            self.assertTrue(str(candidate["source_ref"]).startswith("raw-finding:"))
            self.assertEqual(db.one("SELECT COUNT(*) count FROM alerts")["count"], 0)
        finally:
            db.close()
            temp.cleanup()

    def test_alert_free_baseline_runs_raw_family_analysis(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            endpoint = "https://example.test/reports/export.csv?accountId={accountId}"
            db.execute(
                "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    endpoint,
                    "absolute_url",
                    "export",
                    88,
                    '[{"category":"export","confidence":88}]',
                    '["Matched export path pattern"]',
                    '["stored_js_indicator"]',
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )
            db.execute(
                "INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    endpoint,
                    "fp",
                    200,
                    "Export report",
                    "nginx",
                    '["nginx 1.25.4"]',
                    "text/csv",
                    120,
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )

            result = run_analysis(paths, db, "RUN-BASELINE", "example.test")

            self.assertEqual(result["engine_version"], ENGINE_VERSION)
            self.assertEqual(result["alerts"], 0)
            self.assertEqual(result["analysis_inputs"], "raw_only")
            self.assertEqual(result["targets_analyzed"], ["example.test"])
            raw_routing = result["bug_candidates"]["raw_surface_routing"]
            self.assertGreater(raw_routing["hypotheses"], 0)
            self.assertEqual(raw_routing["active_requests"], 0)
            self.assertEqual(db.one("SELECT COUNT(*) count FROM alerts")["count"], 0)
            hypothesis = db.one(
                "SELECT state,admission_json FROM analysis_hypotheses "
                "WHERE analysis_id=? AND bug_family='csv_injection'",
                (result["analysis_id"],),
            )
            self.assertIsNotNone(hypothesis)
            self.assertIn(
                hypothesis["state"],
                {"shadow_signal", "shadow_partial", "abstained", "admitted"},
            )
            self.assertNotEqual(hypothesis["state"], "promoted")
            self.assertIsNone(
                db.one(
                    "SELECT candidate_id FROM bug_candidates "
                    "WHERE analysis_id=? AND bug_family='csv_injection'",
                    (result["analysis_id"],),
                )
            )
        finally:
            db.close()
            temp.cleanup()

    def test_raw_cname_is_context_only_for_subdomain_takeover(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO dns_records(target,host,rrtype,value,first_seen,last_seen,last_run_id,is_current) "
                "VALUES(?,?,?,?,?,?,?,1)",
                (
                    "example.test",
                    "docs.example.test",
                    "CNAME",
                    "tenant.vendor.invalid",
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )

            result = run_analysis(paths, db, "RUN-BASELINE", "example.test")
            hypothesis = db.one(
                "SELECT state,supporting_evidence_json FROM analysis_hypotheses "
                "WHERE analysis_id=? AND bug_family='subdomain_takeover'",
                (result["analysis_id"],),
            )
            self.assertIsNotNone(hypothesis)
            self.assertNotEqual(hypothesis["state"], "promoted")
            self.assertIn("dangling_dns_dependency_surface", hypothesis["supporting_evidence_json"])
            self.assertEqual(db.one("SELECT COUNT(*) count FROM bug_candidates")["count"], 0)
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from api_server import authenticate, create_token
from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, utc_now
from dashboard import DashboardHandler
from evidence import build_evidence_export
from platform_v6 import (
    apply_target_template,
    build_burp_roundtrip_package,
    correlate_security_stories,
    data_quality_snapshot,
    import_burp_roundtrip_result,
    list_target_templates,
    performance_diagnostics,
    process_due_revalidations,
    queue_notification,
    rank_review_queue,
    run_scheduled_workflow,
    report_quality,
    retention_preview,
    review_value_for_case,
    security_posture,
    set_revalidation_policy,
    validation_intelligence,
    verify_audit_chain,
)


class PlatformV60Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\nTELEGRAM_ENABLED="no"\nDASHBOARD_AUTH_ENABLED="yes"\n', encoding="utf-8")
        paths.policy.write_text(json.dumps({
            "schema": 3,
            "defaults": {"limits": {"max_http_requests": 1000, "max_runtime_minutes": 60}},
            "targets": [{"name": "example.com", "roots": ["example.com"], "include": [r"(^|\.)example\.com$"], "exclude": [r"^status\.example\.com$"], "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"}}],
        }), encoding="utf-8")
        db = Database(paths.db)
        now = utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-1',?,'success',?,?,'example.com',1)", (APP_VERSION, now, now))
        db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES('RUN-1','example.com','h','success','report',?,?,?,0)", (now, now, str(paths.output/'RUN-1')))
        for stage in ("subdomains","dns","urls","javascript","endpoint_validation","fingerprint","report"):
            db.execute("INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,finished_at,heartbeat_at,metrics_json) VALUES('RUN-1','example.com',?,'success',1,?,?,?,'{}')", (stage, now, now, now))
        db.execute("INSERT INTO assets(target,host,sources_json,confidence,wildcard,resolved,first_seen,last_seen,last_run_id) VALUES('example.com','api.example.com','[]',90,0,1,?,?, 'RUN-1')", (now, now))
        db.execute("INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) VALUES('example.com','https://api.example.com/account','endpoint','fixture',?,?, 'RUN-1')", (now, now))
        db.execute("INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,body_hash,first_seen,last_seen,last_run_id) VALUES('example.com','https://api.example.com/account','fp',200,'Account','test','[]','application/json',30,'b',?,?, 'RUN-1')", (now, now))
        db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-1','RUN-1','example.com','6','r','analysis','success',?,?, '{}')", (now, now))
        db.execute("INSERT INTO endpoint_contracts(analysis_id,target,source_run_id,alert_id,endpoint,method,input_fields_json,output_fields_json,auth_boundary,object_relations_json,confidence,created_at) VALUES('AN-1','example.com','RUN-1',1,'/api/account','GET','{}','[]','bearer','[]',90,?)", (now,))
        db.execute("INSERT INTO response_shape_fingerprints(analysis_id,target,endpoint,status_code,shape_hash,keys_json,types_json,sensitive_keys_json,confidence,created_at) VALUES('AN-1','example.com','/api/account',200,'shape1','[\"email\"]','{}','[\"email\"]',90,?)", (now,))
        db.execute("INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at) VALUES('AN-1','example.com','/api/account','anonymous','anonymous',200,'shape1','{}','fixture',80,?)", (now,))
        db.execute("INSERT INTO evidence_records(evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES('E1','AN-1','RUN-1','example.com','http','supports','http','fixture','fixture','fixture','1','fixture','root',80,80,'direct','evidence','ref','h',?,?,?)", (now, now, now))
        db.execute("INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json) VALUES('C1','cfp','AN-1','RUN-1',NULL,'example.com','api.example.com','GET /api/account','/api/account','information_disclosure','candidate','Account disclosure','summary',75,70,90,82,'plausible','[]','[]','[]','review','[]','r','unreviewed','',?,?,78,45,40,80,'[\"authenticated context\"]')", (now, now))
        db.execute("INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,validation_state,created_at,updated_at) VALUES('CASE-1','k','AN-1','RUN-1','example.com','Account disclosure case','summary','information_disclosure',82,'ready_for_validation','','in_scope',50,'completed',?,?)", (now, now))
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-1','candidate','C1','supports_case','{}',?)", (now,))
        db.execute("INSERT INTO validation_plans(plan_id,case_id,target,level,status,plan_json,approval_phrase_hash,created_by,created_at,updated_at) VALUES('P1','CASE-1','example.com','passive_live','completed','{\"test_identity_ids\":[\"T1\"]}','','test',?,?)", (now, now))
        db.execute("INSERT INTO validation_runs(run_id,plan_id,case_id,target,status,result,summary_json,started_at,finished_at,executed_by) VALUES('VR1','P1','CASE-1','example.com','completed','strengthened','{\"comparison\":true}',?,?, 'test')", (now, now))
        obs = {"context":"anonymous","shape_hash":"shape1","raw_body_stored":False}
        db.execute("INSERT INTO validation_observations(run_id,sequence,method,url,status_code,observation_json,created_at) VALUES('VR1',1,'GET','https://api.example.com/account',200,?,?)", (json.dumps(obs), now))
        db.execute("INSERT INTO report_drafts(draft_id,case_id,title,body_json,status,readiness_score,created_by,created_at,updated_at) VALUES('D1','CASE-1','Report','{\"affected_asset\":\"api.example.com\",\"observed_behavior\":\"data returned\",\"impact\":\"sensitive data\",\"evidence\":[\"E1\"],\"scope_confirmation\":\"in scope\",\"redacted\":true}','draft',50,'test',?,?)", (now, now))
        return temp, paths, db

    def test_schema_and_new_tables(self):
        temp, paths, db = self.project()
        try:
            self.assertEqual((APP_VERSION, SCHEMA_VERSION, db.meta_get("schema_version")), ("8.1.0", 16, "16"))
            names={row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in ("validation_intelligence","revalidation_policies","data_quality_snapshots","review_rankings","burp_roundtrip_packages","notification_events","retention_policies","performance_samples","report_quality_snapshots","audit_integrity"):
                self.assertIn(name,names)
        finally: db.close(); temp.cleanup()

    def test_validation_intelligence_is_explainable(self):
        temp, paths, db = self.project()
        try:
            result=validation_intelligence(db,"VR1")
            self.assertEqual(result["result"],"strengthened")
            self.assertIn("test_reliability",result);self.assertIn("context_coverage",result);self.assertIn("limitations",result)
            self.assertGreater(db.one("SELECT COUNT(*) count FROM validation_intelligence")["count"],0)
        finally: db.close(); temp.cleanup()

    def test_data_quality_exposes_auth_blind_spot(self):
        temp, paths, db = self.project()
        try:
            result=data_quality_snapshot(db,"RUN-1")
            self.assertGreater(result["score"],0)
            codes={b["code"] for b in result["blind_spots"]}
            self.assertIn("single_auth_context",codes)
        finally: db.close(); temp.cleanup()

    def test_cost_aware_review_ranking(self):
        temp, paths, db = self.project()
        try:
            result=review_value_for_case(db,"CASE-1")
            self.assertGreater(result["review_value"],0)
            row=db.one("SELECT review_value,analyst_effort,information_gain FROM security_cases WHERE case_id='CASE-1'")
            self.assertEqual(row["review_value"],result["review_value"])
        finally: db.close(); temp.cleanup()

    def test_burp_roundtrip_never_stores_raw_bodies(self):
        temp, paths, db = self.project()
        try:
            package=build_burp_roundtrip_package(paths,db,"CASE-1",actor="test")
            self.assertTrue(Path(package["path"]).exists())
            result=import_burp_roundtrip_result(db,package["package_id"],{"decision":"needs_more_evidence","reason_code":"insufficient_evidence","request_metadata":{"Authorization":"Bearer secret"},"response_metadata":{"email":"person@example.com"}},actor="test")
            serialized=json.dumps(result)
            self.assertNotIn("Bearer secret",serialized);self.assertNotIn("person@example.com",serialized);self.assertFalse(result["raw_body_stored"])
        finally: db.close(); temp.cleanup()

    def test_story_correlation_creates_links(self):
        temp, paths, db = self.project()
        try:
            result=correlate_security_stories(db,"AN-1")
            self.assertGreaterEqual(result["stories"],1);self.assertGreaterEqual(result["links"],1)
        finally: db.close(); temp.cleanup()

    def test_revalidation_policy_and_notification_dedup(self):
        temp, paths, db = self.project()
        try:
            policy=set_revalidation_policy(db,"CASE-1","interval",interval_days=7,actor="test")
            self.assertEqual(policy["trigger"],"interval")
            first=queue_notification(db,{"event_type":"authentication_boundary","title":"Authentication boundary regression","score":95},target="example.com")
            second=queue_notification(db,{"event_type":"authentication_boundary","title":"Authentication boundary regression","score":95},target="example.com")
            self.assertFalse(first["deduplicated"]);self.assertTrue(second["deduplicated"])
        finally: db.close(); temp.cleanup()

    def test_retention_preview_protects_evidence(self):
        temp, paths, db = self.project()
        try:
            old=paths.logs/'old.log';old.write_text('x'*20);os.utime(old,(1,1))
            preview=retention_preview(paths,db)
            self.assertIn("protected_files",preview);self.assertGreaterEqual(preview["files"],1)
        finally: db.close(); temp.cleanup()

    def test_target_templates_apply_without_touching_scope(self):
        temp, paths, db = self.project()
        try:
            before=json.loads(paths.policy.read_text())['targets'][0]['include']
            preview=apply_target_template(paths,"example.com","api-heavy",dry_run=True)
            self.assertTrue(preview["dry_run"])
            apply_target_template(paths,"example.com","api-heavy",dry_run=False,actor="test")
            after=json.loads(paths.policy.read_text())['targets'][0]
            self.assertEqual(after['include'],before);self.assertEqual(after['analysis']['profile'],'balanced')
        finally: db.close(); temp.cleanup()

    def test_report_quality_and_audit_chain(self):
        temp, paths, db = self.project()
        try:
            result=report_quality(db,draft_id="D1")
            self.assertIn("missing",result);self.assertLess(result["quality_score"],100)
            db.audit("fixture_event",actor="test",details={"x":1})
            self.assertTrue(verify_audit_chain(db)["ok"])
        finally: db.close(); temp.cleanup()

    def test_api_tokens_have_scopes_and_expiration(self):
        temp, paths, db = self.project()
        try:
            token=create_token(db,"test","analyst",["read","validation"],30)
            ok,name,role,scopes=authenticate(db,"Bearer "+token)
            self.assertTrue(ok);self.assertEqual(role,"analyst");self.assertIn("validation",scopes)
        finally: db.close(); temp.cleanup()

    def test_dashboard_v6_pages_render(self):
        temp, paths, db = self.project();validation_intelligence(db,"VR1");data_quality_snapshot(db,"RUN-1");review_value_for_case(db,"CASE-1");db.close()
        try:
            handler=object.__new__(DashboardHandler);handler.paths=paths;handler.db_path=paths.db;handler.config=Config(paths);handler.path='/'
            captured={};handler.send_html=lambda title,body,status=200:captured.update(title=title,body=body,status=status)
            for method,title in (("validation_intelligence_page","Validation intelligence"),("data_quality_page","Data quality"),("review_priority_page","Review priority"),("automation_page","Automation"),("report_quality_page","Report quality"),("performance_page","Performance"),("retention_page","Retention"),("templates_page","Target templates"),("platform_security_page","Platform security")):
                handler.query=lambda:{};captured.clear();getattr(handler,method)();self.assertEqual(captured["title"],title)
        finally: temp.cleanup()

    def test_security_posture_and_performance_are_bounded(self):
        temp, paths, db = self.project()
        try:
            posture=security_posture(paths,Config(paths),db,persist=True)
            perf=performance_diagnostics(paths,db,limit=10)
            self.assertIn("checks",posture);self.assertLessEqual(len(perf["largest_tables"]),25)
        finally: db.close(); temp.cleanup()

    def test_evidence_export_contains_v6_intelligence(self):
        temp, paths, db = self.project()
        try:
            validation_intelligence(db, "VR1", persist=True)
            rank_review_queue(db, refresh=True)
            build_burp_roundtrip_package(paths, db, "CASE-1", actor="tester")
            report_quality(db, case_id="CASE-1", persist=True)
            correlate_security_stories(db, "AN-1", persist=True)
            filename, data = build_evidence_export(db, target="example.com", entity_type="asset", entity_value="api.example.com")
            self.assertTrue(filename.endswith(".zip"))
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                payload = json.loads(archive.read("evidence.json"))
            self.assertTrue(payload["validation_intelligence"])
            self.assertTrue(payload["review_rankings"])
            self.assertTrue(payload["burp_roundtrip_packages"])
            self.assertTrue(payload["report_quality_snapshots"])
            self.assertIn("data_quality_snapshots", payload)
            self.assertNotIn("raw_request_body", json.dumps(payload))
        finally:
            db.close(); temp.cleanup()

    def test_due_revalidation_executes_offline_only(self):
        temp, paths, db = self.project()
        try:
            set_revalidation_policy(db, "CASE-1", "interval", interval_days=1, actor="test")
            db.execute("UPDATE revalidation_policies SET next_due_at='2000-01-01T00:00:00Z' WHERE case_id='CASE-1'")
            result = process_due_revalidations(paths, Config(paths), db, limit=10, execute_offline=True, actor="test")
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["items"][0]["network_requests"], 0)
            self.assertTrue(db.one("SELECT 1 FROM validation_intelligence WHERE validation_run_id=?", (result["items"][0]["validation_run_id"],)))
        finally:
            db.close(); temp.cleanup()

    def test_scheduled_workflow_dry_run_honors_policy(self):
        temp, paths, db = self.project()
        try:
            now = utc_now()
            db.execute("INSERT INTO schedule_policies(target,cadence,enabled,max_runtime_minutes,request_budget,quiet_hours,created_at,updated_at) VALUES('example.com','3h',1,120,10000,'',?,?)", (now, now))
            result = run_scheduled_workflow(paths, Config(paths), db, "example.com", dry_run=True, actor="test")
            self.assertEqual(result["status"], "planned")
            self.assertEqual(result["request_budget"], 10000)
        finally:
            db.close(); temp.cleanup()


if __name__ == "__main__":
    unittest.main()

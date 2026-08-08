from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, utc_now
from dashboard import DashboardHandler, _layout
from workspace_v7 import (
    attack_surface_graph,
    authentication_contexts,
    browser_compatibility,
    build_evidence_linked_report,
    case_autopilot,
    change_intelligence,
    cockpit,
    differential_intelligence,
    evidence_gap_for_case,
    false_positive_learning,
    import_browser_capture,
    operator_diagnostics,
    recent_error_events,
    recon_coverage,
    record_error_event,
    safe_repair,
    safety_center,
    smart_recon_plan,
    target_memory,
    universal_search,
    workspace_v7_sync,
)


class WorkspaceV70Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="no"\nDASHBOARD_HOST="127.0.0.1"\nDASHBOARD_AUTH_ENABLED="no"\nTELEGRAM_ENABLED="no"\n',
            encoding="utf-8",
        )
        paths.policy.write_text(json.dumps({
            "schema": 3,
            "defaults": {"limits": {"max_http_requests": 1000, "max_runtime_minutes": 60}},
            "targets": [{"name": "example.com", "roots": ["example.com"], "include": [r"(^|\.)example\.com$"], "exclude": [], "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"}}],
        }), encoding="utf-8")
        db = Database(paths.db)
        now = utc_now()
        # Two successful runs make change intelligence and planning meaningful.
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-OLD',?,'success','2026-08-01T00:00:00Z','2026-08-01T00:10:00Z','example.com',1)", (APP_VERSION,))
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-NEW',?,'success','2026-08-02T00:00:00Z','2026-08-02T00:10:00Z','example.com',1)", (APP_VERSION,))
        for run in ('RUN-OLD','RUN-NEW'):
            db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?, 'example.com','h','success','report',?,?,?,0)", (run, now, now, str(paths.output/run)))
            for stage in ('subdomains','dns','urls','javascript','endpoint_validation','fingerprint','report'):
                db.execute("INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,finished_at,heartbeat_at,duration_seconds,metrics_json) VALUES(?, 'example.com',?,'success',1,?,?,?,?, '{}')", (run, stage, now, now, now, 1.5))
        db.execute("INSERT INTO assets(target,host,sources_json,confidence,wildcard,resolved,first_seen,last_seen,last_run_id) VALUES('example.com','api.example.com','[]',92,0,1,?,?, 'RUN-NEW')", (now, now))
        db.execute("INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) VALUES('example.com','https://api.example.com/orders/42','endpoint','fixture',?,?, 'RUN-NEW')", (now, now))
        db.execute("INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) VALUES('example.com','https://api.example.com/orders/{id}','path','object',90,'[]','[]','[]',?,?, 'RUN-NEW')", (now, now))
        db.execute("INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES('example.com','https://example.com/app.js','j1','sj1','',100,?,?,?, 'RUN-NEW')", (now, now, now))
        db.execute("INSERT INTO js_indicators(target,js_url,kind,value,redacted,first_seen,last_seen,last_run_id) VALUES('example.com','https://example.com/app.js','endpoint','/api/orders/{id}',0,?,?, 'RUN-NEW')", (now, now))
        db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-1','RUN-NEW','example.com','7','r','analysis','success',?,?, '{}')", (now, now))
        db.execute("INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at) VALUES('AN-1','example.com','/api/orders/42','User A','authenticated',200,'shape-a','{}','fixture',85,?)", (now,))
        db.execute("INSERT INTO response_shape_fingerprints(analysis_id,target,endpoint,status_code,shape_hash,keys_json,types_json,sensitive_keys_json,confidence,created_at) VALUES('AN-1','example.com','/api/orders/42',200,'shape-a','[\"id\",\"owner\"]','{}','[]',90,?)", (now,))
        db.execute("INSERT INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) VALUES('AN-1','example.com','/api/orders/42','authenticated:User A',90,'[]',?)", (now,))
        db.execute("INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json) VALUES('C-BOLA','fp','AN-1','RUN-NEW',NULL,'example.com','api.example.com','GET https://api.example.com/orders/42','/api/orders/42','broken_object_authorization','candidate','Possible object authorization issue','Object ownership should remain bound to the authorized identity.',78,72,88,84,'plausible','[{\"text\":\"Direct endpoint observation\"}]','[]','[\"second identity\"]','Collect a second authorized context','[]','r','unreviewed','',?,?,78,40,45,80,'[\"second identity\"]')", (now, now))
        db.execute("INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,validation_state,created_at,updated_at) VALUES('CASE-BOLA','k','AN-1','RUN-NEW','example.com','Possible BOLA','Object ownership should remain bound to the authorized identity.','broken_object_authorization',84,'needs_evidence','','in_scope',45,'not_started',?,?)", (now, now))
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-BOLA','candidate','C-BOLA','supports_case','{}',?)", (now,))
        # A scope snapshot makes Safety Center explicit rather than inferring scope from config.
        db.execute("INSERT INTO scope_snapshots(target,policy_hash,authorization_status,scope_json,created_at) VALUES('example.com','policy-h','authorized','{\"roots\":[\"example.com\"]}',?)", (now,))
        return temp, paths, db

    def test_version_schema_and_workspace_tables(self):
        temp, paths, db = self.project()
        try:
            self.assertEqual((APP_VERSION, SCHEMA_VERSION, db.meta_get('schema_version')), ('8.4.4', 18, '18'))
            tables = {r[0] for r in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in ('evidence_gap_snapshots','case_autopilot_tasks','auth_context_profiles','differential_findings','recon_coverage_snapshots','target_memory','false_positive_learning','smart_recon_plans','report_claims','browser_capture_events','operator_diagnostics','error_events','recovery_actions'):
                self.assertIn(name, tables)
        finally: db.close(); temp.cleanup()

    def test_evidence_gap_keeps_bola_manual_and_names_missing_context(self):
        temp, paths, db = self.project()
        try:
            result = evidence_gap_for_case(db, 'CASE-BOLA', persist=True)
            self.assertEqual(result['automation'], 'manual_only')
            missing = {x['key'] for x in result['requirements'] if x['status']=='missing'}
            self.assertIn('second_identity', missing)
            self.assertIn('ownership_map', missing)
            self.assertGreater(db.one("SELECT COUNT(*) c FROM evidence_gap_snapshots")['c'], 0)
        finally: db.close(); temp.cleanup()

    def test_family_alias_bola_idor_maps_to_manual_only(self):
        temp, paths, db = self.project()
        try:
            db.execute("UPDATE security_cases SET primary_family='BOLA / IDOR' WHERE case_id='CASE-BOLA'")
            result = evidence_gap_for_case(db, 'CASE-BOLA', persist=False)
            self.assertEqual(result['bug_family'], 'broken_object_authorization')
            self.assertEqual(result['automation'], 'manual_only')
        finally: db.close(); temp.cleanup()

    def test_case_autopilot_only_creates_investigation_tasks(self):
        temp, paths, db = self.project()
        try:
            result = case_autopilot(db, 'CASE-BOLA', actor='test', persist=True)
            self.assertTrue(result['tasks'])
            self.assertTrue(all(t['type'] in {'evidence','decision','report'} for t in result['tasks']))
            self.assertFalse(any('exploit' in t['title'].lower() for t in result['tasks']))
            self.assertGreater(db.one("SELECT COUNT(*) c FROM case_autopilot_tasks WHERE case_id='CASE-BOLA'")['c'], 0)
            self.assertEqual(db.one("SELECT analyst_decision FROM bug_candidates WHERE candidate_id='C-BOLA'")['analyst_decision'], 'unreviewed')
        finally: db.close(); temp.cleanup()

    def test_browser_capture_is_metadata_only_redacts_and_rejects_lookalike_host(self):
        temp, paths, db = self.project()
        try:
            capture = paths.root/'capture.json'
            capture.write_text(json.dumps({'entries':[
                {'url':'https://api.example.com/orders/42?token=supersecret&view=full','method':'GET','status':200,'headers':{'Authorization':'Bearer secret','Cookie':'sid=secret','Content-Type':'application/json','X-Debug-Token':'also-secret'},'response_shape':{'id':'number'}},
                {'url':'https://evil-example.com/orders/42','method':'GET','status':200},
            ]}), encoding='utf-8')
            result = import_browser_capture(paths, db, target='example.com', file_path=capture, context_label='User A', actor='test')
            self.assertEqual(result['imported'], 1); self.assertEqual(result['skipped'], 1); self.assertFalse(result['raw_secrets_stored'])
            row = db.one("SELECT url,metadata_json FROM browser_capture_events LIMIT 1")
            self.assertIn('token=%5Bredacted%5D', row['url'])
            text = row['metadata_json'].lower()
            self.assertNotIn('bearer secret', text); self.assertNotIn('sid=secret', text); self.assertNotIn('also-secret', text)
            contexts = authentication_contexts(db, target='example.com', persist=False)
            self.assertTrue(any(c['label']=='User A' and 'browser_capture' in c['sources'] for c in contexts))
        finally: db.close(); temp.cleanup()

    def test_recon_coverage_reports_role_blind_spot_not_security_conclusion(self):
        temp, paths, db = self.project()
        try:
            result = recon_coverage(db, target='example.com', persist=True)
            self.assertGreater(result['overall'], 0)
            self.assertIn('Role comparison coverage is weak', result['blind_spots'])
            self.assertLess(result['components']['role'], 50)
        finally: db.close(); temp.cleanup()

    def test_attack_surface_graph_links_target_endpoint_candidate(self):
        temp, paths, db = self.project()
        try:
            graph = attack_surface_graph(db, target='example.com')
            kinds = {n['kind'] for n in graph['nodes']}
            self.assertTrue({'target','endpoint','candidate','context'}.issubset(kinds))
            self.assertTrue(any(e['relation']=='candidate' for e in graph['edges']))
            self.assertTrue(any(e['relation']=='observes' for e in graph['edges']))
        finally: db.close(); temp.cleanup()

    def test_target_memory_is_persistent_without_secrets(self):
        temp, paths, db = self.project()
        try:
            memory = target_memory(db, target='example.com', persist=True)
            self.assertEqual(memory['target'], 'example.com')
            self.assertGreater(memory['confidence'], 0)
            stored = db.one("SELECT memory_json FROM target_memory WHERE target='example.com'")['memory_json'].lower()
            self.assertNotIn('authorization:', stored); self.assertNotIn('cookie:', stored)
        finally: db.close(); temp.cleanup()

    def test_false_positive_learning_is_advisory_only(self):
        temp, paths, db = self.project()
        try:
            now=utc_now()
            for i in range(8):
                db.execute("INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f'NOISE-{i}',f'nfp-{i}','AN-1','RUN-NEW','example.com','','/noise','/noise','noisy_family','candidate','Noise','Noise',40,30,20,30,'weak','[]','[]','[]','ignore','[]','r','rejected','',now,now))
            result=false_positive_learning(db,target='example.com',persist=True)
            noisy=next(x for x in result if x['bug_family']=='noisy_family')
            self.assertEqual(noisy['recommendation'],'shadow_review')
            # Learning does not mutate rule governance state automatically.
            self.assertEqual(db.one("SELECT COUNT(*) c FROM analysis_rules")['c'],0)
        finally: db.close(); temp.cleanup()

    def test_smart_recon_plan_never_auto_enables_active_modules(self):
        temp, paths, db = self.project()
        try:
            plan=smart_recon_plan(db,target='example.com',persist=True)
            self.assertTrue(plan['requires_user_confirmation'])
            self.assertFalse(plan['active_modules_automatically_enabled'])
            self.assertTrue(plan['prioritize'])
            self.assertTrue(db.one("SELECT 1 FROM smart_recon_plans WHERE plan_id=?",(plan['plan_id'],)))
        finally: db.close(); temp.cleanup()

    def test_unconfirmed_report_is_blocked(self):
        temp, paths, db = self.project()
        try:
            report=build_evidence_linked_report(db,'CASE-BOLA',actor='test',persist=True)
            self.assertTrue(report['blocked']); self.assertFalse(report['confirmed'])
            self.assertIn('unconfirmed', report['body']['claims'][0]['claim'].lower())
        finally: db.close(); temp.cleanup()

    def test_confirmed_report_links_evidence_but_does_not_infer_impact(self):
        temp, paths, db = self.project()
        try:
            now=utc_now()
            db.execute("UPDATE security_cases SET state='confirmed' WHERE case_id='CASE-BOLA'")
            db.execute("INSERT INTO evidence_records(evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES('EV-1','AN-1','RUN-NEW','example.com','authorization_context','supporting','behavioral','fixture','secret/path','fixture','1','auth','root-ev-1',92,88,'direct','Authorized context shows the endpoint and object relationship.','RAW-SECRET-REFERENCE','hash',?,?,?)", (now,now,now))
            db.execute("INSERT INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES('C-BOLA','EV-1','supporting',90,'supports',?)", (now,))
            report=build_evidence_linked_report(db,'CASE-BOLA',actor='test',persist=True)
            self.assertFalse(report['blocked']); self.assertTrue(report['confirmed'])
            self.assertIn('not automatically inferred', report['body']['impact'])
            linked=next(x for x in report['body']['evidence_links'] if x.get('evidence_id')=='EV-1')
            self.assertIn('Authorized context', linked['summary'])
            serialized=json.dumps(report).lower()
            self.assertNotIn('raw-secret-reference',serialized); self.assertNotIn('secret/path',serialized)
        finally: db.close(); temp.cleanup()

    def test_error_event_recursively_redacts_secret_fields(self):
        temp, paths, db = self.project()
        try:
            eid=record_error_event(db,'RM-DASH-CSRF-002',details={'nested':{'Authorization':'Bearer secret','safe':'ok'},'csrf_token':'abc'})
            event=next(x for x in recent_error_events(db) if x['error_id']==eid)
            self.assertEqual(event['details']['nested']['Authorization'],'[redacted]')
            self.assertEqual(event['details']['csrf_token'],'[redacted]')
            self.assertEqual(event['details']['nested']['safe'],'ok')
        finally: db.close(); temp.cleanup()

    def test_safe_repair_defaults_to_preview(self):
        temp, paths, db = self.project()
        try:
            result=safe_repair(paths,db,dry_run=True,actor='test')
            self.assertTrue(result['dry_run'])
            self.assertEqual(result['destructive_scope'],'none outside stale state and expired sessions')
            self.assertTrue(db.one("SELECT 1 FROM recovery_actions WHERE action_id=?",(result['action_id'],)))
        finally: db.close(); temp.cleanup()

    def test_safety_center_keeps_automatic_live_disabled(self):
        temp, paths, db = self.project()
        try:
            result=safety_center(paths,Config(paths),db)
            self.assertTrue(result['scope_ready'])
            self.assertFalse(result['validation_policy']['automatic_live'])
            self.assertIn('broken_object_authorization',result['validation_policy']['manual_only_families'])
        finally: db.close(); temp.cleanup()

    def test_universal_search_finds_case_candidate_and_endpoint(self):
        temp, paths, db = self.project()
        try:
            self.assertTrue(universal_search(db,'CASE-BOLA')['Cases'])
            self.assertTrue(universal_search(db,'C-BOLA')['Candidates'])
            self.assertTrue(universal_search(db,'orders')['Endpoints'])
        finally: db.close(); temp.cleanup()

    def test_workspace_sync_refreshes_case_and_target_intelligence(self):
        temp, paths, db = self.project()
        try:
            result=workspace_v7_sync(paths,Config(paths),db,target='example.com',actor='test')
            self.assertEqual(result['version'],'8.4.4')
            self.assertIn('example.com',result['targets'])
            self.assertGreaterEqual(result['cases'],1)
            self.assertTrue(db.one("SELECT 1 FROM target_memory WHERE target='example.com'"))
            self.assertTrue(db.one("SELECT 1 FROM evidence_gap_snapshots WHERE case_id='CASE-BOLA'"))
        finally: db.close(); temp.cleanup()

    def test_operator_diagnostics_and_browser_compatibility(self):
        temp, paths, db = self.project()
        try:
            diag=operator_diagnostics(paths,Config(paths),db,persist=True)
            self.assertIn(diag['overall'],{'ok','warn','error'})
            self.assertTrue(any(c['id']=='DB-SCHEMA' and str(SCHEMA_VERSION) in c['detail'] for c in diag['checks']))
            safari=browser_compatibility('Mozilla/5.0 Version/26.0 Safari/605.1.15')
            self.assertEqual(safari['family'],'safari'); self.assertTrue(safari['supported'])
        finally: db.close(); temp.cleanup()

    def test_command_palette_and_workspace_nav_render(self):
        html=_layout('Test','<h1>Body</h1>',current_path='/')
        self.assertIn('commandPalette',html)
        self.assertIn('Evidence gaps',html)
        self.assertIn('Attack surface graph',html)
        self.assertIn('Safety Center',html)

    def test_dashboard_case_page_contains_evidence_gap_and_autopilot(self):
        temp, paths, db = self.project(); db.close()
        try:
            handler=object.__new__(DashboardHandler); handler.paths=paths; handler.config=Config(paths); handler.db_path=paths.db; handler.path='/case?id=CASE-BOLA'; handler.query=lambda:{'id':['CASE-BOLA']}
            captured={}; handler.send_html=lambda title,body,status=200:captured.update(title=title,body=body,status=status)
            handler.case_page()
            self.assertIn('Evidence gap',captured['body']); self.assertIn('Next best actions',captured['body']); self.assertIn('Investigation autopilot',captured['body'])
        finally: temp.cleanup()


if __name__ == '__main__':
    unittest.main()

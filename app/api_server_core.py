from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import shlex
import signal
import subprocess
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from core import APP_VERSION, AppPaths, Config, Database, Logger, ReconError, atomic_write_text, json_dumps, parse_bool, parse_int, safe_json_loads, utc_now
from worker_scope import WORKER_CAPABILITIES, task_scope_policy, worker_supports_scope
from bug_candidates import set_bug_candidate_decision
from candidate_intelligence import candidate_calibration, candidate_evaluation
from behavioral_intelligence import behavioral_summary
from security_reasoning import evidence_trace, family_calibration_report, reasoning_regression_gate, reasoning_summary, shadow_rule_report
from safe_validation import (
    approve_validation_plan, create_validation_plan, execute_validation_plan, record_validation_feedback,
    validation_detail, validation_eligibility,
)
from plugins import PluginManager
from product_platform import (
    build_report_draft, build_validation_package, case_detail, engine_quality, incremental_checkpoint,
    learn_target_profile, list_cases, list_stories, noise_budget_status, operations_center, platform_sync, rule_governance, run_completeness,
    scope_center, set_case_state, set_notification_policy, set_rule_state, set_schedule_policy, storage_health, target_learning_profiles,
)
from platform_v6 import (
    apply_retention, apply_target_template, build_burp_roundtrip_package, correlate_security_stories,
    data_quality_snapshot, deliver_notifications, due_revalidations, generate_schedule_job,
    import_burp_roundtrip_result, list_target_templates, performance_diagnostics, platform_v6_sync, process_due_revalidations,
    run_scheduled_workflow,
    queue_notification, rank_review_queue, report_quality, retention_preview, review_value_for_case,
    security_posture, set_revalidation_policy, set_retention_policy, validation_intelligence, verify_audit_chain,
)

ROLE_LEVEL={"viewer":10,"analyst":20,"lead_analyst":25,"admin":30}
API_ROLES={*ROLE_LEVEL,"worker"}
API_SCOPES={"read","write","validation","operations","admin","worker"}
ROLE_ALLOWED_SCOPES={
    "viewer":{"read"},
    "analyst":{"read","write","validation"},
    "lead_analyst":{"read","write","validation","operations"},
    "admin":set(API_SCOPES),
    "worker":{"worker"},
}
ROLE_DEFAULT_SCOPES={
    "viewer":["read"],
    "analyst":["read","write"],
    "lead_analyst":["read","write","validation","operations"],
    "admin":["read","write","validation","operations","admin","worker"],
    "worker":["worker"],
}
WORK_LEASE_SECONDS=120
OPERATIONS_POST_PATHS={
    "/api/v1/suite/revalidation",
    "/api/v1/suite/revalidation-process",
    "/api/v1/suite/scheduled-run",
    "/api/v1/suite/schedule-sync",
    "/api/v1/suite/notification-deliver",
    "/api/v1/suite/security-posture",
    "/api/v1/suite/retention-policy",
    "/api/v1/suite/retention-preview",
    "/api/v1/suite/retention-apply",
    "/api/v1/suite/template-apply",
}


def _role_allows(role: str, required: str) -> bool:
    if required=="worker":
        return role in {"worker","admin"}
    if role=="worker":
        return False
    return ROLE_LEVEL.get(role,0)>=ROLE_LEVEL.get(required,999)


def _request_scope(method: str, path: str) -> str:
    if path.startswith("/api/v1/work/") or path.startswith("/api/v1/workers/"):
        return "worker"
    if method=="POST" and path.startswith("/api/v1/validation/"):
        return "validation"
    if method=="POST" and path in OPERATIONS_POST_PATHS:
        return "operations"
    return "read" if method=="GET" else "write"


def _bearer_token_hash(header: str) -> str:
    if not header.startswith("Bearer "):
        return ""
    token=header[7:].strip()
    return hashlib.sha256(token.encode()).hexdigest() if token else ""


def create_token(db: Database, name: str, role: str, scopes: list[str] | None = None, expires_days: int = 90) -> str:
    if role not in API_ROLES: raise ReconError("Invalid API role")
    requested=[
        str(s).strip().lower()
        for s in (scopes if scopes is not None else ROLE_DEFAULT_SCOPES[role])
        if str(s).strip()
    ]
    if not requested:
        requested=list(ROLE_DEFAULT_SCOPES[role])
    if any(scope not in API_SCOPES for scope in requested):
        raise ReconError("Invalid API token scope")
    allowed_for_role=ROLE_ALLOWED_SCOPES[role]
    if any(scope not in allowed_for_role for scope in requested):
        raise ReconError("API token scope exceeds the selected role")
    requested=list(dict.fromkeys(requested))
    expires_days=max(1,min(3650,int(expires_days)))
    expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=expires_days)).replace(microsecond=0).isoformat().replace("+00:00","Z")
    token="rm6_"+secrets.token_urlsafe(36); digest=hashlib.sha256(token.encode()).hexdigest()
    db.execute("INSERT INTO api_tokens(name,token_hash,role,scopes_json,expires_at,created_at) VALUES(?,?,?,?,?,?)",(name,digest,role,json_dumps(requested),expires,utc_now()))
    db.audit("api_token_created",entity_type="api_token",entity_value=name,details={"role":role,"scopes":requested,"expires_at":expires})
    return token


def authenticate(db: Database, header: str) -> tuple[bool,str,str,set[str]]:
    if not header.startswith("Bearer "): return False,"","",set()
    token=header[7:].strip(); digest=hashlib.sha256(token.encode()).hexdigest()
    row=db.one("SELECT id,name,role,scopes_json,expires_at FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL",(digest,))
    if not row: return False,"","",set()
    if row["expires_at"] and str(row["expires_at"])<=utc_now(): return False,"","",set()
    scopes=set(map(str,safe_json_loads(row["scopes_json"],[],expected_type=list)))
    db.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?",(utc_now(),row["id"]))
    return True,str(row["name"]),str(row["role"]),scopes


class APIHandler(BaseHTTPRequestHandler):
    paths: AppPaths; logger: Logger
    def log_message(self, fmt: str, *args: Any) -> None: self.logger.info("API request",client=self.client_address[0],request=fmt%args)
    def db(self): return Database(self.paths.db)
    def send_json(self,value: Any,status:int=200):
        data=(json_dumps(value,pretty=True)+"\n").encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)
    def body(self):
        length=parse_int(self.headers.get("Content-Length"),0,0,2_000_000)
        try:return json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:return {}
    def auth(self,required="viewer",scope: str | None = None):
        header=self.headers.get("Authorization","")
        db=self.db()
        try: ok,name,role,scopes=authenticate(db,header)
        finally: db.close()
        path=urllib.parse.urlsplit(self.path).path
        required_scope=scope or _request_scope(self.command,path)
        scope_ok=required_scope in scopes or (role=="admin" and "admin" in scopes)
        role_ok=_role_allows(role,required)
        if not ok or not role_ok or not scope_ok:
            self.send_json({"error":"unauthorized"},401)
            return None
        self.auth_token_hash=_bearer_token_hash(header)
        return name,role
    def do_GET(self):
        auth=self.auth("viewer")
        if not auth:return
        path=urllib.parse.urlsplit(self.path).path; q=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query); db=self.db()
        try:
            if path=="/api/v1/status": self.send_json({"version":APP_VERSION,"time":utc_now()}); return
            if path=="/api/v1/targets": self.send_json([dict(r) for r in db.all("SELECT DISTINCT target FROM assets UNION SELECT DISTINCT target FROM run_targets ORDER BY target")]); return
            if path=="/api/v1/runs": self.send_json([dict(r) for r in db.all("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",(parse_int((q.get('limit')or[100])[0],100,1,1000),))]); return
            if path=="/api/v1/assets": self.send_json([dict(r) for r in db.all("SELECT a.*,l.state lifecycle_state FROM assets a LEFT JOIN asset_lifecycle l ON l.target=a.target AND l.host=a.host ORDER BY a.last_seen DESC LIMIT ?",(parse_int((q.get('limit')or[500])[0],500,1,5000),))]); return
            if path=="/api/v1/alerts": self.send_json([dict(r) for r in db.all("SELECT * FROM alerts ORDER BY risk_score DESC,last_seen DESC LIMIT ?",(parse_int((q.get('limit')or[500])[0],500,1,5000),))]); return
            if path=="/api/v1/incidents": self.send_json([dict(r) for r in db.all("SELECT * FROM change_incidents ORDER BY risk_score DESC,last_seen DESC LIMIT 500")]); return
            if path=="/api/v1/analysis/runs": self.send_json([dict(r) for r in db.all("SELECT * FROM analysis_runs ORDER BY started_at DESC LIMIT ?",(parse_int((q.get('limit')or[100])[0],100,1,1000),))]); return
            if path=="/api/v1/analysis/results":
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json([dict(r) for r in db.all("SELECT r.*,a.title,a.item,a.status,a.severity FROM analysis_results r JOIN alerts a ON a.id=r.alert_id WHERE r.analysis_id=? ORDER BY r.adjusted_score DESC,r.confidence DESC LIMIT ?",(analysis_id,parse_int((q.get('limit')or[500])[0],500,1,5000))) ] if analysis_id else []); return
            if path=="/api/v1/analysis/clusters":
                analysis_id=str((q.get('analysis_id')or[''])[0]);
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json([dict(r) for r in db.all("SELECT * FROM analysis_clusters WHERE analysis_id=? ORDER BY member_count DESC",(analysis_id,))] if analysis_id else []); return
            if path=="/api/v1/analysis/dataflows":
                analysis_id=str((q.get('analysis_id')or[''])[0]);
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json([dict(r) for r in db.all("SELECT * FROM js_dataflows WHERE analysis_id=? ORDER BY confidence DESC LIMIT ?",(analysis_id,parse_int((q.get('limit')or[500])[0],500,1,5000)))] if analysis_id else []); return
            if path=="/api/v1/analysis/candidates":
                analysis_id=str((q.get('analysis_id')or[''])[0]); target=str((q.get('target')or[''])[0]); family=str((q.get('family')or[''])[0]); state=str((q.get('state')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                where=["analysis_id=?"]; params=[analysis_id]
                if target: where.append("target=?"); params.append(target)
                if family: where.append("bug_family=?"); params.append(family)
                if state: where.append("candidate_state=?"); params.append(state)
                params.append(parse_int((q.get('limit')or[500])[0],500,1,5000))
                self.send_json([dict(r) for r in db.all(f"SELECT * FROM bug_candidates WHERE {' AND '.join(where)} ORDER BY investigation_value DESC,likelihood_score DESC LIMIT ?",tuple(params))] if analysis_id else []); return
            if path=="/api/v1/analysis/candidate":
                candidate_id=str((q.get('id')or[''])[0]); row=db.one("SELECT * FROM bug_candidates WHERE candidate_id=?",(candidate_id,)) if candidate_id else None
                self.send_json(dict(row) if row else {"error":"not found"},200 if row else 404); return
            if path=="/api/v1/analysis/security-reasoning":
                analysis_id=str((q.get('analysis_id')or[''])[0]) or None
                self.send_json(reasoning_summary(db,analysis_id)); return
            if path=="/api/v1/analysis/evidence-trace":
                candidate_id=str((q.get('candidate_id')or[''])[0])
                if not candidate_id: self.send_json({"error":"candidate_id required"},400); return
                self.send_json(evidence_trace(db,candidate_id)); return
            if path=="/api/v1/analysis/family-calibration":
                self.send_json(family_calibration_report(db,str((q.get('target')or[''])[0]) or None)); return
            if path=="/api/v1/analysis/shadow-rules":
                self.send_json(shadow_rule_report(db,str((q.get('analysis_id')or[''])[0]) or None)); return
            if path=="/api/v1/analysis/regression-gate":
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                if not analysis_id: self.send_json({"error":"no completed analysis"},404); return
                self.send_json(reasoning_regression_gate(db,analysis_id,persist=False)); return
            if path=="/api/v1/analysis/candidate-quality":
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json({"evaluation":candidate_evaluation(db,analysis_id) if analysis_id else {},"calibration":candidate_calibration(db,str((q.get('target')or[''])[0]) or None)}); return
            if path=="/api/v1/analysis/candidate-bundles":
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json([dict(r) for r in db.all("SELECT * FROM candidate_bundles WHERE analysis_id=? ORDER BY priority_score DESC",(analysis_id,))] if analysis_id else []); return
            if path=="/api/v1/analysis/semantic":
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                self.send_json({"semantic_js_units":[dict(r) for r in db.all("SELECT * FROM semantic_js_units WHERE analysis_id=? ORDER BY confidence DESC LIMIT 1000",(analysis_id,))],"feature_flags":[dict(r) for r in db.all("SELECT * FROM feature_flags WHERE analysis_id=? ORDER BY confidence DESC LIMIT 1000",(analysis_id,))],"endpoint_contracts":[dict(r) for r in db.all("SELECT * FROM endpoint_contracts WHERE analysis_id=? ORDER BY confidence DESC LIMIT 1000",(analysis_id,))],"response_shapes":[dict(r) for r in db.all("SELECT * FROM response_shape_fingerprints WHERE analysis_id=? ORDER BY confidence DESC LIMIT 1000",(analysis_id,))]} if analysis_id else {}); return
            if path in {"/api/v1/analysis/behavioral","/api/v1/analysis/boundary-diffs","/api/v1/analysis/response-diffs","/api/v1/analysis/protocols","/api/v1/analysis/identity-graph"}:
                analysis_id=str((q.get('analysis_id')or[''])[0])
                if not analysis_id:
                    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1"); analysis_id=str(latest['id']) if latest else ''
                summary=behavioral_summary(db,analysis_id) if analysis_id else {}
                if path.endswith('/boundary-diffs'): payload=summary.get('boundary_diffs',[])
                elif path.endswith('/response-diffs'): payload=summary.get('response_shape_diffs',[])
                elif path.endswith('/protocols'): payload=summary.get('protocol_findings',[])
                elif path.endswith('/identity-graph'): payload={'entities':summary.get('identity_entities',[]),'relations':summary.get('identity_relations',[])}
                else: payload=summary
                self.send_json(payload); return
            if path=="/api/v1/platform/quality":
                self.send_json(engine_quality(db, str((q.get('analysis_id')or[''])[0]) or None, str((q.get('target')or[''])[0]) or None)); return
            if path=="/api/v1/platform/cases":
                self.send_json(list_cases(db,state=str((q.get('state')or[''])[0]) or None,target=str((q.get('target')or[''])[0]) or None,limit=parse_int((q.get('limit')or[200])[0],200,1,2000))); return
            if path=="/api/v1/platform/case":
                case_id=str((q.get('id')or[''])[0]);
                if not case_id: self.send_json({"error":"id required"},400); return
                self.send_json(case_detail(db,case_id)); return
            if path=="/api/v1/platform/stories": self.send_json(list_stories(db,parse_int((q.get('limit')or[200])[0],200,1,1000))); return
            if path=="/api/v1/platform/scope": self.send_json(scope_center(self.paths,db)); return
            if path=="/api/v1/platform/operations": self.send_json(operations_center(self.paths,db)); return
            if path=="/api/v1/platform/storage": self.send_json(storage_health(self.paths,db)); return
            if path=="/api/v1/platform/rules": self.send_json(rule_governance(db)); return
            if path=="/api/v1/platform/completeness": self.send_json(run_completeness(db,str((q.get('run_id')or[''])[0]) or None,persist=False)); return
            if path=="/api/v1/platform/incremental": self.send_json(incremental_checkpoint(db,str((q.get('analysis_id')or[''])[0]) or None)); return
            if path=="/api/v1/platform/learning":
                target=str((q.get('target')or[''])[0]); self.send_json(learn_target_profile(db,target,str((q.get('analysis_id')or[''])[0]) or None,persist=True) if target else target_learning_profiles(db)); return
            if path=="/api/v1/platform/noise-budget": self.send_json(noise_budget_status(db,str((q.get('analysis_id')or[''])[0]) or None,profile=str((q.get('profile')or['balanced'])[0]),target=str((q.get('target')or[''])[0]) or None)); return
            if path=="/api/v1/platform/plugins": self.send_json(PluginManager(self.paths,db).health()); return
            if path=="/api/v1/platform/audit": self.send_json([dict(r) for r in db.all("SELECT * FROM audit_log ORDER BY created_at DESC,id DESC LIMIT ?",(parse_int((q.get('limit')or[200])[0],200,1,2000),))]); return
            if path=="/api/v1/validation/eligibility":
                case_id=str((q.get('case_id')or[''])[0]);
                if not case_id: self.send_json({"error":"case_id required"},400); return
                self.send_json(validation_eligibility(db,case_id)); return
            if path=="/api/v1/validation/plans":
                self.send_json(validation_detail(db,case_id=str((q.get('case_id')or[''])[0]),plan_id=str((q.get('plan_id')or[''])[0]),limit=parse_int((q.get('limit')or[100])[0],100,1,500))); return
            if path=="/api/v1/suite/review-queue": self.send_json(rank_review_queue(db,target=str((q.get('target')or[''])[0]) or None,limit=parse_int((q.get('limit')or[100])[0],100,1,1000),refresh=False)); return
            if path=="/api/v1/suite/data-quality": self.send_json(data_quality_snapshot(db,str((q.get('run_id')or[''])[0]) or None,str((q.get('target')or[''])[0]) or None,persist=False)); return
            if path=="/api/v1/suite/validation-intelligence":
                run_id=str((q.get('validation_run_id')or[''])[0]);
                if not run_id: self.send_json({"error":"validation_run_id required"},400); return
                self.send_json(validation_intelligence(db,run_id,persist=False)); return
            if path=="/api/v1/suite/revalidations": self.send_json(due_revalidations(db,limit=parse_int((q.get('limit')or[100])[0],100,1,1000))); return
            if path=="/api/v1/suite/performance": self.send_json(performance_diagnostics(self.paths,db,limit=parse_int((q.get('limit')or[50])[0],50,1,500))); return
            if path=="/api/v1/suite/security-posture": self.send_json(security_posture(self.paths,Config(self.paths),db,persist=False)); return
            if path=="/api/v1/suite/audit-integrity": self.send_json(verify_audit_chain(db)); return
            if path=="/api/v1/suite/templates": self.send_json(list_target_templates()); return
            if path=="/api/v1/suite/retention-preview": self.send_json(retention_preview(self.paths,db,persist=False)); return
            if path=="/api/v1/search":
                term=str((q.get('q')or[''])[0]); like=f"%{term}%"; out={
                    "assets":[dict(r) for r in db.all("SELECT * FROM assets WHERE host LIKE ? LIMIT 100",(like,))],
                    "urls":[dict(r) for r in db.all("SELECT * FROM urls WHERE url LIKE ? LIMIT 100",(like,))],
                    "alerts":[dict(r) for r in db.all("SELECT * FROM alerts WHERE title LIKE ? OR item LIKE ? LIMIT 100",(like,like))],
                    "bug_candidates":[dict(r) for r in db.all("SELECT * FROM bug_candidates WHERE title LIKE ? OR summary LIKE ? OR endpoint LIKE ? OR bug_family LIKE ? LIMIT 100",(like,like,like,like))],
                }; self.send_json(out); return
            if path=="/api/v1/views": self.send_json([dict(r) for r in db.all("SELECT * FROM saved_views ORDER BY owner,name")]); return
            if path=="/api/v1/workers": self.send_json([dict(r) for r in db.all("SELECT * FROM remote_workers ORDER BY last_heartbeat DESC")]); return
            self.send_json({"error":"not found"},404)
        finally: db.close()
    def do_POST(self):
        path=urllib.parse.urlsplit(self.path).path; required="worker" if path.startswith('/api/v1/work/') or path.startswith('/api/v1/workers/') else "analyst"
        auth=self.auth(required)
        if not auth:return
        actor,role=auth; data=self.body(); db=self.db()
        try:
            if path=="/api/v1/alerts/workflow":
                alert_id=parse_int(data.get('id'),0); db.update_alert_workflow(alert_id,priority=str(data.get('priority','normal')),assignee=str(data.get('assignee','')),note=str(data.get('note',''))); db.audit('api_alert_workflow',actor=actor,entity_type='alert',entity_value=str(alert_id)); self.send_json({"ok":True}); return
            if path=="/api/v1/analysis/candidates/decision":
                candidate_id=str(data.get('candidate_id') or ''); decision=str(data.get('decision') or ''); note=str(data.get('note') or ''); reason=str(data.get('reason') or '')
                self.send_json(set_bug_candidate_decision(db,candidate_id,decision,note,actor=actor,reason_code=reason)); return
            if path=="/api/v1/platform/sync": self.send_json(platform_sync(self.paths,db,str(data.get('analysis_id') or '') or None)); return
            if path=="/api/v1/platform/case/state":
                self.send_json(set_case_state(db,str(data.get('case_id') or ''),str(data.get('state') or ''),assigned_to=data.get('assigned_to'),note=str(data.get('note') or ''),actor=actor)); return
            if path=="/api/v1/platform/validation-package": self.send_json(build_validation_package(db,str(data.get('case_id') or ''),actor=actor)); return
            if path=="/api/v1/platform/report-draft": self.send_json(build_report_draft(db,str(data.get('case_id') or ''),actor=actor)); return
            if path=="/api/v1/platform/rule/state": self.send_json(set_rule_state(db,str(data.get('rule_id') or ''),str(data.get('rule_version') or ''),str(data.get('state') or ''),actor=actor,note=str(data.get('note') or ''))); return
            if path=="/api/v1/platform/schedule": self.send_json(set_schedule_policy(db,str(data.get('target') or ''),str(data.get('cadence') or ''),enabled=bool(data.get('enabled',True)),max_runtime_minutes=parse_int(data.get('max_runtime_minutes'),120),request_budget=parse_int(data.get('request_budget'),10000),quiet_hours=str(data.get('quiet_hours') or ''),actor=actor)); return
            if path=="/api/v1/platform/notification": self.send_json(set_notification_policy(db,str(data.get('target') or '*'),str(data.get('event_type') or ''),str(data.get('mode') or 'digest'),minimum_score=parse_int(data.get('minimum_score'),70),actor=actor)); return
            if path=="/api/v1/validation/plan": self.send_json(create_validation_plan(self.paths,db,str(data.get('case_id') or ''),requested_level=str(data.get('level') or ''),actor=actor)); return
            if path=="/api/v1/validation/approve": self.send_json(approve_validation_plan(db,str(data.get('plan_id') or ''),str(data.get('confirmation') or ''),actor=actor)); return
            if path=="/api/v1/validation/run":
                config=Config(self.paths); self.send_json(execute_validation_plan(self.paths,config,db,str(data.get('plan_id') or ''),allow_live=parse_bool(data.get('allow_live',False), False),actor=actor)); return
            if path=="/api/v1/validation/feedback": self.send_json(record_validation_feedback(db,str(data.get('run_id') or ''),str(data.get('decision') or ''),str(data.get('reason') or ''),str(data.get('note') or ''),actor=actor)); return
            if path=="/api/v1/suite/sync": self.send_json(platform_v6_sync(self.paths,db,run_id=str(data.get('run_id') or '') or None,analysis_id=str(data.get('analysis_id') or '') or None)); return
            if path=="/api/v1/suite/revalidation": self.send_json(set_revalidation_policy(db,str(data.get('case_id') or ''),str(data.get('trigger') or 'manual'),interval_days=parse_int(data.get('interval_days'),7),enabled=parse_bool(data.get('enabled',True),True),actor=actor)); return
            if path=="/api/v1/suite/revalidation-process": self.send_json(process_due_revalidations(self.paths,self.config,db,limit=parse_int(data.get('limit'),50),execute_offline=parse_bool(data.get('execute_offline',True),True),actor=actor)); return
            if path=="/api/v1/suite/scheduled-run": self.send_json(run_scheduled_workflow(self.paths,self.config,db,str(data.get('target') or ''),dry_run=parse_bool(data.get('dry_run',False),False),actor=actor)); return
            if path=="/api/v1/suite/review-value": self.send_json(review_value_for_case(db,str(data.get('case_id') or ''),persist=True)); return
            if path=="/api/v1/suite/burp-export": self.send_json(build_burp_roundtrip_package(self.paths,db,str(data.get('case_id') or ''),actor=actor)); return
            if path=="/api/v1/suite/burp-import": self.send_json(import_burp_roundtrip_result(db,str(data.get('package_id') or ''),data.get('result') if isinstance(data.get('result'),dict) else {},actor=actor)); return
            if path=="/api/v1/suite/story-correlate": self.send_json(correlate_security_stories(db,str(data.get('analysis_id') or '') or None,persist=True)); return
            if path=="/api/v1/suite/schedule-sync": self.send_json(generate_schedule_job(self.paths,db,str(data.get('target') or ''),apply=parse_bool(data.get('apply',False),False),actor=actor)); return
            if path=="/api/v1/suite/notification-queue": self.send_json(queue_notification(db,data.get('event') if isinstance(data.get('event'),dict) else {},target=str(data.get('target') or '*'),actor=actor)); return
            if path=="/api/v1/suite/notification-deliver": self.send_json(deliver_notifications(self.paths,Config(self.paths),db,mode=str(data.get('mode') or 'immediate'),limit=parse_int(data.get('limit'),50),dry_run=parse_bool(data.get('dry_run',False),False))); return
            if path=="/api/v1/suite/security-posture": self.send_json(security_posture(self.paths,Config(self.paths),db,persist=True,apply_safe_permissions=parse_bool(data.get('apply_permissions',False),False))); return
            if path=="/api/v1/suite/retention-policy": self.send_json(set_retention_policy(db,str(data.get('category') or ''),parse_int(data.get('days'),90),enabled=parse_bool(data.get('enabled',True),True),keep_count=parse_int(data.get('keep_count'),0),actor=actor)); return
            if path=="/api/v1/suite/retention-preview": self.send_json(retention_preview(self.paths,db,persist=True)); return
            if path=="/api/v1/suite/retention-apply": self.send_json(apply_retention(self.paths,db,str(data.get('preview_id') or ''),actor=actor,confirmation=str(data.get('confirmation') or ''))); return
            if path=="/api/v1/suite/template-apply": self.send_json(apply_target_template(self.paths,str(data.get('target') or ''),str(data.get('template_id') or ''),actor=actor,dry_run=not parse_bool(data.get('apply',False),False))); return
            if path=="/api/v1/suite/report-quality": self.send_json(report_quality(db,draft_id=str(data.get('draft_id') or '') or None,case_id=str(data.get('case_id') or '') or None,persist=True)); return
            if path=="/api/v1/views":
                now=utc_now(); db.execute("INSERT INTO saved_views(owner,name,view_type,query_json,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(owner,name) DO UPDATE SET view_type=excluded.view_type,query_json=excluded.query_json,updated_at=excluded.updated_at",(actor,str(data.get('name')),str(data.get('view_type','search')),json_dumps(data.get('query',{})),now,now)); self.send_json({"ok":True}); return
            if path=="/api/v1/workers/register":
                worker_id=str(data.get('worker_id') or secrets.token_hex(8))
                requested_capabilities=set(map(str,data.get('capabilities',[])))
                if not requested_capabilities or not requested_capabilities.issubset(WORKER_CAPABILITIES):
                    self.send_json({"error":"invalid worker capabilities"},400); return
                token_hash=str(getattr(self,"auth_token_hash",""))
                existing=db.one("SELECT auth_token_hash FROM remote_workers WHERE worker_id=?",(worker_id,))
                existing_hash=str(existing["auth_token_hash"] or "") if existing else ""
                if existing_hash and not secrets.compare_digest(existing_hash,token_hash):
                    self.send_json({"error":"worker id is bound to another token"},403); return
                now=utc_now()
                db.execute(
                    "INSERT INTO remote_workers(worker_id,name,capabilities_json,status,registered_at,last_heartbeat,metadata_json,auth_token_hash) "
                    "VALUES(?,?,?,'online',?,?,?,?) "
                    "ON CONFLICT(worker_id) DO UPDATE SET "
                    "name=excluded.name,capabilities_json=excluded.capabilities_json,status='online',"
                    "last_heartbeat=excluded.last_heartbeat,metadata_json=excluded.metadata_json,"
                    "auth_token_hash=CASE WHEN remote_workers.auth_token_hash='' "
                    "THEN excluded.auth_token_hash ELSE remote_workers.auth_token_hash END",
                    (
                        worker_id,
                        str(data.get('name',worker_id)),
                        json_dumps(sorted(requested_capabilities)),
                        now,
                        now,
                        json_dumps(data.get('metadata',{})),
                        token_hash,
                    ),
                )
                self.send_json({"worker_id":worker_id}); return
            if path=="/api/v1/workers/heartbeat":
                worker_id=str(data.get('worker_id'))
                row=db.one("SELECT auth_token_hash FROM remote_workers WHERE worker_id=?",(worker_id,))
                if not row or not secrets.compare_digest(str(row["auth_token_hash"] or ""),str(getattr(self,"auth_token_hash",""))):
                    self.send_json({"error":"worker identity mismatch"},403); return
                db.execute("UPDATE remote_workers SET status='online',last_heartbeat=? WHERE worker_id=?",(utc_now(),worker_id))
                self.send_json({"ok":True}); return
            if path=="/api/v1/work/claim":
                worker_id=str(data.get('worker_id'))
                worker=db.one("SELECT capabilities_json,metadata_json,auth_token_hash FROM remote_workers WHERE worker_id=?",(worker_id,))
                if not worker or not secrets.compare_digest(str(worker["auth_token_hash"] or ""),str(getattr(self,"auth_token_hash",""))):
                    self.send_json({"error":"worker identity mismatch"},403); return
                capabilities=set(map(str,safe_json_loads(worker["capabilities_json"],[],expected_type=list)))
                if not worker_supports_scope(safe_json_loads(worker["metadata_json"],{},expected_type=dict)):
                    self.send_json({"work":None}); return
                lease_token=""
                chosen_payload=None
                with db.transaction():
                    db.reclaim_expired_work_leases()
                    after_id=0
                    while chosen_payload is None:
                        rows=db.all("SELECT * FROM work_items WHERE status IN ('queued','retry_pending') AND id>? ORDER BY id LIMIT 50",(after_id,))
                        if not rows:
                            break
                        after_id=int(rows[-1]['id'])
                        for row in rows:
                            payload=safe_json_loads(row['payload_json'], {}, expected_type=dict); kind=str(payload.get('kind',''))
                            if kind not in WORKER_CAPABILITIES or kind not in capabilities:
                                continue
                            try:
                                scope_policy=task_scope_policy(payload)
                            except ReconError:
                                continue
                            if scope_policy.target != row['target'] or not scope_policy.url_in_scope(str(payload.get('url',''))):
                                continue
                            candidate_lease=secrets.token_urlsafe(32)
                            lease_hash=hashlib.sha256(candidate_lease.encode()).hexdigest()
                            lease_expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=WORK_LEASE_SECONDS)).replace(microsecond=0).isoformat().replace("+00:00","Z")
                            if db.work_start(
                                int(row['id']),
                                worker_id,
                                lease_token_hash=lease_hash,
                                lease_expires_at=lease_expires,
                            ):
                                chosen_payload=dict(row)
                                lease_token=candidate_lease
                                break
                if chosen_payload is None:
                    self.send_json({"work":None}); return
                chosen_payload["lease_token"]=lease_token
                self.send_json(chosen_payload); return
            if path=="/api/v1/work/result":
                work_id=parse_int(data.get('id'),0)
                worker_id=str(data.get('worker_id') or '')
                lease_token=str(data.get('lease_token') or '')
                worker=db.one("SELECT auth_token_hash FROM remote_workers WHERE worker_id=?",(worker_id,))
                if not worker or not secrets.compare_digest(str(worker["auth_token_hash"] or ""),str(getattr(self,"auth_token_hash",""))):
                    self.send_json({"error":"worker identity mismatch"},403); return
                if not lease_token:
                    self.send_json({"error":"lease token required"},400); return
                lease_hash=hashlib.sha256(lease_token.encode()).hexdigest()
                if data.get('ok',False):
                    accepted=db.work_finish(
                        work_id,
                        data.get('result',{}),
                        worker_id=worker_id,
                        lease_token_hash=lease_hash,
                    )
                else:
                    accepted=db.work_fail(
                        work_id,
                        str(data.get('error','worker failure')),
                        retry=bool(data.get('retry',True)),
                        worker_id=worker_id,
                        lease_token_hash=lease_hash,
                    )
                if not accepted:
                    self.send_json({"error":"work lease is invalid, expired, or not owned by this worker"},409); return
                self.send_json({"ok":True}); return
            self.send_json({"error":"not found"},404)
        finally: db.close()


def serve_api(paths: AppPaths, logger: Logger, host: str, port: int, allow_remote: bool=False):
    if host not in {'127.0.0.1','localhost','::1'} and not allow_remote: raise ReconError("Remote API bind requires --allow-remote")
    handler=type('BoundAPIHandler',(APIHandler,),{'paths':paths,'logger':logger})
    server=ThreadingHTTPServer((host,port),handler); logger.info("API started",host=host,port=port)
    try: server.serve_forever(poll_interval=.5)
    finally: server.server_close(); logger.info("API stopped")


def api_paths(paths: AppPaths): return paths.state/'api.pid',paths.logs/'api.log'


def _read_api_record(paths: AppPaths) -> tuple[int, str]:
    """Read the API PID record, accepting legacy plain-integer files."""
    pid_path, _ = api_paths(paths)
    try:
        raw = pid_path.read_text(encoding="utf-8").strip()
    except OSError:
        return 0, ""
    if not raw:
        return 0, ""
    try:
        record = json.loads(raw)
    except (TypeError, ValueError):
        try:
            return int(raw), ""
        except ValueError:
            return 0, ""
    if isinstance(record, int):
        return record, ""
    if not isinstance(record, dict):
        return 0, ""
    try:
        pid = int(record.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    return pid, str(record.get("start_token") or "")


def _process_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _process_start_token(pid: int) -> str:
    """Return a boot-relative process-start token where the OS exposes one."""
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        raw = proc_stat.read_text(encoding="utf-8")
        # The executable name is enclosed in parentheses and can itself contain
        # spaces/parentheses. The fields after the final ')' start at field 3;
        # Linux field 22 (starttime) is therefore offset 19.
        fields = raw.rsplit(")", 1)[1].split()
        return fields[19] if len(fields) > 19 else ""
    except (OSError, IndexError):
        return ""


def _api_process_info(paths: AppPaths, pid: int, expected_start_token: str = "") -> dict[str, Any] | None:
    """Validate both the executable command and the process instance.

    A PID file is only a locator. The command must be this checkout's
    ``api foreground`` process, and a token written by newer starts must still
    match the current process instance. This prevents a stale/reused PID from
    being reported as Recon Monitor or signalled by ``api stop``.
    """
    if not _process_alive(pid):
        return None
    current_start_token = _process_start_token(pid)
    if expected_start_token and (
        not current_start_token or current_start_token != expected_start_token
    ):
        return None
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    command = str(result.stdout or "").strip()
    if not command:
        return None
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    expected_script = str((paths.app / "recon_monitor.py").resolve())
    indexes = [index for index, value in enumerate(parts) if value == expected_script]
    if not indexes:
        return None
    tail = parts[indexes[-1] + 1:]
    if len(tail) < 2 or tail[:2] != ["api", "foreground"]:
        return None

    def option(name: str, default: str) -> str:
        try:
            index = tail.index(name)
            return tail[index + 1]
        except (ValueError, IndexError):
            return default

    try:
        port = int(option("--port", "8790"))
    except ValueError:
        port = 8787
    return {
        "pid": pid,
        "host": option("--host", "127.0.0.1"),
        "port": port,
        "allow_remote": "--allow-remote" in tail,
        "command": command,
        "start_token": current_start_token,
    }


def _remove_api_record(paths: AppPaths) -> None:
    api_paths(paths)[0].unlink(missing_ok=True)


def api_status(paths: AppPaths):
    pid, start_token = _read_api_record(paths)
    info = _api_process_info(paths, pid, start_token)
    if info is None:
        _remove_api_record(paths)
        return False, 'API is not running'
    return True, f"API running (PID {pid}) at http://{info['host']}:{info['port']}"


def start_api(paths: AppPaths,host:str,port:int,allow_remote:bool=False):
    active,detail=api_status(paths)
    if active:raise ReconError(detail)
    pid_path,log_path=api_paths(paths); log=open(log_path,'ab'); cmd=[sys.executable,str(paths.app/'recon_monitor.py'),'api','foreground','--host',host,'--port',str(port)]+(['--allow-remote'] if allow_remote else [])
    try:
        proc=subprocess.Popen(cmd,cwd=paths.root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    finally:
        log.close()
    # Store the process instance token alongside the PID. Legacy integer PID
    # files remain readable, but all newly started API processes are bound to
    # the exact instance observed at startup.
    atomic_write_text(
        pid_path,
        json_dumps({"pid": proc.pid, "start_token": _process_start_token(proc.pid)}) + "\n",
    )
    time.sleep(.5)
    return proc.pid


def _signal_api_process(
    paths: AppPaths | None,
    pid: int,
    sig: int,
    expected_start_token: str = "",
) -> bool:
    """Signal a specific process instance when Linux pidfds are available."""
    if expected_start_token and _process_start_token(pid) != expected_start_token:
        return False
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if callable(pidfd_open) and callable(pidfd_send_signal):
        try:
            pidfd = pidfd_open(pid)
        except OSError:
            pidfd = None
        if pidfd is not None:
            try:
                if expected_start_token and _process_start_token(pid) != expected_start_token:
                    return False
                if paths is not None and _api_process_info(paths, pid, expected_start_token) is None:
                    return False
                pidfd_send_signal(pidfd, sig)
                return True
            finally:
                os.close(pidfd)
    if paths is not None and _api_process_info(paths, pid, expected_start_token) is None:
        return False
    os.kill(pid, sig)
    return True


def stop_api(paths: AppPaths):
    pid_path,_=api_paths(paths)
    pid, start_token = _read_api_record(paths)
    info = _api_process_info(paths, pid, start_token)
    if info is None:
        _remove_api_record(paths)
        return False
    try:
        signaled = _signal_api_process(
            paths,
            pid,
            signal.SIGTERM,
            str(info.get("start_token") or start_token),
        )
    except ProcessLookupError:
        _remove_api_record(paths)
        return False
    if not signaled:
        _remove_api_record(paths)
        return False
    for _ in range(30):
        if not _process_alive(pid):
            break
        time.sleep(.1)
    if _process_alive(pid):
        try:
            _signal_api_process(
                paths,
                pid,
                signal.SIGKILL,
                str(info.get("start_token") or start_token),
            )
        except ProcessLookupError:
            pass
    pid_path.unlink(missing_ok=True)
    return True

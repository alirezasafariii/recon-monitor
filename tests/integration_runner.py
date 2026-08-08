#!/usr/bin/env python3
from __future__ import annotations
import contextlib,json,sys,tempfile,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from core import AppPaths,Config,Database,TargetPolicy
from execution import BudgetManager
from stages import StageContext,stage_endpoint_validation

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_HEAD(self):
        if self.path.startswith('/api/admin'):
            self.send_response(401);self.send_header('Content-Type','application/json');self.end_headers()
        else:self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
class Stub:
    def info(self,*a,**k):pass
    warn=error=info
    def update(self,*a,**k):pass
class Runner:pass

def main():
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();port=server.server_address[1]
    try:
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=AppPaths.from_root(root);paths.ensure();paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
            db=Database(paths.db);policy=TargetPolicy.from_dict({'name':'fixture','roots':['example.com'],'include':[r'^127\.0\.0\.1$'],'modules':{'subdomains':False,'dns':False,'urls':False,'javascript':False,'endpoint_validation':True,'fingerprint':False},'limits':{'max_http_requests':100,'max_dns_queries':100,'max_download_mb':10,'max_new_assets':100}})
            run='integration';run_dir=paths.output/'fixture'/'runs'/run;run_dir.mkdir(parents=True);db.create_run_target(run,policy,run_dir,False) if False else None
            endpoint=f'http://127.0.0.1:{port}/api/admin/export';classification={'primary_category':'admin','confidence':90,'categories':['admin'],'reasons':['fixture']};db.upsert_endpoint_intelligence('fixture',endpoint,'absolute_url',classification,'fixture.js',run)
            budget=BudgetManager.create(db,run,'fixture',policy);ctx=StageContext(paths,Config(paths),policy,db,Stub(),Runner(),Stub(),run,run_dir,False,budget)
            metrics=stage_endpoint_validation(ctx);row=db.one('SELECT status_code,reachable FROM endpoint_validations WHERE target=?',('fixture',))
            assert metrics['reachable']==1 and int(row['status_code'])==401 and int(row['reachable'])==1
            db.close();print(json.dumps({'ok':True,'endpoint_validation':metrics,'status_code':401},indent=2));return 0
    finally:server.shutdown();server.server_close()
if __name__=='__main__':raise SystemExit(main())

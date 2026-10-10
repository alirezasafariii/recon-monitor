import argparse,json,subprocess,tempfile,threading,time
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import os,sys
from types import SimpleNamespace
from unittest.mock import MagicMock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from core import CommandRunner,TargetPolicy
from stages import stage_urls
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--output',required=True);a=p.parse_args()
hits=[];lock=threading.Lock()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  with lock:hits.append(self.path)
  body=(''.join(f'<a href="/page/{i}">page {i}</a>' for i in range(100)) if self.path=='/' else 'terminal '+self.path).encode()
  self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
report={'scenario':'stage_durable_frontier_across_short_resumes','attempts':[]}
try:
 with tempfile.TemporaryDirectory() as td:
  folder=Path(td);origin=f'http://127.0.0.1:{server.server_port}/'
  bindir=folder/'bin';bindir.mkdir();(bindir/'katana').symlink_to(Path(a.binary).resolve())
  current=folder/'current';current.mkdir();changes=folder/'changes';changes.mkdir()
  (current/'resolved-hosts.txt').write_text('127.0.0.1\n')
  policy=TargetPolicy.from_dict({'name':'127.0.0.1','roots':['127.0.0.1'],'include':[r'^127\.0\.0\.1$'],'analysis':{'asset_graph':False},'limits':{'timeout_seconds':30,'request_rate':3,'max_urls':1000}})
  db=MagicMock();db.upsert_url.return_value=False;runner=CommandRunner(MagicMock())
  ctx=SimpleNamespace(current=current,changes=changes,policy=policy,db=db,runner=runner,budget=None,run_id='frontier',logger=MagicMock(),progress=MagicMock())
  env={'PATH':str(bindir)+os.pathsep+os.environ.get('PATH',''),'NO_PROXY':'127.0.0.1','no_proxy':'127.0.0.1'}
  try:
   with patch.dict(os.environ,env),patch('stages.tool_path',side_effect=lambda t:a.binary if t=='katana' else None),patch('stages._probe_live_origins',return_value=([origin.rstrip('/')],[])):
    for n in range(8):
     started=time.monotonic();metrics=stage_urls(ctx);outcome=metrics['katana_batch_outcomes'][-1]
     documents=[json.loads(x.read_text()) for x in (current/'katana-frontier').glob('*.json')]
     events=list(outcome['origin_completion'].values())
     row={'attempt':n+1,'exit_code':outcome['exit_code'],'duration':round(time.monotonic()-started,3),'completion':events,'checkpoint_done':sum(i['done'] for d in documents for i in d['items']),'checkpoint_pending':sum(not i['done'] for d in documents for i in d['items']),'collection_status':metrics['collection_status'],'reserved_requests':metrics['katana_reserved_requests'],'request_envelope':metrics['katana_request_envelope']}
     report['attempts'].append(row);print(json.dumps(row),flush=True)
     assert outcome['frontier_checkpoint_enabled'] and row['exit_code']==0,row
     assert row['reserved_requests']<=row['request_envelope'],row
     if events[0]['stop_reason']=='queue_exhausted':
      assert not (current/'katana-pending-origins.txt').read_text().strip()
      break
     assert (current/'katana-pending-origins.txt').read_text().strip()==origin.rstrip('/')
  finally:runner.terminate_active()
  assert report['attempts'][-1]['completion'][0]['stop_reason']=='queue_exhausted',report
  assert hits.count('/')==1,hits
  assert all(f'/page/{i}' in hits for i in range(100)),hits
  assert len(report['attempts'])>1,report
  report['requested_paths']=hits;report['root_requests']=hits.count('/');report['passed']=True
finally:
 server.shutdown();server.server_close();thread.join()
Path(a.output).write_text(json.dumps(report,indent=2));print(json.dumps({'passed':True,'output':a.output}))

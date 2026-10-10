import argparse,json,subprocess,tempfile,threading,time,os
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from collections import Counter
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--output',required=True);a=p.parse_args()
hits=[];lock=threading.Lock()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  with lock:hits.append(self.path)
  body=(''.join(f'<a href="/page/{i}">page {i}</a>' for i in range(15)) if self.path=='/' else 'terminal '+self.path).encode()
  self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
report={'scenario':'durable_frontier_across_short_attempts','attempts':[]}
try:
 with tempfile.TemporaryDirectory() as td:
  folder=Path(td);origin=f'http://127.0.0.1:{server.server_port}/'
  for n in range(8):
   log=folder/f'completion-{n}.jsonl';started=time.monotonic()
   r=subprocess.run([a.binary,'-u',origin,'-silent','-duc','-d','2','-ct','2s','-timeout','5','-retry','0','-c','1','-p','1','-rl','3','-cs',r'^http://127\.0\.0\.1:','-recon-checkpoint-dir',str(folder/'frontier'),'-recon-completion-log',str(log)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=12,env=dict(os.environ,NO_PROXY='127.0.0.1',no_proxy='127.0.0.1'))
   events=[json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
   documents=[json.loads(x.read_text()) for x in (folder/'frontier').glob('*.json')]
   row={'attempt':n+1,'exit_code':r.returncode,'duration':round(time.monotonic()-started,3),'completion':events,'stderr':r.stderr,'checkpoint_done':sum(i['done'] for d in documents for i in d['items']),'checkpoint_pending':sum(not i['done'] for d in documents for i in d['items'])}
   report['attempts'].append(row);print(json.dumps(row),flush=True)
   assert r.returncode==0,row
   assert len(events)==1,row
   if events[0]['stop_reason']=='queue_exhausted':break
  assert report['attempts'][-1]['completion'][0]['stop_reason']=='queue_exhausted',report
  assert hits.count('/')==1,hits
  assert all(f'/page/{i}' in hits for i in range(15)),hits
  assert len(report['attempts'])>1,report
  report['requested_paths']=hits;report['root_requests']=hits.count('/');report['passed']=True
finally:
 server.shutdown();server.server_close();thread.join()
Path(a.output).write_text(json.dumps(report,indent=2));print(json.dumps({'passed':True,'output':a.output}))

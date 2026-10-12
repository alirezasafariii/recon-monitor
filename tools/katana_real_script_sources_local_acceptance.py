"""Replay hash-verified user sources on localhost, without public network access."""
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--sources', required=True)
p.add_argument('--output', required=True)
a=p.parse_args()
root=Path(a.sources)
expected={
 'polyfills-91891880ac99.js':'91891880ac99e7d27c27d760f1433b9577be70d78b34ec0ec2282b31e2810e64',
 'polyfills-92564ba55628.js':'92564ba55628ae71c3c8325f65d2163d5b27b7e3b9b77fde712d4811e1d85094',
 'edge-source.html':'df781458e001454bd940ace4562fbc87c95585040c70278b272172a57923facf',
}
bodies={}
for name, sha in expected.items():
 data=(root/name).read_bytes()
 if hashlib.sha256(data).hexdigest()!=sha: raise SystemExit('SHA mismatch: '+name)
 bodies['/'+name]=data
class Scripts(HTMLParser):
 def __init__(self): super().__init__();self.current=None;self.scripts=[]
 def handle_starttag(self, tag, attrs):
  if tag=='script' and not dict(attrs).get('src'):self.current=[]
 def handle_data(self,data):
  if self.current is not None:self.current.append(data)
 def handle_endtag(self,tag):
  if tag=='script' and self.current is not None:
   self.scripts.append(''.join(self.current));self.current=None
parser=Scripts();parser.feed(bodies['/edge-source.html'].decode())
pendo=[s for s in parser.scripts if 'cdn.pendo.io' in s]
assert len(pendo)==1, 'Expected one saved Pendo loader'
page='<base href="/">'+''.join('<script src="/'+n+'"></script>' for n in expected if n.endswith('.js'))
page+='<script>'+pendo[0]+'</script><script src="/real.js"></script>'
hits=[]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  hits.append(self.path)
  body=page.encode() if self.path=='/Edge/' else bodies.get(self.path,b'console.log(1);')
  self.send_response(200)
  self.send_header('Content-Type','text/html' if self.path=='/Edge/' else 'application/javascript')
  self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
 with tempfile.TemporaryDirectory() as tmp:
  log=Path(tmp)/'completion.jsonl'
  result=subprocess.run([str(Path(a.binary).resolve()),'-u',f'http://127.0.0.1:{server.server_port}/Edge/',
   '-silent','-duc','-jc','-d','2','-ct','15s','-timeout','5','-retry','0','-c','1','-p','1','-rl','10',
   '-cs',r'^http://127\.0\.0\.1:', '-recon-completion-log',str(log)],
   stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=25,
   env=dict(os.environ,NO_PROXY='127.0.0.1',no_proxy='127.0.0.1'))
  assert result.returncode==0,result.stderr
  bad={ '/Zone.js','/zone.js','/pendo.js' } & set(hits)
  assert not bad,hits
  assert {'/Edge/','/real.js','/polyfills-91891880ac99.js','/polyfills-92564ba55628.js'}<=set(hits),hits
  completion=[json.loads(l) for l in log.read_text().splitlines()]
  assert len(completion)==1 and completion[0]['stop_reason']=='queue_exhausted',completion
  assert completion[0]['failed_requests']==0 and completion[0]['pending_items']==0,completion
  report={'passed':True,'scenario':'real_import_meta_sources','source_hashes':expected,'requested_paths':hits,'completion':completion}
  Path(a.output).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
finally:
 server.shutdown();server.server_close();thread.join()

import threading,tempfile,subprocess,json,argparse
parser=argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
args=parser.parse_args()
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
hits=[]
class H(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  hits.append(self.path)
  body=(b'<a href="/a/">a</a><a href="/b/">b</a>' if self.path=='/' else b'<a href="proof">proof</a>' if self.path in ['/a/','/b/'] else b'<html>proof</html>')
  self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(body)
s=ThreadingHTTPServer(('127.0.0.1',0),H);t=threading.Thread(target=s.serve_forever,daemon=True);t.start()
try:
 with tempfile.TemporaryDirectory() as d:
  p=Path(d)/'completion.jsonl'
  r=subprocess.run([args.binary,'-u',f'http://127.0.0.1:{s.server_port}/','-silent','-duc','-ct','8s','-d','3','-c','1','-p','1','-rl','3','-recon-completion-log',str(p)],capture_output=True,text=True,timeout=15)
  report=json.loads(p.read_text());diag=json.loads(Path(str(p)+'.diagnostics.jsonl').read_text())
  assert r.returncode==0,(r.returncode,r.stderr)
  assert {'/a/proof','/b/proof'}.issubset(hits),hits
  assert report['stop_reason']=='queue_exhausted',report
  assert not any(diag['unparsed_reasons'].values()),diag
  print(json.dumps({'scenario':'same_body_distinct_relative_bases','requested_paths':hits,'completion':report,'diagnostics':diag,'exit_code':r.returncode},indent=2))
finally:s.shutdown();s.server_close();t.join()

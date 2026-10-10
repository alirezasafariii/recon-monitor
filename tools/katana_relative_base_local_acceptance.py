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
  r=subprocess.run([args.binary,'-u',f'http://127.0.0.1:{s.server_port}/','-silent','-duc','-ct','8s','-d','3','-c','1','-p','1','-rl','3','-recon-completion-log',str(p)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
  raw=p.read_text(); diag_raw=Path(str(p)+'.diagnostics.jsonl').read_text()
  rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
  diag_rows=[json.loads(line) for line in diag_raw.splitlines() if line.strip()]
  print(json.dumps({'completion_raw':raw,'diagnostics_raw':diag_raw,'stderr':r.stderr}))
  assert len(rows)==1 and len(diag_rows)==1, 'Unexpected input/completion rows'
  report=rows[0];diag=diag_rows[0]
  assert r.returncode==0,(r.returncode,r.stderr)
  assert {'/a/proof','/b/proof'}.issubset(hits),hits
  assert report['stop_reason']=='queue_exhausted',report
  assert not any(diag['unparsed_reasons'].values()),diag
  print(json.dumps({'scenario':'same_body_distinct_relative_bases','requested_paths':hits,'completion':report,'diagnostics':diag,'exit_code':r.returncode},indent=2))
finally:s.shutdown();s.server_close();t.join()


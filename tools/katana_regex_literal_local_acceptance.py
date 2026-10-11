"""Verify HTML base href resolves scripts from the document base."""
import argparse
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
hits = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        hits.append(self.path)
        if self.path == '/Edge/':
            body = b'<script src="/bundle.js"></script>'
        elif self.path == '/bundle.js':
            body = b'var a=/./.exec.apply(this,arguments),b=/./.test; node.src="/real.js";'
        else:
            body = b'console.log(1);'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if self.path in ('/', '/Edge/') else 'application/javascript')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
s = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
t = threading.Thread(target=s.serve_forever, daemon=True)
t.start()
try:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / 'completion.jsonl'
        result = subprocess.run([
            str(Path(a.binary).resolve()), '-u', f'http://127.0.0.1:{s.server_port}/Edge/',
            '-silent', '-duc', '-jc', '-d', '2', '-ct', '8s', '-timeout', '5',
            '-retry', '0', '-c', '1', '-p', '1', '-rl', '3', '-cs', r'^http://127\.0\.0\.1:',
            '-recon-completion-log', str(log),
        ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
           env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
        assert result.returncode == 0, result.stderr
        assert set(hits) == {'/Edge/', '/bundle.js', '/real.js'}, hits
        completion = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(completion) == 1 and completion[0]['stop_reason'] == 'queue_exhausted', completion
        report = {'passed': True, 'scenario': 'regex_literal_isolation', 'requested_paths': hits, 'completion': completion}
        Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    s.shutdown()
    s.server_close()
    t.join()

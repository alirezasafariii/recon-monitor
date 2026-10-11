"""Verify inline script metadata cannot become HTML-regex crawl requests."""
import argparse
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
hits = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        hits.append(self.path)
        if self.path == '/metadata/':
            body = (b'<script>var y={agent:"js-agent.newrelic.com/nr-spa-1208.min.js"};'
                    b'r.src="https://"+t.agent;</script><a href="/real/">real</a>')
        elif self.path == '/real/':
            body = (b'<script>j.src="./js-agent.newrelic.com/real.min.js";'
                    b'k.src="main.220215ce8a8bcc63.js";</script>')
        else:
            body = b'console.log(1);'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if self.path in ('/metadata/', '/real/') else 'application/javascript')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as temp:
        completion = Path(temp) / 'completion.jsonl'
        origin = f'http://127.0.0.1:{server.server_port}'
        source = origin + '/metadata/'
        result = subprocess.run([
            str(Path(args.binary).resolve()), '-u', source, '-silent', '-duc', '-jc',
            '-d', '2', '-ct', '6s', '-timeout', '5', '-retry', '0',
            '-c', '1', '-p', '1', '-rl', '3', '-cs', r'^http://127\.0\.0\.1:',
            '-recon-completion-log', str(completion),
        ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12,
           env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
        assert result.returncode == 0, result.stderr
        rows = [json.loads(line) for line in Path(str(completion)+'.provenance.jsonl').read_text().splitlines()]
        assert not any('nr-spa-1208.min.js' in r['url'] for r in rows), rows
        assert set(hits) == {'/metadata/', '/real/', '/real/js-agent.newrelic.com/real.min.js', '/real/main.220215ce8a8bcc63.js'}, hits
        report = {'passed': True, 'scenario': 'inline_script_body_isolation', 'records': rows, 'requested_paths': hits}
        Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    server.shutdown()
    server.server_close()
    thread.join()

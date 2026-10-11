"""Verify event metadata is excluded while real script references survive."""
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
            body = (b"<script>w[l].push({'gtm.start':Date.now(),event:'gtm.js'});"
                    b"j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;</script>"
                    b'<a href="/real/">real</a>')
        elif self.path == '/real/':
            body = b"<script>j.src='gtm.js';</script>"
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
        assert not any(r['url'] == origin+'/metadata/gtm.js' for r in rows), rows
        assert any(r['raw_reference'] == 'gtm.js' and r['source'] == origin+'/real/' and r['url'] == origin+'/real/gtm.js' for r in rows), rows
        assert any(r['url'].startswith('https://www.googletagmanager.com/gtm.js') for r in rows), rows
        assert set(hits) == {'/metadata/', '/real/', '/real/gtm.js'}, hits
        report = {'passed': True, 'scenario': 'gtm_event_metadata', 'records': rows, 'requested_paths': hits}
        Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    server.shutdown()
    server.server_close()
    thread.join()

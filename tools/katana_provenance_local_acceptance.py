"""Verify parser provenance without external requests."""
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
        body = (b'<script src="child.js"></script><script src="/root.js"></script>'
                b'<script src="//outside.invalid/cdn.js"></script>') if self.path == '/a/' else b'console.log(1);'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if self.path == '/a/' else 'application/javascript')
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
        source = origin + '/a/'
        result = subprocess.run([
            str(Path(args.binary).resolve()), '-u', source, '-silent', '-duc',
            '-d', '2', '-ct', '6s', '-timeout', '5', '-retry', '0',
            '-c', '1', '-p', '1', '-rl', '3', '-cs', r'^http://127\.0\.0\.1:',
            '-recon-completion-log', str(completion),
        ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12,
           env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
        assert result.returncode == 0, result.stderr
        rows = [json.loads(line) for line in Path(str(completion)+'.provenance.jsonl').read_text().splitlines()]
        for raw, expected in [('child.js', origin+'/a/child.js'), ('/root.js', origin+'/root.js'), ('//outside.invalid/cdn.js', 'http://outside.invalid/cdn.js')]:
            assert any(r['raw_reference'] == raw and r['source'] == source and r['url'] == expected for r in rows), (raw, rows)
        assert set(hits) == {'/a/', '/a/child.js', '/root.js'}, hits
        report = {'passed': True, 'scenario': 'discovery_provenance', 'records': rows, 'requested_paths': hits}
        Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    server.shutdown()
    server.server_close()
    thread.join()

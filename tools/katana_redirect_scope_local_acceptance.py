"""Ensure standard crawling never follows a redirect beyond crawl scope."""
import argparse
import json
import os
import re
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
outside_hits = []
class Outside(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        outside_hits.append(self.path)
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

outside = ThreadingHTTPServer(('127.0.0.1', 0), Outside)
class Inside(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        hits.append(self.path)
        body = b'<a href="/same">same</a><a href="/external">external</a>' if self.path == '/' else b'<html></html>'
        if self.path in ('/same', '/external'):
            self.send_response(302)
            self.send_header('Location', '/final' if self.path == '/same' else f'http://127.0.0.1:{outside.server_port}/login')
            body = b''
        else:
            self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
inside = ThreadingHTTPServer(('127.0.0.1', 0), Inside)
threads = []
for server in (inside, outside):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    threads.append(thread)
try:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / 'completion.jsonl'
        origin = f'http://127.0.0.1:{inside.server_port}'
        result = subprocess.run([
            str(Path(a.binary).resolve()), '-u', origin + '/',
            '-silent', '-duc', '-d', '2', '-ct', '8s', '-timeout', '3',
            '-retry', '0', '-c', '1', '-p', '1', '-rl', '3',
            '-cs', '^' + re.escape(origin) + r'(?:/|$)',
            '-recon-checkpoint-dir', str(Path(tmp)/'checkpoint'),
            '-recon-completion-log', str(log),
        ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
            env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
        assert result.returncode == 0, result.stderr
        assert not outside_hits, outside_hits
        assert {'/', '/same', '/final', '/external'} <= set(hits), hits
        completion = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(completion) == 1 and completion[0]['stop_reason'] == 'queue_exhausted', completion
        report = {'passed': True, 'scenario': 'redirect_scope', 'inside_requests': hits, 'outside_requests': outside_hits, 'completion': completion}
        Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    for server in (inside, outside):
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join()

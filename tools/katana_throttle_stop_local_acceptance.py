"""A throttled origin must stop, preserve pending work, and resume on recovery."""
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
throttled = True
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        hits.append(self.path)
        blocked = self.path == '/throttle' and throttled
        body = (b'<a href="/remaining">remaining</a><a href="/throttle">throttle</a>' if self.path == '/' else
                b'<a href="/must-not-parse">error link</a>' if blocked else b'<html></html>')
        self.send_response(429 if blocked else 200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
s = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
t = threading.Thread(target=s.serve_forever, daemon=True)
t.start()
try:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        origin = f'http://127.0.0.1:{s.server_port}'
        reports = []
        for attempt in range(2):
            log = tmp / f'completion-{attempt}.jsonl'
            error_log = tmp / f'errors-{attempt}.jsonl'
            result = subprocess.run([
                str(Path(a.binary).resolve()), '-u', origin,
                '-silent', '-duc', '-d', '2', '-ct', '8s', '-timeout', '3',
                '-retry', '0', '-c', '1', '-p', '1', '-rl', '3',
                '-cs', '^' + re.escape(origin) + r'(?:/|$)',
                '-elog', str(error_log),
                '-recon-checkpoint-dir', str(tmp/'checkpoint'),
                '-recon-completion-log', str(log),
            ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
                env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
            records = [json.loads(line) for line in log.read_text().splitlines()]
            assert len(records) == 1, records
            completion = records[0]
            checkpoint = json.loads(next((tmp/'checkpoint').glob('*.json')).read_text())
            assert not any('/must-not-parse' in i['url'] for i in checkpoint['items']), checkpoint
            if attempt == 0:
                assert hits == ['/', '/throttle'], hits
                assert completion['failed_requests'] == 1 and completion['pending_items'] == 2, completion
                assert completion['stop_reason'] == 'cancelled', completion
                errors = [json.loads(line) for line in error_log.read_text().splitlines()]
                assert any('HTTP 429' in row.get('error','') for row in errors), errors
                throttled = False
            else:
                assert completion['stop_reason'] == 'queue_exhausted', completion
                assert completion['pending_items'] == 0 and completion['failed_requests'] == 0, completion
                assert '/remaining' in hits and '/must-not-parse' not in hits, hits
            reports.append(completion)
        report = {'passed': True, 'scenario': 'throttle_stop_and_recovery', 'requests': hits, 'completion': reports}
        Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    s.shutdown()
    s.server_close()
    t.join()

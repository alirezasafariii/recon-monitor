"""Loopback recovery of both pending and acknowledged filtered frontier items."""
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
binary = Path(a.binary).resolve()
if not binary.is_file() or not os.access(binary, os.X_OK):
    raise SystemExit('Executable producer is required')
hits = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        hits.append(self.path)
        body = b'<a href="/proof">proof</a>' if self.path == '/' else b'terminal'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
report = {'scenario': 'filtered_checkpoint_recovery', 'passed': False}
try:
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        frontier = folder / 'frontier'
        frontier.mkdir(mode=0o700)
        seed = f'http://127.0.0.1:{server.server_port}/'
        inputs = folder / 'inputs.txt'
        inputs.write_text(seed + '\n')
        completion = folder / 'completion.jsonl'
        command = [str(binary), '-list', str(inputs), '-silent', '-duc',
                   '-d', '2', '-ct', '6s', '-timeout', '5', '-retry', '0',
                   '-c', '1', '-p', '1', '-rl', '3',
                   '-cs', r'^http://127\.0\.0\.1:',
                   '-recon-checkpoint-dir', str(frontier),
                   '-recon-completion-log', str(completion)]
        def run():
            completion.write_text('')
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=12,
                                    env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
            events = [json.loads(line) for line in completion.read_text().splitlines() if line.strip()]
            assert result.returncode == 0 and len(events) == 1, (result.returncode, result.stderr, events)
            return events[0]
        first = run()
        assert first['stop_reason'] == 'queue_exhausted', first
        checkpoint, = frontier.glob('*.json')
        state = json.loads(checkpoint.read_text())
        for item in state['items']:
            if item['url'] == seed + 'proof':
                item['done'] = False
        # Simulate older durable admissions: a filtered item already skipped,
        # and another waiting when the previous session reached its deadline.
        state['items'].extend([
            {'url': seed + 'logo.png', 'depth': 1, 'done': True},
            {'url': seed + 'font.woff2', 'depth': 1, 'done': False},
        ])
        checkpoint.write_text(json.dumps(state))
        before = len(hits)
        resumed = run()
        resumed_hits = hits[before:]
        final = json.loads(checkpoint.read_text())
        assert resumed['stop_reason'] == 'queue_exhausted', resumed
        assert resumed['attempted_requests'] == 1 and resumed['pending_items'] == 0, resumed
        assert resumed_hits == ['/proof'], resumed_hits
        assert all(item['done'] for item in final['items']), final
        report.update(passed=True, resumed_completion=resumed,
                      resumed_requested_paths=resumed_hits,
                      filtered_items_requested=False)
finally:
    server.shutdown()
    server.server_close()
    thread.join()
Path(a.output).write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))

#!/usr/bin/env python3
"""Assert experimental Katana completion across concurrent loopback origins."""
import argparse
import json
import os
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from katana_completion_contract import read_completion, origin_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    results = []
    for scenario in ('siblings', 'mixed_error', 'scope_skip', 'duplicate_content'):
        servers, threads = [], []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlsplit(self.path).path
                with self.server.lock:
                    self.server.hits.append(path)
                if path == '/slow':
                    time.sleep(1)
                    if self.server.fail:
                        self.connection.close()
                        return
                pages = {'/': '<a href="/fast">fast</a><a href="/slow">slow</a>',
                         '/fast': '<html>fast sibling</html>',
                         '/slow': '<a href="/proof">delayed child</a>',
                         '/proof': '<html>delayed proof</html>'}
                if scenario == 'scope_skip' and path == '/':
                    pages['/'] += '<a href="/excluded">excluded</a>'
                body = pages.get(path, 'unexpected')
                if scenario != 'duplicate_content':
                    body += f'<p>origin {self.server.server_port} path {path}</p>'
                body = body.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        try:
            for i in range(2):
                server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                server.hits, server.lock = [], threading.Lock()
                server.fail = scenario == 'mixed_error' and i == 1
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start(); servers.append(server); threads.append(thread)
            origins = [f'http://127.0.0.1:{s.server_port}/' for s in servers]
            with tempfile.TemporaryDirectory(prefix='katana-concurrent-') as tmp:
                folder = Path(tmp)
                inputs, completion = folder/'inputs.txt', folder/'completion.jsonl'
                inputs.write_text('\n'.join(origins)+'\n')
                command = [str(binary), '-list', str(inputs), '-silent', '-duc',
                           '-d', '3', '-ct', '10s', '-timeout', '30', '-retry', '0',
                           '-c', '3', '-p', '2', '-rl', '3',
                           '-cs', r'^http://127\.0\.0\.1:',
                           '-recon-completion-log', str(completion)]
                if scenario == 'scope_skip':
                    command += ['-cos', r'/excluded$']
                env = dict(os.environ, NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
                started = time.monotonic()
                result = subprocess.run(command, text=True, capture_output=True, timeout=20, env=env)
                outcomes = read_completion(completion, origins, returncode=result.returncode, timed_out=False)
                for i, origin in enumerate(origins):
                    outcome = outcomes[origin_key(origin)]
                    expected = 'partial' if servers[i].fail else 'completed'
                    assert outcome['status'] == expected, (scenario, outcomes, result.stderr)
                    assert ('/proof' in servers[i].hits) == (not servers[i].fail), servers[i].hits
                    if scenario == 'scope_skip':
                        assert '/excluded' not in servers[i].hits, servers[i].hits
                if scenario == 'duplicate_content':
                    assert all(o['stop_reason'] == 'queue_exhausted' for o in outcomes.values()), outcomes
                    assert all('/proof' in server.hits for server in servers), [server.hits for server in servers]
                    assert all(o['counters']['failed_requests'] == 0 for o in outcomes.values()), outcomes
                row = {'scenario': scenario, 'concurrency': 3, 'parallelism': 2,
                       'duration_seconds': round(time.monotonic()-started, 3),
                       'exit_code': result.returncode, 'outcomes': outcomes,
                       'requested_paths': [s.hits for s in servers],
                       'completion_raw': completion.read_text(), 'stderr': result.stderr}
                results.append(row)
                print(json.dumps(row), flush=True)
        finally:
            for server in servers:
                server.shutdown(); server.server_close()
            for thread in threads:
                thread.join()
    args.output.write_text(json.dumps(results, indent=2)+'\n')


if __name__ == '__main__':
    main()

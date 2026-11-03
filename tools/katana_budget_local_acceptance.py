#!/usr/bin/env python3
"""Real Katana: a busy loopback frontier uses spare capacity after fair turns."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, CommandRunner, Config, Database, Logger, Progress, TargetPolicy
from execution import BudgetManager
from stages import StageContext, stage_urls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    servers, threads = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.server.hits.append(self.path)
            body = (''.join(f'<a href="/page/{i}">page {i}</a>' for i in range(24))
                    if self.server.busy and self.path == '/' else 'terminal ' + self.path)
            body = (body + f' origin {self.server.server_port}').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    report = {'scenario': 'fair_turns_then_busy_frontier_continuation'}
    try:
        for index in range(6):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.hits, server.busy = [], index == 5
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        origins = [f'http://127.0.0.1:{server.server_port}' for server in servers]
        with tempfile.TemporaryDirectory(prefix='recon-katana-budget-') as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            bindir = Path(temp) / 'bin'
            bindir.mkdir()
            (bindir / 'katana').symlink_to(binary)
            policy = TargetPolicy.from_dict({
                'name': '127.0.0.1', 'roots': ['127.0.0.1'],
                'include': [r'^127\.0\.0\.1$'], 'analysis': {'asset_graph': False},
                'limits': {'timeout_seconds': 90, 'request_rate': 3,
                           'max_urls': 90, 'max_http_requests': 90},
            })
            db = Database(paths.db)
            logger = Logger(paths, verbose=False)
            run = db.create_run(policy.name, 1, 'loopback')
            run_dir = paths.output / run
            db.create_run_target(run, policy, run_dir, True)
            runner = CommandRunner(logger, db)
            try:
                ctx = StageContext(paths, Config(paths), policy, db, logger, runner,
                                   Progress(False), run, run_dir, False,
                                   BudgetManager.create(db, run, policy.name, policy))
                (ctx.current / 'resolved-hosts.txt').write_text('127.0.0.1\n')
                env = {'PATH': str(bindir) + os.pathsep + os.environ.get('PATH', ''),
                       'NO_PROXY': '127.0.0.1,localhost', 'no_proxy': '127.0.0.1,localhost'}
                with patch.dict(os.environ, env), \
                        patch('stages.tool_path', side_effect=lambda tool: str(binary) if tool == 'katana' else None), \
                        patch('stages._probe_live_origins', return_value=(origins, [])):
                    metrics = stage_urls(ctx)
                batches = metrics['katana_batch_outcomes']
                initial = [batch for batch in batches if batch['scheduling_phase'] == 'initial']
                continuations = [batch for batch in batches if batch['scheduling_phase'] == 'continuation']
                assert metrics['collection_status'] == 'completed', metrics
                assert metrics['katana_pending_origins'] == 0, metrics
                assert len(initial) == 6 and continuations, batches
                assert len({origin for batch in batches[:6] for origin in batch['origin_urls']}) == 6
                assert all(batch['origin_urls'] == [origins[-1]] for batch in continuations)
                assert max(batch['timeout_seconds'] for batch in continuations) > initial[-1]['timeout_seconds']
                charged = ctx.budget.snapshot()['http_requests']['used']
                assert charged == metrics['katana_reserved_requests'] <= metrics['katana_request_envelope'] <= 90
                assert charged == sum(batch['reserved_requests'] for batch in batches)
                assert all(server.hits.count('/') == 1 for server in servers), [s.hits for s in servers]
                assert all(f'/page/{i}' in servers[-1].hits for i in range(24)), servers[-1].hits
                assert not (ctx.current / 'katana-pending-origins.txt').read_text().strip()
                report.update(passed=True, origins=len(origins), batches=len(batches),
                              continuation_batches=len(continuations), reserved_requests=charged,
                              request_envelope=metrics['katana_request_envelope'],
                              duration_seconds=metrics['katana_duration_seconds'],
                              busy_origin_paths=servers[-1].hits,
                              completed_origins=metrics['katana_origins_completed'])
            finally:
                runner.terminate_active()
                db.close()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()

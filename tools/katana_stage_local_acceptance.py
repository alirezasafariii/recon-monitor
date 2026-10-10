#!/usr/bin/env python3
"""Real stage_urls/CommandRunner/Katana acceptance; loopback only, DB stubbed."""
import argparse
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import CommandRunner, TargetPolicy
from stages import stage_urls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    reports = []
    servers, threads = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.hits.append(self.path)
            if self.path == '/slow':
                time.sleep(1)
                if self.server.fail:
                    self.connection.close()
                    return
            body = ({'/': '<a href="/slow">slow</a>',
                     '/slow': '<a href="/proof">proof</a>',
                     '/proof': '<html>proof</html>'}.get(self.path, 'missing')
                    + f'<p>origin {self.server.server_port} path {self.path}</p>').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *unused):
            pass

    try:
        for _ in range(2):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.hits, server.fail = [], False
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start(); servers.append(server); threads.append(thread)
        origins = [f'http://127.0.0.1:{s.server_port}' for s in servers]
        policy = TargetPolicy.from_dict({
            'name': '127.0.0.1', 'roots': ['127.0.0.1'],
            'include': [r'^127\.0\.0\.1$'],
            'analysis': {'asset_graph': False},
            'limits': {'timeout_seconds': 90, 'request_rate': 3, 'max_urls': 90},
        })
        with tempfile.TemporaryDirectory(prefix='recon-katana-stage-') as tmp:
            root = Path(tmp); bindir = root/'bin'; bindir.mkdir()
            (bindir/'katana').symlink_to(binary)
            env = dict(PATH=str(bindir)+os.pathsep+os.environ.get('PATH',''),
                       NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
            for scenario in ('healthy', 'mixed_error'):
                current=root/scenario/'current'; current.mkdir(parents=True)
                changes=root/scenario/'changes'; changes.mkdir()
                (current/'resolved-hosts.txt').write_text('127.0.0.1\n')
                db=MagicMock(); db.upsert_url.return_value=False
                runner=CommandRunner(MagicMock())
                ctx=SimpleNamespace(current=current,changes=changes,policy=policy,
                                    db=db,runner=runner,budget=None,run_id=scenario,
                                    logger=MagicMock(),progress=MagicMock())
                servers[1].fail = scenario == 'mixed_error'
                try:
                    with patch.dict(os.environ,env), patch('stages.tool_path',side_effect=lambda t:str(binary) if t=='katana' else None), patch('stages._probe_live_origins',return_value=(origins, [])):
                        for phase in ('initial','resume') if scenario=='mixed_error' else ('initial',):
                            if phase=='resume': servers[1].fail=False
                            metrics=stage_urls(ctx)
                            pending=(current/'katana-pending-origins.txt').read_text().splitlines()
                            completed=(current/'katana-completed-origins.txt').read_text().splitlines()
                            expected=[origins[1]] if scenario=='mixed_error' and phase=='initial' else []
                            assert pending==expected,(scenario,phase,pending,metrics)
                            assert set(completed)==set(origins)-set(expected),completed
                            outcome=metrics['katana_batch_outcomes'][-1]
                            assert outcome['completion_contract']=='v1',outcome
                            if phase=='resume': assert outcome['origin_urls']==[origins[1]],outcome
                            report={'scenario':scenario,'phase':phase,'pending':pending,'completed':completed,
                                    'katana_status':metrics['katana_status'],'last_batch':outcome}
                            reports.append(report); print(json.dumps(report),flush=True)
                finally:
                    runner.terminate_active()
    finally:
        for server in servers: server.shutdown(); server.server_close()
        for thread in threads: thread.join()
    args.output.write_text(json.dumps(reports,indent=2)+'\n')


if __name__ == '__main__':
    main()

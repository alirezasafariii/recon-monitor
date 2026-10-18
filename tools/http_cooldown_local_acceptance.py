#!/usr/bin/env python3
"""Real HTTP 429, database reopen, fresh run, and zero-request cooldown proof."""
import argparse
import json
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, Config, Database, Logger, Progress, StageError, TargetPolicy
from stages import StageContext, _download_url, _origin_probe_one, _safe_validate_endpoint, stage_urls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    hits = []
    class Handler(BaseHTTPRequestHandler):
        status = 429
        def do_HEAD(self):
            hits.append(self.path)
            self.send_response(self.status); self.send_header('Retry-After', '120'); self.end_headers()
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='recon-cooldown-real-') as temp:
            paths = AppPaths.from_root(Path(temp)); paths.ensure()
            policy = TargetPolicy.from_dict({'name': '127.0.0.1', 'roots': ['127.0.0.1']})
            db = Database(paths.db)
            try:
                def context():
                    run = db.create_run(policy.name, 1, 'loopback')
                    db.create_run_target(run, policy, paths.output / run, False)
                    return StageContext(paths, Config(paths), policy, db, Logger(paths, verbose=False),
                                        SimpleNamespace(), Progress(False), run, paths.output / run, False)
                with patch('safe_transport.resolve_public_addresses', return_value=(True, ['127.0.0.1'])):
                    first = context()
                    observed = _origin_probe_one(first, origin)
                    assert observed['status_code'] == 429 and len(hits) == 1, observed
                    db.close(); db = Database(paths.db)
                    second = context()
                    (second.current / 'resolved-hosts.txt').write_text('127.0.0.1\n')
                    (second.current / 'port-web-origins.txt').write_text(origin + '\n')
                    with patch('stages.tool_path', return_value=None):
                        metrics = stage_urls(second)
                    assert metrics['collection_status'] == 'partial'
                    assert _origin_probe_one(second, origin)['error'] == 'rate_limit_cooldown'
                    assert _safe_validate_endpoint(second, origin)['error'] == 'rate_limit_cooldown'
                    try:
                        _download_url(second, origin + '/app.js', 1000)
                    except StageError as exc:
                        assert 'rate_limit_cooldown' in str(exc)
                    else:
                        raise AssertionError('Download bypassed shared cooldown')
                    assert len(hits) == 1
                    Handler.status = 200
                    with patch('katana_reliability.time.time', return_value=time.time() + 3601):
                        assert _origin_probe_one(second, origin)['status_code'] == 200
                    assert len(hits) == 2
                    report = {'passed': True, 'first_run': first.run_id, 'fresh_run': second.run_id,
                              'requests_before_cooldown': 1, 'requests_during_cooldown': 0,
                              'requests_after_expiry': 1}
            finally:
                db.close()
    finally:
        server.shutdown(); server.server_close(); thread.join()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

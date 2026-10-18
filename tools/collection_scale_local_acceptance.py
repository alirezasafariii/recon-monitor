#!/usr/bin/env python3
"""Real Katana/Orchestrator continuation across hundreds of loopback origins.

Only URL collection is live; other stages and reporting are controlled fixtures.
Operator Next is requested through the real database lifecycle after each chunk.
"""
import argparse
import asyncio
import contextlib
from collections import Counter
import io
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy
from stages import stage_urls, _probe_live_origins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--origins', type=int, default=200)
    parser.add_argument('--chunk', type=int, default=40)
    parser.add_argument('--initial-timeout', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    assert 100 <= args.origins <= 500 and 1 <= args.chunk < args.origins
    binary = args.binary.resolve(strict=True)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    servers, hits, control = [], set(), {}
    requests = Counter()

    async def handle(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            method, path, _ = request.split(b'\r\n', 1)[0].decode().split(' ', 2)
            port = writer.get_extra_info('sockname')[1]
            if method == 'GET':
                hits.add((port, path))
                requests[(port, path)] += 1
                if path == '/' and port not in control['seen']:
                    control['seen'].add(port)
                    if len(control['seen']) >= args.chunk and not control['next'] and not control['timeout_phase']:
                        runner, db, policy = control['runner'], control['db'], control['policy']
                        row = db.one("SELECT attempt FROM stage_runs WHERE run_id=? AND target=? AND stage='urls'",
                                     (runner.current_run_id, policy.name))
                        control['next'] = db.request_stage_next(runner.current_run_id, policy.name, 'urls', row['attempt'], 'local-acceptance')
            if method == 'GET' and path == '/proof' and control['timeout_phase']:
                await asyncio.sleep(args.initial_timeout + 5)
            body = (b'<a href="/proof">proof</a>' if path == '/' else b'terminal proof') + str(port).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                         + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n'
                         + (body if method != 'HEAD' else b''))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def start():
        for _ in range(args.origins):
            servers.append(await asyncio.start_server(handle, '127.0.0.1', 0))
        return [f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}' for server in servers]

    async def close():
        for server in servers: server.close()
        for server in servers: await server.wait_closed()

    report = {'origins': args.origins, 'attempts': []}
    try:
        origins = asyncio.run_coroutine_threadsafe(start(), loop).result(15)
        if args.workdir:
            args.workdir.mkdir(parents=True, exist_ok=False)
        workspace = contextlib.nullcontext(str(args.workdir)) if args.workdir else tempfile.TemporaryDirectory(prefix='recon-scale-')
        with workspace as temp:
            paths = AppPaths.from_root(Path(temp)); paths.ensure()
            bindir = paths.root / 'bin'; bindir.mkdir(); (bindir / 'katana').symlink_to(binary)
            paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
            policy = TargetPolicy.from_dict({'name': '127.0.0.1', 'roots': ['127.0.0.1'],
                'include': [r'^127\.0\.0\.1$'], 'analysis': {'asset_graph': False},
                'limits': {'timeout_seconds': 3600, 'request_rate': 50, 'http_threads': 50,
                           'max_urls': 50000, 'max_http_requests': 1000000, 'max_runtime_minutes': 30}})
            db = runtime.Database(paths.db)
            try:
                baseline = db.create_run(policy.name, 1, 'fixture')
                db.create_run_target(baseline, policy, paths.output / baseline, True)
                db.upsert_url(policy.name, origins[0] + '/baseline', 'url', 'fixture', baseline)
                db.finish_run_target(baseline, policy.name, 'success')
                commit = lambda: db.one('SELECT run_id FROM successful_recon_commits WHERE target=?', (policy.name,))[0]
                assert commit() == baseline
                def offline(ctx):
                    (ctx.current / 'resolved-hosts.txt').write_text('127.0.0.1\n')
                    (ctx.current / 'port-web-origins.txt').write_text('\n'.join(origins) + '\n')
                    return {'collection_status': 'completed'}
                functions = {name: offline for name in runtime.STAGE_FUNCTIONS}
                functions['urls'] = stage_urls
                resume, previous_pending = None, args.origins
                certified_roots = {}
                for attempt in range(args.origins // args.chunk + 12):
                    runner = runtime.Orchestrator(paths, Config(paths), Logger(paths, verbose=False), db,
                                                  progress=False, allow_active=False)
                    policy.limits.timeout_seconds = args.initial_timeout if attempt == 0 else 3600
                    control.update(runner=runner, db=db, policy=policy, seen=set(), next=False, timeout_phase=attempt == 0)
                    env = {'PATH': str(bindir) + os.pathsep + os.environ.get('PATH', ''), 'NO_PROXY': '127.0.0.1,localhost', 'no_proxy': '127.0.0.1,localhost'}
                    captured = io.StringIO()
                    with patch.dict(os.environ, env), patch.dict(runtime.STAGE_FUNCTIONS, functions), \
                            patch('stages.tool_path', side_effect=lambda tool: str(binary) if tool == 'katana' else None), \
                            patch('safe_transport.resolve_public_addresses', return_value=(True, ['127.0.0.1'])), \
                            patch('stages._probe_live_origins', side_effect=lambda ctx, urls: _probe_live_origins(ctx, [url for url in urls if url in origins])), \
                            patch.object(runner, '_record_versions'), patch.object(runner, 'install_signal_handlers'), \
                            patch('recon_monitor_core.stage_report', return_value={'analysis': {'analysis_id': 'loopback-fixture'}, 'finding_notifications': {'status': 'success'}}), \
                            contextlib.redirect_stdout(captured):
                        code = runner.run(PolicySet({}, [policy], paths.policy), resume_id=resume)
                    resume = runner.current_run_id
                    current = Path(db.one('SELECT run_dir FROM run_targets WHERE run_id=? AND target=?', (resume, policy.name))[0]) / 'current'
                    if not (current / 'katana-pending-origins.txt').exists():
                        raise AssertionError({'code': code, 'stages': [dict(row) for row in db.all('SELECT stage,status,error FROM stage_runs WHERE run_id=?', (resume,))], 'output': captured.getvalue()[-4000:]})
                    pending = (current / 'katana-pending-origins.txt').read_text().splitlines()
                    urls = set((current / 'katana-urls.txt').read_text().splitlines())
                    for port, count in certified_roots.items():
                        assert requests[(port, '/')] == count, 'Certified origin was fetched again'
                    for origin in (current / 'katana-completed-origins.txt').read_text().splitlines():
                        port = int(origin.rsplit(':', 1)[1])
                        certified_roots[port] = requests[(port, '/')]
                    metrics = json.loads((current / 'url-collection.json').read_text())['metrics']
                    budget = {row['metric']: row['used'] for row in db.all('SELECT metric,used FROM run_budgets WHERE run_id=? AND target=?', (resume, policy.name))}
                    row = {'attempt': attempt + 1, 'exit_code': code, 'pending': len(pending),
                           'observed_urls': len(urls), 'budget': budget, 'baseline_preserved': commit() == baseline,
                           'timeout_phase': attempt == 0, 'reason': metrics['katana_stop_reason'],
                           'last_outcomes': [{key: outcome.get(key) for key in ('origin_urls', 'status', 'stop_reason', 'origin_completion', 'exit_code')} for outcome in metrics.get('katana_batch_outcomes', [])[-5:]]}
                    report['attempts'].append(row); print(json.dumps(row), flush=True)
                    assert (len(pending) < previous_pending or attempt == 0 and len(urls) > 0), row
                    previous_pending = len(pending)
                    assert budget.get('http_requests', 0) <= policy.limits.max_http_requests, row
                    if pending:
                        assert code == 2 and row['baseline_preserved'], row
                    else:
                        assert code == 0 and commit() == resume, row
                        assert all(origin + '/proof' in urls for origin in origins), len(urls)
                        assert all((int(origin.rsplit(':', 1)[1]), '/proof') in hits for origin in origins)
                        break
                else:
                    raise AssertionError('Backlog did not finish within bounded attempts')
                assert len(report['attempts']) > 1
                assert len(certified_roots) == args.origins
                report.update(passed=True, run_id=resume, requested_pages=len(hits), final_url_count=len(urls),
                              certified_origins_revisited=False, root_requests=sum(count for (port, path), count in requests.items() if path == '/'))
            finally:
                db.close()
    finally:
        asyncio.run_coroutine_threadsafe(close(), loop).result(15)
        loop.call_soon_threadsafe(loop.stop); thread.join(); loop.close()
        args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

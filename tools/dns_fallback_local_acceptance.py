#!/usr/bin/env python3
"""Real dnsx and dig against a loopback authoritative fixture, including resume."""
import argparse
import contextlib
import json
import socketserver
import struct
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, CommandRunner, Config, Database, Logger, Progress, TargetPolicy
from execution import BudgetManager
from stages import StageContext, stage_dns


def name(value):
    return b''.join(bytes([len(part)]) + part.encode() for part in value.rstrip('.').split('.')) + b'\0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dnsx', type=Path, required=True)
    parser.add_argument('--dig', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    dnsx, dig = args.dnsx.resolve(strict=True), args.dig.resolve(strict=True)
    queries = []
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            position, labels = 12, []
            while packet[position]:
                size = packet[position]; position += 1
                labels.append(packet[position:position + size].decode()); position += size
            position += 1
            host = '.'.join(labels).lower()
            rrtype, _ = struct.unpack('!HH', packet[position:position + 4])
            queries.append((host, rrtype))
            missing = host == 'missing.example.test'
            positive = not missing and rrtype in (1, 2)
            if positive:
                data = bytes((192, 0, 2, 20)) if rrtype == 1 else name('ns.example.test')
                record = b'\xc0\x0c' + struct.pack('!HHIH', rrtype, 1, 300, len(data)) + data
            else:
                data = name('ns.example.test') + name('hostmaster.example.test') + struct.pack('!IIIII', 1, 300, 300, 3600, 60)
                record = name('example.test') + struct.pack('!HHIH', 6, 1, 300, len(data)) + data
            response = packet[:2] + struct.pack('!HHHHH', 0x8583 if missing else 0x8580, 1,
                                               int(positive), int(not positive), 0)
            sock.sendto(response + packet[12:position + 4] + record, self.client_address)
    server = socketserver.UDPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    port = server.server_address[1]
    class Runner(CommandRunner):
        def run(self, command, **kwargs):
            command = list(command)
            if Path(str(command[0])).name == 'dnsx':
                command[0] = str(dnsx)
                command.extend(['-r', f'127.0.0.1:{port}', '-duc'])
            return super().run(command, **kwargs)
    report = {'scenario': 'real_dnsx_dig_negative_resume', 'attempts': []}
    try:
        with tempfile.TemporaryDirectory(prefix='recon-dns-real-') as temp:
            paths = AppPaths.from_root(Path(temp)); paths.ensure()
            policy = TargetPolicy.from_dict({'name': 'example.test', 'roots': ['example.test'],
                'limits': {'dns_rate': 1000, 'max_dns_queries': 10000, 'timeout_seconds': 30}})
            db = Database(paths.db)
            logger = Logger(paths, verbose=False)
            run = db.create_run(policy.name, 1, 'loopback')
            db.create_run_target(run, policy, paths.output / run, True)
            hosts = [f'h{index:03}.example.test' for index in range(129)] + ['missing.example.test']
            try:
                ctx = StageContext(paths, Config(paths), policy, db, logger, Runner(logger, db), Progress(False),
                                   run, paths.output / run, False)
                (ctx.current / 'subdomains.txt').write_text('\n'.join(hosts) + '\n')
                with patch('stages.tool_path', side_effect=lambda tool: str(dnsx) if tool == 'dnsx' else None), \
                        patch('dns_explicit.tool_path', return_value=str(dig)), \
                        patch('dns_explicit.RESOLVER', '127.0.0.1'), patch('dns_explicit.RESOLVER_PORT', port):
                    for attempt in range(6):
                        if attempt == 1:
                            db.close(); db = Database(paths.db); ctx.db = db
                            ctx.runner = Runner(logger, db)
                        ctx.budget = BudgetManager.create(db, run, policy.name, policy)
                        metrics = stage_dns(ctx)
                        row = {'attempt': attempt + 1, 'status': metrics['collection_status'],
                               'queries': metrics['dns_explicit_queries'],
                               'reused_queries': metrics['dns_explicit_reused_queries']}
                        report['attempts'].append(row); print(json.dumps(row), flush=True)
                        assert row['queries'] <= 128
                        if row['status'] == 'completed':
                            final = stage_dns(ctx)
                            assert final['dns_explicit_queries'] == 0 and final['collection_status'] == 'completed'
                            break
                    else:
                        raise AssertionError('DNS did not complete within bounded attempts')
                    assert len(report['attempts']) > 1
                    assert db.one("SELECT COUNT(*) FROM dns_records WHERE target=? AND rrtype='NS' AND value='ns.example.test' AND is_current=1", (policy.name,))[0] == 1, [dict(row) for row in db.all("SELECT host,rrtype,value,is_current FROM dns_records WHERE rrtype='NS' LIMIT 5")]
                    assert db.one("SELECT COUNT(*) FROM dns_records WHERE target=? AND host='missing.example.test' AND is_current=1", (policy.name,))[0] == 0
                    report.update(passed=True, wire_queries=len(queries), reused_after_completion=final['dns_explicit_reused_queries'])
            finally:
                db.close()
    finally:
        server.shutdown(); server.server_close(); thread.join()
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

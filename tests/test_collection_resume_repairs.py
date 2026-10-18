from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

import recon_monitor_core as runtime
import test_dns_collection_quality as dns_fixture
import test_javascript_execution_quality as js_fixture
import test_katana_execution_quality as katana_fixture
import test_source_map_resume as map_fixture
from test_dns_explicit import packet
from core import Config, Logger, PolicySet
from dns_explicit import parse_response
from execution import BudgetManager
from stages import stage_dns, stage_javascript, stage_urls


class CollectionResumeRepairs(unittest.TestCase):
    def fixture(self, cls):
        fixture = cls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def dns_runner(self, calls, *, ns_missing=False):
        flags = dns_fixture.DNSCollectionQualityTests.FLAGS

        def run(args, **kwargs):
            out = Path(kwargs['output_path'])
            if args[0] == '/usr/bin/dig':
                host, rrtype = args[2:4]
                calls.append((host, rrtype))
                answer = f'{host}. 300 IN NS ns.example.test.' if rrtype == 'NS' else ''
                out.write_text(packet(host, rrtype, answer=answer))
            else:
                rrtype = next(value for flag, value in flags.items() if flag in args)
                hosts = Path(args[args.index('-l') + 1]).read_text().splitlines()
                rows = []
                if rrtype == 'A' or (rrtype == 'NS' and not ns_missing):
                    values = ['192.0.2.20'] if rrtype == 'A' else ['ns.example.test']
                    rows = [{'host': host, rrtype.lower(): values} for host in hosts]
                out.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            return SimpleNamespace(returncode=0, timed_out=False, operator_next=False,
                                   duration=.1, lines=len(out.read_text().splitlines()))
        return run

    @contextlib.contextmanager
    def dns_tools(self):
        with patch('stages.tool_path', return_value='dnsx'), \
                patch('dns_explicit.tool_path', return_value='/usr/bin/dig'), \
                patch('dns_explicit.time.sleep'):
            yield

    def test_dns_129_hosts_advance_after_reopen_with_bounded_queries(self):
        f = self.fixture(dns_fixture.DNSCollectionQualityTests)
        ctx = f._context(None)
        hosts = [f'h{i:03}.example.test' for i in range(129)]
        (ctx.current / 'subdomains.txt').write_text('\n'.join(hosts) + '\n')
        calls = []
        ctx.runner = SimpleNamespace(run=self.dns_runner(calls))
        ctx.budget = BudgetManager.create(ctx.db, ctx.run_id, ctx.policy.name, ctx.policy)
        statuses, queries = [], []
        with self.dns_tools():
            for index in range(4):
                if index == 1:
                    f.db.close()
                    f.db = runtime.Database(f.paths.db)
                    f.addCleanup(f.db.close)
                    ctx.db = f.db
                    ctx.budget = BudgetManager.create(ctx.db, ctx.run_id, ctx.policy.name, ctx.policy)
                result = stage_dns(ctx)
                statuses.append(result['collection_status'])
                queries.append(result['dns_explicit_queries'])
        self.assertEqual(statuses, ['partial', 'partial', 'completed', 'completed'])
        self.assertEqual(queries, [128, 128, 2, 0])
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(len(calls), 258)
        self.assertEqual(result['dns_explicit_reused_queries'], 258)
        self.assertLessEqual(ctx.budget.snapshot()['dns_queries']['used'], ctx.policy.limits.max_dns_queries)

    def test_missing_or_tampered_dns_proof_is_queried_again(self):
        for damage in ('delete', 'change'):
            with self.subTest(damage=damage):
                f = self.fixture(dns_fixture.DNSCollectionQualityTests)
                ctx = f._context(None)
                calls = []
                ctx.runner = SimpleNamespace(run=self.dns_runner(calls))
                with self.dns_tools():
                    first = stage_dns(ctx)
                    proof = ctx.current / first['dns_explicit_query_outcomes'][0]['raw_artifact']
                    if damage == 'delete':
                        proof.unlink()
                    else:
                        proof.write_text('not a DNS response')
                    calls.clear()
                    resumed = stage_dns(ctx)
                self.assertEqual(resumed['collection_status'], 'completed')
                self.assertEqual(len(calls), 1)
                self.assertEqual(resumed['dns_explicit_reused_queries'], 1)

    def test_dns_receipts_do_not_cross_run_or_policy(self):
        f = self.fixture(dns_fixture.DNSCollectionQualityTests)
        ctx = f._context(None)
        calls = []
        ctx.runner = SimpleNamespace(run=self.dns_runner(calls))
        with self.dns_tools():
            stage_dns(ctx)
            calls.clear()
            ctx.run_id = 'different-run'
            self.assertEqual(stage_dns(ctx)['dns_explicit_queries'], 2)
            ctx.policy.raw['description'] = 'changed policy'
            self.assertEqual(stage_dns(ctx)['dns_explicit_queries'], 2)

    def test_fresh_dns_failure_cannot_be_replaced_by_cached_negative(self):
        f = self.fixture(dns_fixture.DNSCollectionQualityTests)
        ctx = f._context(None)
        normal = self.dns_runner([])
        ctx.runner = SimpleNamespace(run=normal)
        with self.dns_tools():
            self.assertEqual(stage_dns(ctx)['collection_status'], 'completed')
            ctx.db.upsert_dns(f.TARGET, f.TARGET, 'AAAA', '2001:db8::42', 'older')
            def failure(args, **kwargs):
                result = normal(args, **kwargs)
                if '-aaaa' in args:
                    kwargs['output_path'].write_text(json.dumps({'host': f.TARGET, 'status_code': 'SERVFAIL'}) + '\n')
                return result
            ctx.runner = SimpleNamespace(run=failure)
            resumed = stage_dns(ctx)
        self.assertEqual(resumed['collection_status'], 'partial')
        self.assertIn('AAAA', resumed['failed_rrtypes'])
        self.assertIsNotNone(ctx.db.one("SELECT 1 FROM dns_records WHERE rrtype='AAAA' AND value='2001:db8::42' AND is_current=1"))

    def test_positive_ns_fallback_is_a_complete_observation(self):
        f = self.fixture(dns_fixture.DNSCollectionQualityTests)
        ctx = f._context(None)
        ctx.runner = SimpleNamespace(run=self.dns_runner([], ns_missing=True))
        with self.dns_tools():
            result = stage_dns(ctx)
        self.assertEqual(result['collection_status'], 'completed')
        self.assertIsNotNone(ctx.db.one("SELECT 1 FROM dns_records WHERE rrtype='NS' AND value='ns.example.test' AND is_current=1"))

    def test_ns_parser_validates_rrset_and_response(self):
        host = 'example.test'
        valid = packet(host, 'NS', answer=f'{host}. 300 IN NS ns1.example.test.\n{host}. 300 IN NS ns2.example.test.')
        self.assertEqual(parse_response(valid, host, 'NS'), ('ns1.example.test', 'ns2.example.test'))
        for invalid in (valid.replace('NOERROR', 'NXDOMAIN'), valid.replace('qr rd', 'qr tc rd'),
                        valid.replace('ns1.example.test.', 'bad!name.'), valid.replace(';example.test. IN NS', ';other.test. IN NS')):
            self.assertIsNone(parse_response(invalid, host, 'NS'))

    @staticmethod
    def javascript(_ctx, url, _limit):
        return {'url': url, 'status_code': 200, 'data': b'const value = 1;', 'content_type': 'application/javascript'}

    def test_javascript_201_files_finish_after_one_resume_and_keep_evidence(self):
        f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
        urls = [f'https://example.test/asset{i:03}.js' for i in range(201)]
        f.inputs(urls)
        with patch('stages._download_url', side_effect=self.javascript) as download:
            first = stage_javascript(f.ctx)
            second = stage_javascript(f.ctx)
            third = stage_javascript(f.ctx)
        self.assertEqual([row['downloaded'] for row in (first, second, third)], [200, 1, 0])
        self.assertEqual([row['collection_status'] for row in (first, second, third)], ['partial', 'completed', 'completed'])
        self.assertEqual(download.call_count, 201)
        self.assertEqual(set((f.ctx.changes / 'new-js-files.txt').read_text().splitlines()), set(urls))
        self.assertEqual(len((f.ctx.current / 'javascript-availability.jsonl').read_text().splitlines()), 201)

    def test_javascript_unverified_absence_retries_without_disappearance(self):
        for status in (404, 410):
            for extra in ({'transport_status': 'error'}, {'transport_status': 'stopped_for_safety'},
                          {'transport_status': ''}, {'truncated': True}, {'redirect_outside_scope': True},
                          {'final_url': 'https://outside.invalid/app.js'}, {'error': 'read_failed'},
                          {'transport_error': 'read_failed'}, {'operator_next': True}):
                with self.subTest(status=status, extra=extra):
                    f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
                    url = 'https://example.test/app.js'
                    f.inputs([url])
                    with patch('stages._download_url', side_effect=self.javascript):
                        stage_javascript(f.ctx)
                    # A fresh run has a known available asset to compare against.
                    f.ctx.run_id = f.ctx.db.create_run(f.ctx.policy.name, 1, 'offline')
                    f.ctx.run_dir = f.ctx.paths.output / f.ctx.run_id
                    f.ctx.db.create_run_target(f.ctx.run_id, f.ctx.policy, f.ctx.run_dir, False)
                    f.inputs([url])
                    absent = {'url': url, 'final_url': url, 'status_code': status,
                              'not_found': True, 'transport_status': 'ok', **extra}
                    with patch('stages._download_url', return_value=absent):
                        result = stage_javascript(f.ctx)
                    self.assertEqual(result['collection_status'], 'partial')
                    self.assertEqual(result['not_found'], 0)
                    self.assertEqual(result['disappeared'], 0)
                    self.assertEqual(f.ctx.db.work_status(f.ctx.run_id, f.ctx.policy.name, 'javascript-items', url), 'retry_pending')
                    self.assertEqual((f.ctx.changes / 'not-found-js-files.txt').read_text(), '')
                    with patch('stages._download_url', side_effect=self.javascript):
                        self.assertEqual(stage_javascript(f.ctx)['collection_status'], 'completed')

    def test_download_rejects_incomplete_404_and_410_before_stage_processing(self):
        from stages import _download_url
        f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
        url = 'https://example.test/app.js'
        for status in (404, 410):
            for extra in ({'truncated': True}, {'redirect_outside_scope': True},
                          {'transport_status': 'error'}, {'error': 'read_failed'},
                          {'final_url': 'https://outside.invalid/app.js'}):
                with self.subTest(status=status, extra=extra), patch('stages.perform_pinned_download',
                        return_value={'status_code': status, 'transport_status': 'ok', 'error': 'http_error', **extra}):
                    result = _download_url(f.ctx, url, 100000)
                    self.assertFalse(result.get('not_found'))
                    self.assertIn('error', result)
                    self.assertNotIn('data', result)

    def test_javascript_absence_survives_201_file_resume_and_database_reopen(self):
        for status in (404, 410):
            with self.subTest(status=status):
                f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
                urls = [f'https://example.test/asset{i:03}.js' for i in range(201)]
                absent = urls[0]
                f.inputs(urls)
                def download(ctx, url, limit):
                    return ({'url': url, 'final_url': url, 'status_code': status,
                             'not_found': True, 'transport_status': 'ok'} if url == absent
                            else self.javascript(ctx, url, limit))
                with patch('stages._download_url', side_effect=download) as requests:
                    first = stage_javascript(f.ctx)
                    self.assertEqual(first['collection_status'], 'partial')
                    f.ctx.db.close()
                    f.ctx.db = runtime.Database(f.ctx.paths.db)
                    f.addCleanup(f.ctx.db.close)
                    # Output files are disposable: reconstruct from the queue receipt.
                    (f.ctx.current / 'javascript-not-found.jsonl').unlink()
                    (f.ctx.changes / 'not-found-js-files.txt').write_text('https://outside.invalid/fake.js\n')
                    second = stage_javascript(f.ctx)
                    third = stage_javascript(f.ctx)
                self.assertEqual(requests.call_count, 201)
                self.assertEqual([second['collection_status'], third['collection_status']], ['completed', 'completed'])
                self.assertEqual([second['not_found'], third['not_found']], [1, 1])
                self.assertEqual((f.ctx.changes / 'not-found-js-files.txt').read_text().splitlines(), [absent])
                self.assertEqual([json.loads(line) for line in (f.ctx.current / 'javascript-not-found.jsonl').read_text().splitlines()],
                                 [{'url': absent, 'status_code': status}])
                # Invalidate the policy-bound receipt: this URL must be checked again.
                f.ctx.policy.raw['receipt_test_revision'] = 2
                with patch('stages._download_url', side_effect=self.javascript) as request:
                    recovered = stage_javascript(f.ctx)
                request.assert_called_once()
                self.assertEqual(recovered['not_found'], 0)
                self.assertEqual((f.ctx.changes / 'not-found-js-files.txt').read_text(), '')

    def test_legacy_javascript_absence_receipt_is_rechecked(self):
        f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
        url = 'https://example.test/old.js'
        f.inputs([url])
        with patch('stages._download_url', return_value={'url': url, 'status_code': 404,
                'not_found': True, 'transport_status': 'ok'}):
            stage_javascript(f.ctx)
        old = json.loads(f.ctx.db.one("SELECT result_json FROM work_items WHERE stage='javascript-items'")[0])
        old.pop('absence_proof_version')
        f.ctx.db.execute("UPDATE work_items SET result_json=? WHERE stage='javascript-items'", (json.dumps(old),))
        with patch('stages._download_url', side_effect=self.javascript) as download:
            result = stage_javascript(f.ctx)
        download.assert_called_once()
        self.assertEqual(result['repaired_completed_work_items'], 1)
        self.assertEqual(result['not_found'], 0)
        self.assertEqual((f.ctx.changes / 'not-found-js-files.txt').read_text(), '')

    def test_corrupt_completed_javascript_cannot_spend_a_verified_slot(self):
        f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
        f.ctx.policy.limits.max_js_files = 1
        f.inputs(['https://example.test/a.js', 'https://example.test/b.js'])
        with patch('stages._download_url', side_effect=self.javascript):
            stage_javascript(f.ctx)
            blob = f.ctx.db.one("SELECT blob_path FROM js_files WHERE url='https://example.test/a.js'")[0]
            Path(blob).unlink()
            repair = stage_javascript(f.ctx)
            finish = stage_javascript(f.ctx)
        self.assertEqual(repair['collection_status'], 'partial')
        self.assertEqual(repair['repaired_completed_work_items'], 1)
        self.assertEqual(finish['collection_status'], 'completed')

    def test_partial_javascript_does_not_promote_baseline_until_resume_finishes(self):
        f = self.fixture(js_fixture.JavascriptExecutionQualityTests)
        paths, db, policy = f.ctx.paths, f.ctx.db, f.ctx.policy
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
        urls = ['https://example.test/a.js', 'https://example.test/b.js']
        policy.limits.max_js_files = 1
        def offline(ctx):
            (ctx.current / 'urls.txt').write_text('\n'.join(urls) + '\n')
            (ctx.current / 'url-collection.json').write_text(json.dumps({'run_id': ctx.run_id, 'target': policy.name, 'metrics': {'collection_status': 'completed'}}))
            return {'collection_status': 'completed'}
        functions = {name: offline for name in runtime.STAGE_FUNCTIONS}
        functions['javascript'] = stage_javascript
        report = {'analysis': {'analysis_id': 'offline'}, 'finding_notifications': {'status': 'success'}}
        def execute(resume=None):
            runner = runtime.Orchestrator(paths, Config(paths), Logger(paths, verbose=False), db, progress=False, allow_active=False)
            with patch.dict(runtime.STAGE_FUNCTIONS, functions), patch('stages._download_url', side_effect=self.javascript), \
                    patch.object(runner, '_record_versions'), patch.object(runner, 'install_signal_handlers'), \
                    patch.object(runner, '_update_latest_pointers'), patch('recon_monitor_core.stage_report', return_value=report), \
                    contextlib.redirect_stdout(io.StringIO()):
                return runner.run(PolicySet({}, [policy], paths.policy), resume_id=resume), runner.current_run_id
        code, run_id = execute()
        self.assertEqual(code, 2)
        self.assertFalse(db.target_has_history(policy.name))
        self.assertEqual(execute(run_id)[0], 0)
        self.assertTrue(db.target_has_history(policy.name))

    def test_source_map_404_and_410_are_terminal_only_for_this_parent_and_run(self):
        for status in (404, 410):
            with self.subTest(status=status):
                f = self.fixture(map_fixture.SourceMapResumeTests)
                absent = {'url': f.MAP, 'final_url': f.MAP, 'status_code': status, 'not_found': True, 'transport_status': 'ok'}
                first = f.first_failure(absent)
                with patch('stages._download_url', side_effect=AssertionError('completed observation retried')):
                    resumed = stage_javascript(f.ctx)
                self.assertEqual(first['collection_status'], 'completed')
                self.assertEqual(resumed['collection_status'], 'completed')
                self.assertEqual(resumed['source_map_not_found'], 1)
                self.assertEqual(resumed['source_map_failures'], 0)
                f.new_run()
                with patch('stages._download_url', side_effect=lambda _ctx, url, _limit: f.result(url, f.JS if url == f.URL else f.MAP_DATA)) as download:
                    available = stage_javascript(f.ctx)
                self.assertEqual(download.call_count, 2)
                self.assertEqual(available['source_maps'], 1)

    def test_source_map_failures_and_unverified_404_remain_partial(self):
        for failure in ({'status_code': 503, 'error': 'unavailable'}, {'status_code': 429, 'error': 'throttled'},
                        {'status_code': 404, 'not_found': True, 'transport_status': 'stopped_for_safety'},
                        {'status_code': 404, 'not_found': True, 'transport_status': 'ok', 'truncated': True},
                        {'status_code': 404, 'not_found': True, 'transport_status': 'ok', 'final_url': 'https://outside.invalid/'}):
            with self.subTest(failure=failure):
                f = self.fixture(map_fixture.SourceMapResumeTests)
                result = f.first_failure({'url': f.MAP, **failure})
                self.assertEqual(result['collection_status'], 'partial')
                self.assertEqual(result['source_map_failures'], 1)
                self.assertEqual(f.map_items()[0]['status'], 'retry_pending')

    def test_source_map_absence_is_revalidated_after_policy_change(self):
        f = self.fixture(map_fixture.SourceMapResumeTests)
        f.first_failure({'url': f.MAP, 'final_url': f.MAP, 'status_code': 404, 'not_found': True, 'transport_status': 'ok'})
        f.policy.raw['description'] = 'new scan policy context'
        with patch('stages._download_url', return_value=f.result(f.MAP, f.MAP_DATA)) as download:
            result = stage_javascript(f.ctx)
        download.assert_called_once()
        self.assertEqual(result['source_maps'], 1)
        self.assertEqual(result['collection_status'], 'completed')

    def test_stock_katana_uses_process_deadline_for_whole_batch(self):
        f = self.fixture(katana_fixture.KatanaExecutionQualityTests)
        with tempfile.TemporaryDirectory() as tmp:
            def run(args, **kwargs):
                self.assertEqual(args[args.index('-ct')+1], '0s')
                self.assertLess(57.5, kwargs['timeout'])
                kwargs['output_path'].write_text('https://h0.example.test/a.js\n')
                return SimpleNamespace(returncode=0, timed_out=False, operator_next=False, duration=57.5, lines=1)
            ctx = f._context(Path(tmp), SimpleNamespace(run=run))
            live = [f'https://h{i}.example.test' for i in range(5)]
            with patch('stages.tool_path', side_effect=lambda name: name == 'katana'), \
                    patch('stages._probe_live_origins', return_value=(live, [])):
                result = stage_urls(ctx)
            self.assertEqual(result['collection_status'], 'completed')
            self.assertEqual(result['katana_origins_completed'], 5)


if __name__ == '__main__':
    unittest.main()

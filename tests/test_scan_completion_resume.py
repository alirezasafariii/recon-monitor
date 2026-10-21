from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

import recon_monitor_core as runtime
import test_javascript_execution_quality as js_fixture
import test_source_map_resume as map_fixture
from execution import BudgetManager, WorkQueue
from stages import stage_javascript


class ScanCompletionResumeTests(unittest.TestCase):
    def fixture(self, kind=js_fixture.JavascriptExecutionQualityTests):
        fixture = kind()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    @staticmethod
    def success(_ctx, url, _limit):
        return {'url': url, 'status_code': 200, 'transport_status': 'ok',
                'content_type': 'application/javascript', 'data': b'const value = 1;'}

    def test_failed_items_do_not_starve_unattempted_files(self):
        f = self.fixture()
        f.ctx.policy.limits.max_js_files = 2
        urls = [f'https://example.test/{name}.js' for name in 'abcd']
        f.inputs(urls)
        calls = []
        def download(ctx, url, limit):
            calls.append(url)
            if len(calls) <= 2:
                return {'url': url, 'status_code': 503, 'error': 'http_error'}
            return self.success(ctx, url, limit)
        with patch('stages._download_url', side_effect=download):
            first = stage_javascript(f.ctx)
            second = stage_javascript(f.ctx)
            third = stage_javascript(f.ctx)
        self.assertEqual(calls, urls[:2] + urls[2:] + urls[:2])
        self.assertEqual([r['collection_status'] for r in (first, second, third)],
                         ['partial', 'partial', 'completed'])
        self.assertEqual(len((f.ctx.current / 'javascript-availability.jsonl').read_text().splitlines()), 4)

    def test_failed_remote_javascript_can_be_recovered_locally(self):
        f = self.fixture()
        f.ctx.resume_failed_work = True
        url = 'https://example.test/app.js'
        f.inputs([url])
        queue = WorkQueue(f.ctx.db, f.ctx.run_id, f.ctx.policy.name, 'javascript-items')
        work_id = queue.enqueue(url)
        queue.start(work_id, 'remote-fixture')
        queue.fail(work_id, 'http_error', retry=False, result={
            'url': url, 'status_code': 400, 'transport_status': 'ok', 'error': 'http_error'})
        with patch('stages._download_url', side_effect=self.success) as download:
            result = stage_javascript(f.ctx)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(result['collection_status'], 'completed')
        self.assertEqual(queue.counts(), {'completed': 1})

    def test_failed_map_can_resume_without_downloading_the_parent_again(self):
        f = self.fixture(map_fixture.SourceMapResumeTests)
        f.ctx.resume_failed_work = True
        f.first_failure()
        item = f.map_items()[0]
        queue = WorkQueue(f.db, f.run_id, f.policy.name, 'javascript-source-map-items')
        queue.fail(item['id'], 'old terminal failure', retry=False)
        with patch('stages._download_url', return_value=f.result(f.MAP, f.MAP_DATA)) as download:
            result = stage_javascript(f.ctx)
        download.assert_called_once_with(f.ctx, f.MAP, f.policy.limits.max_js_bytes)
        self.assertEqual(result['collection_status'], 'completed')

    def run_stage(self, f):
        orchestrator = runtime.Orchestrator(f.ctx.paths, f.ctx.config, f.ctx.logger,
                                           f.ctx.db, progress=False, allow_active=False)
        self.addCleanup(orchestrator.db_writer.close)
        f.ctx.runner = orchestrator.runner
        f.ctx.progress = orchestrator.progress
        with patch('recon_monitor_core.time.sleep'):
            return orchestrator._run_stage(f.ctx, 'javascript', 'JavaScript', 1, 1, 1, 1, True, False)

    def test_transient_failure_retries_within_policy_without_refetching_healthy_files(self):
        f = self.fixture()
        urls = ['https://example.test/healthy.js', 'https://example.test/retry.js']
        f.inputs(urls)
        calls = []
        def download(ctx, url, limit):
            calls.append(url)
            if url == urls[1] and calls.count(url) == 1:
                return {'url': url, 'status_code': 503, 'error': 'http_error'}
            return self.success(ctx, url, limit)
        with patch('stages._download_url', side_effect=download):
            status, metrics = self.run_stage(f)
        self.assertEqual(status, 'success')
        self.assertEqual(metrics['collection_status'], 'completed')
        self.assertEqual(calls.count(urls[0]), 1)
        self.assertEqual(calls.count(urls[1]), 2)
        self.assertEqual(f.ctx.db.stage_status(f.ctx.run_id, f.ctx.policy.name, 'javascript'), 'success')
        self.assertEqual((f.ctx.current / 'javascript-errors.jsonl').read_text(), '')

    def test_retries_are_bounded_and_persistent_failure_retains_partial(self):
        for code, expected in ((503, 2), (400, 1), (429, 1)):
            with self.subTest(status_code=code):
                f = self.fixture()
                f.ctx.policy.limits.retries = 1
                url = 'https://example.test/app.js'
                f.inputs([url])
                with patch('stages._download_url', return_value={
                    'url': url, 'status_code': code, 'error': 'http_error', 'transport_status': 'ok',
                }) as download:
                    _, metrics = self.run_stage(f)
                self.assertEqual(download.call_count, expected)
                self.assertEqual(metrics['collection_status'], 'partial')
                self.assertEqual(f.ctx.db.stage_status(f.ctx.run_id, f.ctx.policy.name, 'javascript'), 'partial')
                saved = json.loads((f.ctx.current / 'javascript-errors.jsonl').read_text())
                self.assertEqual(saved['status_code'], code)
                self.assertEqual(metrics['download_http_status_summary'], f'HTTP {code}=1')
                self.assertEqual(metrics['collection_attempt'], expected)
                if code == 400:
                    self.assertIn('HTTP 400', metrics['completion_next_action'])
                    self.assertIn('refresh', metrics['completion_next_action'])

    def test_transport_timeout_retries_but_scope_budget_and_cooldown_do_not(self):
        for error, expected in (
            ('connection timed out', 2), ('Run budget exhausted: http_requests 2/1', 1),
            ('non_public_resolution_blocked', 1), ('HTTP host is in rate_limit_cooldown', 1),
            ('outside_scope_or_invalid_url', 1),
        ):
            with self.subTest(error=error):
                f = self.fixture()
                f.ctx.policy.limits.retries = 1
                url = 'https://example.test/app.js'
                f.inputs([url])
                with patch('stages._download_url', return_value={'url': url, 'error': error}) as download:
                    _, metrics = self.run_stage(f)
                self.assertEqual(download.call_count, expected)
                self.assertEqual(metrics['collection_status'], 'partial')

    def test_operator_next_prevents_retry_even_with_another_transient_failure(self):
        f = self.fixture()
        urls = ['https://example.test/a.js', 'https://example.test/b.js']
        f.inputs(urls)
        f.ctx.policy.limits.js_workers = 1
        def download(ctx, url, _limit):
            if url == urls[0]:
                return {'url': url, 'status_code': 503, 'error': 'http_error'}
            self.assertTrue(ctx.db.request_stage_next(ctx.run_id, ctx.policy.name, 'javascript', 1, 'analyst'))
            return {'url': url, 'operator_next': True}
        with patch('stages._download_url', side_effect=download) as calls:
            _, metrics = self.run_stage(f)
        self.assertEqual(calls.call_count, 2)
        self.assertEqual(metrics['collection_status'], 'partial')
        self.assertEqual(metrics['collection_attempt'], 1)
        self.assertIn('operator_next', metrics['collection_reasons'])

    def test_automatic_retry_preserves_the_cumulative_request_budget(self):
        f = self.fixture()
        url = 'https://example.test/app.js'
        f.inputs([url])
        f.ctx.policy.limits.max_http_requests = 1
        f.ctx.budget = BudgetManager.create(f.ctx.db, f.ctx.run_id, f.ctx.policy.name, f.ctx.policy)
        admitted = []
        def transport(candidate, _policy, **kwargs):
            kwargs['before_request'](candidate)
            admitted.append(candidate)
            return {'status_code': 503, 'error': 'http_error', 'headers': {}, 'transport_status': 'ok'}
        with patch('stages.perform_pinned_download', side_effect=transport):
            _, metrics = self.run_stage(f)
        self.assertEqual(admitted, [url])
        self.assertEqual(f.ctx.budget.snapshot()['http_requests']['used'], 1)
        self.assertEqual(metrics['collection_status'], 'partial')
        self.assertIn('budget', metrics['completion_next_action'].lower())


if __name__ == '__main__':
    unittest.main()

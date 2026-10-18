import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import Database, StageError
from katana_reliability import load_shared_throttle_state, persist_shared_throttle_state, register_throttling
from stages import _download_url, _origin_probe_one, _safe_validate_endpoint, stage_urls, stage_fingerprint, stage_nuclei
import test_javascript_execution_quality as fixture


class SharedHTTPCooldownTests(unittest.TestCase):
    def context(self):
        f = fixture.JavascriptExecutionQualityTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        (f.ctx.current / 'resolved-hosts.txt').write_text('example.test\n')
        return f.ctx

    def test_fresh_run_and_policy_cannot_probe_cooling_host(self):
        ctx = self.context()
        with patch('katana_reliability.time.time', return_value=1000), patch('stages.time.time', return_value=1000), \
                patch('stages.tool_path', return_value=None), patch('stages._probe_live_origins', return_value=([], [
                    {'url': 'https://example.test', 'status_code': 429, 'transport_status': 'stopped_for_safety'}])):
            first = stage_urls(ctx)
        self.assertEqual(first['collection_status'], 'partial')
        ctx.db.close()
        ctx.db = Database(ctx.paths.db)
        self.addCleanup(ctx.db.close)
        ctx.run_id = ctx.db.create_run(ctx.policy.name, 1, 'fresh')
        ctx.run_dir = ctx.paths.output / ctx.run_id
        ctx.policy.raw['new_policy'] = True
        ctx.db.create_run_target(ctx.run_id, ctx.policy, ctx.run_dir, False)
        (ctx.current / 'resolved-hosts.txt').write_text('example.test\n')
        with patch('katana_reliability.time.time', return_value=1001), patch('stages.tool_path', return_value=None), \
                patch('stages._probe_live_origins', return_value=([], [])) as probe:
            second = stage_urls(ctx)
        probe.assert_called_once_with(ctx, [])
        self.assertEqual(second['collection_status'], 'partial')
        self.assertIn('katana_rate_limit_cooldown', second['collection_reasons'])
        # After expiry, both schemes may be probed again.
        with patch('katana_reliability.time.time', return_value=4601), patch('stages.tool_path', return_value=None), \
                patch('stages._probe_live_origins', return_value=([], [])) as probe:
            stage_urls(ctx)
        self.assertEqual(set(probe.call_args.args[1]), {'https://example.test', 'http://example.test'})

    def test_legacy_file_is_imported_into_shared_state(self):
        ctx = self.context()
        (ctx.current / 'katana-throttle-state.json').write_text(json.dumps({
            'version': 1, 'hosts': {'example.test': {'retry_not_before': 5000, 'reason': 'http_429'}}}))
        with patch('katana_reliability.time.time', return_value=2000), patch('stages.tool_path', return_value=None), \
                patch('stages._probe_live_origins', return_value=([], [])):
            stage_urls(ctx)
        self.assertIn('example.test', load_shared_throttle_state(ctx.db, now=2001))

    def test_in_process_http_entry_points_respect_shared_state(self):
        ctx = self.context()
        persist_shared_throttle_state(ctx.db, {'example.test': {'retry_not_before': 5000}}, ctx.run_id)
        url = 'https://example.test/app.js'
        def transport(_url, _policy, **kwargs):
            kwargs['before_request'](url)
            self.fail('request passed cooldown gate')
        with patch('katana_reliability.time.time', return_value=2000), \
                patch('stages.perform_pinned_request', side_effect=AssertionError('probe attempted')):
            self.assertEqual(_origin_probe_one(ctx, url)['error'], 'rate_limit_cooldown')
            self.assertEqual(_safe_validate_endpoint(ctx, url)['error'], 'rate_limit_cooldown')
            with patch('stages.perform_pinned_download', side_effect=transport):
                with self.assertRaisesRegex(StageError, 'rate_limit_cooldown'):
                    _download_url(ctx, url, 1000)

    def test_concurrent_runs_cannot_shorten_cooldown_and_hosts_are_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.db'
            Database(path).close()
            errors = []
            def write(until):
                db = Database(path)
                try:
                    persist_shared_throttle_state(db, {'example.test': {'retry_not_before': until}}, str(until))
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    db.close()
            threads = [threading.Thread(target=write, args=(value,)) for value in (3000, 9000, 4000, 5000)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(errors, [])
            db = Database(path)
            try:
                self.assertEqual(load_shared_throttle_state(db, now=1000)['example.test']['retry_not_before'], 9000)
                self.assertEqual(load_shared_throttle_state(db, now=9000), {})
                self.assertEqual(load_shared_throttle_state(db, now=1000, host='other.test'), {})
            finally:
                db.close()

    def test_longer_retry_after_is_preserved_across_stage_bookkeeping(self):
        ctx = self.context()
        state = {}
        register_throttling(state, ['example.test'], now=1000, retry_after='7200')
        self.assertEqual(state['example.test']['retry_not_before'], 8200)
        persist_shared_throttle_state(ctx.db, state, 'first')
        shorter = {}
        register_throttling(shorter, ['example.test'], now=1100)
        persist_shared_throttle_state(ctx.db, shorter, 'second')
        self.assertEqual(load_shared_throttle_state(ctx.db, now=5000)['example.test']['retry_not_before'], 8200)
        register_throttling(state, ['other.test'], now=1000, retry_after='Thu, 01 Jan 1970 02:30:00 GMT')
        self.assertEqual(state['other.test']['retry_not_before'], 9000)

    def test_external_http_tools_do_not_admit_throttled_hosts(self):
        ctx = self.context()
        persist_shared_throttle_state(ctx.db, {'example.test': {'retry_not_before': 5000}}, ctx.run_id)
        url = 'https://example.test/'
        (ctx.current / 'base-urls.txt').write_text(url + '\n')
        (ctx.changes / 'new-live-http.txt').write_text(url + '\n')
        ctx.policy.modules['nuclei'] = True
        ctx.policy.active['nuclei_template_ids'] = ['test-template']
        with patch('katana_reliability.time.time', return_value=2000), \
                patch('stages.tool_path', return_value='tool'), patch.object(type(ctx.policy), 'active_allowed', return_value=True), \
                patch.object(ctx.runner, 'run', create=True, side_effect=AssertionError('external tool ran')):
            self.assertEqual(stage_fingerprint(ctx)['collection_status'], 'partial')
            self.assertEqual(stage_nuclei(ctx)['collection_status'], 'partial')

    def test_probe_retains_server_retry_after_in_shared_state(self):
        ctx = self.context()
        def request(item, _policy, **kwargs):
            return kwargs['observation']('HEAD', item['url'], 429, {'Retry-After': '7200'}, b'', 'http_error'), 'stopped_for_safety'
        with patch('stages.time.time', return_value=1000), patch('stages.perform_pinned_request', side_effect=request):
            self.assertEqual(_origin_probe_one(ctx, 'https://example.test')['status_code'], 429)
        self.assertEqual(load_shared_throttle_state(ctx.db, now=1001)['example.test']['retry_not_before'], 8200)

    def test_existing_revision_is_upgraded_without_losing_data(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.db'
            db = Database(path)
            db.execute('DROP TABLE http_host_cooldowns')
            db.execute("UPDATE schema_meta SET value='recon-reliability-20261018-1' WHERE key='migration_revision'")
            db.close()
            db = Database(path)
            try:
                persist_shared_throttle_state(db, {'example.test': {'retry_not_before': 5000}}, 'new')
                self.assertIn('example.test', load_shared_throttle_state(db, now=1000))
            finally:
                db.close()

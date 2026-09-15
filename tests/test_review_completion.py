from __future__ import annotations

import json
import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import recon_monitor_core
import test_baseline_raw_analysis_v960 as baseline_fixture
import test_recon_alert_outbox as outbox_fixture
import test_finding_notifications as finding_fixture
from analysis_engine import run_analysis, replay_analysis
from analysis_input_snapshot import analysis_inputs
from bug_candidates import _raw_surface_rows
from core import ReconError, utc_now
from finding_notifications import process_finding_notifications
from finding_notification_outbox import deliver_finding_notification_outbox
from recon_alert_outbox import deliver_recon_alert_outbox


class ReviewCompletionTests(unittest.TestCase):
    def test_renewal_blocks_reclaim_and_cannot_resurrect_expired_lease(self):
        from recon_alert_outbox import _claim_due_rows
        from notification_leases import renew_recon_lease
        fx = outbox_fixture.ReconAlertOutboxTests()
        fx.setUp()
        try:
            fx._enqueue(fx._alert())
            owner, rows = _claim_due_rows(fx.db, now='2099-01-01T00:00:00Z', target='', run_id='', limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(renew_recon_lease(fx.db.conn, owner, now=dt.datetime(2099, 1, 1, 0, 4, tzinfo=dt.timezone.utc)), 1)
            _, reclaimed = _claim_due_rows(fx.db, now='2099-01-01T00:06:00Z', target='', run_id='', limit=10)
            self.assertEqual(reclaimed, [])
            self.assertEqual(renew_recon_lease(fx.db.conn, owner, now=dt.datetime(2099, 1, 1, 0, 10, tzinfo=dt.timezone.utc)), 0)
            _, reclaimed = _claim_due_rows(fx.db, now='2099-01-01T00:10:00Z', target='', run_id='', limit=10)
            self.assertEqual(len(reclaimed), 1)
        finally:
            fx.tearDown()

    def test_snapshot_preserves_javascript_and_cleans_up_after_failure(self):
        from analysis_input_snapshot import _freeze_blob
        temp, paths, db, ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        try:
            source = paths.state / 'original.js'
            source.write_text('old content')
            frozen = Path(_freeze_blob(paths, str(source)))
            source.write_text('new content')
            self.assertEqual(frozen.read_text(), 'old content')
            with self.assertRaisesRegex(RuntimeError, 'test interruption'):
                with analysis_inputs(paths, db, 'RUN-BASELINE', 'example.test'):
                    raise RuntimeError('test interruption')
            self.assertFalse(db.all("SELECT name FROM sqlite_temp_master WHERE type='table'"))
        finally:
            db.close()
            temp.cleanup()

    def test_replay_preserves_raw_inputs_after_new_scan(self):
        temp, paths, db, ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        try:
            now = utc_now()
            db.execute('''INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,
                confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                ('example.test', 'https://example.test/login', 'endpoint', 'authentication', 80,
                 '[]', '[]', '[]', now, now, 'RUN-BASELINE'))
            first = run_analysis(paths, db, 'RUN-BASELINE', 'example.test')
            db.execute("UPDATE endpoint_intelligence SET last_run_id='RUN-NEXT',endpoint='https://example.test/other'")
            second = replay_analysis(paths, db, 'RUN-BASELINE', 'example.test')
            self.assertGreater(first['bug_candidates']['raw_surface_routing']['hypotheses'], 0)
            self.assertEqual(first['bug_candidates']['raw_surface_routing']['hypotheses'],
                             second['bug_candidates']['raw_surface_routing']['hypotheses'])
            self.assertEqual(first['input_snapshot'], second['input_snapshot'])
            self.assertEqual(db.one('SELECT last_run_id FROM endpoint_intelligence')[0], 'RUN-NEXT')
            aggregate = replay_analysis(paths, db, 'RUN-BASELINE')
            self.assertEqual(first['bug_candidates']['raw_surface_routing']['hypotheses'],
                             aggregate['bug_candidates']['raw_surface_routing']['hypotheses'])
        finally:
            db.close()
            temp.cleanup()

    def test_missing_or_corrupted_snapshot_fails_closed(self):
        temp, paths, db, ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        try:
            with self.assertRaisesRegex(ReconError, 'no immutable'):
                replay_analysis(paths, db, 'RUN-BASELINE', 'example.test')
            run_analysis(paths, db, 'RUN-BASELINE', 'example.test')
            db.execute("UPDATE analysis_input_snapshots SET payload_json='{}'")
            with self.assertRaisesRegex(ReconError, 'integrity'):
                replay_analysis(paths, db, 'RUN-BASELINE', 'example.test')
            self.assertFalse(db.all('SELECT * FROM sqlite_temp_master WHERE type=\'table\''))
        finally:
            db.close()
            temp.cleanup()

    def test_raw_inventory_includes_last_page_and_dns(self):
        temp, paths, db, ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        try:
            now = utc_now()
            with db.transaction():
                db.conn.executemany('''INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,
                    confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                    [('example.test', f'https://example.test/{i:05}', 'endpoint', 'general', 80,
                      '[]', '[]', '[]', now, now, 'RUN-BASELINE') for i in range(5001)])
            db.execute('''INSERT INTO dns_records(target,host,rrtype,value,first_seen,last_seen,last_run_id,is_current)
                VALUES('example.test','cdn.example.test','CNAME','provider.test',?,?, 'RUN-BASELINE',1)''', (now, now))
            rows = _raw_surface_rows(db, run_id='RUN-BASELINE', target='example.test')
            self.assertEqual(len(rows), 5002)
            self.assertTrue(any(row['endpoint'].endswith('/05000') for row in rows))
            self.assertTrue(any(row['kind'] == 'dns_cname' for row in rows))
        finally:
            db.close()
            temp.cleanup()

    def test_long_messages_and_large_queue_preserve_every_event(self):
        fx = outbox_fixture.ReconAlertOutboxTests()
        fx.setUp()
        try:
            ids = [fx._alert(dedup_key=f'event-{i}') for i in range(105)]
            for aid in ids:
                fx._enqueue(aid)
            row = fx.db.one('SELECT event_id,payload_json FROM recon_alert_notification_outbox WHERE alert_id=?', (ids[0],))
            payload = json.loads(row['payload_json'])
            payload['item'] = 'x' * 16000 + 'END-OF-CHANGE'
            fx.db.execute('UPDATE recon_alert_notification_outbox SET payload_json=? WHERE event_id=?',
                          (json.dumps(payload), row['event_id']))
            messages = []
            def send(*args):
                messages.append(args[-1])
                return {'delivered': len(messages) != 2, 'channel': 'fixture'}
            result = deliver_recon_alert_outbox(config=None, logger=None, db=fx.db, limit=500, transport=send)
            self.assertEqual(result['delivered'], 104)
            self.assertEqual(result['retry_pending'], 1)
            self.assertEqual(len(messages), 105)
            self.assertTrue(any('END-OF-CHANGE' in msg for msg in messages))
            self.assertEqual(fx.db.one("SELECT COUNT(*) FROM alerts WHERE last_notified IS NOT NULL")[0], 104)
        finally:
            fx.tearDown()

    def test_lost_lease_cannot_acknowledge_or_send_next_event(self):
        fx = outbox_fixture.ReconAlertOutboxTests()
        fx.setUp()
        try:
            fx._enqueue(fx._alert(dedup_key='first'))
            fx._enqueue(fx._alert(dedup_key='second'))
            calls = []
            def send(*args):
                calls.append(args[-1])
                fx.db.execute("UPDATE recon_alert_notification_outbox SET lease_id='another-worker'")
                return {'delivered': True}
            result = deliver_recon_alert_outbox(config=None, logger=None, db=fx.db, transport=send)
            self.assertEqual(len(calls), 1)
            self.assertEqual(result['delivered'], 0)
            self.assertEqual(fx.db.one("SELECT COUNT(*) FROM alerts WHERE last_notified IS NOT NULL")[0], 0)
        finally:
            fx.tearDown()

    def test_findings_never_notify_on_first_or_later_scan(self):
        fx = finding_fixture.FindingNotificationTests()
        fx.setUp()
        try:
            for i in (1, 2):
                fx._analysis(f'AN-{i}', f'RUN-{i}')
                fx._candidate(f'AN-{i}', f'RUN-{i}', f'C-{i}', investigation=99, state='strong_candidate')
                result = process_finding_notifications(fx._ctx(f'RUN-{i}'), {'analysis_id': f'AN-{i}'}, baseline=i == 1)
                self.assertEqual(result['queued'], 0)
                self.assertTrue(result['baseline_suppresses_findings'])
            with patch('finding_notification_outbox.deliver_notification_message') as send:
                result = deliver_finding_notification_outbox(config=fx.config, logger=fx.logger, db=fx.db)
                send.assert_not_called()
                self.assertEqual(result['delivered'], 0)
            self.assertEqual(fx.db.one('SELECT COUNT(*) FROM bug_candidates')[0], 2)
        finally:
            fx.tearDown()

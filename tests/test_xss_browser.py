from __future__ import annotations
import html
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, Config, Database, PolicySet, ReconError, APP_VERSION, utc_now
import xss_browser as worker

class Fixture(BaseHTTPRequestHandler):
    stored = ''
    posts = 0
    def log_message(self, *args): pass
    def do_POST(self):
        Fixture.posts += 1
        body = self.rfile.read(int(self.headers.get('Content-Length', '0'))).decode()
        Fixture.stored = urllib.parse.parse_qs(body).get('text', [''])[0]
        self.send_response(303); self.send_header('Location', '/read'); self.end_headers()
    def do_GET(self):
        p = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(p.query).get('q', [''])[0]
        csp = ''
        if p.path == '/session':
            if self.headers.get('Cookie') != 'session=synthetic-test-secret':
                self.send_response(401); self.end_headers(); return
            body = '<p>' + q + '</p>'
        elif p.path == '/dom':
            body = '<div id="out"></div><script>out.innerHTML=decodeURIComponent(location.hash.slice(1))</script>'
        elif p.path == '/dom-safe':
            body = '<div id="out"></div><script>out.textContent=decodeURIComponent(location.hash.slice(1))</script>'
        elif p.path == '/write':
            body = '<form method="post" action="/write"><textarea name="text"></textarea><button>Save</button></form>'
        elif p.path == '/read': body = Fixture.stored
        elif p.path == '/attribute': body = '<input value=\"' + q + '\">'
        elif p.path == '/js-single': body = "<script>const q='" + q + "';</script>"
        elif p.path == '/js-double': body = '<script>const q=\"' + q + '\";</script>'
        elif p.path == '/same-redirect':
            self.send_response(302); self.send_header('Location', '/reflect?' + p.query); self.end_headers(); return
        elif p.path == '/denied':
            self.send_response(403); self.end_headers(); return
        elif p.path == '/large': body = 'x' * (2 * 1024 * 1024) + '<p>' + q + '</p>'
        elif p.path == '/safe': body = '<p>' + html.escape(q) + '</p>'
        elif p.path == '/csp':
            body = q; csp = "script-src 'none'"
        elif p.path == '/redirect':
            self.send_response(302); self.send_header('Location', 'http://outside.test/'); self.end_headers(); return
        elif p.path.startswith('/.__recon_xss_missing_'):
            self.send_response(404); self.end_headers(); return
        else: body = '<p>' + q + '</p>'
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        if csp: self.send_header('Content-Security-Policy', csp)
        self.end_headers(); self.wfile.write(body.encode())

class BrowserWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest('Optional Playwright dependency is not installed')
        cls.executable = os.environ.get('XSS_TEST_CHROMIUM') or shutil.which('chromium')
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch(executable_path=cls.executable)
        except Exception:
            cls.pw.stop()
            raise unittest.SkipTest('Chromium unavailable; install optional browser dependencies')
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), getattr(cls, 'handler', Fixture))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.base = 'http://fixture.test:' + str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.browser.close(); cls.pw.stop(); cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.paths = AppPaths.from_root(Path(self.tmp.name)); self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\n')
        self.paths.policy.write_text(json.dumps({'targets': [{'name': 'fixture.test', 'roots': ['fixture.test'], 'active': {'confirmation': 'I_AM_AUTHORIZED_FOR_ACTIVE_TESTING'}}]}))
        self.policy = PolicySet.load(self.paths).targets[0]
        self.pinning = patch.object(worker, 'resolve_public_addresses', return_value=(True, ['127.0.0.1']))
        self.pinning.start(); self.addCleanup(self.pinning.stop)
    def spec(self, path, family='reflected_xss', kind='query'):
        return {'id': 'test', 'family': family, 'url': self.base + path, 'input': {'kind': kind, 'name': 'q'}}
    def execute(self, test, **kwargs):
        plan = {'version': 1, 'target': 'fixture.test', 'tests': [test], 'max_seconds': 20, 'max_requests': 30}
        worker.validate_plan(plan, self.policy)
        return worker.execute_test(self.browser, self.policy, plan, test, verify=True, allow_write=kwargs.get('write', False))
    def test_reflected_executes_and_safe_encoding_does_not(self):
        vulnerable = self.execute(self.spec('/reflect'))
        self.assertEqual(vulnerable['status'], 'execution_observed', vulnerable)
        self.assertTrue(vulnerable['phases'][-1]['analysis']['direct'])
        safe = self.execute(self.spec('/safe'))
        self.assertEqual(safe['status'], 'not_demonstrated', safe)
        self.assertFalse(safe['phases'][-1]['analysis']['direct'])
    def test_attribute_and_javascript_string_contexts(self):
        for path in ('/attribute', '/js-single', '/js-double'):
            with self.subTest(path=path):
                result = self.execute(self.spec(path))
                self.assertEqual(result['status'], 'execution_observed', result)
                self.assertTrue(result['phases'][-1]['analysis']['direct'])

    def test_same_origin_redirect_and_access_denied(self):
        result = self.execute(self.spec('/same-redirect'))
        self.assertEqual(result['status'], 'execution_observed', result)
        result = self.execute(self.spec('/denied'))
        self.assertEqual(result['status'], 'incomplete', result)

    def test_csp_keeps_unescaped_reflection_unconfirmed(self):
        result = self.execute(self.spec('/csp'))
        self.assertEqual(result['status'], 'not_demonstrated', result)
        self.assertFalse(result['confirmed'])
    def test_dom_runtime_flow_and_execution(self):
        result = self.execute(self.spec('/dom', 'dom_xss', 'hash'))
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertTrue(result['sink_events'])
        self.assertTrue(result['phases'][-1]['analysis']['direct'])
        safe = self.execute(self.spec('/dom-safe', 'dom_xss', 'hash'))
        self.assertEqual(safe['status'], 'not_demonstrated', safe)
        self.assertFalse(safe['sink_events'])
    def test_stored_write_read_workflow(self):
        test = self.spec('/write', 'stored_xss', 'form')
        test['steps'] = [{'action': 'fill', 'selector': 'textarea', 'value': '{probe}'},
                         {'action': 'click', 'selector': 'button'},
                         {'action': 'goto', 'url': self.base + '/read'}]
        test['cleanup'] = [{'action': 'goto', 'url': self.base + '/write'},
                           {'action': 'fill', 'selector': 'textarea', 'value': ''},
                           {'action': 'click', 'selector': 'button'}]
        result = self.execute(test, write=True)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertTrue(result['phases'][-1]['analysis']['direct'], result)
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(Fixture.stored, '')
    def test_redirect_scope_block_and_legacy_budgets_are_ignored(self):
        result = self.execute(self.spec('/redirect'))
        self.assertEqual(result['status'], 'incomplete', result)
        plan = {'max_requests': 1, 'max_seconds': 0}
        test = self.spec('/reflect')
        result = worker.execute_test(self.browser, self.policy, plan, test, verify=True, allow_write=False)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertGreater(len(result['requests']), 1)
        large = worker.execute_test(self.browser, self.policy, plan, self.spec('/large'), verify=True, allow_write=False)
        self.assertEqual(large['status'], 'execution_observed', large)
        self.assertGreater(sum(r.get('bytes', 0) for r in large['requests']), 2 * 1024 * 1024)
        calls = [0]
        def stop_during_stream():
            calls[0] += 1
            if calls[0] >= 5:
                raise InterruptedError('synthetic stop')
        stopped = worker.execute_test(self.browser, self.policy, plan, self.spec('/large'),
            verify=False, allow_write=False, check=stop_during_stream)
        self.assertEqual(stopped['status'], 'incomplete')
    def test_storage_state_authentication_and_secret_redaction(self):
        test = self.spec('/session')
        denied = self.execute(test)
        self.assertEqual(denied['status'], 'incomplete')
        state = {'cookies': [{'name': 'session', 'value': 'synthetic-test-secret', 'domain': 'fixture.test',
                              'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}], 'origins': []}
        result = worker.execute_test(self.browser, self.policy, {'max_requests': 30, 'max_seconds': 20},
            test, verify=True, allow_write=False, storage_state=state)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertNotIn('synthetic-test-secret', json.dumps(result))

    def test_private_dns_is_blocked_before_connect(self):
        with patch.object(worker, 'resolve_public_addresses', return_value=(False, ['127.0.0.1'])), patch.object(worker, 'build_pinned_opener') as connect:
            result = self.execute(self.spec('/reflect'))
        self.assertEqual(result['status'], 'incomplete')
        connect.assert_not_called()

    def test_cli_help_and_invalid_plan(self):
        import recon_monitor
        args = recon_monitor.build_parser().parse_args(['xss-browser', '--plan', 'a', '--analysis', 'b'])
        self.assertEqual(args.analysis, 'b')
        for field in ({'kind': 'eval', 'name': 'q'}, {'kind': 'query', 'name': ''}):
            test = self.spec('/'); test['input'] = field
            with self.assertRaises(ReconError):
                worker.validate_plan({'version': 1, 'target': 'fixture.test', 'tests': [test]}, self.policy)
    def test_public_run_persists_hypotheses_and_private_redacted_report(self):
        db = Database(self.paths.db); self.addCleanup(db.close)
        now = utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES('r',?,'success',?,1)", (APP_VERSION, now))
        db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,status,started_at) VALUES('a','r','fixture.test','fixture','fixture','success',?)", (now,))
        plan = {'version': 1, 'target': 'fixture.test', 'tests': [self.spec('/reflect')]}
        with self.assertRaises(ReconError): worker.run(self.paths, db, plan, analysis_id='a')
        self.browser.close(); self.pw.stop()
        try:
            result = worker.run(self.paths, db, plan, analysis_id='a', allow_active=True, verify=True, executable=self.executable)
            import hunt_agent
            db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,run_dir) VALUES('r','fixture.test','fixture','success',?,?)", (now, str(self.paths.output / 'r')))
            plan_path = self.paths.root / 'browser-plan.json'
            plan_path.write_text(json.dumps(plan))
            mission = hunt_agent.create_mission(self.paths, db, target='fixture.test', source_run='r',
                planner='rules', max_cases=1, browser_plan=str(plan_path), browser_active=True,
                browser_verify=True, browser_chromium=self.executable or '')
            mission['state']['analysis_id'] = 'a'
            hunt_agent.save(db, mission, 'ready')
            agent_result = hunt_agent.run_mission(self.paths, db, mission['mission_id'])
            stored = hunt_agent.mission(db, mission['mission_id'])
            self.assertEqual(agent_result['status'], 'completed', {'steps': stored['steps'], 'browser_report': json.loads(Path(stored['steps'][0]['result']['report']).read_text())})
            self.assertEqual([s['tool'] for s in stored['steps']], ['browser', 'investigate', 'validate', 'report'])
            self.assertTrue(stored['state']['cases'])
        finally:
            from playwright.sync_api import sync_playwright
            type(self).pw = sync_playwright().start()
            type(self).browser = self.pw.chromium.launch(executable_path=self.executable)
        self.assertEqual(result['status'], 'completed')
        report = Path(result['report']); data = report.read_text()
        self.assertNotIn('response_text', data)
        self.assertNotIn('onerror=', data)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertGreater(db.one('SELECT COUNT(*) FROM analysis_hypotheses')[0], 0)
        self.assertGreater(db.one('SELECT COUNT(*) FROM bug_candidates')[0], 0)
        self.assertGreater(db.one('SELECT COUNT(*) FROM candidate_evidence_links')[0], 0)
        self.assertGreater(db.one('SELECT COUNT(*) FROM candidate_evidence_snapshots')[0], 0)
        self.assertEqual(db.one('SELECT analyst_decision FROM bug_candidates')[0], 'unreviewed')

if __name__ == '__main__': unittest.main()

"""Native Chromium redirects: execution evidence and pinned-hop controls."""
from __future__ import annotations

import html
import json
import unittest
import urllib.parse
from unittest.mock import patch

import test_xss_browser as fixtures
import xss_browser as worker


class RedirectFixture(fixtures.Fixture):
    writes = []
    direct_hits = 0

    def do_POST(self):
        p = urllib.parse.urlsplit(self.path)
        if p.path.startswith('/write-'):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            RedirectFixture.writes.append(p.path)
            self.send_response(int(p.path.removeprefix('/write-')))
            self.send_header('Location', '/write-target')
            self.end_headers()
            return
        super().do_POST()

    do_PUT = do_POST

    def do_GET(self):
        p = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(p.query)
        path, q = p.path, query.get('q', [''])[0]
        safe = path.endswith('-safe')
        route = path.removesuffix('-safe')
        suffix = '-safe' if safe else ''
        port = str(self.server.server_port)
        if path == '/direct':
            RedirectFixture.direct_hits += 1
        if path.startswith('/hop'):
            mode = path.removeprefix('/hop')
            final = '/dir/final' if mode.startswith('-relative') else '/final' + mode
            self.send_response(int(query.get('status', ['302'])[0]))
            target = ('http://cdn.fixture.test:' + port if mode.startswith('-cors') else '') + final
            self.send_header('Location', target + '?' + p.query)
            if mode.startswith('-cookie'):
                self.send_header('Set-Cookie', 'redirect_session=synthetic-private; HttpOnly; SameSite=Lax; Path=/')
            self.end_headers()
            return
        if route == '/session-bounce':
            self.send_response(302)
            ready = 'redirect_session=synthetic-private' in self.headers.get('Cookie', '')
            self.send_header('Location', ('/final-cookie' if ready else '/session-bounce') + suffix + '?' + p.query)
            if not ready:
                self.send_header('Set-Cookie', 'redirect_session=synthetic-private; HttpOnly; Path=/')
            self.end_headers(); return
        if path in {'/loop-a', '/loop-b'}:
            self.send_response(302); self.send_header('Location', '/loop-b' if path.endswith('a') else '/loop-a'); self.end_headers(); return
        if path == '/outside':
            self.send_response(302); self.send_header('Location', 'http://outside.test/leak?' + p.query); self.end_headers(); return
        if path == '/private':
            self.send_response(302); self.send_header('Location', 'http://private.fixture.test:' + port + '/final?' + p.query); self.end_headers(); return
        if path == '/reader-bounce':
            self.send_response(302); self.send_header('Location', '/reader-final'); self.end_headers(); return
        if route.startswith('/final-cookie') and 'redirect_session=synthetic-private' not in self.headers.get('Cookie', ''):
            self.send_response(403); self.end_headers(); return
        media = 'text/html; charset=utf-8'
        if route in {'/fetch', '/fetch-json', '/fetch-cookie', '/fetch-cookie-loop', '/fetch-cors', '/xhr', '/iframe', '/iframe-dom', '/iframe-relative', '/iframe-sandbox', '/iframe-nested'}:
            mode = '-json' if route == '/fetch-json' else '-cookie' if route == '/fetch-cookie' else '-cors' if route == '/fetch-cors' else '-dom' if route == '/iframe-dom' else '-relative' if route == '/iframe-relative' else ''
            start = '/hop' + mode + suffix + '?' + p.query
            if route == '/fetch-cookie-loop':
                start = '/session-bounce' + suffix + '?' + p.query
            if route == '/xhr':
                body = '<div id="out"></div><script>const x=new XMLHttpRequest();x.open("GET",' + json.dumps(start) + ');x.onload=()=>{if(new URL(x.responseURL).pathname.startsWith("/final"))out.innerHTML=x.responseText};x.send()</script>'
            elif route.startswith('/iframe'):
                if route == '/iframe-dom':
                    start += '#' + urllib.parse.quote(q, safe='')
                elif route == '/iframe-nested':
                    start = '/nested' + suffix + '?' + p.query
                body = '<iframe ' + ('sandbox="allow-scripts" ' if route == '/iframe-sandbox' else '') + 'src="' + html.escape(start, quote=True) + '"></iframe>'
            else:
                render = 'r.json().then(v=>v.html)' if mode == '-json' else 'r.text()'
                body = '<div id="out"></div><script>fetch(' + json.dumps(start) + ').then(r=>{if(!r.redirected||!new URL(r.url).pathname.startsWith("/final"))throw Error("native redirect metadata missing");return ' + render + '}).then(v=>out.innerHTML=v)</script>'
        elif route == '/nested':
            body = '<iframe src="' + html.escape('/hop' + suffix + '?' + p.query, quote=True) + '"></iframe>'
        elif route == '/final-dom':
            body = '<div id="out"></div><script>out.' + ('textContent' if safe else 'innerHTML') + '=decodeURIComponent(location.hash.slice(1))</script>'
        elif path == '/dir/final':
            body = '<div id="out"></div><script src="relative.js"></script>'
        elif path == '/dir/relative.js':
            media = 'application/javascript'
            body = 'out.innerHTML=new URL(location.href).searchParams.get("q")'
        elif route.startswith('/final'):
            value = html.escape(q) if safe else q
            body = json.dumps({'html': value}) if route == '/final-json' else value
            if route == '/final-json':
                media = 'application/json'
        elif route in {'/blocked-fetch', '/loop-fetch', '/private-fetch'}:
            start = '/outside' if route == '/blocked-fetch' else '/loop-a' if route == '/loop-fetch' else '/private'
            body = '<script>fetch(' + json.dumps(start + '?' + p.query) + ').catch(()=>{})</script>'
        elif route == '/blocked-iframe':
            body = '<iframe src="/outside?' + html.escape(p.query, quote=True) + '"></iframe>'
        elif route == '/writer':
            body = '<p>controlled write workflow</p>'
        elif route == '/reader-final':
            body = '<script>fetch("/write-307",{method:"POST",body:"reader-write"}).catch(()=>{})</script>'
        else:
            return super().do_GET()
        self.send_response(200); self.send_header('Content-Type', media)
        if route == '/final-cors' and query.get('allow') == ['1']:
            self.send_header('Access-Control-Allow-Origin', 'http://fixture.test:' + port)
        self.end_headers(); self.wfile.write(body.encode())


class BrowserRedirectTests(unittest.TestCase):
    handler = RedirectFixture
    setUpClass = classmethod(fixtures.BrowserWorkerTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.BrowserWorkerTests.tearDownClass.__func__)
    setUp = fixtures.BrowserWorkerTests.setUp
    spec = fixtures.BrowserWorkerTests.spec
    execute = fixtures.BrowserWorkerTests.execute

    def pair(self, path, family='reflected_xss'):
        for safe in (False, True):
            with self.subTest(path=path, safe=safe):
                spec = self.spec(path + ('-safe' if safe else ''), family)
                spec['probes'] = ['html']
                result = self.execute(spec)
                self.assertEqual(result['status'], 'not_demonstrated' if safe else 'execution_observed', result)
                self.assertFalse(result['confirmed'])
                redirects = [r for r in result['requests'] if r.get('status') == 302]
                self.assertTrue(redirects, result)
                self.assertTrue(any(r.get('redirected_from') in {x['id'] for x in redirects} for r in result['requests']), result)
                if not safe:
                    self.assertTrue(result['phases'][-1]['analysis']['direct'], result)
                    if family == 'dom_xss':
                        self.assertTrue(result['phases'][-1]['analysis']['family_analyzer']['exact_sink_attribution'])
                    if path.startswith('/iframe'):
                        self.assertIn('iframe', result['phases'][-1]['coverage']['executing_frames'])

    def test_native_fetch_and_xhr_redirect_pairs(self):
        for path in ('/fetch', '/fetch-json', '/xhr'):
            self.pair(path)

    def test_native_iframe_redirect_pairs(self):
        self.pair('/iframe')
        self.pair('/iframe-nested')

    def test_native_get_redirect_statuses(self):
        for status in (301, 303, 307, 308):
            with self.subTest(status=status):
                spec = self.spec('/fetch?status=' + str(status)); spec['probes'] = ['html']
                result = self.execute(spec)
                self.assertEqual(result['status'], 'execution_observed', result)
                self.assertTrue(any(r.get('status') == status for r in result['requests']))

    def test_dom_sink_in_redirected_iframe_pair(self):
        self.pair('/iframe-dom', 'dom_xss')

    def test_redirect_cookies_and_secrets(self):
        self.pair('/fetch-cookie')
        self.pair('/fetch-cookie-loop')
        spec = self.spec('/fetch-cookie'); spec['probes'] = ['html']
        self.assertNotIn('synthetic-private', json.dumps(self.execute(spec)))

    def test_cross_origin_resource_redirect_obeys_native_cors(self):
        for safe in (False, True):
            for allowed in (False, True):
                with self.subTest(safe=safe, cors=allowed):
                    spec = self.spec('/fetch-cors' + ('-safe' if safe else '') + '?allow=' + str(int(allowed)), 'dom_xss')
                    spec['probes'] = ['html']
                    spec['resource_origins'] = ['http://cdn.fixture.test:' + str(self.server.server_port)]
                    result = self.execute(spec)
                    expected = 'incomplete' if not allowed else 'not_demonstrated' if safe else 'execution_observed'
                    self.assertEqual(result['status'], expected, result)
                    if not allowed:
                        self.assertFalse(any(p['execution_observed'] for p in result['phases']))

    def test_final_iframe_url_controls_relative_resources(self):
        spec = self.spec('/iframe-relative'); spec['probes'] = ['html']
        result = self.execute(spec)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertTrue(any('/dir/relative.js' in r['url'] for r in result['requests']), result)

    def test_opaque_sandbox_execution_is_not_target_execution(self):
        spec = self.spec('/iframe-sandbox'); spec['probes'] = ['html']
        result = self.execute(spec)
        self.assertEqual(result['status'], 'not_demonstrated', result)
        self.assertFalse(any(p['execution_observed'] for p in result['phases']))

    def test_redirect_scope_is_checked_before_connect_for_fetch_and_iframe(self):
        for path in ('/blocked-fetch', '/blocked-iframe'):
            with self.subTest(path=path):
                spec = self.spec(path); spec['probes'] = ['html']
                result = self.execute(spec)
                self.assertEqual(result['status'], 'incomplete', result)
                self.assertIn('redirect_outside_scope', result['errors'])
                self.assertFalse(any('outside.test' in r['url'] for r in result['requests']))

    def test_each_redirect_hop_resolves_and_rejects_private_dns(self):
        spec = self.spec('/private-fetch'); spec['probes'] = ['html']
        spec['resource_origins'] = ['http://private.fixture.test:' + str(self.server.server_port)]
        def addresses(host, port):
            return (False, ['127.0.0.1']) if host == 'private.fixture.test' else (True, ['127.0.0.1'])
        with patch.object(worker, 'resolve_public_addresses', side_effect=addresses) as resolve:
            result = self.execute(spec)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('non_public_or_missing_dns', result['errors'])
        self.assertTrue(any(c.args[0] == 'private.fixture.test' for c in resolve.call_args_list))
        self.assertFalse(any('private.fixture.test' in r['url'] for r in result['requests']))

    def test_cycles_stop_without_a_hop_quota(self):
        spec = self.spec('/loop-fetch'); spec['probes'] = ['html']
        result = self.execute(spec)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('redirect_cycle', result['errors'])

    def test_write_redirects_never_replay_non_get_requests(self):
        for method, code in [('POST', 307), ('POST', 308), ('PUT', 302)]:
            with self.subTest(method=method, status=code):
                RedirectFixture.writes.clear()
                spec = self.spec('/writer', 'stored_xss', 'form'); spec['probes'] = ['html']
                spec['steps'] = [{'action': 'request', 'method': method, 'url': self.base + '/write-' + str(code), 'json': {'text': '{probe}'}}]
                result = self.execute(spec, write=True)
                self.assertEqual(result['status'], 'incomplete', result)
                self.assertIn('redirect_requires_non_get_replay', result['errors'])
                self.assertEqual(RedirectFixture.writes, ['/write-' + str(code)])

    def test_post_303_is_followed_as_get_without_replaying_write(self):
        RedirectFixture.writes.clear()
        spec = self.spec('/writer', 'stored_xss', 'form'); spec['probes'] = ['html']
        spec['steps'] = [{'action': 'request', 'method': 'POST', 'url': self.base + '/write-303', 'json': {'text': '{probe}'}}]
        result = self.execute(spec, write=True)
        self.assertEqual(result['status'], 'not_demonstrated', result)
        self.assertEqual(RedirectFixture.writes, ['/write-303', '/write-303'])  # One write per selected phase.
        self.assertTrue(all(r['method'] == 'GET' for r in result['requests'] if '/write-target' in r['url']))

    def test_reader_redirect_keeps_its_read_only_role(self):
        RedirectFixture.writes.clear()
        spec = self.spec('/writer', 'stored_xss', 'form'); spec['probes'] = ['html']
        spec['steps'] = [{'action': 'request', 'method': 'POST', 'url': self.base + '/write-303', 'json': {'text': '{probe}'}}]
        spec['read_session'] = {'url': self.base + '/reader-bounce'}
        result = self.execute(spec, write=True)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('outside_scope_or_unapproved_method', result['errors'])
        self.assertNotIn('/write-307', RedirectFixture.writes)

    def test_manual_stop_interrupts_native_redirect_work(self):
        calls = []
        def stop():
            calls.append(True)
            if len(calls) >= 6:
                raise InterruptedError('synthetic manual stop')
        spec = self.spec('/fetch'); spec['probes'] = ['html']
        result = worker.execute_test(self.browser, self.policy, {}, spec, verify=True, allow_write=False, check=stop)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('InterruptedError', result['errors'])

    def test_interception_failure_cannot_fall_back_to_native_target_network(self):
        from xss_browser_transport import ChromiumTransport
        def disabled(*a, **kw):
            transport = ChromiumTransport(*a, **kw)
            transport.session.send('Fetch.disable')
            return transport
        spec = self.spec('/fetch'); spec['probes'] = ['html']
        with patch.object(worker, 'ChromiumTransport', side_effect=disabled):
            result = self.execute(spec)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertEqual(result['requests'], [])

    def test_unattached_browser_requests_cannot_connect_even_to_ip_literals(self):
        from xss_browser_transport import RejectingProxy
        blocked = []
        proxy = RejectingProxy(lambda: blocked.append(True))
        self.addCleanup(proxy.close)
        ctx = self.browser.new_context(proxy=proxy.settings)
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        before = RedirectFixture.direct_hits
        from playwright.sync_api import Error
        with self.assertRaises(Error):
            page.goto('http://127.0.0.1:' + str(self.server.server_port) + '/direct', timeout=3000)
        self.assertTrue(blocked)
        self.assertEqual(RedirectFixture.direct_hits, before)


if __name__ == '__main__':
    unittest.main()

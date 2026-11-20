"""Real-Chromium positive/negative coverage pairs for named XSS paths."""
from __future__ import annotations
import html
import json
import unittest
import urllib.parse
import test_xss_browser as fixtures
import xss_browser as worker


class CoverageFixture(fixtures.Fixture):
    note = ''
    def do_PUT(self):
        value = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        CoverageFixture.note = value.get('text', '')
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b'{}')
    def do_DELETE(self):
        # Consume the JSON request before closing; unread bytes cause a TCP
        # reset on macOS instead of a clean response EOF.
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        CoverageFixture.note = ''
        self.send_response(200); self.end_headers()
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(parsed.query).get('q', [''])[0]
        path = parsed.path
        safe = path.endswith('-safe')
        route = path.removesuffix('-safe')
        value = html.escape(q, quote=True) if safe else q
        contexts = {'/ctx/scriptclose': '<script>const q=' + (json.dumps(q).replace('<', '\\u003c') if safe else json.dumps(q)) + ';</script>',
                    '/ctx/style': '<style>.q{color:' + value + '}</style>',
                    '/ctx/svg': '<div>' + value + '</div>', '/ctx/textarea': '<textarea>' + value + '</textarea>',
                    '/ctx/title': '<title>' + value + '</title>',
                    '/ctx/comment': '<!--' + value + '-->',
                    '/ctx/unquoted': '<input value=' + (('"' + value + '"') if safe else q) + '>',
                    '/ctx/template': '<script>const q=`' + (q.replace('`', '\\`').replace('${', '\\${') if safe else q) + '`;</script>',
                    '/ctx/url': '<a id="go" href="' + (('/next?q=' + urllib.parse.quote(q, safe='')) if safe else html.escape(q, quote=True)) + '">open</a>'}
        if path == '/cdn.js':
            body = 'document.body.innerHTML=decodeURIComponent(location.hash.slice(1))'
            self.send_response(200); self.send_header('Content-Type', 'application/javascript'); self.end_headers(); self.wfile.write(body.encode()); return
        elif path == '/resource':
            body = '<body><script src="http://cdn.fixture.test:' + str(self.server.server_port) + '/cdn.js"></script></body>'
        elif route in contexts:
            body = contexts[route]
        elif route.startswith('/exec/'):
            mode = route.split('/')[-1]
            code = {'eval': 'eval(v)', 'function': 'Function(v)()', 'timer': 'setTimeout(v, 10)'}[mode]
            if safe: code = 'document.body.textContent = v'
            body = '<script>const v=decodeURIComponent(location.hash.slice(1));' + code + '</script>'
        elif route.startswith('/sink/'):
            mode = route.split('/')[-1]
            scripts = {
                'outer': 'document.querySelector("#host").outerHTML=v',
                'adjacent': 'document.body.insertAdjacentHTML("beforeend",v)',
                'write': 'document.write(v)', 'writeln': 'document.writeln(v)',
                'srcdoc-attr': 'const f=document.createElement("iframe");document.body.append(f);f.setAttribute("srcdoc",v)',
                'range': 'document.body.appendChild(document.createRange().createContextualFragment(v))',
                'parser': 'for(const n of new DOMParser().parseFromString(v,"text/html").body.childNodes) document.body.appendChild(document.importNode(n,true))',
                'shadow': 'document.querySelector("#host").attachShadow({mode:"open"}).innerHTML=v',
                'srcdoc': 'const f=document.createElement("iframe");document.body.append(f);f.srcdoc=v',
                'attribute': 'const b=document.createElement("button");document.body.append(b);b.setAttribute("onclick",v);b.click()'}
            code = scripts[mode]
            if safe:
                code = 'document.body.textContent=v'
                if mode in {'srcdoc', 'srcdoc-attr'}:
                    code = 'const f=document.createElement("iframe");f.setAttribute("sandbox","allow-scripts");document.body.append(f);f.srcdoc=v'
            body = '<div id="host"></div><script>const v=decodeURIComponent(location.hash.slice(1));' + code + '</script>'
        elif route.startswith('/source/'):
            mode = route.split('/')[-1]
            read = {'local': 'localStorage.getItem("test")', 'session': 'sessionStorage.getItem("test")', 'name': 'window.name'}
            sink = 'textContent' if safe else 'innerHTML'
            if mode == 'message':
                code = 'addEventListener("message",e=>{' + ('if(e.origin===location.origin)' if safe else '') + 'out.' + sink + '=e.data.html})'
            else: code = 'out.' + sink + '=' + read[mode]
            body = '<div id="out"></div><script>' + code + '</script>'
        elif path in {'/tt', '/tt-permissive'}:
            setup = 'trustedTypes.createPolicy("default",{createHTML:s=>s});' if path.endswith('permissive') else ''
            body = '<div id="out"></div><script>' + setup + 'out.innerHTML=decodeURIComponent(location.hash.slice(1))</script>'
        elif path == '/async':
            body = '<div id="out"></div><script>setTimeout(()=>out.innerHTML=decodeURIComponent(location.hash.slice(1)),700)</script>'
        elif path == '/api-read': body = CoverageFixture.note
        elif path == '/api-edit': body = '<p>controlled API fixture</p>'
        else: return super().do_GET()
        self.send_response(200); self.send_header('Content-Type', 'text/html');
        if path in {'/tt', '/tt-permissive'}: self.send_header('Content-Security-Policy', "require-trusted-types-for 'script'")
        self.end_headers(); self.wfile.write(body.encode())


class BrowserCoverageTests(unittest.TestCase):
    handler = CoverageFixture
    setUpClass = classmethod(fixtures.BrowserWorkerTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.BrowserWorkerTests.tearDownClass.__func__)
    setUp = fixtures.BrowserWorkerTests.setUp
    spec = fixtures.BrowserWorkerTests.spec
    execute = fixtures.BrowserWorkerTests.execute

    def pair(self, path, family, kind, probe, name='q', steps=None):
        results = []
        for suffix in ('', '-safe'):
            spec = self.spec(path + suffix, family, kind)
            spec['input']['name'] = name
            spec['probes'] = [probe]
            if steps: spec['steps'] = steps
            result = self.execute(spec)
            expected = 'not_demonstrated' if suffix else 'execution_observed'
            self.assertEqual(result['status'], expected, {'path': path + suffix, 'errors': result['errors'], 'phases': result['phases']})
            self.assertFalse(result['confirmed'])
            if not suffix:
                self.assertEqual(result['phases'][-1]['analysis']['direct'], kind not in {'local_storage', 'session_storage', 'window_name'}, result)
            results.append(result)
        return results

    def test_reflected_context_pairs(self):
        for path, probe in [('textarea','textarea'), ('title','title'), ('comment','comment'),
                            ('unquoted','unquoted_attribute'), ('template','js_template'), ('style','style'), ('svg','svg'), ('scriptclose','script_close')]:
            with self.subTest(context=path): self.pair('/ctx/' + path, 'reflected_xss', 'query', probe)

    def test_url_context_requires_reviewed_interaction(self):
        self.pair('/ctx/url', 'reflected_xss', 'query', 'url', steps=[{'action': 'click', 'selector': '#go'}])

    def test_eval_function_and_timer_preserve_native_execution(self):
        for mode in ('eval', 'function', 'timer'):
            with self.subTest(sink=mode):
                results = self.pair('/exec/' + mode, 'dom_xss', 'hash', 'js_expression')
                self.assertFalse(results[0]['phases'][-1]['analysis']['family_analyzer']['exact_sink_attribution'])

    def test_additional_html_sink_pairs(self):
        for mode in ('range', 'parser', 'shadow', 'srcdoc', 'srcdoc-attr', 'outer', 'adjacent', 'write', 'writeln'):
            with self.subTest(sink=mode): self.pair('/sink/' + mode, 'dom_xss', 'hash', 'html')

    def test_event_handler_attribute_pair(self):
        self.pair('/sink/attribute', 'dom_xss', 'hash', 'js_expression')

    def test_browser_source_pairs(self):
        for route, kind, name in [('local','local_storage','test'), ('session','session_storage','test'),
                                  ('name','window_name','window.name'), ('message','post_message','html')]:
            with self.subTest(source=kind):
                results = self.pair('/source/' + route, 'dom_xss', kind, 'html', name)
                if kind != 'post_message':
                    self.assertTrue(results[0]['phases'][-1]['analysis']['family_analyzer']['source_control_preconditions'])
                    self.assertFalse(results[0]['phases'][-1]['analysis']['family_analyzer']['confirmation_ready_from_stored_target_evidence'])

    def test_explicit_async_observation_window(self):
        spec = self.spec('/async', 'dom_xss', 'hash')
        spec.update(probes=['html'], settle_ms=1000)
        result = self.execute(spec)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertTrue(result['phases'][-1]['analysis']['direct'])

    def test_trusted_types_enforcement_and_permissive_policy(self):
        for path, expected in [('/tt', 'not_demonstrated'), ('/tt-permissive', 'execution_observed')]:
            spec = self.spec(path, 'dom_xss', 'hash')
            spec['probes'] = ['html']
            result = self.execute(spec)
            self.assertEqual(result['status'], expected, result)
            if path == '/tt':
                self.assertTrue(any(c['directive'] == 'require-trusted-types-for' and c['disposition'] == 'enforce'
                                    for p in result['phases'] for c in p['coverage']['observed_controls']))

    def test_explicit_scoped_resource_origin(self):
        spec = self.spec('/resource', 'dom_xss', 'hash')
        spec['probes'] = ['html']
        denied = self.execute(spec)
        self.assertEqual(denied['status'], 'incomplete')
        spec['resource_origins'] = ['http://cdn.fixture.test:' + str(self.server.server_port)]
        result = self.execute(spec)
        self.assertEqual(result['status'], 'execution_observed', result)
        spec['resource_origins'] = ['https://outside.test']
        with self.assertRaises(worker.ReconError):
            worker.validate_plan({'version': 1, 'target': 'fixture.test', 'tests': [spec]}, self.policy)

    def test_plan_scope_source_and_origin_contracts(self):
        self.assertEqual(worker.origin_text('https://EXAMPLE.test:443/x'), 'https://example.test')
        self.assertEqual(worker.origin_text('http://example.test:80/'), 'http://example.test')
        for url in ('http://example.test:0', 'https://@example.test', 'file:///tmp/example'):
            with self.assertRaises(worker.ReconError): worker.origin(url)
        spec = self.spec('/api-edit', 'stored_xss', 'form')
        spec['steps'] = [{'action': 'request', 'method': 'PUT', 'url': 'https://outside.test/api', 'json': {'text': '{probe}'}}]
        with self.assertRaises(worker.ReconError):
            worker.validate_plan({'version': 1, 'target': 'fixture.test', 'tests': [spec]}, self.policy)
        spec = self.spec('/source/name', 'reflected_xss', 'window_name')
        with self.assertRaises(worker.ReconError):
            worker.validate_plan({'version': 1, 'target': 'fixture.test', 'tests': [spec]}, self.policy)

    def test_stored_json_api_write_read_cleanup(self):
        spec = self.spec('/api-edit', 'stored_xss', 'form')
        spec.update(probes=['html'], steps=[
            {'action': 'request', 'method': 'PUT', 'url': self.base + '/api-note', 'json': {'text': '{probe}'}},
            {'action': 'goto', 'url': self.base + '/api-read'}], cleanup=[
            {'action': 'request', 'method': 'DELETE', 'url': self.base + '/api-note', 'json': {}}])
        plan = {'version': 1, 'target': 'fixture.test', 'tests': [spec]}
        worker.validate_plan(plan, self.policy)
        denied = worker.execute_test(self.browser, self.policy, plan, spec, verify=False, allow_write=False)
        self.assertEqual(denied['status'], 'incomplete')
        self.assertEqual(CoverageFixture.note, '')
        result = worker.execute_test(self.browser, self.policy, plan, spec, verify=True, allow_write=True)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertTrue(result['phases'][-1]['analysis']['direct'])
        self.assertEqual(CoverageFixture.note, '')
        self.assertEqual(result['cleanup'], 'completed')

if __name__ == '__main__': unittest.main()

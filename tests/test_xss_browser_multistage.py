"""Encoded flows, real renderers/sanitizer, and separate-session Stored evidence."""
from __future__ import annotations
import base64
import hashlib
import html
import json
from pathlib import Path
import unittest
import urllib.parse
import test_xss_browser as basic
from test_xss_browser_coverage import CoverageFixture
import xss_browser as worker
from xss_browser_encodings import DEFAULT_ENCODINGS

ASSETS = Path(__file__).parent / 'fixtures' / 'xss_browser_vendor'


class MultistageFixture(CoverageFixture):
    note = ''
    reader_posts = 0
    def do_POST(self):
        if self.path == '/notes/trap':
            MultistageFixture.reader_posts += 1
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.send_response(200); self.end_headers(); return
        super().do_POST()
    def do_PUT(self):
        if self.path == '/notes/save':
            if self.headers.get('Cookie') != 'role=writer':
                self.send_response(403); self.end_headers(); return
            value = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            MultistageFixture.note = value['text']
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b'{"saved":true}'); return
        super().do_PUT()
    def do_DELETE(self):
        if self.path == '/notes/save':
            if self.headers.get('Cookie') != 'role=writer':
                self.send_response(403); self.end_headers(); return
            MultistageFixture.note = ''
            self.send_response(200); self.end_headers(); return
        super().do_DELETE()
    def do_GET(self):
        p = urllib.parse.urlsplit(self.path)
        path = p.path
        safe = path.endswith('-safe')
        route = path.removesuffix('-safe')
        q = urllib.parse.parse_qs(p.query).get('q', [''])[0]
        if path.startswith('/__vendor/'):
            name = path.removeprefix('/__vendor/')
            if name not in {'react.js', 'react-dom.js', 'vue.js', 'purify.js'}:
                self.send_response(404); self.end_headers(); return
            data = (ASSETS / name).read_bytes()
            self.send_response(200); self.send_header('Content-Type', 'application/javascript'); self.end_headers(); self.wfile.write(data); return
        before = 'let v=decodeURIComponent(location.hash.slice(1));'
        body = None
        if route.startswith('/encoding/'):
            mode = route.split('/')[-1]
            decode = {'url2': 'v=decodeURIComponent(decodeURIComponent(v));',
                      'html': 'const t=document.createElement("textarea");t.innerHTML=v;v=t.value;',
                      'base64': 'v=atob(v);', 'json': 'v=JSON.parse(v);',
                      'unicode': 'v=JSON.parse(\'"\'+v+\'"\');',
                      'composed': 'v=atob(decodeURIComponent(v));const t=document.createElement("textarea");t.innerHTML=v;v=t.value;'}[mode]
            body = '<div id="out"></div><script>' + before + decode + 'out.' + ('textContent' if safe else 'innerHTML') + '=v;</script>'
        elif route == '/encoded-inline':
            body = '<div id="out"></div><script>const v=atob(' + json.dumps(q) + ');out.' + ('textContent' if safe else 'innerHTML') + '=v;</script>'
        elif route == '/reparse':
            body = '<div id="out"></div><script>' + before + 'for(let i=0;i<2;i++){const t=document.createElement("template");t.innerHTML=v;v=t.content.textContent}out.' + ('textContent' if safe else 'innerHTML') + '=v;</script>'
        elif route == '/framework/react':
            props = ',null,v' if safe else ',{dangerouslySetInnerHTML:{__html:v}}'
            body = '<div id="root"></div><script src="/__vendor/react.js"></script><script src="/__vendor/react-dom.js"></script><script>' + before + 'ReactDOM.createRoot(document.getElementById("root")).render(React.createElement("div"' + props + '));</script>'
        elif route == '/framework/vue':
            template = '<div>{{ value }}</div>' if safe else '<div v-html="value"></div>'
            body = '<div id="root">' + template + '</div><script src="/__vendor/vue.js"></script><script>' + before + 'Vue.createApp({data(){return {value:v}}}).mount("#root");</script>'
        elif route == '/sanitizer/redecode':
            tail = 'out.innerHTML=clean;' if safe else 'const t=document.createElement("textarea");t.innerHTML=clean;out.innerHTML=t.value;'
            body = '<div id="out"></div><script src="/__vendor/purify.js"></script><script>' + before + 'const clean=DOMPurify.sanitize(v);' + tail + '</script>'
        elif route == '/sanitizer/raw':
            body = '<div id="out"></div><script src="/__vendor/purify.js"></script><script>' + before + 'out.innerHTML=DOMPurify.sanitize(v);</script>'
        elif path == '/notes/edit': body = '<p>controlled writer</p>'
        elif path.startswith('/notes/'):
            if self.headers.get('Cookie') != 'role=reader':
                self.send_response(403); self.end_headers(); return
            if path == '/notes/attempt-write':
                body = '<button id="send" onclick="fetch(\'/notes/trap\',{method:\'POST\',body:\'x\'})">send</button>'
            elif path == '/notes/data':
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(json.dumps({'text': MultistageFixture.note}).encode()); return
            if route == '/notes/json-view':
                body = '<div id="out"></div><script>fetch("/notes/data").then(r=>r.json()).then(r=>out.' + ('textContent' if safe else 'innerHTML') + '=r.text)</script>'
            elif route == '/notes/view': body = html.escape(MultistageFixture.note) if safe else MultistageFixture.note
        if body is None: return super().do_GET()
        self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())


class MultistageCoverageTests(unittest.TestCase):
    handler = MultistageFixture
    setUpClass = classmethod(basic.BrowserWorkerTests.setUpClass.__func__)
    tearDownClass = classmethod(basic.BrowserWorkerTests.tearDownClass.__func__)
    setUp = basic.BrowserWorkerTests.setUp
    spec = basic.BrowserWorkerTests.spec
    execute = basic.BrowserWorkerTests.execute

    def pair(self, path, chains, family='dom_xss', kind='hash'):
        for safe in (False, True):
            spec = self.spec(path + ('-safe' if safe else ''), family, kind)
            spec.update(probes=['html'], encodings=chains)
            worker.validate_plan({'version': 1, 'target': 'fixture.test', 'tests': [spec]}, self.policy)
            result = self.execute(spec)
            self.assertEqual(result['status'], 'not_demonstrated' if safe else 'execution_observed', {'path': path, 'safe': safe, 'errors': result['errors'], 'phases': result['phases']})
            if not safe: self.assertTrue(result['phases'][-1]['analysis']['direct'], result)
            self.assertNotIn('onerror=', json.dumps(result))

    def test_encoded_and_composed_dom_pairs(self):
        for mode, chain in [('url2',['url','url']), ('html',['html_entities']), ('base64',['base64']),
                            ('json',['json']), ('unicode',['js_unicode']), ('composed',['html_entities','base64','url'])]:
            with self.subTest(encoding=mode): self.pair('/encoding/' + mode, [chain])

    def test_default_profiles_reach_encoded_path(self):
        spec = self.spec('/encoding/base64', 'dom_xss', 'hash')
        spec.pop('encodings'); spec['probes'] = ['html']
        result = self.execute(spec)
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertEqual(result['phases'][-1]['coverage']['encoding_chain'], ['base64'])
        self.assertIn(['html_entities','base64','url'], DEFAULT_ENCODINGS)

    def test_reflected_encoded_response_requires_browser_execution(self):
        self.pair('/encoded-inline', [['base64']], family='reflected_xss', kind='query')

    def test_parse_decode_serialize_cycle_pairs(self):
        self.pair('/reparse', [['html_entities','html_entities']])

    def test_real_react_and_vue_renderer_pairs(self):
        for name in ('react','vue'):
            with self.subTest(renderer=name): self.pair('/framework/' + name, [[]])

    def test_real_sanitizer_followed_by_decode(self):
        self.pair('/sanitizer/redecode', [['html_entities']])
        for chain in ([], ['html_entities']):
            spec = self.spec('/sanitizer/raw', 'dom_xss', 'hash')
            spec.update(probes=['html'], encodings=[chain])
            result = self.execute(spec)
            self.assertEqual(result['status'], 'not_demonstrated', result)

    def test_vendored_libraries_match_pinned_provenance(self):
        metadata = json.loads((ASSETS/'provenance.json').read_text())
        self.assertEqual({m['package'] for m in metadata}, {'react','react-dom','vue','dompurify'})
        for m in metadata:
            for name, digest in m['files'].items():
                self.assertEqual(hashlib.sha256((ASSETS/name).read_bytes()).hexdigest(), digest)

    def test_reader_session_rejects_probe_reinjection_and_write_steps(self):
        spec = self.spec('/notes/edit', 'stored_xss', 'form')
        spec['steps'] = [{'action':'request','method':'PUT','url':self.base+'/notes/save','json':{'text':'{probe}'}}]
        for reader in ({'url':self.base+'/notes/view','steps':[{'action':'request','method':'POST','url':self.base+'/notes/save','json':{}}]},
                       {'url':self.base+'/notes/view','steps':[{'action':'fill','selector':'input','value':'{probe}'}]},
                       {'url':'https://outside.test/view'}):
            spec['read_session'] = reader
            with self.assertRaises(worker.ReconError):
                worker.validate_plan({'version':1,'target':'fixture.test','tests':[spec]}, self.policy)

    def test_separate_reader_session_html_and_json_pairs(self):
        def state(role):
            return {'cookies':[{'name':'role','value':role,'domain':'fixture.test','path':'/','expires':-1,
                                'httpOnly':True,'secure':False,'sameSite':'Lax'}], 'origins':[]}
        reader_file = self.paths.root/'reader.json'; reader_file.write_text(json.dumps(state('reader')))
        for path in ('/notes/view', '/notes/json-view'):
            for safe in (False, True):
                MultistageFixture.note = ''
                spec = self.spec('/notes/edit', 'stored_xss', 'form')
                spec.update(probes=['html'], encodings=[[]],
                    steps=[{'action':'request','method':'PUT','url':self.base+'/notes/save','json':{'text':'{probe}'}}],
                    read_session={'url':self.base+path+('-safe' if safe else ''), 'storage_state':str(reader_file)},
                    cleanup=[{'action':'request','method':'DELETE','url':self.base+'/notes/save','json':{}}])
                plan = {'version':1,'target':'fixture.test','tests':[spec]}
                worker.validate_plan(plan,self.policy)
                result = worker.execute_test(self.browser,self.policy,plan,spec,verify=True,allow_write=True,storage_state=state('writer'))
                self.assertEqual(result['status'],'not_demonstrated' if safe else 'execution_observed',result)
                if not safe: self.assertTrue(result['phases'][-1]['analysis']['direct'],result)
                self.assertEqual(result['cleanup'],'completed')
                self.assertEqual(MultistageFixture.note,'')
                self.assertTrue(any(r['role']=='reader' for r in result['requests']))
                self.assertFalse(any(r['role']=='reader' and r['method'] not in {'GET','HEAD','OPTIONS'} for r in result['requests']))
                self.assertNotIn('role=reader',json.dumps(result))

    def test_reader_context_cannot_send_background_writes(self):
        def state(role):
            return {'cookies':[{'name':'role','value':role,'domain':'fixture.test','path':'/','expires':-1,
                                'httpOnly':True,'secure':False,'sameSite':'Lax'}], 'origins':[]}
        reader = self.paths.root/'reader.json'; reader.write_text(json.dumps(state('reader')))
        MultistageFixture.reader_posts = 0
        spec = self.spec('/notes/edit', 'stored_xss', 'form')
        spec.update(probes=['html'], steps=[{'action':'request','method':'PUT','url':self.base+'/notes/save','json':{'text':'{probe}'}}],
            read_session={'url':self.base+'/notes/attempt-write','storage_state':str(reader),
                          'steps':[{'action':'click','selector':'#send'}]},
            cleanup=[{'action':'request','method':'DELETE','url':self.base+'/notes/save','json':{}}])
        plan = {'version':1,'target':'fixture.test','tests':[spec]}
        worker.validate_plan(plan,self.policy)
        result = worker.execute_test(self.browser,self.policy,plan,spec,verify=True,allow_write=True,storage_state=state('writer'))
        self.assertEqual(result['status'],'incomplete',result)
        self.assertEqual(MultistageFixture.reader_posts,0)
        self.assertEqual(result['cleanup'],'completed')

if __name__ == '__main__': unittest.main()

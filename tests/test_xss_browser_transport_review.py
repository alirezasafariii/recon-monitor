"""Real browser regressions for preserved HTTP encoding/rendering semantics."""
from __future__ import annotations
import gzip
import html
import unittest
import urllib.parse
import zlib
import test_xss_browser as fixtures


class TransportFixture(fixtures.Fixture):
    def do_GET(self):
        p=urllib.parse.urlsplit(self.path)
        route=p.path.removesuffix('-safe')
        if p.path == '/redirect-chain':
            self.send_response(302); self.send_header('Location', '/same-redirect?' + p.query); self.end_headers(); return
        if p.path == '/fetch-redirect':
            self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
            self.wfile.write(b"<script>fetch('/same-redirect'+location.search)</script>"); return
        if route not in {'/gzip','/deflate','/raw-deflate','/stacked','/broken','/unknown','/utf16','/cp1256','/meta'}:
            return super().do_GET()
        q=urllib.parse.parse_qs(p.query).get('q',[''])[0]
        if p.path.endswith('-safe'):q=html.escape(q)
        body='<html><head>' + ('<meta charset="windows-1256">' if route=='/meta' else '') + '</head><body>سلام<p>'+q+'</p></body></html>'
        charset='utf-16' if route=='/utf16' else 'cp1256' if route in {'/cp1256','/meta'} else 'utf-8'
        data=body.encode(charset);coding=None
        if route=='/gzip':data=gzip.compress(data);coding='gzip'
        elif route=='/deflate':data=zlib.compress(data);coding='deflate'
        elif route=='/raw-deflate':
            c=zlib.compressobj(wbits=-15);data=c.compress(data)+c.flush();coding='deflate'
        elif route=='/stacked':data=zlib.compress(gzip.compress(data));coding='gzip, deflate'
        elif route=='/broken':coding='gzip'
        elif route=='/unknown':coding='x-unsupported'
        self.send_response(200)
        self.send_header('Content-Type','text/html'+('' if route=='/meta' else '; charset='+charset))
        if coding:self.send_header('Content-Encoding',coding)
        self.end_headers();self.wfile.write(data)


class BrowserTransportReviewTests(unittest.TestCase):
    def test_redirect_hops_remain_brokered_and_fetch_redirect_fails_closed(self):
        result = self.execute(self.spec('/redirect-chain'))
        self.assertEqual(result['status'], 'execution_observed', result)
        self.assertEqual([r['status'] for r in result['requests'][:3]], [302,302,200])
        result = self.execute(self.spec('/fetch-redirect'))
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('redirect_requires_explicit_main_frame_workflow', result['errors'])
        self.assertFalse(any('/reflect' in r['url'] for r in result['requests']))

    handler=TransportFixture
    setUpClass=classmethod(fixtures.BrowserWorkerTests.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.BrowserWorkerTests.tearDownClass.__func__)
    setUp=fixtures.BrowserWorkerTests.setUp
    spec=fixtures.BrowserWorkerTests.spec
    execute=fixtures.BrowserWorkerTests.execute

    def pair(self,path):
        for safe in (False,True):
            test=self.spec(path+('-safe' if safe else ''));test['probes']=['html']
            result=self.execute(test)
            self.assertEqual(result['status'],'not_demonstrated' if safe else 'execution_observed',result)
            if not safe:
                self.assertIsNotNone(result['phases'][-1]['analysis'],result)
                self.assertTrue(result['phases'][-1]['analysis']['direct'],result)
            self.assertFalse(result['confirmed'])

    def test_supported_content_codings_keep_browser_semantics(self):
        for route in ('/gzip','/deflate','/raw-deflate','/stacked'):
            with self.subTest(coding=route):self.pair(route)

    def test_charset_evidence_matches_actual_rendering(self):
        for route in ('/utf16','/cp1256','/meta'):
            with self.subTest(charset=route):self.pair(route)

    def test_invalid_or_unknown_content_coding_is_incomplete(self):
        for route in ('/broken','/unknown'):
            test=self.spec(route);test['probes']=['html']
            result=self.execute(test)
            self.assertEqual(result['status'],'incomplete',result)
            self.assertFalse(any(p['execution_observed'] for p in result['phases']),result)

class DecoderStopReviewTests(unittest.TestCase):
    def test_browser_error_code_does_not_export_url_or_secrets(self):
        message = 'Page.goto: net::ERR_NAME_NOT_RESOLVED at https://fixture.test/?secret=private'
        self.assertEqual(fixtures.worker.error_kind(RuntimeError(message)), 'ERR_NAME_NOT_RESOLVED')
        self.assertEqual(fixtures.worker.error_kind(RuntimeError('private')), 'RuntimeError')

    def test_stop_interrupts_decompression_without_a_byte_quota(self):
        from xss_browser_http import decode_entity
        for coding,compress in [('gzip',gzip.compress),('deflate',zlib.compress)]:
            calls=[0]
            def stop():
                calls[0]+=1
                if calls[0]>=5:raise InterruptedError('operator stop')
            with self.subTest(coding=coding),self.assertRaises(InterruptedError):
                decode_entity(compress(b'x'*2_000_000),coding,stop)

if __name__=='__main__':unittest.main()

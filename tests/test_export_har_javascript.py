from __future__ import annotations

import base64
import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tools'))

from core import AppPaths, PolicySet, ReconError
from export_har_javascript import export_javascript


class HarJavascriptExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding='utf-8')
        self.paths.policy.write_text(json.dumps({'targets': [{
            'name': 'example.test', 'roots': ['example.test'],
            'exclude': [r'^excluded\.example\.test$'],
            'limits': {'max_js_files': 2},
        }]}), encoding='utf-8')
        self.har = self.paths.root / 'browser.har'
        self.output = self.paths.root / 'javascript.zip'

    def entry(self, url='https://example.test/app.js', text='window.fixture=1;',
              method='GET', status=200, mime='application/javascript', encoding=''):
        content = {'mimeType': mime, 'text': text}
        if encoding:
            content['encoding'] = encoding
        return {'request': {'url': url, 'method': method,
                            'headers': [{'name': 'Cookie', 'value': 'PRIVATE_COOKIE'}],
                            'postData': {'text': 'PRIVATE_REQUEST_BODY'}},
                'response': {'status': status, 'content': content,
                             'headers': [{'name': 'Set-Cookie', 'value': 'PRIVATE_RESPONSE_COOKIE'}]}}

    def run_export(self, entries):
        self.har.write_text(json.dumps({'log': {'entries': entries}}), encoding='utf-8')
        return export_javascript(self.paths, self.har, 'example.test', self.output)

    def index(self):
        with zipfile.ZipFile(self.output) as archive:
            return json.loads(archive.read('index.json'))

    def test_exports_mime_identified_and_base64_javascript_deduplicated(self):
        first = self.entry('https://example.test/ConstantsJSBase?store=PRIVATE_QUERY#PRIVATE_FRAGMENT')
        second = self.entry('https://example.test/module.js',
                            base64.b64encode(b'export const fixture=2;').decode(), encoding='base64')
        with patch('socket.create_connection', side_effect=AssertionError('Network replay attempted')):
            result = self.run_export([first, first, second])
        self.assertEqual((result['sources'], result['artifacts'], result['exported_observations']), (2, 2, 3))
        self.assertFalse(result['scan_status_changed'])
        self.assertFalse(self.paths.db.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        with zipfile.ZipFile(self.output) as archive:
            index = json.loads(archive.read('index.json'))
            self.assertNotIn('PRIVATE_', archive.read('index.json').decode())
            self.assertIn('store=%5Bredacted%5D', index['sources'][0]['url'])
            for record in index['sources']:
                data = archive.read(record['file'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), record['sha256'])
                self.assertEqual(len(data), record['bytes'])
            self.assertEqual(set(archive.namelist()), {'index.json'} | {r['file'] for r in index['sources']})

    def test_scope_excludes_lookalikes_excluded_hosts_and_url_credentials(self):
        result = self.run_export([
            self.entry(), self.entry('https://example.test.evil.test/app.js'),
            self.entry('https://excluded.example.test/app.js'),
            self.entry('https://user:PRIVATE_PASSWORD@example.test/app.js'),
            self.entry('file:///private/app.js'), self.entry('https://[invalid/app.js'),
        ])
        self.assertEqual(result['sources'], 1)
        self.assertEqual(result['omitted']['outside_scope_or_invalid_url'], 5)

    def test_post_json_html_and_partial_or_error_responses_are_not_exported(self):
        result = self.run_export([
            self.entry(), self.entry(method='POST'), self.entry(status=206), self.entry(status=400),
            self.entry('https://example.test/api', text='PRIVATE_JSON_BODY', mime='application/json'),
            self.entry('https://example.test/page', text='PRIVATE_HTML_BODY', mime='text/html'),
        ])
        self.assertEqual(result['sources'], 1)
        self.assertEqual(result['omitted'], {'non_get': 1, 'non_200': 2})
        with zipfile.ZipFile(self.output) as archive:
            all_bytes = b''.join(archive.read(name) for name in archive.namelist())
        self.assertNotIn(b'PRIVATE_', all_bytes)

    def test_missing_invalid_or_over_limit_bodies_are_reported(self):
        limit = PolicySet.load(self.paths).select('example.test')[0].limits.max_js_bytes
        result = self.run_export([
            self.entry(), self.entry('https://example.test/missing.js', text=''),
            self.entry('https://example.test/invalid.js', text='not_base64!', encoding='base64'),
            self.entry('https://example.test/large.js', text='x' * (limit + 1)),
        ])
        self.assertEqual(result['sources'], 1)
        self.assertEqual(result['omitted'], {'missing_body': 1, 'invalid_encoding': 1, 'body_limit': 1})

    def test_file_quota_is_explicit_and_duplicates_do_not_consume_it(self):
        result = self.run_export([self.entry(), self.entry(),
                                  self.entry('https://example.test/second.js'),
                                  self.entry('https://example.test/third.js')])
        self.assertEqual(result['sources'], 2)
        self.assertEqual(result['artifacts'], 1)
        self.assertEqual(result['omitted']['file_limit'], 1)

    def test_invalid_input_or_authorization_preserves_existing_output(self):
        self.output.write_bytes(b'previous-export')
        self.har.write_text('{"log": []}', encoding='utf-8')
        with self.assertRaises(ReconError):
            export_javascript(self.paths, self.har, 'example.test', self.output)
        with self.assertRaises(ReconError):
            self.run_export([self.entry(text='')])
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="no"\n', encoding='utf-8')
        with self.assertRaises(ReconError):
            self.run_export([self.entry()])
        self.assertEqual(self.output.read_bytes(), b'previous-export')

    def test_atomic_write_failure_preserves_har_and_previous_archive(self):
        self.output.write_bytes(b'previous-export')
        with patch('zipfile.ZipFile.writestr', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError):
                self.run_export([self.entry()])
        self.assertEqual(self.output.read_bytes(), b'previous-export')
        self.assertTrue(self.har.is_file())
        self.assertEqual(list(self.output.parent.glob('.har-js-*')), [])
        with self.assertRaises(ReconError):
            export_javascript(self.paths, self.har, 'example.test', self.har)

    def test_cli_exports_using_the_selected_project_policy(self):
        self.har.write_text(json.dumps({'log': {'entries': [self.entry()]}}), encoding='utf-8')
        result = subprocess.run([
            sys.executable, str(ROOT / 'tools' / 'export_har_javascript.py'),
            '--root', str(self.paths.root), '--har', str(self.har), '--target', 'example.test',
            '--output', str(self.output),
        ], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['sources'], 1)


if __name__ == '__main__':
    unittest.main()

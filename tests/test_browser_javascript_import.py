from __future__ import annotations

import hashlib
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import browser_javascript as browser
from core import AppPaths, Config, Database, PolicySet, ReconError
from dashboard import DashboardHandler
from storage import ContentAddressedStore


class BrowserJavascriptImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\nTELEGRAM_BOT_TOKEN="INSTALLATION_SECRET"\n')
        self.paths.policy.write_text(json.dumps({'targets': [{
            'name': 'example.test', 'roots': ['example.test'],
            'exclude': [r'^excluded\.example\.test$'],
            'headers': {'Authorization': 'Bearer INSTALLATION_SECRET'},
            'limits': {'max_js_files': 3, 'max_js_bytes': 10000},
        }]}))
        self.policy = PolicySet.load(self.paths).select('example.test')[0]
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.run_id = self.db.create_run('example.test', 1, 'fixture')
        self.db.create_run_target(self.run_id, self.policy, self.paths.output / 'source-run', baseline=False)
        self.db.stage_begin(self.run_id, 'example.test', 'javascript', 1)
        self.db.stage_finish(self.run_id, 'example.test', 'javascript', 'partial', metrics={'collection_status': 'partial'})
        self.db.finish_run_target(self.run_id, 'example.test', 'partial')
        self.db.finish_run(self.run_id, 'partial')
        self.latest = self.paths.output / 'LATEST'
        self.latest.write_text('existing-successful-baseline\n')
        store = ContentAddressedStore(self.paths, self.db)
        digest, self.old_blob, _ = store.put(b'const oldBaseline = true;')
        store.set_reference('js_file', 'existing', digest)
        self.db.upsert_js('example.test', 'https://example.test/app.js', digest, digest,
                         str(self.old_blob), self.old_blob.stat().st_size, self.run_id)
        self.archive = self.paths.root / 'browser.zip'
        self.body = (b'const endpoint="/api/orders/42?token=PRIVATE_VALUE";\n'
                     b'const gql="query FetchOrder($id: ID!) { order(id:$id) { id } }";\n'
                     b'const prose="query string";\n'
                     b'const input=location.search;document.body.innerHTML=input;\n'
                     b'//# sourceMappingURL=app.js.map\n')

    def records(self, bodies=None, urls=None):
        bodies = bodies or [self.body]
        urls = urls or ['https://example.test/app.js']
        rows, artifacts = [], {}
        for data, url in zip(bodies, urls):
            digest = hashlib.sha256(data).hexdigest()
            artifacts[digest + '.js'] = data
            rows.append({'url': url, 'method': 'GET', 'status_code': 200,
                         'content_type': 'application/javascript', 'sha256': digest,
                         'bytes': len(data), 'file': digest + '.js'})
        return {'format': browser.FORMAT, 'target': 'example.test', 'provenance': 'local_har',
                'sources': rows, 'javascript_observations': len(rows),
                'exported_observations': len(rows), 'omitted': {'missing_body': 1}}, artifacts

    def write_archive(self, index=None, artifacts=None):
        if index is None:
            index, artifacts = self.records()
        with zipfile.ZipFile(self.archive, 'w', zipfile.ZIP_STORED) as archive:
            for name, data in (artifacts or {}).items():
                archive.writestr(name, data)
            archive.writestr('index.json', json.dumps(index))

    def import_archive(self, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(patch('platform.platform',return_value='offline-import-test'))
            for name in ('socket.create_connection', 'socket.socket.connect', 'socket.getaddrinfo',
                         'urllib.request.OpenerDirector.open', 'subprocess.Popen'):
                mock = stack.enter_context(patch(name, side_effect=AssertionError('Offline import attempted external work')))
                stack.callback(mock.assert_not_called)
            return browser.import_browser_javascript(self.paths, self.db, target='example.test',
                run_id=self.run_id, file_path=self.archive, **kwargs)

    def source_state(self):
        tables = ('runs', 'run_targets', 'stage_runs', 'urls', 'js_files', 'js_indicators',
                  'js_availability_history', 'analysis_runs', 'bug_candidates', 'alerts',
                  'work_items', 'cas_references', 'object_store')
        return {table: [dict(row) for row in self.db.all(f'SELECT * FROM {table}')]
                for table in tables}

    def test_real_engine_analyzes_browser_sources_without_changing_scan_or_baseline(self):
        self.write_archive()
        before = self.source_state()
        result = self.import_archive(context_label='Admin account')
        report = browser.browser_javascript_report(self.db, result['import_id'])
        self.assertEqual(result['analysis_status'], 'success')
        self.assertEqual(result['source_count'], 1)
        self.assertFalse(result['scan_status_changed'])
        self.assertEqual((result['auth_state'], result['collection_status'], result['network_requests']), ('unknown', 'partial', 0))
        self.assertEqual(self.source_state(), before)
        self.assertEqual(self.latest.read_text(), 'existing-successful-baseline\n')
        self.assertEqual(self.old_blob.read_bytes(), b'const oldBaseline = true;')
        self.assertEqual(report['source_run_status'], 'partial')
        self.assertTrue(any('/api/orders/42?' in row['endpoint'] for row in report['endpoints']))
        self.assertEqual(report['graphql_operation_count'], 1)
        self.assertEqual(report['graphql_operations'][0]['declaration'], 'query FetchOrder')
        self.assertNotIn('PRIVATE_VALUE', json.dumps(report))
        self.assertEqual(len(report['source_map_references']), 1)
        self.assertEqual(report['source_maps_fetched'], 0)
        self.assertEqual(report['static_intelligence']['source_maps'], 0)
        self.assertGreater(report['static_intelligence']['dataflows'], 0)
        self.assertNotIn('confirmed', {row['candidate_state'] for row in report['candidates']})
        root = self.paths.state / 'browser-javascript' / result['import_id']
        for file in (root / 'config.env', root / 'policies/targets.json'):
            self.assertNotIn('INSTALLATION_SECRET', file.read_text())
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / 'report.json').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((root / 'state/recon-v2.db').stat().st_mode), 0o600)

    def test_duplicate_import_reuses_analysis_without_new_source_or_audit_rows(self):
        self.write_archive()
        first = self.import_archive()
        audits = self.db.one('SELECT COUNT(*) n FROM audit_log')['n']
        with patch('browser_javascript._analyze', side_effect=AssertionError('Analyzed duplicate')):
            second = self.import_archive()
        self.assertEqual(first['import_id'], second['import_id'])
        self.assertTrue(second['reused'])
        self.assertEqual(len(browser.list_browser_javascript_imports(self.db)), 1)
        self.assertEqual(self.db.one('SELECT COUNT(*) n FROM audit_log')['n'], audits)

    def test_extensionless_javascript_and_repeated_body_have_independent_source_references(self):
        index, artifacts = self.records([self.body, self.body],
            ['https://example.test/ConstantsJSBase?store=SECRET#SECRET', 'https://example.test/app.js'])
        self.write_archive(index, artifacts)
        result = self.import_archive()
        report = browser.browser_javascript_report(self.db, result['import_id'])
        self.assertEqual((result['source_count'], result['artifact_count']), (2, 1))
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertIn('store=%5Bredacted%5D', report['sources'][0]['url'])

    def test_bundled_graphql_whitespace_escapes_are_not_mistaken_for_word_characters(self):
        text = r'const a="\nmutation AddItem($id: ID!) { add(id:$id) {id} }";'
        text += r'const b="\nquery\nGetItems { items {id} }"; const prose="query string";'
        values = browser._source_indicators('https://example.test/app.js', text, self.policy)
        self.assertEqual({value for kind,value,_ in values if kind=='graphql_operation'},
                         {'mutation AddItem','query GetItems'})

    def test_only_final_standalone_source_map_directive_is_recorded(self):
        text = '// library\n//# sourceMappingURL=embedded-library.js.map\nconst a=1;\n'
        self.assertFalse(any(kind=='source_map_reference' for kind,_,_ in
                            browser._source_indicators('https://example.test/app.js',text,self.policy)))
        text += '//# sourceMappingURL=app.js.map\n'
        values = browser._source_indicators('https://example.test/app.js',text,self.policy)
        self.assertEqual([value for kind,value,_ in values if kind=='source_map_reference'],
                         ['https://example.test/app.js.map'])

    def test_rejects_out_of_scope_sources_and_credentials_before_creating_evidence(self):
        for url in ['https://evil.test/app.js', 'https://example.test.evil.test/app.js',
                    'https://excluded.example.test/app.js', 'https://u:p@example.test/app.js',
                    'file:///private/app.js', 'https://example.test:bad/app.js']:
            with self.subTest(url=url):
                index, artifacts = self.records(urls=[url]);self.write_archive(index, artifacts)
                with self.assertRaises(ReconError): self.import_archive()
        self.assertEqual(browser.list_browser_javascript_imports(self.db), [])
        self.assertFalse((self.paths.state / 'browser-javascript').exists())

    def test_rejects_wrong_format_target_method_status_mime_and_extra_metadata(self):
        cases = [('format', 'HAR'), ('target', 'other.test'), ('provenance', 'live'),
                 ('unknown', {'Cookie': 'PRIVATE'})]
        for key, value in cases:
            index, artifacts = self.records();index[key] = value;self.write_archive(index, artifacts)
            with self.subTest(key=key), self.assertRaises(ReconError): self.import_archive()
        for key, value in [('method', 'POST'), ('status_code', 206), ('status_code', True),
                           ('content_type', 'text/html'), ('headers', {'Cookie': 'PRIVATE'}),
                           ('bytes', True)]:
            index, artifacts = self.records();index['sources'][0][key] = value;self.write_archive(index, artifacts)
            with self.subTest(key=key, value=value), self.assertRaises(ReconError): self.import_archive()

    def test_rejects_zip_traversal_symlinks_duplicate_names_and_unindexed_bodies(self):
        index, artifacts = self.records()
        for extra in ['../outside.js', '/tmp/outside.js', 'subdir/code.js', '0'*64+'.js']:
            self.write_archive(index, {**artifacts, extra: b'bad'})
            with self.subTest(extra=extra), self.assertRaises(ReconError): self.import_archive()
        self.write_archive(index, artifacts)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.archive, 'a') as archive:archive.writestr('index.json', json.dumps(index))
        with self.assertRaises(ReconError):self.import_archive()
        self.write_archive(index, {})
        info = zipfile.ZipInfo(next(iter(artifacts)));info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(self.archive, 'a') as archive:archive.writestr(info, 'outside.js')
        with self.assertRaises(ReconError):self.import_archive()

    def test_rejects_hash_size_crc_and_json_integrity_errors(self):
        index, artifacts = self.records();name=next(iter(artifacts))
        self.write_archive(index, {name: self.body+b'changed'})
        with self.assertRaises(ReconError):self.import_archive()
        index['sources'][0]['bytes'] += 1;self.write_archive(index, artifacts)
        with self.assertRaises(ReconError):self.import_archive()
        self.write_archive()
        raw=self.archive.read_bytes();at=raw.index(self.body)
        self.archive.write_bytes(raw[:at]+b'!'+raw[at+1:])
        with self.assertRaises(ReconError):self.import_archive()
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.writestr('index.json', '{"format":"a","format":"b"}')
        with self.assertRaises(ReconError):self.import_archive()

    def test_rejects_limits_and_ambiguous_redacted_versions(self):
        index, artifacts = self.records([b'x'*10001], ['https://example.test/large.js'])
        self.write_archive(index, artifacts)
        with self.assertRaises(ReconError):self.import_archive()
        index, artifacts = self.records([self.body]*4, [f'https://example.test/{i}.js' for i in range(4)])
        self.write_archive(index, artifacts)
        with self.assertRaises(ReconError):self.import_archive()
        index, artifacts = self.records([self.body, b'other'],
            ['https://example.test/app.js?a=1', 'https://example.test/app.js?a=2'])
        self.write_archive(index, artifacts)
        with self.assertRaisesRegex(ReconError, 'ambiguous'):self.import_archive()
        self.write_archive()
        with patch('browser_javascript.MAX_EXPANDED_BYTES', 10), self.assertRaises(ReconError):self.import_archive()
        with patch('browser_javascript.MAX_ARCHIVE_BYTES', 10), self.assertRaises(ReconError):self.import_archive()

    def test_shared_body_cannot_amplify_processing_beyond_the_archive_budget(self):
        index, artifacts=self.records([b'x'*8000]*3,[f'https://example.test/{i}.js' for i in range(3)])
        self.write_archive(index,artifacts)
        with patch('browser_javascript.MAX_EXPANDED_BYTES',12000):
            with self.assertRaisesRegex(ReconError,'processing'):self.import_archive()

    def test_failed_analysis_does_not_publish_import_or_change_source(self):
        self.write_archive();before=self.source_state()
        with patch('browser_javascript._analyze', side_effect=RuntimeError('fixture failure')):
            with self.assertRaises(RuntimeError):self.import_archive()
        self.assertEqual(browser.list_browser_javascript_imports(self.db), [])
        self.assertEqual(self.source_state(), before)
        self.assertEqual(list((self.paths.state/'browser-javascript').iterdir()), [])

    def test_authorization_stopped_source_run_and_target_binding_are_required(self):
        self.write_archive()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="no"\n')
        with self.assertRaises(ReconError):self.import_archive()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
        self.db.execute("UPDATE runs SET status='running' WHERE id=?", (self.run_id,))
        with self.assertRaises(ReconError):self.import_archive()
        self.db.execute("UPDATE runs SET status='partial' WHERE id=?", (self.run_id,))
        from core import TargetPolicy
        other = TargetPolicy.from_dict({'name':'other.test','roots':['other.test']})
        self.run_id = self.db.create_run('other.test',1,'other-fixture')
        self.db.create_run_target(self.run_id,other,self.paths.output/'other-run',baseline=False)
        self.db.finish_run(self.run_id,'partial')
        with self.assertRaises(ReconError):self.import_archive()

    def test_reuse_detects_missing_or_corrupt_evidence_instead_of_silently_replacing_it(self):
        self.write_archive();result=self.import_archive()
        root=self.paths.state/'browser-javascript'/result['import_id']
        digest=hashlib.sha256(self.body).hexdigest()
        body=AppPaths.from_root(root).objects/digest[:2]/digest[2:4]/digest
        body.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ReconError,'corrupted'):self.import_archive()
        self.assertEqual(body.read_bytes(),b'corrupted')
        self.assertEqual(len(browser.list_browser_javascript_imports(self.db)),1)

    def test_rejects_linked_evidence_directory(self):
        self.write_archive()
        outside=self.paths.root/'outside';outside.mkdir()
        (self.paths.state/'browser-javascript').symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ReconError,'symlink'):self.import_archive()
        self.assertEqual(list(outside.iterdir()),[])

    def test_reuse_rejects_relocated_linked_evidence(self):
        self.write_archive();self.import_archive()
        base=self.paths.state/'browser-javascript';relocated=self.paths.root/'relocated'
        base.rename(relocated);base.symlink_to(relocated,target_is_directory=True)
        with self.assertRaisesRegex(ReconError,'corrupted'):self.import_archive()

    def test_failed_publication_cleans_sandbox_and_rolls_back_import_row(self):
        self.write_archive();before=self.source_state()
        with patch.object(self.db,'audit',side_effect=RuntimeError('publication failed')):
            with self.assertRaises(RuntimeError):self.import_archive()
        self.assertEqual(browser.list_browser_javascript_imports(self.db),[])
        self.assertEqual(self.source_state(),before)
        self.assertEqual(list((self.paths.state/'browser-javascript').iterdir()),[])

    def test_authorization_change_during_analysis_prevents_publication(self):
        self.write_archive();real=browser._analyze
        def changed(*args):
            result=real(*args)
            self.paths.config.write_text('I_HAVE_AUTHORIZATION="no"\n')
            return result
        with patch('browser_javascript._analyze',side_effect=changed):
            with self.assertRaisesRegex(ReconError,'changed'):self.import_archive()
        self.assertEqual(browser.list_browser_javascript_imports(self.db),[])

    def test_safety_dashboard_uses_the_canonical_audit_result(self):
        handler=DashboardHandler.__new__(DashboardHandler)
        handler.paths=self.paths;handler.config=Config(self.paths)
        handler.db=lambda:Database(self.paths.db)
        rendered=[];handler.send_html=lambda title,body:rendered.append(body)
        handler.safety_center_page()
        self.assertIn('Audit integrity',rendered[0])
        self.assertIn('valid',rendered[0])
        self.assertNotIn('attention',rendered[0])

    def test_report_integrity_and_read_only_empty_views(self):
        before=self.db.conn.total_changes
        self.assertEqual(browser.list_browser_javascript_imports(self.db), [])
        self.assertFalse(browser._has_imports(self.db))
        self.assertEqual(self.db.conn.total_changes, before)
        self.write_archive();result=self.import_archive()
        with self.assertRaises(ReconError):browser.browser_javascript_report(self.db, '../escape')
        self.db.execute("UPDATE browser_javascript_imports SET report_json='{}'")
        with self.assertRaisesRegex(ReconError,'integrity'):browser.browser_javascript_report(self.db,result['import_id'])

    def test_dashboard_displays_escaped_offline_evidence_without_source_bodies(self):
        self.write_archive();result=self.import_archive(context_label='<script>CONTEXT_XSS</script>')
        handler=DashboardHandler.__new__(DashboardHandler)
        handler.paths=self.paths;handler.config=Config(self.paths)
        handler.query=lambda:{'import_id':[result['import_id']]}
        handler.db=lambda:Database(self.paths.db)
        rendered=[];handler.send_html=lambda title,body:rendered.append(body)
        before=self.source_state();handler.browser_javascript_page()
        page=rendered[0]
        self.assertIn('query FetchOrder',page)
        self.assertIn('Authentication: <strong>unknown</strong>',page)
        self.assertIn('&lt;script&gt;CONTEXT_XSS&lt;/script&gt;',page)
        self.assertNotIn('<script>CONTEXT_XSS</script>',page)
        self.assertNotIn('PRIVATE_VALUE',page)
        self.assertNotIn('document.body.innerHTML=input',page)
        self.assertEqual(self.source_state(),before)

    def test_cli_dispatch_imports_and_lists_the_actual_report(self):
        import recon_monitor_core as cli
        self.write_archive();output=io.StringIO()
        with patch.object(cli,'ROOT_DIR',self.paths.root),redirect_stdout(output):
            status=cli.main(['workspace','javascript-import','--target','example.test',
                             '--run',self.run_id,'--file',str(self.archive)])
        self.assertEqual(status,0,output.getvalue())
        result=json.loads(output.getvalue());self.assertEqual(result['source_count'],1)
        output=io.StringIO()
        with patch.object(cli,'ROOT_DIR',self.paths.root),redirect_stdout(output):
            status=cli.main(['workspace','javascript-show','--import-id',result['import_id']])
        self.assertEqual(status,0)
        self.assertEqual(json.loads(output.getvalue())['analysis_id'],result['analysis_id'])


if __name__ == '__main__':
    unittest.main()

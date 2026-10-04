from __future__ import annotations

import ast
import datetime as dt
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from core import APP_VERSION, AppPaths, Config, Database
from dashboard_core import DashboardHandler, _command_center_snapshot, _filter_panel, _layout, _recon_surface_items, _latest_completed_analysis
from dashboard_design import pagination
from dashboard_search import SEARCH_GROUPS, search_workspace
from dashboard_artifact_search import contains_text
from workspace_v7 import universal_search

ROOT = Path(__file__).resolve().parents[1]


class FormInventory(HTMLParser):
    """Inspect native controls, including those inside closed details."""
    def __init__(self, markup: str):
        super().__init__()
        self.forms: list[dict] = []
        self.details: list[dict] = []
        self.current = None
        self.detail_stack: list[dict] = []
        self.fields: list[tuple[str, dict, bool]] = []
        self.links: list[str] = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form':
            self.current = {'attrs': values, 'fields': []}
            self.forms.append(self.current)
        if tag == 'details':
            self.details.append(values)
            self.detail_stack.append(values)
        if tag in {'input', 'select', 'textarea'}:
            self.fields.append((tag, values, bool(self.detail_stack)))
            if self.current is not None: self.current['fields'].append(values)
        if tag == 'a' and values.get('href'): self.links.append(values['href'])

    def handle_endtag(self, tag):
        if tag == 'form': self.current = None
        if tag == 'details' and self.detail_stack: self.detail_stack.pop()


class DashboardRedesignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.tmp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
        self.paths.policy.write_text('{"schema":1,"defaults":{},"targets":[]}')
        self.db = Database(self.paths.db)
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def insert(self, table, **values):
        self.db.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))

    def run_row(self, run_id='R1', target='example.test', status='success', started=None):
        self.insert('runs', id=run_id, version=APP_VERSION, status=status, started_at=started or self.now, target_count=1)
        self.insert('run_targets', run_id=run_id, target=target, policy_hash='test', status=status, started_at=started or self.now, run_dir=str(self.paths.output / run_id))

    def urls(self, count=2055, *, target='example.test', source='R1'):
        self.db.conn.executemany("INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) VALUES(?,?,'url','katana',?,?,?)", [(target, f'https://{target}/catalogneedle/{i:05}', self.now, self.now, source) for i in range(count)])

    def render(self, method, params=None, route=None):
        handler = object.__new__(DashboardHandler)
        handler.paths = self.paths
        handler.db_path = self.paths.db
        handler.config = Config(self.paths)
        handler.path = route or '/' + method
        handler.query = lambda: params or {}
        result = {}
        handler.send_html = lambda title, body, status=200: result.update(title=title, body=body, status=status)
        with patch('socket.socket.connect', side_effect=AssertionError('dashboard rendering must not contact a target')):
            getattr(handler, method)()
        self.assertEqual(result['status'], 200)
        return result['body']

    def test_closed_advanced_filters_preserve_native_controls_and_active_summary(self):
        fields = "<label>Query<input name='q' value='a&amp;b'></label><label>Target<select name='target'><option selected>x.test</option></select></label><label>Risk<input type='number' name='risk' value='70'></label><input type='hidden' name='display' value='table'>"
        markup = _filter_panel(fields, {'Risk': 70, 'Search': 'a&b'}, '/search', title='Filters', result_count=2055)
        parsed = FormInventory(markup)
        self.assertEqual(len(parsed.forms), 1)
        self.assertEqual(parsed.forms[0]['attrs']['method'], 'get')
        fields_by_name = {v['name']: (v, advanced) for _, v, advanced in parsed.fields}
        self.assertEqual(set(fields_by_name), {'q', 'target', 'risk', 'display'})
        self.assertFalse(fields_by_name['q'][1])
        self.assertFalse(fields_by_name['target'][1])
        self.assertTrue(fields_by_name['risk'][1])
        self.assertFalse(fields_by_name['display'][1])
        self.assertTrue(all('disabled' not in v for v, _ in fields_by_name.values()))
        self.assertTrue(all('open' not in d for d in parsed.details))
        self.assertIn('2055', markup)
        self.assertIn('a&amp;b', markup)
        self.assertIn("class='filter-chip'", markup)

    def test_search_counts_and_stable_pages_include_every_record_beyond_old_caps(self):
        self.urls()
        found = []
        for page in range(1, 22):
            data = search_workspace(self.db, 'catalogneedle', target='example.test', group='URLs', page=page)
            self.assertEqual(data['total'], 2055)
            found.extend(row['value'] for row in data['rows'].get('URLs', []))
        self.assertEqual(len(found), 2055)
        self.assertEqual(len(set(found)), 2055)
        self.assertEqual(found[0], 'https://example.test/catalogneedle/00000')
        self.assertEqual(found[-1], 'https://example.test/catalogneedle/02054')
        last = search_workspace(self.db, 'catalogneedle', group='URLs', page=10**12)
        self.assertEqual(last['page'], 21)
        self.assertEqual(len(last['rows']['URLs']), 55)

    def test_target_and_source_filters_do_not_mix_other_targets_or_runs(self):
        self.urls(2, source='R1')
        self.urls(3, target='other.test', source='R2')
        data = search_workspace(self.db, '*', target='example.test', run_id='R1', group='URLs')
        self.assertEqual(data['total'], 2)
        self.assertTrue(all(r['target']=='example.test' and r['source_run_id']=='R1' for r in data['rows']['URLs']))
        self.assertEqual(search_workspace(self.db, '*', target='example.test', run_id='R2', group='URLs')['total'], 0)

    def test_literal_percent_underscore_and_quotes_are_not_sql_wildcards(self):
        self.insert('urls', target='example.test', url='https://example.test/a%_b', first_seen=self.now, last_seen=self.now)
        self.insert('urls', target='example.test', url='https://example.test/axxb', first_seen=self.now, last_seen=self.now)
        self.assertEqual(search_workspace(self.db, '%_', group='URLs')['total'], 1)
        self.assertEqual(search_workspace(self.db, "'; DROP TABLE urls;--", group='URLs')['total'], 0)
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM urls')[0], 2)

    def test_original_cli_search_groups_remain_available(self):
        self.insert('assets', target='example.test', host='api.example.test', first_seen=self.now, last_seen=self.now)
        old = universal_search(self.db, 'example.test')
        self.assertTrue(old['Assets'])
        self.assertEqual(set(old), {'Cases','Stories','Candidates','Endpoints','Assets','JavaScript','Evidence','Captures'})

    def test_search_raw_ports_notes_tags_and_stage_metrics(self):
        self.run_row()
        self.insert('ports', target='example.test', host='portneedle.example.test', port=6379, first_seen=self.now, last_seen=self.now, last_run_id='R1')
        self.insert('investigation_notes', target='example.test', entity_type='asset', entity_value='api.example.test', note='reviewneedle', created_at=self.now, updated_at=self.now)
        self.insert('entity_tags', target='example.test', entity_type='asset', entity_value='api.example.test', tag='tagneedle', created_at=self.now)
        self.insert('stage_runs', run_id='R1', target='example.test', stage='urls', status='partial', started_at=self.now, metrics_json='{"katana_stop_reason":"batch_timeout"}')
        for query, group in [('portneedle','Ports'),('reviewneedle','Notes'),('tagneedle','Tags'),('batch_timeout','Stages')]:
            self.assertEqual(search_workspace(self.db, query, group=group)['total'], 1)
        row = search_workspace(self.db, 'batch_timeout', group='Stages')['rows']['Stages'][0]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(row['href']).query)['id'], ['R1'])

    def test_recon_raw_page_and_count_include_records_beyond_two_thousand(self):
        self.urls()
        body = self.render('recon_workspace', {'target':['example.test'],'view':['raw'],'raw':['url'],'q':['catalogneedle'],'page':['21']}, '/recon')
        self.assertIn('2055', body)
        self.assertIn('Page 21 of 21', body)
        self.assertIn('/catalogneedle/02054', body)
        self.assertNotIn('/catalogneedle/00000</code>', body)
        links = FormInventory(body).links
        previous = next(h for h in links if 'page=20' in h)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(previous).query)
        self.assertEqual(query['raw'], ['url'])
        self.assertEqual(query['q'], ['catalogneedle'])
        self.assertEqual(query['target'], ['example.test'])

    def test_raw_specialist_pages_report_total_and_keep_filters_in_pagination(self):
        self.urls()
        body = self.render('urls', {'target':['example.test'],'source':['katana'],'page':['21']})
        self.assertIn('Page 21 of 21', body)
        self.assertIn('2055', body)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(next(h for h in FormInventory(body).links if 'page=20' in h)).query)
        self.assertEqual(query['source'], ['katana'])
        self.assertIn('02054', body)

    def test_recon_multilabel_categories_and_other_do_not_drop_observations(self):
        for url in ['https://example.test/api/admin/upload', 'https://example.test/unclassified']:
            self.insert('urls', target='example.test', url=url, first_seen=self.now, last_seen=self.now)
        items, meta = _recon_surface_items(self.db)
        self.assertEqual(len(items), 2)
        by_value = {row['value']: row for row in items}
        self.assertTrue({'apis','admin_internal','file_upload'} <= set(by_value['https://example.test/api/admin/upload']['categories']))
        self.assertEqual(by_value['https://example.test/unclassified']['categories'], ['other'])
        self.assertIsNone(meta['coverage_overall'])

    def test_change_alert_search_and_paging_do_not_hide_records_after_three_hundred(self):
        self.run_row('R0', started='2026-01-01T00:00:00Z')
        self.run_row('R1', started=self.now)
        self.urls(405)
        data = search_workspace(self.db, 'catalogneedle', group='Change alerts', target='example.test')
        self.assertEqual(data['total'], 405)
        last = search_workspace(self.db, 'catalogneedle', group='Change alerts', page=5)
        self.assertEqual(len(last['rows']['Change alerts']), 5)
        body = self.render('alerts', {'view':['all'],'target':['example.test'],'q':['catalogneedle'],'sort':['value'],'page':['5']}, '/alerts')
        self.assertIn('Page 5 of 5', body)
        self.assertIn('405 results', body)
        preset = next(h for h in FormInventory(body).links if 'view=attention' in h)
        preset_query = urllib.parse.parse_qs(urllib.parse.urlsplit(preset).query)
        self.assertEqual(preset_query['target'], ['example.test'])
        self.assertEqual(preset_query['q'], ['catalogneedle'])
        self.assertEqual(preset_query['sort'], ['value'])
        self.assertNotIn('page', preset_query)

    def test_notes_filter_keeps_matching_entity_and_delete_post_control(self):
        for target, note in [('example.test','reviewneedle'),('other.test','different')]:
            self.insert('investigation_notes', target=target, entity_type='asset', entity_value='api.'+target, note=note, created_at=self.now, updated_at=self.now)
        body = self.render('notes', {'target':['example.test'],'q':['reviewneedle']})
        self.assertIn('reviewneedle', body)
        self.assertNotIn('api.other.test</code>', body)
        self.assertTrue(any(f['attrs'].get('action')=='/notes/delete' and f['attrs']['method']=='post' for f in FormInventory(body).forms))

    def test_exact_search_record_retains_full_details_and_escapes_markup(self):
        note = '<script>alert("stored")</script> provenance detail'
        self.insert('investigation_notes', target='example.test', entity_type='asset', entity_value='api.example.test', note=note, created_at=self.now, updated_at=self.now)
        data = search_workspace(self.db, '*', group='Notes', record='api.example.test')
        details = json.loads(data['rows']['Notes'][0]['record_details'])
        self.assertEqual(details['note'], note)
        body = self.render('search', {'q':['*'],'group':['Notes'],'record':['api.example.test']}, '/search')
        self.assertIn('Stored record details', body)
        self.assertIn('&lt;script&gt;', body)
        self.assertNotIn('<script>alert', body)

    def test_validation_approval_hash_is_not_indexed_or_in_record_details(self):
        self.insert('security_cases', case_id='C1', case_key='CK1', analysis_id='A1', source_run_id='R1', target='example.test', title='Case', summary='summary', primary_family='bola', created_at=self.now, updated_at=self.now)
        self.insert('validation_plans', plan_id='P1', case_id='C1', target='example.test', level='manual_only', status='draft', plan_json='{}', approval_phrase_hash='privateapprovalhash', created_by='test', created_at=self.now, updated_at=self.now)
        self.assertEqual(search_workspace(self.db, 'privateapprovalhash', group='Validation plans')['total'], 0)
        data=search_workspace(self.db,'*',group='Validation plans',record='P1')
        self.assertNotIn('approval_phrase_hash', json.loads(data['rows']['Validation plans'][0]['record_details']))

    def test_last_run_and_analysis_respect_selected_target(self):
        self.run_row('RA', 'example.test', started='2026-10-01T00:00:00Z')
        self.run_row('RB', 'other.test', started='2026-10-02T00:00:00Z')
        for name, target, source, date in [('AA','example.test','RA','2026-10-01'),('AB','other.test','RB','2026-10-02')]:
            self.insert('analysis_runs', id=name, source_run_id=source, target=target, engine_version='test', rule_version='test', status='success', started_at=date)
        snapshot = _command_center_snapshot(self.db, 'example.test')
        self.assertEqual(snapshot['latest_run']['id'], 'RA')
        self.assertEqual(snapshot['latest_analysis']['id'], 'AA')
        self.assertEqual([r['id'] for r in snapshot['recent_runs']], ['RA'])

    def test_global_analysis_remains_visible_for_its_source_target(self):
        self.run_row('RA', 'example.test', started='2026-10-01T00:00:00Z')
        self.run_row('RB', 'other.test', started='2026-10-02T00:00:00Z')
        for name, source, date in [('GLOBAL-A','RA','2026-10-01'),('GLOBAL-B','RB','2026-10-02')]:
            self.insert('analysis_runs', id=name, source_run_id=source, target='*', engine_version='test', rule_version='test', status='success', started_at=date)
        self.assertEqual(_latest_completed_analysis(self.db, 'example.test')['id'], 'GLOBAL-A')
        data = search_workspace(self.db, '*', target='example.test', group='Analyses')
        self.assertEqual([r['value'] for r in data['rows']['Analyses']], ['GLOBAL-A'])

    def test_read_only_search_does_not_commit_or_rollback_an_existing_transaction(self):
        with self.db.transaction():
            self.insert('urls', target='example.test', url='https://example.test/in-transaction', first_seen=self.now, last_seen=self.now)
            self.assertEqual(search_workspace(self.db, 'in-transaction', group='URLs')['total'], 1)
            self.assertTrue(self.db.conn.in_transaction)
        self.assertFalse(self.db.conn.in_transaction)
        self.assertEqual(search_workspace(self.db, 'in-transaction', group='URLs')['total'], 1)
        self.assertFalse(self.db.conn.in_transaction)

    def test_timeout_and_zero_js_inputs_are_visible_before_raw_metrics_details(self):
        self.run_row(status='partial')
        self.insert('stage_runs', run_id='R1', target='example.test', stage='urls', status='partial', started_at=self.now, finished_at=self.now, exit_code=124, duration_seconds=1800,
                    metrics_json=json.dumps({'collection_status':'partial','katana_status':'timeout','katana_timed_out':True,'katana_input_origins':24,'katana_origins_completed':15,'katana_pending_origins':9,'katana_observed':73,'katana_stop_reason':'batch_timeout','katana_exit_code':124,'katana_duration_seconds':1800}))
        self.insert('stage_runs', run_id='R1', target='example.test', stage='javascript', status='success', started_at=self.now, metrics_json='{"files":0,"downloaded":0}')
        body = self.render('run_review', {'id':['R1']}, '/run-review')
        visible = body.split("<details class='panel' id='stage-", 1)[0]
        for value in ['Partial / Timeout','No JS input','24 input','15 completed','9 pending','73 lines','batch_timeout','124','1800']:
            self.assertIn(value, visible)
        self.assertIn('<pre', body)
        snapshot = _command_center_snapshot(self.db)
        self.assertEqual(snapshot['collection_quality'], {'partial':1,'timeout':1,'no_input':1})
        self.assertEqual(snapshot['decisions'][0]['kind'], 'run')

    def test_live_next_stage_form_keeps_attempt_target_and_post_contract(self):
        self.run_row(status='running')
        self.db.execute("UPDATE run_targets SET current_stage='urls' WHERE run_id='R1'")
        self.insert('stage_runs', run_id='R1', target='example.test', stage='urls', status='running', attempt=3, started_at=self.now)
        body = self.render('run_review', {'id':['R1']}, '/run-review')
        form = next(f for f in FormInventory(body).forms if f['attrs'].get('action')=='/run/next-stage')
        self.assertEqual(form['attrs']['method'], 'post')
        fields = {v['name']:v.get('value') for v in form['fields']}
        self.assertEqual(fields, {'run_id':'R1','target':'example.test','stage':'urls','attempt':'3'})

    def test_stored_text_is_opt_in_and_reads_past_chunk_boundaries(self):
        path = self.paths.blobs / 'script.js'
        path.write_bytes(b'a'*65531 + b'uniqueneedle' + b'z'*100000)
        self.insert('js_files', target='example.test', url='https://example.test/app.js', raw_hash='hash', semantic_hash='sem', blob_path=str(path), content_length=path.stat().st_size, first_seen=self.now, last_seen=self.now, last_run_id='R1')
        self.assertTrue(contains_text(path, 'uniqueneedle'))
        self.assertEqual(search_workspace(self.db, 'uniqueneedle', paths=self.paths)['total'], 0)
        data = search_workspace(self.db, 'uniqueneedle', include_files=True, paths=self.paths)
        self.assertEqual(data['counts']['Stored text'], 1)
        self.assertEqual(data['unavailable_files'], 0)
        self.assertEqual(search_workspace(self.db, 'uniqueneedle', target='other.test', include_files=True, paths=self.paths)['total'], 0)

    def test_stored_text_rejects_external_paths_and_symbolic_links(self):
        outside = self.paths.root / 'config.env'
        outside.write_text('privateneedle')
        link = self.paths.blobs / 'linked.js'
        link.symlink_to(outside)
        for i, path in enumerate([outside, link]):
            self.insert('js_files', target='example.test', url=f'https://example.test/{i}.js', raw_hash=str(i), semantic_hash=str(i), blob_path=str(path), content_length=13, first_seen=self.now, last_seen=self.now)
        data = search_workspace(self.db, 'privateneedle', include_files=True, paths=self.paths)
        self.assertEqual(data['counts']['Stored text'], 0)
        self.assertEqual(data['unavailable_files'], 2)

    def test_known_routes_filters_actions_categories_and_raw_types_are_preserved(self):
        baseline = json.loads((ROOT / 'docs/dashboard-redesign-baseline.json').read_text())
        source = (ROOT / 'app/dashboard_core.py').read_text()
        tree = ast.parse(source)
        methods = {n.name:n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        get = methods['do_GET']
        get_source = '\n'.join(source.splitlines()[get.lineno-1:get.end_lineno])
        for route in baseline['routes']:
            self.assertIn('"'+route+'"', get_source)
        for page in baseline['pages']:
            node = methods[page['handler']]
            text = '\n'.join(source.splitlines()[node.lineno-1:node.end_lineno])
            for field in page['form_field_candidates']:
                literal = "name='"+field+"'" in text
                select = re.search(r"_select(?:_pairs)?\(\s*['\"]"+re.escape(field)+r"['\"]", text)
                self.assertTrue(literal or select, (page['handler'],field))
            for action in page['post_action_candidates']:
                self.assertIn("action='"+action+"'", text, (page['handler'],action))
        # Verify every new search workspace link resolves to a known GET route.
        for item in SEARCH_GROUPS:
            self.assertIn(item.route, baseline['routes'])

    def test_layout_preserves_csrf_and_full_specialist_navigation(self):
        body = "<form method='post' action='/workspace/sync'><input name='target' value='example.test'></form>"
        markup = _layout('Analysis', body, csrf='token', username='admin', role='admin', current_path='/analysis?target=example.test')
        parsed = FormInventory(markup)
        form = next(f for f in parsed.forms if f['attrs'].get('action')=='/workspace/sync')
        self.assertEqual({v['name']:v.get('value') for v in form['fields']}, {'target':'example.test','csrf':'token'})
        for href in ['/hypotheses','/clusters','/dataflows','/auth-contexts','/analysis-quality','/semantic-intelligence']:
            self.assertIn(href+'?target=example.test', parsed.links)
        for href in ['/','/recon','/analysis','/potential-findings','/alerts']:
            self.assertIn(href+'?target=example.test', parsed.links)
        search = next(f for f in parsed.forms if f['attrs'].get('action')=='/search')
        self.assertEqual({v['name']:v.get('value','') for v in search['fields']}, {'q':'','target':'example.test'})
        self.assertIn("id='densityToggle'", markup)
        self.assertIn("id='focusToggle'", markup)
        self.assertIn("id='themeToggle'", markup)

    def test_empty_investigation_queue_retains_context_without_empty_metric_tiles(self):
        from dashboard import _investigation_queue_panel
        analysis_id = 'AN-20261004-long-context-identifier'
        markup = _investigation_queue_panel(analysis_id, [])
        parsed = FormInventory(markup)
        self.assertIn(analysis_id, markup)
        self.assertIn('0 clusters', markup)
        self.assertIn('Potential Findings remain available below', markup)
        self.assertNotIn("class='attention-card'", markup)
        self.assertNotIn("class='empty-state'", markup)
        self.assertEqual(len(parsed.details), 1)
        self.assertNotIn('open', parsed.details[0])
        for field in ['Clusters', 'High priority', 'Strong correlation', 'Change-linked', 'cluster strength ≥60', 'not confirmed vulnerabilities']:
            self.assertIn(field, markup)

    def test_pagination_escapes_query_values_without_losing_their_meaning(self):
        markup = pagination('/search', {'q':"a&b'<>"}, 200, 1, 100)
        href = FormInventory(markup).links[0]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)['q'], ["a&b'<>"])

    @unittest.skipUnless(shutil.which('node'), 'Node is optional; needed for offline JavaScript behavior checks')
    def test_production_scroll_and_live_polling_behavior_without_network(self):
        class ScriptParser(HTMLParser):
            def __init__(self): super().__init__(); self.active=False; self.parts=[]
            def handle_starttag(self, tag, attrs):
                if tag=='script': self.active=True
            def handle_endtag(self, tag):
                if tag=='script': self.active=False
            def handle_data(self, text):
                if self.active: self.parts.append(text)
        parser=ScriptParser(); parser.feed(_layout('Recon','',current_path='/recon'))
        result = subprocess.run([shutil.which('node'),str(ROOT/'tests/dashboard_ui_behavior.js')], input='\n'.join(parser.parts), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()

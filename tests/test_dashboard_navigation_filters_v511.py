from __future__ import annotations

import json
import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from core import AppPaths, Database, utc_now
from dashboard import DashboardHandler, _layout
from product_platform import list_cases


class DashboardNavigationFiltersV511Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = AppPaths.from_root(self.root)
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding='utf-8')
        self.paths.policy.write_text(json.dumps({
            'schema': 1,
            'defaults': {},
            'targets': [
                {'name': 'example.com', 'roots': ['example.com'], 'include': ['*.example.com'], 'exclude': []},
                {'name': 'api.example.net', 'roots': ['api.example.net'], 'include': [], 'exclude': []},
            ],
        }), encoding='utf-8')
        self.db = Database(self.paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json,error) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ('A1', 'R1', 'example.com', '5.1.0', 'v1', 'balanced', 'success', now, now, '{}', None),
        )
        self.db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('C1', 'K1', 'A1', 'R1', 'example.com', 'Tenant access boundary', 'Possible cross-tenant access', 'bola', 91, 'ready_for_validation', 'alice', 'in_scope', 82, now, now),
        )
        self.db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('C2', 'K2', 'A1', 'R1', 'api.example.net', 'Response exposure', 'Possible disclosure', 'information_disclosure', 45, 'needs_evidence', '', 'unknown', 25, now, now),
        )
        self.db.execute("UPDATE security_cases SET validation_state='awaiting_approval' WHERE case_id='C1'")
        self.db.execute("UPDATE security_cases SET validation_state='not_started' WHERE case_id='C2'")
        self.db.execute(
            "INSERT INTO validation_plans(plan_id,case_id,target,level,status,plan_json,approval_phrase_hash,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ('P1', 'C1', 'example.com', 'controlled', 'awaiting_approval', '{}', 'hash', 'test', now, now),
        )
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count,error) VALUES(?,?,?,?,?,?,?,?)",
            ('R1', '5.1.0', 'success', now, now, 'example.com', 1, None),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,?,0)",
            ('R1', 'example.com', 'h', 'success', 'report', now, now, str(self.paths.output / 'R1')),
        )
        self.db.close()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def handler(self, path: str, query: dict[str, list[str]] | None = None):
        handler = object.__new__(DashboardHandler)
        handler.paths = self.paths
        handler.db_path = self.paths.db
        handler.path = path
        handler.query = lambda: query or {}
        captured: dict[str, object] = {}
        handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
        return handler, captured

    def test_navigation_is_grouped_collapsible_and_marks_active_section(self) -> None:
        html = _layout('Cases', '<p>body</p>', current_path='/cases')
        for group in ('workspace', 'analysis', 'quality', 'operations', 'inventory', 'advanced'):
            self.assertIn(f"data-nav-group='{group}'", html)
        self.assertIn('Decide, validate, report', html)
        self.assertIn('Candidates and reasoning', html)
        self.assertIn('Scope, runs and platform health', html)
        self.assertIn("class='nav-item active' href='/potential-findings'", html)
        self.assertNotIn("class='nav-item active' href='/cases'", html)
        self.assertIn("localStorage.setItem(key", html)
        self.assertIn("<strong>System</strong>", html)

    def test_recon_workspace_has_three_clean_layers(self) -> None:
        handler, captured = self.handler('/recon', {'view': ['overview']})
        handler.recon_workspace()
        body = str(captured.get('body') or '')
        self.assertIn('Attack Surface Summary', body)
        self.assertIn('New / Changed Surface', body)
        self.assertIn('High-interest Areas', body)
        self.assertIn('Coverage / Blind Spots', body)

        handler, captured = self.handler('/recon?view=categories', {'view': ['categories']})
        handler.recon_workspace()
        body = str(captured.get('body') or '')
        for label in ('Hosts &amp; Subdomains','APIs','Authentication','Admin / Internal','File &amp; Upload','Data / Object','Client-side / JavaScript','Infrastructure','Other'):
            self.assertIn(label, body)

        handler, captured = self.handler('/recon?view=raw', {'view': ['raw']})
        handler.recon_workspace()
        body = str(captured.get('body') or '')
        for label in ('Hosts','URLs','Endpoints','Ports','JavaScript','Fingerprints'):
            self.assertIn(label, body)


    def test_case_query_supports_multi_dimension_filters_and_sorting(self) -> None:
        db = Database(self.paths.db)
        try:
            rows = list_cases(
                db,
                q='tenant',
                target='example.com',
                family='bola',
                assigned_to='alice',
                validation_state='awaiting_approval',
                scope_status='in_scope',
                min_priority=80,
                min_readiness=70,
                sort='readiness',
            )
            self.assertEqual([row['case_id'] for row in rows], ['C1'])
            unassigned = list_cases(db, assigned_to='__unassigned__')
            self.assertEqual([row['case_id'] for row in unassigned], ['C2'])
        finally:
            db.close()

    def test_case_safe_validation_and_run_pages_render_filter_panels(self) -> None:
        handler, captured = self.handler('/cases', {
            'q': ['tenant'], 'target': ['example.com'], 'family': ['bola'],
            'owner': ['alice'], 'validation': ['awaiting_approval'], 'sort': ['readiness'],
        })
        handler.cases_page()
        body = str(captured['body'])
        self.assertIn('Case filters', body)
        self.assertIn("name='validation'", body)
        self.assertIn("name='owner'", body)
        self.assertIn('Tenant access boundary', body)
        self.assertNotIn('Response exposure', body)

        handler, captured = self.handler('/safe-validation', {
            'target': ['example.com'], 'family': ['bola'], 'level': ['controlled'],
            'plan_status': ['awaiting_approval'],
        })
        handler.safe_validation_page()
        body = str(captured['body'])
        self.assertIn('Validation filters', body)
        self.assertIn("name='plan_status'", body)
        self.assertIn('P1', body)

        handler, captured = self.handler('/runs', {'target': ['example.com'], 'status': ['success']})
        handler.runs()
        body = str(captured['body'])
        self.assertIn('Run filters', body)
        self.assertIn("name='error'", body)
        self.assertIn('R1', body)

    def test_inventory_pages_expose_structured_filter_controls(self) -> None:
        routes = (
            ('/assets', 'assets', ('Asset filters', "name='lifecycle'", "name='wildcard'")),
            ('/endpoints', 'endpoints', ('Endpoint filters', "name='category'", "name='source'")),
            ('/urls', 'urls', ('URL filters', "name='kind'", "name='source'")),
            ('/javascript', 'javascript', ('JavaScript filters', "name='kind'", "name='redacted'")),
            ('/fingerprints', 'fingerprints', ('HTTP / TLS filters', "name='status_class'", "name='technology'")),
            ('/alerts', 'alerts', ('Alert filters', "name='owner'", "name='priority'")),
        )
        for path, method, expected in routes:
            handler, captured = self.handler(path, {})
            getattr(handler, method)()
            body = str(captured['body'])
            for needle in expected:
                self.assertIn(needle, body, f'{needle!r} missing from {path}')


if __name__ == '__main__':
    unittest.main()

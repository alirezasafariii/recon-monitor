from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from core import AppPaths, Database
from dashboard import DashboardHandler, _change_alert_events, _layout


class DashboardFourWorkspacesV70Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = AppPaths.from_root(self.root)
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding='utf-8')
        self.paths.policy.write_text(json.dumps({'schema': 1, 'defaults': {}, 'targets': [{'name': 'example.com', 'roots': ['example.com'], 'include': [], 'exclude': []}]}), encoding='utf-8')
        self.db = Database(self.paths.db)
        for rid, start, finish in (
            ('R1', '2026-08-01T00:00:00Z', '2026-08-01T00:10:00Z'),
            ('R2', '2026-08-08T00:00:00Z', '2026-08-08T00:10:00Z'),
        ):
            self.db.execute('INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count,error) VALUES(?,?,?,?,?,?,?,?)', (rid, '7.0.0', 'success', start, finish, 'example.com', 1, None))
            self.db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,?,0)", (rid, 'example.com', 'h', 'success', 'report', start, finish, str(self.root / rid)))
        for endpoint, first in (
            ('/api/v1/users', '2026-08-01T00:05:00Z'),
            ('/api/v2/admin', '2026-08-08T00:05:00Z'),
        ):
            self.db.execute("INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ('example.com', endpoint, 'url', 'api', 90, '[]', '[]', '[]', first, '2026-08-08T00:06:00Z', 'R2'))
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

    def test_primary_navigation_exposes_four_research_workspaces(self) -> None:
        page = _layout('Recon', '<p>body</p>', current_path='/recon')
        for group, label in (('recon', '01 · Recon'), ('analysis', '02 · Analysis'), ('findings', '03 · Potential Findings'), ('alerts', '04 · Alerts')):
            self.assertIn(f"data-nav-group='{group}'", page)
            self.assertIn(label, page)
        self.assertIn("class='nav-item active' href='/recon'", page)

    def test_recheck_creates_alert_only_for_new_endpoint(self) -> None:
        db = Database(self.paths.db)
        try:
            events = _change_alert_events(db, 'example.com')
        finally:
            db.close()
        self.assertTrue(any(e['kind'] == 'endpoint' and e['value'] == '/api/v2/admin' and e['change'] == 'added' for e in events))
        self.assertFalse(any(e['kind'] == 'endpoint' and e['value'] == '/api/v1/users' and e['change'] == 'added' for e in events))
        admin = next(e for e in events if e['value'] == '/api/v2/admin')
        self.assertEqual(admin['priority'], 'high')
        self.assertEqual(admin['previous_run'], 'R1')
        self.assertEqual(admin['run_id'], 'R2')

    def test_alert_page_has_search_and_change_filters(self) -> None:
        handler, captured = self.handler('/alerts', {'target': ['example.com']})
        handler.alerts()
        body = str(captured['body'])
        self.assertIn('Alert search &amp; filters', body)
        self.assertIn("name='q'", body)
        self.assertIn("name='kind'", body)
        self.assertIn("name='change'", body)
        self.assertIn("name='priority'", body)
        self.assertIn('/api/v2/admin', body)
        self.assertIn('R1', body)
        self.assertIn('R2', body)


if __name__ == '__main__':
    unittest.main()

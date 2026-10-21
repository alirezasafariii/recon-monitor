from __future__ import annotations

import json
import unittest

import test_workspace_v70 as fixtures
from core import utc_now
from workspace_v7 import authentication_contexts, import_browser_capture, recon_coverage


class BrowserCaptureAuthStateTests(unittest.TestCase):
    def setUp(self):
        self.temp, self.paths, self.db = fixtures.WorkspaceV70Tests().project()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.db.close)

    def capture(self, label):
        path = self.paths.root / 'capture.json'
        path.write_text(json.dumps({'entries': [{
            'url': 'https://example.com/shop?token=private',
            'method': 'POST', 'status_code': 200,
            'content_type': 'application/json',
            'auth_state': 'authenticated',
            'headers': {'Cookie': 'sid=private'},
        }]}), encoding='utf-8')
        result = import_browser_capture(self.paths, self.db, target='example.com',
                                        file_path=path, context_label=label)
        self.assertEqual(result['imported'], 1)
        return self.contexts()[label]

    def contexts(self):
        return {item['label']: item for item in authentication_contexts(
            self.db, target='example.com', analysis_id='AN-1', persist=True)}

    def observe(self, label, state):
        self.db.execute(
            "INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,"
            "status_code,shape_hash,headers_json,source_ref,confidence,created_at) "
            "VALUES('AN-1','example.com','/api/account',?,?,200,'shape','{}',?,90,?)",
            (label, state, 'fixture-' + state, utc_now()),
        )

    def imported_observation(self, label, state=None):
        self.db.execute(
            "INSERT INTO imported_http_evidence(observation_id,case_id,target,source_type,"
            "source_file,observation_json,imported_by,created_at) "
            "VALUES(?,'CASE-BOLA','example.com','har','fixture.har',?,'test',?)",
            (label, json.dumps({'context': label, 'auth_state': state,
                               'url': 'https://example.com/api/account', 'status_code': 200}), utc_now()),
        )

    def test_browser_label_and_http_success_do_not_establish_login(self):
        context = self.capture('browser-observed')
        self.assertEqual(context['auth_state'], 'unknown')
        self.assertIn('browser_capture', context['sources'])
        self.assertEqual(context['endpoint_count'], 1)
        persisted = self.db.one("SELECT * FROM auth_context_profiles WHERE label='browser-observed'")
        self.assertEqual(persisted['auth_state'], 'unknown')
        self.assertNotIn('sid=private', self.db.one('SELECT metadata_json FROM browser_capture_events')['metadata_json'])

    def test_account_name_alone_does_not_establish_login(self):
        self.assertEqual(self.capture('Account A')['auth_state'], 'unknown')

    def test_declared_public_context_is_anonymous(self):
        self.assertEqual(self.capture('public')['auth_state'], 'anonymous')

    def test_explicit_behavior_state_takes_precedence_over_ordinary_label(self):
        self.observe('Browser visitor', 'anonymous')
        self.assertEqual(self.contexts()['Browser visitor']['auth_state'], 'anonymous')
        self.assertEqual(self.contexts()['User A']['auth_state'], 'authenticated')

    def test_conflicting_observations_are_unknown_in_either_order(self):
        for label, states in (('mixed-a', ('anonymous', 'authenticated')),
                              ('mixed-b', ('authenticated', 'anonymous'))):
            for state in states:
                self.observe(label, state)
            self.assertEqual(self.contexts()[label]['auth_state'], 'unknown')

    def test_public_label_conflicting_with_authenticated_observation_is_unknown(self):
        self.observe('public', 'authenticated')
        self.assertEqual(self.contexts()['public']['auth_state'], 'unknown')

    def test_imported_http_requires_explicit_auth_state(self):
        self.imported_observation('Imported browser')
        self.imported_observation('Imported account', 'authenticated')
        self.imported_observation('Imported guest', 'anonymous')
        contexts = self.contexts()
        self.assertEqual(contexts['Imported browser']['auth_state'], 'unknown')
        self.assertEqual(contexts['Imported account']['auth_state'], 'authenticated')
        self.assertEqual(contexts['Imported guest']['auth_state'], 'anonymous')

    def test_conflicting_state_across_sources_is_unknown(self):
        self.observe('Mixed sources', 'authenticated')
        self.imported_observation('Mixed sources', 'anonymous')
        self.assertEqual(self.contexts()['Mixed sources']['auth_state'], 'unknown')

    def test_malformed_imported_auth_state_is_unknown(self):
        self.imported_observation('Malformed imported state', {'authenticated': True})
        self.assertEqual(self.contexts()['Malformed imported state']['auth_state'], 'unknown')

    def test_identity_or_role_name_does_not_establish_login(self):
        self.db.execute(
            "INSERT INTO identity_entities(analysis_id,target,entity_type,entity_value,"
            "confidence,evidence_json,created_at) "
            "VALUES('AN-1','example.com','role','Admin',90,'{}',?)", (utc_now(),),
        )
        self.assertEqual(self.contexts()['Admin']['auth_state'], 'unknown')

    def test_unknown_and_anonymous_captures_do_not_inflate_auth_or_role_coverage(self):
        self.capture('browser-observed')
        self.capture('Account A')
        self.capture('public')
        coverage = recon_coverage(self.db, target='example.com', persist=False)
        self.assertEqual(coverage['components']['authenticated'], 28)
        self.assertEqual(coverage['components']['role'], 0)
        self.db.execute("DELETE FROM behavioral_observations WHERE analysis_id='AN-1'")
        coverage = recon_coverage(self.db, target='example.com', persist=False)
        self.assertEqual(coverage['components']['authenticated'], 0)
        self.assertEqual(coverage['components']['role'], 0)

    def test_explicit_second_authenticated_context_still_counts(self):
        self.observe('User B', 'authenticated')
        self.capture('browser-observed')
        coverage = recon_coverage(self.db, target='example.com', persist=False)
        self.assertEqual(coverage['components']['authenticated'], 56)
        self.assertEqual(coverage['components']['role'], 35)

    def test_recompute_repairs_existing_profile_without_changing_capture_or_run(self):
        self.capture('browser-observed')
        self.db.execute("UPDATE auth_context_profiles SET auth_state='authenticated' WHERE label='browser-observed'")
        self.db.execute("UPDATE runs SET status='partial' WHERE id='RUN-NEW'")
        run_before = dict(self.db.one("SELECT * FROM runs WHERE id='RUN-NEW'"))
        capture_before = [dict(row) for row in self.db.all('SELECT * FROM browser_capture_events')]
        context_before = dict(self.db.one("SELECT * FROM auth_context_profiles WHERE label='browser-observed'"))
        self.contexts()
        context_after = self.db.one("SELECT * FROM auth_context_profiles WHERE label='browser-observed'")
        self.assertEqual(context_after['auth_state'], 'unknown')
        self.assertEqual(context_after['context_id'], context_before['context_id'])
        self.assertEqual(dict(self.db.one("SELECT * FROM runs WHERE id='RUN-NEW'")), run_before)
        self.assertEqual([dict(row) for row in self.db.all('SELECT * FROM browser_capture_events')], capture_before)


if __name__ == '__main__':
    unittest.main()

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import bug_candidates
from core import utc_now
from hypothesis_admission import record_hypothesis
from test_graphql_data_exposure_differential_admission import (
    ANALYSIS_ID, RUN_ID, TARGET, GraphqlDataExposureFixture,
)


class GraphqlStaticAdmissionTests(unittest.TestCase):
    def test_many_static_operations_need_independent_policy_or_response_evidence(self):
        for separate_sources in (False, True):
            with (self.subTest(separate_sources=separate_sources),
                  tempfile.TemporaryDirectory() as root,
                  closing(GraphqlDataExposureFixture(Path(root))) as fixture):
                db = fixture.db
                for index, operation in enumerate((
                    'query Account', 'query ACCOUNT_ICON_URL_QUERY',
                    'query CustomerIdentityToken', 'mutation UpdateUserPreferences',
                )):
                    source = f'https://example.test/app{index if separate_sources else 0}.js'
                    db.execute('''INSERT INTO graphql_intelligence(analysis_id,target,run_id,
                        js_url,operation_name,operation_type,identifiers_json,sensitive_fields_json,
                        confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',
                        (ANALYSIS_ID, TARGET, RUN_ID, source, operation,
                         operation.split()[0], '[]', json.dumps(['account']), 70, utc_now()))
                bug_candidates._static_candidates(db, ANALYSIS_ID, RUN_ID, TARGET)
                rows = db.all("SELECT * FROM analysis_hypotheses WHERE bug_family='graphql_data_exposure'")
                self.assertTrue(rows)
                self.assertGreaterEqual(max(json.loads(r['admission_json'])['independent_sources'] for r in rows), 2)
                for row in rows:
                    self.assertFalse(json.loads(row['admission_json'])['admitted'])
                    self.assertFalse(row['promoted_candidate_id'])
                self.assertEqual(db.one("SELECT COUNT(*) FROM bug_candidates WHERE bug_family='graphql_data_exposure'")[0], 0)

                # A separately documented field policy still supplies the missing
                # context; preserving recall does not depend on hiding all GraphQL.
                row = rows[0]
                updated = record_hypothesis(db, analysis_id=ANALYSIS_ID, source_run_id=RUN_ID,
                    target=TARGET, alert_id=None, asset=row['asset'], endpoint=row['endpoint'],
                    source_ref=row['source_ref'], family='graphql_data_exposure',
                    variant=row['bug_variant'], support=[{
                        'type': 'field_policy_context', 'source': 'stored_security_policy',
                        'source_group': 'documented_role_field_policy', 'weight': 15,
                        'text': 'A documented role-specific field boundary exists.',
                    }], contradict=[], missing=[], rule_ids=['test-policy-context'],
                    summary='Stored field policy supplements static operations.')
                self.assertTrue(updated['assessment']['admitted'])


if __name__ == '__main__':
    unittest.main()

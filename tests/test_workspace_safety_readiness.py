from __future__ import annotations

import unittest
from unittest.mock import patch

import test_workspace_v70 as fixtures
from core import Config
from product_platform import scope_center
from workspace_v7 import safety_center


class WorkspaceSafetyReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp, self.paths, self.db = fixtures.WorkspaceV70Tests().project()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.db.close)
        self.db.audit('readiness_fixture', actor='test')

    def readiness(self):
        return safety_center(self.paths, Config(self.paths), self.db)

    def test_verified_audit_and_scope_allow_ready_but_authorization_is_required(self):
        result = self.readiness()
        self.assertTrue(result['audit_integrity']['ok'])
        self.assertTrue(result['scope_ready'])
        self.assertEqual(result['status'], 'SAFE TO RUN')
        self.paths.config.write_text(self.paths.config.read_text().replace(
            'I_HAVE_AUTHORIZATION="yes"', 'I_HAVE_AUTHORIZATION="no"'), encoding='utf-8')
        self.assertEqual(self.readiness()['status'], 'ACTION REQUIRED')

    def test_missing_scope_stays_unready_until_snapshot_refresh(self):
        self.db.execute('DELETE FROM scope_snapshots')
        result = self.readiness()
        self.assertTrue(result['audit_integrity']['ok'])
        self.assertFalse(result['scope_ready'])
        self.assertEqual(result['status'], 'ACTION REQUIRED')
        scope_center(self.paths, self.db, persist=True)
        self.assertEqual(self.readiness()['status'], 'SAFE TO RUN')

    def test_tampered_audit_stays_unready(self):
        self.db.execute("UPDATE audit_log SET action='modified_after_signing'")
        result = self.readiness()
        self.assertFalse(result['audit_integrity']['ok'])
        self.assertEqual(result['status'], 'ACTION REQUIRED')

    def test_missing_canonical_audit_result_is_not_accepted(self):
        with patch('platform_v6.verify_audit_chain', return_value={'valid': True}):
            self.assertEqual(self.readiness()['status'], 'ACTION REQUIRED')

    def test_verifier_error_stays_unready_with_canonical_failure_result(self):
        with patch('platform_v6.verify_audit_chain', side_effect=RuntimeError('verifier unavailable')):
            result = self.readiness()
        self.assertIs(result['audit_integrity'].get('ok'), False)
        self.assertEqual(result['status'], 'ACTION REQUIRED')
        self.assertEqual(result['audit_integrity']['error'], 'verifier unavailable')


if __name__ == '__main__':
    unittest.main()

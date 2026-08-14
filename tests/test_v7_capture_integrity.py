from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

from v7_capture_guard import (
    ENGINE_BASELINE_COMMIT,
    SOURCE_ASSIGNMENT_COMMIT,
    validate_capture_source_freeze,
)
from v7_literal_evidence_publish import _targeted_positive_confirmation


class V7CaptureIntegrityTests(unittest.TestCase):
    def test_frozen_source_assignment_revalidates(self) -> None:
        result = validate_capture_source_freeze()
        self.assertTrue(result['passed'], result['errors'])
        self.assertEqual(result['engine_baseline_commit'], 'b8b15261cc4049a1e5e425a83e57b6378a856113')
        self.assertEqual(result['source_assignment_commit'], '5c2c81075b870fe43db817c59a65f27423012f08')
        self.assertEqual(result['family_count'], 36)
        self.assertEqual(result['unique_root_count'], 36)
        self.assertEqual(result['unique_project_count'], 36)
        self.assertEqual(result['recomputed_engine_seen_count'], 0)
        self.assertEqual(result['targeted_fallback_count'], 4)
        self.assertFalse(result['scoring_executed'])
        self.assertFalse(result['first_blind_consumed'])
        self.assertFalse(result['merge_authorized'])

    def test_targeted_family_confirmation_requires_direct_fields(self) -> None:
        row = {
            'adjudication': {
                'family_literal_confirmed': True,
                'family_literal_family': 'ssrf',
                'family_literal_confirmation_basis': 'direct upstream vulnerable-path observation',
                'family_literal_confirmation_signals': ['server fetches attacker-controlled URL'],
            }
        }
        self.assertTrue(_targeted_positive_confirmation(row, 'ssrf', Path('sample.json')))
        self.assertFalse(_targeted_positive_confirmation(row, 'sql_injection', Path('sample.json')))
        row['adjudication']['family_literal_confirmation_signals'] = []
        self.assertFalse(_targeted_positive_confirmation(row, 'ssrf', Path('sample.json')))


if __name__ == '__main__':
    unittest.main()

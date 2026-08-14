from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

import v7_boundary_capture as boundary


class V7BoundaryCaptureTests(unittest.TestCase):
    def test_extracts_github_urls_recursively_without_patch_content(self) -> None:
        payload = {
            'references': ['https://github.com/acme/repo/commit/abcdef1234567'],
            'description': 'Fixed in https://github.com/acme/repo/pull/42.',
            'patch': 'https://github.com/ignore/patch/1',
        }
        urls = boundary.urls_from(payload)
        self.assertIn('https://github.com/acme/repo/commit/abcdef1234567', urls)
        self.assertIn('https://github.com/acme/repo/pull/42', urls)
        self.assertNotIn('https://github.com/ignore/patch/1', urls)

    def test_version_boundary_normalizes_advisory_shapes(self) -> None:
        global_adv = {
            'vulnerabilities': [{
                'package': {'ecosystem': 'pip', 'name': 'demo'},
                'vulnerable_version_range': '< 2.0.0',
                'first_patched_version': {'identifier': '2.0.0'},
            }]
        }
        rows = boundary.version_boundaries({}, global_adv)
        self.assertEqual(rows[0]['package'], 'demo')
        self.assertEqual(rows[0]['patched_version'], '2.0.0')
        self.assertEqual(rows[0]['vulnerable_version_range'], '< 2.0.0')


if __name__ == '__main__':
    unittest.main()

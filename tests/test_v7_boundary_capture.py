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

    def test_single_direct_commit_is_the_only_exact_fix_candidate(self) -> None:
        direct = {
            'kind': 'commit',
            'sha': 'a' * 40,
            'parent_shas': ['b' * 40],
            'file_count': 3,
            'reference_url': 'https://github.com/acme/repo/commit/' + 'a' * 40,
        }
        derived = {
            'kind': 'commit',
            'sha': 'c' * 40,
            'parent_shas': ['d' * 40],
            'file_count': 2,
            'derived_from_pull_request': 'https://github.com/acme/repo/pull/42',
        }
        result = boundary.select_direct_fix_commit([direct, derived])
        self.assertEqual(result['candidate_count'], 1)
        self.assertFalse(result['ambiguous'])
        self.assertEqual(result['selected']['sha'], 'a' * 40)

    def test_multiple_direct_commits_are_ambiguous_fail_closed(self) -> None:
        commits = [
            {
                'kind': 'commit',
                'sha': char * 40,
                'parent_shas': ['f' * 40],
                'file_count': 1,
                'reference_url': 'https://github.com/acme/repo/commit/' + char * 40,
            }
            for char in ('a', 'b')
        ]
        result = boundary.select_direct_fix_commit(commits)
        self.assertEqual(result['candidate_count'], 2)
        self.assertTrue(result['ambiguous'])
        self.assertIsNone(result['selected'])

    def test_global_advisory_accepts_only_frozen_ghsa_aliases(self) -> None:
        entry = {
            'family': 'open_redirect',
            'source_root': 'GHSA-xcvf-46f4-xwxf',
            'frozen_ghsa_aliases': [
                'ghsa-xcvf-46f4-xwxf',
                'ghsa-vrw8-fxc6-2r93',
            ],
        }
        result = boundary.validate_global_advisory_identity(
            entry,
            {'ghsa_id': 'GHSA-vrw8-fxc6-2r93'},
        )
        self.assertTrue(result['alias_used'])
        with self.assertRaisesRegex(RuntimeError, 'global advisory identity drift'):
            boundary.validate_global_advisory_identity(
                entry,
                {'ghsa_id': 'GHSA-zzzz-yyyy-xxxx'},
            )


if __name__ == '__main__':
    unittest.main()

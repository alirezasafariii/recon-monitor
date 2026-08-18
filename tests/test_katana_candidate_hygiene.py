from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from stages import (
    _katana_candidate_malformed,
    stage_urls,
)


class KatanaCandidateHygieneTests(
    unittest.TestCase
):

    def test_encoded_backslash_in_path_is_rejected(self):
        self.assertTrue(
            _katana_candidate_malformed(
                "https://example.test/"
                "%5C/example.test%5C/"
                "wp-includes%5C/js%5C/app.js"
            )
        )


    def test_literal_backslash_in_path_is_rejected(self):
        self.assertTrue(
            _katana_candidate_malformed(
                "https://example.test/"
                "foo\\bar\\app.js"
            )
        )


    def test_normal_relative_gtm_candidate_is_not_rejected(self):
        self.assertFalse(
            _katana_candidate_malformed(
                "https://example.test/"
                "blog/article/gtm.js"
            )
        )


    def test_normal_wordpress_asset_is_not_rejected(self):
        self.assertFalse(
            _katana_candidate_malformed(
                "https://example.test/"
                "wp-includes/js/wp-embed.min.js"
            )
        )


    def test_encoded_backslash_in_query_does_not_trigger_path_filter(self):
        self.assertFalse(
            _katana_candidate_malformed(
                "https://example.test/app.js"
                "?value=%5C"
            )
        )


    def test_stage_urls_applies_hygiene_before_normalization(self):
        source = inspect.getsource(
            stage_urls
        )

        hygiene_pos = source.index(
            "_katana_candidate_malformed"
        )

        normalize_pos = source.index(
            "normalize_url",
            hygiene_pos,
        )

        self.assertLess(
            hygiene_pos,
            normalize_pos,
        )

        self.assertIn(
            '"katana_rejected_malformed"',
            source,
        )


if __name__ == "__main__":
    unittest.main()

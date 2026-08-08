from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from reporting import render_report_html  # noqa: E402


class ReportingTests(unittest.TestCase):
    def test_html_escapes_items(self) -> None:
        report = {
            "target": "example.com",
            "run_id": "r1",
            "generated_at": "now",
            "baseline": False,
            "counts": {"assets": 1},
            "stages": {},
            "changes": {
                "events": [
                    {
                        "severity": "HIGH",
                        "risk_score": 80,
                        "category": "new_url",
                        "title": "test",
                        "item": "<script>alert(1)</script>",
                    }
                ]
            },
        }
        rendered = render_report_html(report)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()

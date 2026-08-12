from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected exactly one stale-version replacement, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "tests/test_analysis_coverage_v610.py",
    '        self.assertEqual(ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(REASONING_ENGINE_VERSION, "6.16.0")',
    '        self.assertEqual(ENGINE_VERSION, CANDIDATE_ENGINE_VERSION)\n'
    '        self.assertEqual(ENGINE_VERSION, REASONING_ENGINE_VERSION)\n'
    '        self.assertGreaterEqual(\n'
    '            tuple(int(part) for part in ENGINE_VERSION.split(".")),\n'
    '            (6, 10, 0),\n'
    '        )',
)

replace_once(
    "tests/test_analysis_ranking_v650.py",
    '        self.assertEqual(REASONING_ENGINE_VERSION, "6.16.0")',
    '        self.assertGreaterEqual(\n'
    '            tuple(int(part) for part in REASONING_ENGINE_VERSION.split(".")),\n'
    '            (6, 5, 0),\n'
    '        )',
)

replace_once(
    "tests/test_raw_precision_calibration_v6140.py",
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.16.0")',
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)\n'
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)\n'
    '        self.assertGreaterEqual(\n'
    '            tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")),\n'
    '            (6, 14, 0),\n'
    '        )',
)

from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing inherited-test anchor in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(ENGINE_VERSION, "6.12.0")', 'self.assertEqual(ENGINE_VERSION, "6.14.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.12.0")', 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.14.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.12.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.14.0")')
replace_once("tests/test_analysis_ranking_v650.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.12.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.14.0")')
replace_once("tests/test_detector_execution_intelligence_v6100.py", 'self.assertEqual(EXECUTION_ENGINE_VERSION, "1.1.0")', 'self.assertEqual(EXECUTION_ENGINE_VERSION, "1.2.0")')
replace_once("tests/test_detector_execution_intelligence_v6100.py", 'self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.11.6.12")', 'self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.12.6.14")')
replace_once("tests/test_raw_condition_reconstruction_v6120.py", 'self.assertEqual(EXECUTION_ENGINE_VERSION, "1.1.0")', 'self.assertEqual(EXECUTION_ENGINE_VERSION, "1.2.0")')
replace_once("tests/test_raw_condition_reconstruction_v6120.py", 'self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.11.6.12")', 'self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.12.6.14")')

replace_once(
    "tests/test_raw_condition_reconstruction_v6120.py",
    '''        no_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "a", "status_code": 200}, {"context": "b", "status_code": 200}]})
        self.assertNotIn("response_difference", types(no_diff, "account_enumeration"))
        with_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "a", "status_code": 200, "response_text": "sent"}, {"context": "b", "status_code": 404, "response_text": "unknown"}]})
        self.assertIn("response_difference", types(with_diff, "account_enumeration"))
        self.assertTrue(admitted(with_diff, "account_enumeration"))
''',
    '''        no_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200}, {"context": "absent_identity", "status_code": 200}]})
        self.assertNotIn("response_difference", types(no_diff, "account_enumeration"))
        same_class_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200, "response_text": "sent"}, {"context": "another_existing_identity", "status_code": 404, "response_text": "unknown"}]})
        self.assertNotIn("response_difference", types(same_class_diff, "account_enumeration"))
        with_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200, "response_text": "sent"}, {"context": "absent_identity", "status_code": 404, "response_text": "unknown"}]})
        self.assertIn("response_difference", types(with_diff, "account_enumeration"))
        self.assertTrue(admitted(with_diff, "account_enumeration"))
''',
)

print("Analysis 6.14 inherited test contracts updated")

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"patch target not found in {path}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "app/bug_candidates.py",
    "from family_detectors import detector_rule_ids, evaluate_family_detector",
    "from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids",
)
replace_once("app/bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "6.9.0"', 'CANDIDATE_ENGINE_VERSION = "6.10.0"')
replace_once("app/bug_candidates.py", 'CANDIDATE_RULE_VERSION = "2026.08.10.6.9"', 'CANDIDATE_RULE_VERSION = "2026.08.11.6.10"')

replace_once(
    "app/bug_candidates.py",
    '''    count = 0\n\n    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:\n        nonlocal count\n        extraction = evaluate_family_detector(family, support, contradict, channel="alert")''',
    '''    execution_map = execute_detector_intelligence(\n        target=target, endpoint=endpoint, method=method, endpoint_schema=endpoint_schema, details=details,\n        evidence_for=evidence_for, evidence_against=evidence_against, category=category, business_context=context,\n    )\n    emitted_execution_families: set[str] = set()\n    count = 0\n\n    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:\n        nonlocal count\n        execution_packet = execution_map.get(family, {})\n        if execution_packet:\n            support = _merge_evidence_lists(support, list(execution_packet.get("support", [])))\n            contradict = _merge_evidence_lists(contradict, list(execution_packet.get("contradict", [])))\n            rules = list(dict.fromkeys([*rules, *execution_packet.get("rule_ids", []), *execution_rule_ids(family)]))\n        emitted_execution_families.add(family)\n        extraction = evaluate_family_detector(family, support, contradict, channel="alert")''',
)

replace_once(
    "app/bug_candidates.py",
    '''    return count\n\n\ndef _static_candidates(db: Database, analysis_id: str, run_id: str, target: str | None) -> int:''',
    '''    # Execution-only families still enter the hidden hypothesis ledger even when\n    # legacy surface heuristics did not emit them. Admission remains the only promotion gate.\n    for execution_family, execution_packet in execution_map.items():\n        if execution_family in emitted_execution_families:\n            continue\n        if not execution_packet.get("support") and not execution_packet.get("contradict"):\n            continue\n        emit(\n            execution_family,\n            "raw_execution_intelligence",\n            10,\n            [],\n            [],\n            [\n                "Correlate the execution signal with an independent target artifact",\n                "Verify the family-specific vulnerability condition and blocking controls",\n            ],\n            ["detector-execution-fallback"],\n            f"Stored raw artifacts produced family-specific {execution_family.replace('_', ' ')} evidence; admission remains evidence-gated.",\n        )\n\n    return count\n\n\ndef _static_candidates(db: Database, analysis_id: str, run_id: str, target: str | None) -> int:''',
)

replace_once("app/analysis_engine.py", 'ENGINE_VERSION = "6.9.0"', 'ENGINE_VERSION = "6.10.0"')
replace_once("app/analysis_engine.py", 'RULE_VERSION = "2026.08.10.6.9"', 'RULE_VERSION = "2026.08.11.6.10"')
replace_once("app/security_reasoning.py", 'REASONING_ENGINE_VERSION = "6.9.0"', 'REASONING_ENGINE_VERSION = "6.10.0"')
replace_once("app/security_reasoning.py", 'REASONING_RULE_VERSION = "2026.08.10.6.9"', 'REASONING_RULE_VERSION = "2026.08.11.6.10"')

replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(ENGINE_VERSION, "6.9.0")', 'self.assertEqual(ENGINE_VERSION, "6.10.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.9.0")', 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.10.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.9.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.10.0")')
replace_once("tests/test_analysis_ranking_v650.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.9.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.10.0")')

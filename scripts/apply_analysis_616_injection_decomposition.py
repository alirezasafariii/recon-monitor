from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing replacement anchor in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Version lineage: execution/reconstruction semantics are unchanged; only candidate
# orchestration and physical collector ownership change in this phase.
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.14.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.14"',
    'CANDIDATE_ENGINE_VERSION = "6.16.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.16"',
)
replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.14.0"\nRULE_VERSION = "2026.08.12.6.14"',
    'ENGINE_VERSION = "6.16.0"\nRULE_VERSION = "2026.08.12.6.16"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.14.0"\nREASONING_RULE_VERSION = "2026.08.12.6.14"',
    'REASONING_ENGINE_VERSION = "6.16.0"\nREASONING_RULE_VERSION = "2026.08.12.6.16"',
)

replace_once(
    "app/bug_candidates.py",
    'from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids\n',
    'from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids\nfrom raw_family_collectors import collect_injection_observations\n',
)

path = Path("app/bug_candidates.py")
text = path.read_text(encoding="utf-8")

# Physically route the five injection families through their dedicated collector
# contracts. emit() still merges the authoritative execution packet and applies the
# existing detector firewall, hidden-hypothesis ledger, admission gate, and candidate
# quality guard unchanged.
bola_marker = "    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n"
if bola_marker not in text:
    raise SystemExit("missing BOLA insertion marker")
injection_loop = '''    # Analysis 6.16 — physical raw collector ownership for server-side injection families.\n    # The collector contributes emission metadata only; target evidence is still owned\n    # by execute_detector_intelligence() and merged inside emit().\n    for observation in collect_injection_observations(execution_map):\n        emit(\n            observation.family,\n            observation.variant,\n            observation.base,\n            [],\n            [],\n            list(observation.missing),\n            list(observation.rules),\n            observation.summary,\n            direct=observation.direct,\n            impact=observation.impact,\n        )\n\n'''
text = text.replace(bola_marker, injection_loop + bola_marker, 1)

# Delete the physically duplicated legacy SQL/NoSQL/Command/SSTI/LDAP collector block.
start_marker = "    # Analysis 6.1 — OWASP A03 Injection coverage. Surface clues remain hidden\n"
end_marker = "    # API4:2023 — resource consumption.\n"
start = text.find(start_marker)
end = text.find(end_marker, start + 1)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("could not locate legacy injection collector block")
replacement = '''    # Analysis 6.16: SQL/NoSQL/Command/SSTI/LDAP legacy collection was physically\n    # removed from this orchestrator. Dedicated raw_family_collectors now own emission\n    # metadata while detector execution/reconstruction owns all target evidence.\n\n'''
text = text[:start] + replacement + text[end:]
path.write_text(text, encoding="utf-8")

# Inherited version assertions follow the production orchestration version. The
# execution/reconstruction versions remain 1.2.0/1.1.0 from Analysis 6.14.
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(ENGINE_VERSION, "6.14.0")', 'self.assertEqual(ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.14.0")', 'self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_analysis_coverage_v610.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.14.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_analysis_ranking_v650.py", 'self.assertEqual(REASONING_ENGINE_VERSION, "6.14.0")', 'self.assertEqual(REASONING_ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_raw_precision_calibration_v6140.py", 'self.assertEqual(analysis_engine.ENGINE_VERSION, "6.14.0")', 'self.assertEqual(analysis_engine.ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_raw_precision_calibration_v6140.py", 'self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.14.0")', 'self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.16.0")')
replace_once("tests/test_raw_precision_calibration_v6140.py", 'self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.14.0")', 'self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.16.0")')

# Raw v3 is already consumed. In a later engine generation, its freeze verifier must
# detect protected production mutations rather than incorrectly passing against the
# current tree. The original manifest/hash remains immutable.
replace_once(
    "tests/test_raw_recon_v3_protocol_v6150.py",
    '''    def test_freeze_verifier_passes(self):\n        report = verify_v3_freeze(ROOT / "benchmarks/raw/splits/v3.json")\n        self.assertTrue(report["passed"], report["errors"])\n''',
    '''    def test_consumed_freeze_detects_postfreeze_engine_mutation(self):\n        manifest = json.loads((ROOT / "benchmarks/raw/splits/v3.json").read_text(encoding="utf-8"))\n        self.assertEqual(manifest["evaluation_status"], "evaluated_once_consumed")\n        self.assertTrue(manifest["evaluation"]["fresh_run_consumed"])\n        report = verify_v3_freeze(ROOT / "benchmarks/raw/splits/v3.json")\n        self.assertFalse(report["passed"], report["errors"])\n        errors = [str(value) for value in report["errors"]]\n        expected_paths = {"app/analysis_engine.py", "app/bug_candidates.py", "app/security_reasoning.py"}\n        changed_paths = {\n            path\n            for path in expected_paths\n            if any(f"protected file changed after v3 freeze: {path}" in error for error in errors)\n        }\n        self.assertEqual(changed_paths, expected_paths, errors)\n        self.assertFalse(any("benchmarks/raw/analysis_raw_v3.jsonl" in error for error in errors), errors)\n        self.assertFalse(any("app/raw_recon_v3_benchmark.py" in error for error in errors), errors)\n        self.assertFalse(any("app/raw_recon_v3_corpus.py" in error for error in errors), errors)\n''',
)

print("Analysis 6.16 injection collector decomposition applied")

from __future__ import annotations

import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_v7_terminal_receipt_is_consumed_and_never_rerunnable():
    receipt=json.loads((ROOT/'benchmarks/raw/sources/v7_first_blind_consumption.json').read_text())
    assert receipt['first_blind_consumed'] is True
    assert receipt['rerun_allowed'] is False
    assert receipt['state']=='consumed_execution_error'
    assert receipt['execution_error']=='v7 evaluator cardinality mismatch'


def test_v8_builder_explicitly_repairs_case_mode_contract():
    source=(ROOT/'tools/build_v8_pipeline.py').read_text()
    for mode in ('single_family_fresh_v8','2_family_interference_v8','3_family_interference_v8'):
        assert mode in source
    assert 'v8_preblind_contract.py' in source
    assert 'def verify_freeze(' in source


def test_v8_source_firewall_is_declared_through_v7_without_using_v7_outcome():
    source=(ROOT/'tools/build_v8_pipeline.py').read_text()
    assert 'all_exposed_sources_and_provenance_v1_through_consumed_v7' in source
    assert 'v7_first_blind_score_used' in source
    assert 'v7_first_blind_case_errors_used' in source
    assert 'v7_first_blind_error_used' in source
    assert 'v7_first_blind_outcome_used_for_selection' in source


def test_v8_generation_is_allowlisted_not_glob_translated():
    source=(ROOT/'tools/build_v8_pipeline.py').read_text()
    assert 'TRANSLATE_MODULES' in source
    assert 'FORBIDDEN_V8_COUNTERPARTS' in source
    assert 'for src in sorted(APP.glob("*v7*.py"))' not in source
    for forbidden in (
        'raw_recon_v8_collision_supplement.py',
        'raw_recon_v8_targeted_supplement.py',
        'raw_recon_v8_missing5_supplement.py',
        'workspace_v8.py',
    ):
        assert not (ROOT/'app'/forbidden).exists()


def test_v8_hygiene_guard_exists_and_blocks_first_blind_state():
    guard=ROOT/'app/v8_preblind_hygiene.py'
    assert guard.exists()
    text=guard.read_text()
    assert 'v8_first_blind_consumption.json' in text
    assert 'analysis_raw_v8_first_blind.json' in text
    assert 'candidate_selection_uses_v7_first_blind_score' in text
    assert 'selection_uses_v7_first_blind_error' in text

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


def test_v8_source_firewall_is_declared_through_v7():
    source=(ROOT/'tools/build_v8_pipeline.py').read_text()
    assert 'all_exposed_sources_and_provenance_v1_through_consumed_v7' in source
    assert 'selection_uses_v7_first_blind_error' in source
    assert 'v7_first_blind_consumption.json' in source

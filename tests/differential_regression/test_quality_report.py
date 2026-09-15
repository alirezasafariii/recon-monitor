from __future__ import annotations

from pathlib import Path
import json

from app.differential_analysis import DifferentialAnalyzer


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    with (FIXTURE_DIR / name).open(encoding="utf-8") as f:
        return json.load(f)


def expected_signals_for(case: dict) -> set[str]:
    if "expected_signals" in case:
        return set(case["expected_signals"])

    expected = case.get("expected", {})
    return set(expected.get("signals", []))


def test_differential_regression_fixtures():
    analyzer = DifferentialAnalyzer()

    for fixture in FIXTURE_DIR.glob("*.json"):
        case = load_fixture(fixture.name)
        signals = analyzer.compare(case["before"], case["after"])
        signal_types = {signal.signal_type for signal in signals}

        expected = expected_signals_for(case)
        assert expected.issubset(signal_types), fixture.name

        if not expected:
            assert not signal_types, fixture.name

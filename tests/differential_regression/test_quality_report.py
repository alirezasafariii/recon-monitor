from __future__ import annotations

from pathlib import Path
import json

from app.differential_analysis import DifferentialAnalyzer


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    with (FIXTURE_DIR / name).open(encoding="utf-8") as f:
        return json.load(f)


def test_differential_regression_fixtures():
    analyzer = DifferentialAnalyzer()

    for fixture in FIXTURE_DIR.glob("*.json"):
        case = load_fixture(fixture.name)
        signals = analyzer.compare(case["before"], case["after"])
        signal_types = {signal.signal_type for signal in signals}

        expected = set(case.get("expected_signals", []))
        assert expected.issubset(signal_types), fixture.name

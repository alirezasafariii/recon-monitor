import json
from pathlib import Path

from app.differential_analysis import DifferentialAnalyzer


FIXTURES = Path(__file__).parent / "fixtures"


def test_regression_fixtures():
    analyzer = DifferentialAnalyzer()

    for fixture in FIXTURES.glob("*.json"):
        case = json.loads(fixture.read_text())
        signals = analyzer.compare(case["before"], case["after"])
        signal_names = {signal.signal_type for signal in signals}

        assert set(case["expected_signals"]).issubset(signal_names)

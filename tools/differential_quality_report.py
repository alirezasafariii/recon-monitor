from __future__ import annotations

"""Regression quality report for differential analysis.

This tool is intentionally read-only. It evaluates regression fixtures without
changing scoring or producing findings.
"""

import json
from pathlib import Path

from app.differential_analysis import DifferentialAnalyzer


FIXTURES = Path(__file__).parent.parent / "tests" / "differential_regression" / "fixtures"


def run_report() -> dict[str, int | float]:
    analyzer = DifferentialAnalyzer()
    total = 0
    passed = 0
    failed = 0
    expected_signal_cases = 0
    unexpected_signal_cases = 0

    for fixture in FIXTURES.glob("*.json"):
        total += 1
        case = json.loads(fixture.read_text(encoding="utf-8"))
        signals = analyzer.compare(case.get("before"), case.get("after"))
        actual = {signal.signal_type for signal in signals}
        expected = set(case.get("expected_signals", case.get("expected", {}).get("signals", [])))

        if expected:
            expected_signal_cases += 1
            if expected.issubset(actual):
                passed += 1
            else:
                failed += 1
        elif actual:
            unexpected_signal_cases += 1
            failed += 1
        else:
            passed += 1

    precision_denominator = expected_signal_cases + unexpected_signal_cases
    precision = (
        expected_signal_cases / precision_denominator
        if precision_denominator
        else 1.0
    )

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "expected_signal_cases": expected_signal_cases,
        "unexpected_signal_cases": unexpected_signal_cases,
        "precision": round(precision, 3),
    }


if __name__ == "__main__":
    print(json.dumps(run_report(), indent=2))

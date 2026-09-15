from __future__ import annotations

"""Lightweight regression quality report for differential analysis.

This tool is intentionally read-only. It evaluates regression fixtures without
changing scoring or producing findings.
"""

import json
from pathlib import Path

from app.differential_analysis import DifferentialAnalyzer


FIXTURES = Path(__file__).parent.parent / "tests" / "differential_regression" / "fixtures"


def run_report() -> dict[str, int]:
    analyzer = DifferentialAnalyzer()
    total = 0
    passed = 0
    failed = 0

    for fixture in FIXTURES.glob("*.json"):
        total += 1
        case = json.loads(fixture.read_text(encoding="utf-8"))
        signals = analyzer.compare(case.get("before"), case.get("after"))
        actual = {signal.signal_type for signal in signals}
        expected = set(case.get("expected_signals", case.get("expected", {}).get("signals", [])))

        if expected.issubset(actual):
            passed += 1
        else:
            failed += 1

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
    }


if __name__ == "__main__":
    print(json.dumps(run_report(), indent=2))

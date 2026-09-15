from __future__ import annotations

"""Adapter layer for feeding differential signals into analysis.

Kept separate from analysis_engine initially so existing scoring behaviour is
unchanged while differential signals are evaluated.
"""

from typing import Any, Mapping

from differential_analysis import DifferentialAnalyzer


DIFFERENTIAL_SIGNAL_VERSION = "0.1.0"


def enrich_analysis_context(
    previous_observation: Mapping[str, Any] | None,
    current_observation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return additional context that can be consumed by analysis scoring."""

    signals = DifferentialAnalyzer().compare(
        previous_observation,
        current_observation,
    )

    return {
        "differential_version": DIFFERENTIAL_SIGNAL_VERSION,
        "differential_signals": [
            {
                "type": signal.signal_type,
                "severity": signal.severity,
                "confidence": signal.confidence,
                "details": signal.details,
            }
            for signal in signals
        ],
    }

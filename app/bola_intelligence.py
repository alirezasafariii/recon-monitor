from __future__ import annotations

"""Compatibility surface for the dedicated BOLA family analyzer.

Existing callers keep importing ``analyze_bola_signal`` and the historical BOLA
engine/version constants from this module. The implementation now lives under
``family_analyzers`` so every vulnerability family can evolve independently
without changing the Candidate Engine call contract.
"""

from family_analyzers.bola import (
    BOLA_ENGINE_VERSION,
    BOLA_FAMILY_ANALYZER_RULE_VERSION,
    BOLA_FAMILY_ANALYZER_VERSION,
    BOLA_METHOD,
    BOLA_RULE_VERSION,
    BolaFamilyAnalyzer,
    analyze_bola_signal,
)

__all__ = [
    "BOLA_ENGINE_VERSION",
    "BOLA_RULE_VERSION",
    "BOLA_FAMILY_ANALYZER_VERSION",
    "BOLA_FAMILY_ANALYZER_RULE_VERSION",
    "BOLA_METHOD",
    "BolaFamilyAnalyzer",
    "analyze_bola_signal",
]

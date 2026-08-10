from __future__ import annotations

"""Explicit router for independently versioned family analyzers."""

from typing import Any

from family_reasoning import FAMILY_ORDER

from .base import FamilyAnalyzer
from .bola import BolaFamilyAnalyzer


FAMILY_ANALYZER_ROUTER_VERSION = "1.0.0"

_ANALYZERS: dict[str, type[FamilyAnalyzer]] = {
    "broken_object_authorization": BolaFamilyAnalyzer,
}


def registered_families() -> tuple[str, ...]:
    return tuple(family for family in FAMILY_ORDER if family in _ANALYZERS)


def pending_families() -> tuple[str, ...]:
    return tuple(family for family in FAMILY_ORDER if family not in _ANALYZERS)


def analyzer_for_family(family: str) -> FamilyAnalyzer | None:
    analyzer_type = _ANALYZERS.get(str(family or ""))
    return analyzer_type() if analyzer_type else None


def router_status() -> dict[str, Any]:
    registered = registered_families()
    pending = pending_families()
    return {
        "version": FAMILY_ANALYZER_ROUTER_VERSION,
        "registered_count": len(registered),
        "registered": list(registered),
        "pending_count": len(pending),
        "pending": list(pending),
        "target_family_count": len(FAMILY_ORDER),
        "generic_family_analyzer_fallback": False,
    }

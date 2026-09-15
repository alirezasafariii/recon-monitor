from __future__ import annotations

"""Differential analysis primitives.

This module compares previous and current observations and emits
security-relevant signals. It intentionally does not create findings or run
active validation.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(slots=True)
class DifferentialSignal:
    signal_type: str
    severity: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)


class DifferentialAnalyzer:
    """Detect security-relevant changes between two observations."""

    def compare(
        self,
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any] | None,
    ) -> list[DifferentialSignal]:
        if not previous or not current:
            return []

        signals: list[DifferentialSignal] = []
        signals.extend(self._auth_change(previous, current))
        signals.extend(self._status_change(previous, current))
        signals.extend(self._response_change(previous, current))
        signals.extend(self._endpoint_change(previous, current))
        return signals

    def _auth_change(self, previous, current):
        before = previous.get("auth_state", "unknown")
        after = current.get("auth_state", "unknown")

        if before != after and after in {"public", "unknown"}:
            return [DifferentialSignal(
                "auth_boundary_change",
                "high",
                0.85,
                {"before": before, "after": after},
            )]
        return []

    def _status_change(self, previous, current):
        if previous.get("status_code") in {401, 403} and current.get("status_code") == 200:
            return [DifferentialSignal(
                "protected_to_public_transition",
                "high",
                0.9,
                {"before": previous.get("status_code"), "after": 200},
            )]
        return []

    def _response_change(self, previous, current):
        old_keys = set(previous.get("response_keys", []))
        new_keys = set(current.get("response_keys", []))
        added = sorted(new_keys - old_keys)

        if added:
            return [DifferentialSignal(
                "response_structure_change",
                "medium",
                0.7,
                {"new_fields": added},
            )]
        return []

    def _endpoint_change(self, previous, current):
        if not previous.get("exists") and current.get("exists"):
            return [DifferentialSignal(
                "new_endpoint_exposure",
                "medium",
                0.75,
                {"path": current.get("path")},
            )]
        return []


def compare_observations(previous, current):
    return DifferentialAnalyzer().compare(previous, current)

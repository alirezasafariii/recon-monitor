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
    signal_strength: str
    confidence: float
    category: str
    evidence: list[str] = field(default_factory=list)
    requires_validation: bool = True
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
                "auth_boundary_change", "high", 0.85, "access_control",
                [f"auth:{before}->{after}"], True,
                {"before": before, "after": after},
            )]
        return []

    def _status_change(self, previous, current):
        if previous.get("status_code") in {401, 403} and current.get("status_code") == 200:
            return [DifferentialSignal(
                "protected_to_public_transition", "high", 0.9, "access_control",
                [f"status:{previous.get('status_code')}->200"], True,
                {"before": previous.get("status_code"), "after": 200},
            )]
        return []

    def _response_change(self, previous, current):
        added = sorted(set(current.get("response_keys", [])) - set(previous.get("response_keys", [])))
        if added:
            return [DifferentialSignal(
                "response_structure_change", "medium", 0.7, "data_exposure",
                [f"new_fields:{','.join(added)}"], True,
                {"new_fields": added},
            )]
        return []

    def _endpoint_change(self, previous, current):
        if not previous.get("exists") and current.get("exists"):
            return [DifferentialSignal(
                "new_endpoint_exposure", "medium", 0.75, "attack_surface",
                [f"path:{current.get('path', 'unknown')}"], True,
                {"path": current.get("path")},
            )]
        return []


def compare_observations(previous, current):
    return DifferentialAnalyzer().compare(previous, current)

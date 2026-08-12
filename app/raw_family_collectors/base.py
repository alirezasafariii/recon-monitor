from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RawFamilyObservation:
    """Emission metadata for one family-owned raw collector.

    The collector never manufactures target evidence. Evidence remains owned by
    detector execution/reconstruction and is merged by the candidate orchestrator.
    """

    family: str
    variant: str
    base: int
    missing: tuple[str, ...]
    rules: tuple[str, ...]
    summary: str
    direct: bool = False
    impact: int | None = None

    def packet_present(self, execution_map: Mapping[str, Mapping[str, Any]]) -> bool:
        packet = execution_map.get(self.family) or {}
        return bool(packet.get("support") or packet.get("contradict"))

"""Domain events used to decouple business flows.

Events are pure domain objects. They must not know about transports,
databases, or UI layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class DomainEvent:
    created_at: datetime

    @classmethod
    def now(cls):
        return cls(created_at=datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class PotentialFindingCreated(DomainEvent):
    finding_id: str
    target: str


@dataclass(frozen=True, slots=True)
class ReconSnapshotCreated(DomainEvent):
    run_id: str
    target: str

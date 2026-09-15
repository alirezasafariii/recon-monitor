from __future__ import annotations

from app.infrastructure.repositories import SQLiteFindingRepository


class FakeGateway:
    def __init__(self):
        self.calls = []
        self.rows = {}

    def execute(self, query, params):
        self.calls.append((query, params))

    def one(self, query, params):
        return self.rows.get(params[0])


def test_finding_repository_save_uses_persistence_gateway():
    gateway = FakeGateway()
    repository = SQLiteFindingRepository(gateway)

    finding = {
        "target": "example.test",
        "dedup_key": "finding-1",
        "template_id": "template-a",
        "name": "Example finding",
        "severity": "medium",
        "matched_at": "2026-01-01T00:00:00Z",
        "details_json": "{}",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-01T00:00:00Z",
        "last_run_id": "run-1",
    }

    result = repository.save(finding)

    assert result == "finding-1"
    assert len(gateway.calls) == 1
    assert "INSERT INTO findings" in gateway.calls[0][0]


def test_finding_repository_get_delegates_to_gateway():
    gateway = FakeGateway()
    gateway.rows["finding-1"] = {"dedup_key": "finding-1"}

    repository = SQLiteFindingRepository(gateway)

    assert repository.get("finding-1") == {"dedup_key": "finding-1"}

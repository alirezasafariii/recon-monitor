from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import postgres_mirror as mirror
from core import APP_VERSION, Database, ReconError


class PostgreSQLFixture:
    """Execute the mirror's parameterized DML against a transactional SQLite sink.

    Only PostgreSQL schema/type/time syntax is translated. SQLite enforces the
    same unique key and real commits/rollbacks, rather than mocking row effects.
    No psycopg installation, PostgreSQL service, or network access is needed.
    """

    def __init__(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.execute(
            "CREATE TABLE mirror_rows(table_name TEXT NOT NULL,row_key TEXT NOT NULL,"
            "payload TEXT NOT NULL,synced_at TEXT NOT NULL,PRIMARY KEY(table_name,row_key))"
        )
        self.fail_table = None
        self.fail_cleanup = False
        self.fail_commit = False
        self.connections = 0
        self.writes = 0
        self.cleanups = 0

    def connect(self, _config):
        self.connections += 1
        return _FixtureConnection(self)

    def rows(self, table=None):
        sql = "SELECT table_name,row_key,payload FROM mirror_rows"
        params = ()
        if table is not None:
            sql += " WHERE table_name=?"
            params = (table,)
        return {
            (name, key): json.loads(payload)
            for name, key, payload in self.db.execute(sql, params)
        }

    def seed(self, table, row, key=None):
        if key is None:
            prefix = json.dumps(row, sort_keys=True, default=str)[:400]
            key = hashlib.sha256(prefix.encode()).hexdigest()
        self.db.execute(
            "INSERT OR REPLACE INTO mirror_rows VALUES(?,?,?,'old-sync')",
            (table, key, json.dumps(row)),
        )


class _FixtureConnection:
    def __init__(self, fixture):
        self.fixture = fixture
        self.has_writes = False

    def __enter__(self):
        self.fixture.db.execute("BEGIN")
        return self

    def __exit__(self, exc_type, _exc, _traceback):
        if self.fixture.db.in_transaction:
            if exc_type is None:
                try:
                    self.commit()
                except Exception:
                    self.fixture.db.rollback()
                    raise
            else:
                self.fixture.db.rollback()

    def cursor(self):
        return _FixtureCursor(self)

    def commit(self):
        if self.has_writes and self.fixture.fail_commit:
            raise RuntimeError("offline commit failure")
        self.fixture.db.commit()


class _FixtureCursor:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return None

    def execute(self, sql, params=()):
        fixture = self.connection.fixture
        if sql.startswith("CREATE SCHEMA") or sql.startswith("CREATE TABLE"):
            return
        if sql.startswith("INSERT"):
            if params[0] == fixture.fail_table:
                raise RuntimeError("offline write failure")
            fixture.writes += 1
            self.connection.has_writes = True
        if sql.startswith("DELETE"):
            fixture.cleanups += 1
            if fixture.fail_cleanup:
                raise RuntimeError("offline cleanup failure")
            self.connection.has_writes = True
        translated = (
            sql.replace("recon_monitor.", "")
            .replace("%s", "?")
            .replace("::jsonb", "")
            .replace("now()", "'new-sync'")
        )
        fixture.db.execute(translated, params)


class PostgresMirrorTests(unittest.TestCase):
    NOW = "2026-10-04T00:00:00Z"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Database(Path(temp.name) / "source.db")
        self.addCleanup(self.db.close)
        self.pg = PostgreSQLFixture()
        self.addCleanup(self.pg.db.close)
        connector = patch.object(mirror, "_connect", side_effect=self.pg.connect)
        connector.start()
        self.addCleanup(connector.stop)

    def _fixtures(self):
        common = {"first_seen": self.NOW, "last_seen": self.NOW}
        return {
            "runs": {"id": "RUN-A", "version": APP_VERSION, "status": "success", "started_at": self.NOW},
            "run_targets": {"run_id": "RUN-A", "target": "example.test", "policy_hash": "policy", "status": "success", "started_at": self.NOW, "run_dir": "offline"},
            "assets": {"target": "example.test", "host": "api.example.test", **common},
            "dns_records": {"target": "example.test", "host": "api.example.test", "rrtype": "A", "value": "192.0.2.1", **common},
            "urls": {"target": "example.test", "url": "https://api.example.test/path", **common},
            "alerts": {"id": 1, "target": "example.test", "dedup_key": "alert-one", "category": "change", "severity": "low", "risk_score": 10, "title": "Offline alert", **common},
            "asset_edges": {"target": "example.test", "source_type": "host", "source_value": "api.example.test", "relation": "links", "destination_type": "url", "destination_value": "/path", **common},
            "endpoint_intelligence": {"target": "example.test", "endpoint": "/path", "kind": "endpoint", "primary_category": "api", "confidence": 50, **common},
            "technology_observations": {"target": "example.test", "url": "https://api.example.test", "technology": "offline-tech", "confidence": 50, "confidence_label": "medium", **common},
            "change_incidents": {"id": 1, "target": "example.test", "correlation_key": "incident-one", "title": "Offline incident", "severity": "low", "risk_score": 10, **common},
            "asset_lifecycle": {"target": "example.test", "host": "api.example.test", **common},
        }

    def _insert(self, table, row):
        columns = ",".join(row)
        placeholders = ",".join("?" for _ in row)
        self.db.execute(f"INSERT INTO {table}({columns}) VALUES({placeholders})", tuple(row.values()))

    def _populate(self):
        for table, row in self._fixtures().items():
            self._insert(table, row)

    def _sync(self):
        return mirror.sync({}, self.db)

    def test_alerts_with_identical_400_character_prefix_remain_distinct(self):
        row = self._fixtures()["alerts"]
        row["details_json"] = json.dumps({"evidence": "same-prefix-" * 100})
        self._insert("alerts", row)
        self._insert("alerts", {**row, "id": 2, "dedup_key": "alert-one", "target": "other.test"})
        source = [dict(row) for row in self.db.all("SELECT * FROM alerts")]
        self.assertEqual(*(json.dumps(row, sort_keys=True)[:400] for row in source))
        result = self._sync()
        self.assertEqual(result["tables"]["alerts"], 2)
        self.assertEqual({row["id"] for row in self.pg.rows("alerts").values()}, {1, 2})

    def test_long_primary_key_values_are_not_truncated(self):
        row = self._fixtures()["urls"]
        prefix = "https://example.test/" + "a" * 1000
        for suffix in ("first", "second"):
            self._insert("urls", {**row, "url": prefix + suffix})
        self._sync()
        self.assertEqual({row["url"] for row in self.pg.rows("urls").values()}, {prefix + "first", prefix + "second"})

    def test_non_key_changes_update_one_row_for_every_supported_table(self):
        self._populate()
        first = self._sync()
        keys = set(self.pg.rows())
        changes = {
            "runs": ("status", "failed"),
            "run_targets": ("status", "failed"),
            "assets": ("confidence", 99),
            "dns_records": ("is_current", 0),
            "urls": ("source", "changed-source"),
            "alerts": ("dedup_key", "renamed-alert"),
            "asset_edges": ("metadata_json", '{"changed":true}'),
            "endpoint_intelligence": ("confidence", 99),
            "technology_observations": ("confidence", 99),
            "change_incidents": ("correlation_key", "renamed-incident"),
            "asset_lifecycle": ("state", "inactive"),
        }
        for table, (column, value) in changes.items():
            self.db.execute(f"UPDATE {table} SET {column}=?", (value,))
        second = self._sync()
        self.assertEqual(first["tables"], second["tables"])
        self.assertEqual(set(self.pg.rows()), keys)
        for table, (column, value) in changes.items():
            with self.subTest(table=table):
                mirrored = list(self.pg.rows(table).values())
                self.assertEqual(len(mirrored), 1)
                self.assertEqual(mirrored[0][column], value)

    def test_all_primary_key_components_distinguish_rows_in_every_table(self):
        self._populate()
        for table in mirror.TABLES:
            original = dict(self.db.one(f"SELECT * FROM {table}"))
            columns = [row["name"] for row in self.db.all(f"PRAGMA table_info({table})") if row["pk"]]
            for index, column in enumerate(columns):
                changed = dict(original)
                value = changed[column]
                changed[column] = value + index + 1 if isinstance(value, int) else value + f"-different-{index}"
                if table == "run_targets" and column == "run_id":
                    if self.db.one("SELECT id FROM runs WHERE id=?", (changed[column],)) is None:
                        self._insert("runs", {**self._fixtures()["runs"], "id": changed[column]})
                if table == "alerts":
                    changed["dedup_key"] = "alert-different"
                if table == "change_incidents":
                    changed["correlation_key"] = "incident-different"
                self._insert(table, changed)
        self._sync()
        for table in mirror.TABLES:
            with self.subTest(table=table):
                source = [dict(row) for row in self.db.all(f"SELECT * FROM {table}")]
                self.assertCountEqual(list(self.pg.rows(table).values()), source)

    def test_repeat_sync_does_not_create_duplicates(self):
        self._populate()
        first = self._sync()
        before = self.pg.rows()
        second = self._sync()
        self.assertEqual(first["tables"], second["tables"])
        self.assertEqual(self.pg.rows(), before)

    def test_primary_keys_do_not_depend_on_select_order(self):
        row = self._fixtures()["alerts"]
        self._insert("alerts", row)
        self._insert("alerts", {**row, "id": 2, "dedup_key": "alert-two"})
        self._sync()
        before = self.pg.rows()
        self.db.execute("PRAGMA reverse_unordered_selects=ON")
        self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_composite_keys_are_unambiguous_and_parameters_preserve_text(self):
        row = self._fixtures()["assets"]
        pairs = [("a|b", "c"), ("a", "b|c"), ("مثال.test", "quoted'host%_\\\".test")]
        for target, host in pairs:
            self._insert("assets", {**row, "target": target, "host": host})
        self._sync()
        self.assertEqual({(row["target"], row["host"]) for row in self.pg.rows("assets").values()}, set(pairs))

    def test_added_non_key_column_does_not_change_identity(self):
        self._insert("assets", self._fixtures()["assets"])
        self._sync()
        before = set(self.pg.rows())
        self.db.execute("ALTER TABLE assets ADD COLUMN extra_evidence TEXT DEFAULT 'new-column'")
        self._sync()
        self.assertEqual(set(self.pg.rows()), before)
        self.assertEqual(next(iter(self.pg.rows("assets").values()))["extra_evidence"], "new-column")

    def test_primary_key_schema_order_survives_reordered_non_key_columns(self):
        self.db.execute("CREATE TABLE ordered_identity(payload TEXT,second TEXT NOT NULL,first TEXT NOT NULL,PRIMARY KEY(first,second))")
        self._insert("ordered_identity", {"first": "one", "second": "two", "payload": "evidence"})
        with patch.object(mirror, "TABLES", ["ordered_identity"]):
            self._sync()
            before = self.pg.rows()
            self.db.execute("DROP TABLE ordered_identity")
            self.db.execute("CREATE TABLE ordered_identity(first TEXT NOT NULL,payload TEXT,second TEXT NOT NULL,PRIMARY KEY(first,second))")
            self._insert("ordered_identity", {"first": "one", "second": "two", "payload": "evidence"})
            self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_sync_recovers_collision_and_removes_legacy_duplicate_versions(self):
        row = self._fixtures()["alerts"]
        row["details_json"] = json.dumps({"evidence": "shared-prefix-" * 100})
        self._insert("alerts", row)
        self._insert("alerts", {**row, "id": 2, "target": "other.test"})
        source = [dict(row) for row in self.db.all("SELECT * FROM alerts")]
        for alert in source:
            self.pg.seed("alerts", alert)
        self.pg.seed("alerts", {**source[0], "category": "old-category"})
        self.assertEqual(len(self.pg.rows("alerts")), 2)
        self._sync()
        self.assertCountEqual(list(self.pg.rows("alerts").values()), source)
        self.assertTrue(all(key.startswith("pk:v1:") for _table, key in self.pg.rows("alerts")))
        self._sync()
        self.assertEqual(len(self.pg.rows("alerts")), 2)

    def test_legacy_cleanup_is_scoped_to_supported_tables(self):
        self.pg.seed("external_analytics", {"id": "leave-this-alone"})
        self.pg.seed("assets", self._fixtures()["assets"])
        unrelated = self.pg.rows("external_analytics")
        result = self._sync()
        self.assertEqual(self.pg.rows("external_analytics"), unrelated)
        self.assertEqual(self.pg.rows("assets"), {})
        self.assertEqual(result["tables"], dict.fromkeys(mirror.TABLES, 0))
        self.assertEqual(self.pg.cleanups, len(mirror.TABLES))

    def test_current_format_rows_retain_existing_upsert_only_semantics(self):
        self._insert("assets", self._fixtures()["assets"])
        self._sync()
        before = self.pg.rows()
        self.db.execute("DELETE FROM assets")
        result = self._sync()
        self.assertEqual(result["tables"]["assets"], 0)
        self.assertEqual(self.pg.rows(), before)

    def test_later_write_failure_rolls_back_upserts_and_legacy_cleanup(self):
        self._populate()
        self.pg.seed("runs", {**self._fixtures()["runs"], "status": "old-state"})
        self.pg.seed("alerts", self._fixtures()["alerts"])
        before = self.pg.rows()
        self.pg.fail_table = "asset_lifecycle"
        with self.assertRaisesRegex(RuntimeError, "offline write failure"):
            self._sync()
        self.assertGreater(self.pg.writes, 0)
        self.assertGreater(self.pg.cleanups, 0)
        self.assertEqual(self.pg.rows(), before)
        self.pg.fail_table = None
        self._sync()
        self.assertEqual(len(self.pg.rows()), len(mirror.TABLES))

    def test_cleanup_failure_rolls_back_new_rows(self):
        self._populate()
        self.pg.seed("runs", self._fixtures()["runs"])
        before = self.pg.rows()
        self.pg.fail_cleanup = True
        with self.assertRaisesRegex(RuntimeError, "offline cleanup failure"):
            self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_later_source_read_failure_rolls_back_upserts_and_cleanup(self):
        self._populate()
        self.pg.seed("runs", self._fixtures()["runs"])
        before = self.pg.rows()
        read = self.db.all

        def fail_later(sql, params=()):
            if sql.startswith("SELECT") and "asset_lifecycle" in sql:
                raise RuntimeError("offline source read failure")
            return read(sql, params)

        with patch.object(self.db, "all", side_effect=fail_later):
            with self.assertRaisesRegex(RuntimeError, "offline source read failure"):
                self._sync()
        self.assertGreater(self.pg.writes, 0)
        self.assertGreater(self.pg.cleanups, 0)
        self.assertEqual(self.pg.rows(), before)

    def test_commit_failure_preserves_pre_sync_mirror(self):
        self._populate()
        self.pg.seed("alerts", self._fixtures()["alerts"])
        before = self.pg.rows()
        self.pg.fail_commit = True
        with self.assertRaisesRegex(RuntimeError, "offline commit failure"):
            self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_table_without_primary_key_fails_even_when_empty(self):
        self.db.execute("CREATE TABLE no_identity(value TEXT)")
        self.pg.seed("no_identity", {"value": "previous-data"})
        before = self.pg.rows()
        with patch.object(mirror, "TABLES", ["no_identity"]), self.assertRaisesRegex(ReconError, "primary key"):
            self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_null_primary_key_fails_without_losing_existing_rows(self):
        self._insert("runs", {**self._fixtures()["runs"], "id": None})
        self.pg.seed("runs", self._fixtures()["runs"])
        before = self.pg.rows()
        with self.assertRaisesRegex(ReconError, "primary key"):
            self._sync()
        self.assertEqual(self.pg.rows(), before)

    def test_schema_and_payload_are_read_from_same_main_table(self):
        self._insert("assets", self._fixtures()["assets"])
        self.db.execute("CREATE TEMP VIEW assets AS SELECT target,'shadow.test' AS host,sources_json,confidence,wildcard,resolved,first_seen,last_seen,last_run_id FROM main.assets")
        self._sync()
        self.assertEqual(next(iter(self.pg.rows("assets").values()))["host"], "api.example.test")


if __name__ == "__main__":
    unittest.main()

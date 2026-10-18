from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from core import Database, SCHEMA_VERSION


class DashboardSQLiteConcurrencyTests(unittest.TestCase):
    def test_current_schema_migration_is_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.db"
            db = Database(path)
            try:
                statements = []
                db.conn.set_trace_callback(statements.append)
                db.migrate()
                writes = [
                    stmt for stmt in statements
                    if stmt.lstrip().split(maxsplit=1)[0].upper()
                    in {"UPDATE", "INSERT", "DELETE", "CREATE", "ALTER", "DROP", "REPLACE"}
                ]
                self.assertEqual(writes, [], "Current schema triggered migration writes")
            finally:
                db.close()

    def test_dashboard_style_connection_can_open_during_a_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.db"
            initialized = Database(path)
            initialized.close()
            writer = sqlite3.connect(path, isolation_level=None, timeout=1)
            try:
                writer.execute("BEGIN IMMEDIATE")
                # A simultaneous read-only dashboard request should not run
                # migrations or take a write lock when schema is current.
                dashboard = Database(path)
                try:
                    version = dashboard.one(
                        "SELECT value FROM schema_meta WHERE key='schema_version'"
                    )
                    self.assertEqual(str(version["value"]), str(SCHEMA_VERSION))
                finally:
                    dashboard.close()
            finally:
                writer.execute("ROLLBACK")
                writer.close()

    def test_old_schema_version_still_migrates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.db"
            db = Database(path)
            try:
                db.execute(
                    "UPDATE schema_meta SET value='-1' WHERE key='schema_version'"
                )
                db.migrate()
                row = db.one(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                )
                self.assertEqual(str(row["value"]), str(SCHEMA_VERSION))
            finally:
                db.close()

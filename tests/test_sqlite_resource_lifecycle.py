import contextlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, Database
from operations import BackupManager
from maintenance import migrate_v1_database
from dashboard_review_support import prepare_review
from sqlite_resource_guard import SQLiteResourceGuard


class SQLiteResourceLifecycleTests(unittest.TestCase):
    def test_snapshot_initialization_failures_close_base_connection(self):
        import successful_snapshot
        for hook in ("_migrate_successful_snapshot_schema", "ensure_lifecycle_schema",
                     "ensure_stable_confirmation_schema", "ensure_finding_notification_schema"):
            owner = (successful_snapshot.SuccessfulSnapshotDatabase
                     if hook.startswith("_migrate") else successful_snapshot)
            for error in (RuntimeError("snapshot setup failure"), KeyboardInterrupt()):
                with self.subTest(hook=hook, error=type(error).__name__), tempfile.TemporaryDirectory() as temp:
                    with SQLiteResourceGuard() as guard:
                        with patch.object(owner, hook, side_effect=error):
                            with self.assertRaises(type(error)):
                                successful_snapshot.SuccessfulSnapshotDatabase(Path(temp) / "state.db")
                        guard.assert_all_closed()

    def test_backup_destination_failure_closes_source(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            with contextlib.closing(Database(paths.db)) as db, SQLiteResourceGuard() as guard:
                connect = sqlite3.connect
                def fail_destination(path, *args, **kwargs):
                    if Path(path).parent == paths.backups:
                        raise sqlite3.OperationalError('injected destination failure')
                    return connect(path, *args, **kwargs)
                with patch('sqlite3.connect', side_effect=fail_destination):
                    with self.assertRaisesRegex(sqlite3.OperationalError, 'destination failure'):
                        BackupManager(paths, db, MagicMock()).create()
                guard.assert_all_closed()

    def test_review_destination_and_legacy_source_failure_close_prior_connection(self):
        for operation in ('review', 'legacy'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temp:
                paths = AppPaths.from_root(Path(temp) / 'source')
                paths.ensure()
                paths.policy.write_text('{"targets": []}')
                Database(paths.db).close()
                legacy = paths.root / 'recon.db'
                legacy.touch()
                destination = Path(temp) / 'review'
                if operation == 'review':
                    alias = Path(temp) / 'alias'
                    try:
                        alias.symlink_to(Path(temp), target_is_directory=True)
                        destination = alias / 'review'
                    except OSError:
                        pass
                with SQLiteResourceGuard() as guard:
                    connect = sqlite3.connect
                    def fail_second(path, *args, **kwargs):
                        if (operation == 'legacy' and Path(path) == legacy
                                or operation == 'review' and Path(path).resolve().is_relative_to(destination.resolve())):
                            raise sqlite3.OperationalError('injected second connection failure')
                        return connect(path, *args, **kwargs)
                    with patch('sqlite3.connect', side_effect=fail_second):
                        with self.assertRaisesRegex(sqlite3.OperationalError, 'second connection failure'):
                            if operation == 'legacy':
                                migrate_v1_database(paths, MagicMock())
                            else:
                                prepare_review(paths.root, destination)
                    guard.assert_all_closed()

    def test_guard_detects_missing_close_before_releasing_resource(self):
        with SQLiteResourceGuard() as guard:
            connection = sqlite3.connect(':memory:')
            try:
                with self.assertRaisesRegex(AssertionError, 'never explicitly closed'):
                    guard.assert_all_closed()
            finally:
                connection.close()
            guard.assert_all_closed()

    def test_initialization_and_migration_failure_close_connection(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'state.db'
                if corrupt:
                    path.write_bytes(b'not a SQLite database')
                with SQLiteResourceGuard() as guard:
                    with patch.object(Database, 'migrate', side_effect=RuntimeError('injected migration failure')):
                        with self.assertRaises((RuntimeError, sqlite3.DatabaseError)):
                            Database(path)
                    guard.assert_all_closed()

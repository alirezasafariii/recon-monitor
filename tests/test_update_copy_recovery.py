from __future__ import annotations

import errno
import io
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, ReconError
from operations import BackupManager, UpdateManager


class LoggerStub:
    def info(self, *args, **kwargs):
        pass

    warn = info
    error = info


class UpdateCopyRecoveryTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.getaddrinfo", "socket.socket.connect", "subprocess.Popen"):
            guard = patch(name, side_effect=AssertionError("update regression attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name) / "installed")
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.paths.policy.write_text('{"defaults": {}, "targets": []}\n', encoding="utf-8")
        for name, content in {
            "app/core.py": 'APP_VERSION = "8.8.1"\n',
            "app/old_only.py": "old code\n",
            "docs/old.md": "old documentation\n",
            "tools/old_tool.py": "old program tool\n",
            "README.md": "old readme\n",
            "recon-monitor.sh": "#!/bin/sh\nexit 0\n",
            "plugins/builtin/plugin.py": "old builtin\n",
            "plugins/custom/plugin.py": "user plugin\n",
            "MIGRATION-old.md": "previous migration\n",
            "local-notes.txt": "user notes\n",
        }.items():
            path = self.paths.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        (self.paths.root / "recon-monitor.sh").chmod(0o750)
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO schema_meta(key,value) VALUES('update-fixture','before')")
        self.manager = UpdateManager(self.paths, Config(self.paths), self.db, LoggerStub())
        self.package = Path(temp.name) / "release.zip"
        with zipfile.ZipFile(self.package, "w") as archive:
            for name, content in {
                "app/core.py": 'APP_VERSION = "8.8.2"\n',
                "app/new_only.py": "new code\n",
                "tools/new_tool.py": "new program tool\n",
                "README.md": "new readme\n",
                "recon-monitor.sh": "#!/bin/sh\nexit 0\n# new\n",
                "plugins/builtin/plugin.py": "new builtin\n",
                "plugins/new/plugin.py": "new plugin\n",
                "MIGRATION-new.md": "new migration\n",
                "config.env": "must not overwrite user configuration\n",
            }.items():
                archive.writestr("release/" + name, content)
        self.old_program = self._program_snapshot()
        self.config_bytes = self.paths.config.read_bytes()
        self.policy_bytes = self.paths.policy.read_bytes()
        self.checks = []
        self.run_guard = patch("operations.subprocess.run", side_effect=self._check)
        self.run_guard.start()
        self.addCleanup(self.run_guard.stop)

    def _check(self, command, **kwargs):
        expected = (
            [str(self.paths.root / "recon-monitor.sh"), "init", "--no-wizard"],
            [sys.executable, "-m", "compileall", "-q", str(self.paths.app), str(self.paths.root / "tests")],
            [str(self.paths.root / "recon-monitor.sh"), "test"],
            [str(self.paths.root / "recon-monitor.sh"), "test", "--integration"],
        )
        self.assertIn(command, expected)
        self.assertEqual(Path(kwargs["cwd"]), self.paths.root)
        self.checks.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    def _program_snapshot(self):
        result = {}
        for item in UpdateManager._program_items(self.paths.root):
            path = self.paths.root / item
            if not path.exists():
                continue
            paths = [path, *path.rglob("*")] if path.is_dir() else [path]
            for child in paths:
                name = child.relative_to(self.paths.root).as_posix()
                if child.is_symlink():
                    result[name] = ("link", os.readlink(child))
                elif child.is_dir():
                    result[name] = ("directory",)
                else:
                    result[name] = ("file", child.read_bytes(), child.stat().st_mode & 0o777)
        return result

    def _assert_original_program(self):
        self.assertEqual(self._program_snapshot(), self.old_program)
        self.assertEqual(self.paths.config.read_bytes(), self.config_bytes)
        self.assertEqual(self.paths.policy.read_bytes(), self.policy_bytes)
        self.assertEqual((self.paths.root / "local-notes.txt").read_text(), "user notes\n")

    def _assert_no_transaction(self):
        self.assertFalse(list(self.paths.root.glob(".recon-update-*")))
        self.assertFalse(list(self.paths.root.glob(".recon-rollback-*")))
        self.assertFalse(list(self.paths.state.glob(".recon-update-db-*")))

    def _disk_full(self):
        return OSError(errno.ENOSPC, "injected disk full")

    def test_directory_copy_failure_keeps_installed_app_and_skips_validation(self):
        real_copytree = shutil.copytree

        def fail_app(src, dst, *args, **kwargs):
            if Path(src).name == "app":
                Path(dst).mkdir(parents=True, exist_ok=True)
                (Path(dst) / "partial.py").write_text("partial copy")
                raise self._disk_full()
            return real_copytree(src, dst, *args, **kwargs)

        with patch("operations.shutil.copytree", side_effect=fail_app):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self.assertEqual(self.db.one("SELECT value FROM schema_meta WHERE key='update-fixture'")[0], "before")
        self._assert_no_transaction()

    def test_file_copy_failure_keeps_all_installed_program_items(self):
        real_copy2 = shutil.copy2

        def fail_readme(src, dst, *args, **kwargs):
            if Path(src).name == "README.md":
                raise self._disk_full()
            return real_copy2(src, dst, *args, **kwargs)

        with patch("operations.shutil.copy2", side_effect=fail_readme):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_plugin_merge_failure_keeps_builtin_and_custom_plugins(self):
        real_copytree = shutil.copytree

        def fail_plugins(src, dst, *args, **kwargs):
            if Path(src).name == "plugins" and Path(src) != self.paths.plugins:
                real_copytree(src, dst, *args, **kwargs)
                raise self._disk_full()
            return real_copytree(src, dst, *args, **kwargs)

        with patch("operations.shutil.copytree", side_effect=fail_plugins):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_copying_custom_plugins_failure_keeps_installed_tree(self):
        real_copytree = shutil.copytree

        def fail_custom(src, dst, *args, **kwargs):
            if Path(src) == self.paths.plugins:
                raise self._disk_full()
            return real_copytree(src, dst, *args, **kwargs)

        with patch("operations.shutil.copytree", side_effect=fail_custom):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_database_snapshot_copy_failure_keeps_installed_tree(self):
        # Program staging uses copy2; this injection exercises the separate
        # database snapshot copy and its cleanup before any live rename.
        with patch("operations.shutil.copyfileobj", side_effect=self._disk_full()):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_program_backup_failure_keeps_installed_files(self):
        real_add = tarfile.TarFile.add

        def fail_program(tar, name, *args, **kwargs):
            if Path(name) == self.paths.app:
                raise self._disk_full()
            return real_add(tar, name, *args, **kwargs)

        with patch("operations.tarfile.TarFile.add", new=fail_program):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self.assertFalse(list(self.paths.releases.glob("program-*.tar.gz")))
        self._assert_no_transaction()

    def test_permissions_failure_is_recovered_before_validation(self):
        real_chmod = Path.chmod

        def fail_executable(path, *args, **kwargs):
            if path.name == "recon-monitor.sh":
                raise PermissionError("injected chmod failure")
            return real_chmod(path, *args, **kwargs)

        with patch("pathlib.Path.chmod", new=fail_executable):
            with self.assertRaises((OSError, ReconError)):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_swap_failure_restores_already_replaced_program_items(self):
        real_replace = os.replace

        def fail_readme(src, dst):
            if Path(dst) == self.paths.root / "README.md" and "staged" in Path(src).parts:
                raise self._disk_full()
            return real_replace(src, dst)

        with patch("operations.os.replace", side_effect=fail_readme):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_moving_old_item_failure_restores_prior_swaps(self):
        real_replace = os.replace

        def fail_readme(src, dst):
            if Path(src) == self.paths.root / "README.md" and "previous" in Path(dst).parts:
                raise PermissionError("injected old item move failure")
            return real_replace(src, dst)

        with patch("operations.os.replace", side_effect=fail_readme):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_interruption_after_old_rename_restores_original_tree(self):
        real_replace = os.replace

        def interrupt_after_move(src, dst):
            result = real_replace(src, dst)
            if Path(src) == self.paths.root / "README.md" and "previous" in Path(dst).parts:
                raise KeyboardInterrupt()
            return result

        with patch("operations.os.replace", side_effect=interrupt_after_move):
            with self.assertRaises(KeyboardInterrupt):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()

    def test_failed_program_recovery_retains_original_files_and_reports_path(self):
        real_replace = os.replace

        def fail_app_recovery(src, dst):
            if Path(dst) == self.paths.app and "previous" in Path(src).parts:
                raise PermissionError("injected recovery rename failure")
            return real_replace(src, dst)

        with patch("operations.subprocess.run", side_effect=subprocess.TimeoutExpired("validation", 240)):
            with patch("operations.os.replace", side_effect=fail_app_recovery):
                with self.assertRaisesRegex(ReconError, "Automatic rollback failed.*Recovery files retained") as failure:
                    self.manager.install(self.package)
        transactions = list(self.paths.root.glob(".recon-update-*"))
        self.assertEqual(len(transactions), 1)
        original = transactions[0] / "previous/app"
        self.assertEqual((original / "core.py").read_bytes(), self.old_program["app/core.py"][1])
        self.assertIn(str(transactions[0]), str(failure.exception))
        self.assertFalse((self.paths.releases / "last-program-backup.txt").exists())

    def test_failed_database_recovery_retains_prepared_snapshot(self):
        real_replace = os.replace

        def fail_database(src, dst):
            if Path(dst) == self.paths.db and Path(src).name.startswith(".recon-update-db-"):
                raise self._disk_full()
            return real_replace(src, dst)

        with patch("operations.subprocess.run", side_effect=subprocess.TimeoutExpired("validation", 240)):
            with patch("operations.os.replace", side_effect=fail_database):
                with self.assertRaisesRegex(ReconError, "Database recovery failed.*Recovery files retained") as failure:
                    self.manager.install(self.package)
        self._assert_original_program()
        snapshots = list(self.paths.state.glob(".recon-update-db-*"))
        self.assertEqual(len(snapshots), 1)
        self.assertIn(str(snapshots[0]), str(failure.exception))
        with sqlite3.connect(snapshots[0]) as database:
            self.assertEqual(database.execute("SELECT value FROM schema_meta WHERE key='update-fixture'").fetchone()[0], "before")

    def test_each_validation_failure_restores_exact_program_and_database(self):
        for failing_check in range(4):
            with self.subTest(check=failing_check):
                self.checks.clear()

                def fail_validation(command, **kwargs):
                    self._check(command, **kwargs)
                    self.db.execute("UPDATE schema_meta SET value='after' WHERE key='update-fixture'")
                    if len(self.checks) == failing_check + 1:
                        return subprocess.CompletedProcess(command, 1, stdout="", stderr="injected validation failure")
                    return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

                with patch("operations.subprocess.run", side_effect=fail_validation):
                    with self.assertRaisesRegex(ReconError, "rolled back.*Post-update validation failed"):
                        self.manager.install(self.package)
                self._assert_original_program()
                with sqlite3.connect(self.paths.db) as database:
                    self.assertEqual(database.execute("SELECT value FROM schema_meta WHERE key='update-fixture'").fetchone()[0], "before")
                    self.assertEqual(database.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self._assert_no_transaction()
                self.db = Database(self.paths.db)
                self.addCleanup(self.db.close)
                self.manager.db = self.db

    def test_validation_timeout_restores_original_program(self):
        with patch("operations.subprocess.run", side_effect=subprocess.TimeoutExpired("validation", 240)):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.install(self.package)
        self._assert_original_program()
        self._assert_no_transaction()

    def test_marker_write_failure_rolls_back_and_preserves_previous_marker(self):
        marker = self.paths.releases / "last-program-backup.txt"
        marker.write_text("previous rollback archive\n")
        with patch("operations.atomic_write_text", side_effect=self._disk_full()):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(marker.read_text(), "previous rollback archive\n")
        self._assert_no_transaction()

    def test_audit_failure_rolls_back_and_leaves_marker_unchanged(self):
        real_audit = self.db.audit

        def fail_update(action, **kwargs):
            if action == "update_installed":
                raise self._disk_full()
            return real_audit(action, **kwargs)

        with patch.object(self.db, "audit", side_effect=fail_update):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.install(self.package)
        self._assert_original_program()
        self.assertFalse((self.paths.releases / "last-program-backup.txt").exists())
        self._assert_no_transaction()

    def test_success_preserves_custom_plugins_and_user_files(self):
        result = self.manager.install(self.package)
        self.assertEqual(result["to_version"], "8.8.2")
        self.assertEqual(result["validation"], "passed")
        self.assertEqual(len(self.checks), 4)
        self.assertIn('"8.8.2"', (self.paths.app / "core.py").read_text())
        self.assertFalse((self.paths.app / "old_only.py").exists())
        self.assertEqual((self.paths.plugins / "custom/plugin.py").read_text(), "user plugin\n")
        self.assertEqual((self.paths.plugins / "builtin/plugin.py").read_text(), "new builtin\n")
        self.assertTrue((self.paths.plugins / "new/plugin.py").is_file())
        self.assertTrue((self.paths.root / "docs/old.md").is_file())
        self.assertEqual(self.paths.config.read_bytes(), self.config_bytes)
        self.assertEqual(self.paths.policy.read_bytes(), self.policy_bytes)
        self.assertTrue((self.paths.root / "recon-monitor.sh").stat().st_mode & 0o111)
        self.assertEqual((self.paths.releases / "last-program-backup.txt").read_text().strip(), result["program_backup"])
        self._assert_no_transaction()

    def test_repeated_updates_have_distinct_rollback_archives(self):
        first = self.manager.install(self.package)
        first_archive = Path(first["program_backup"])
        original_archive = first_archive.read_bytes()
        second = self.manager.install(self.package)
        self.assertNotEqual(first["program_backup"], second["program_backup"])
        self.assertEqual(first_archive.read_bytes(), original_archive)
        self._assert_no_transaction()

    def test_cleanup_failure_keeps_successful_update_and_reports_warning(self):
        real_rmtree = shutil.rmtree

        def fail_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(".recon-update-"):
                raise PermissionError("injected staging cleanup failure")
            return real_rmtree(path, *args, **kwargs)

        with patch("operations.shutil.rmtree", side_effect=fail_cleanup):
            with patch.object(self.manager.logger, "warn") as warning:
                result = self.manager.install(self.package)
        self.assertEqual(result["validation"], "passed")
        self.assertIn('"8.8.2"', (self.paths.app / "core.py").read_text())
        warning.assert_called_once()
        self.assertIn("cleanup failure", warning.call_args.kwargs["error"])
        self.assertEqual((self.paths.releases / "last-program-backup.txt").read_text().strip(), result["program_backup"])

    def test_flat_release_with_only_app_is_supported(self):
        with zipfile.ZipFile(self.package, "w") as archive:
            archive.writestr("app/core.py", 'APP_VERSION = "8.8.2"\n')
        result = self.manager.install(self.package)
        self.assertEqual(result["to_version"], "8.8.2")
        self.assertEqual((self.paths.root / "README.md").read_text(), "old readme\n")
        self._assert_no_transaction()

    def test_plugin_merge_does_not_write_through_existing_symlink(self):
        outside = self.paths.root.parent / "outside-plugin.py"
        outside.write_text("external content\n")
        builtin = self.paths.plugins / "builtin/plugin.py"
        builtin.unlink()
        builtin.symlink_to(outside)
        original = self._program_snapshot()
        with self.assertRaisesRegex(ReconError, "outside staging"):
            self.manager.install(self.package)
        self.assertEqual(self._program_snapshot(), original)
        self.assertEqual(outside.read_text(), "external content\n")
        self._assert_no_transaction()

    def test_explicit_rollback_removes_new_only_files_and_migrations(self):
        result = self.manager.install(self.package)
        rollback = self.manager.rollback()
        self.assertEqual(rollback["rolled_back"], result["program_backup"])
        self._assert_original_program()
        self.assertTrue(rollback["dashboard_restart_required"])
        self._assert_no_transaction()

    def test_explicit_rollback_extraction_failure_keeps_current_program(self):
        self.manager.install(self.package)
        updated_program = self._program_snapshot()
        real_copy = shutil.copyfileobj
        calls = 0

        def fail_extract(src, dst, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise self._disk_full()
            return real_copy(src, dst, *args, **kwargs)

        with patch("operations.shutil.copyfileobj", side_effect=fail_extract):
            with self.assertRaises((OSError, ReconError)):
                self.manager.rollback()
        self.assertEqual(self._program_snapshot(), updated_program)
        self._assert_no_transaction()

    def test_explicit_rollback_swap_failure_restores_current_program(self):
        self.manager.install(self.package)
        updated_program = self._program_snapshot()
        real_replace = os.replace

        def fail_readme(src, dst):
            if Path(dst) == self.paths.root / "README.md" and "staged" in Path(src).parts:
                raise self._disk_full()
            return real_replace(src, dst)

        with patch("operations.os.replace", side_effect=fail_readme):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.rollback()
        self.assertEqual(self._program_snapshot(), updated_program)
        self._assert_no_transaction()

    def test_explicit_rollback_audit_failure_restores_current_program(self):
        self.manager.install(self.package)
        updated_program = self._program_snapshot()
        with patch.object(self.db, "audit", side_effect=self._disk_full()):
            with self.assertRaisesRegex(ReconError, "rolled back"):
                self.manager.rollback()
        self.assertEqual(self._program_snapshot(), updated_program)
        self._assert_no_transaction()

    def test_rollback_rejects_non_program_archive_entries_before_replacement(self):
        archive = self.paths.releases / "invalid-program.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            data = b"replacement config"
            member = tarfile.TarInfo("config.env")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        (self.paths.releases / "last-program-backup.txt").write_text(str(archive) + "\n")
        with self.assertRaisesRegex(ReconError, "program"):
            self.manager.rollback()
        self._assert_original_program()
        self._assert_no_transaction()

    def test_invalid_release_does_not_replace_program(self):
        self.package.write_bytes(b"not a zip")
        with self.assertRaisesRegex(ReconError, "valid ZIP"):
            self.manager.install(self.package)
        self._assert_original_program()
        self.assertEqual(self.checks, [])
        self._assert_no_transaction()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import hashlib
import http.cookiejar
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import dashboard_review_support as review
from core import APP_VERSION, AppPaths, Database, ReconError, utc_now
from dashboard_artifact_search import search_artifact_text
from recon_monitor_core import Orchestrator
from session_auth import create_user
from storage import ContentAddressedStore


class RealDataReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="review-regression-", dir=ROOT.parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = AppPaths.from_root(self.root / "installation")
        self.source.ensure()
        self.source.config.write_text('I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_BOT_TOKEN="installed-secret"\n')
        self.source.policy.write_text(json.dumps({"defaults": {}, "targets": [{"name": "example.test", "roots": ["example.test"]}]}))
        self.db = Database(self.source.db)
        self.addCleanup(self.db.close)
        self.db.conn.execute("PRAGMA wal_autocheckpoint=0")
        self.run_id = "existing-run-with-full-identifier"
        now = utc_now()
        self.run_dir = self.source.output / "example.test" / "runs" / self.run_id
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "urls.txt").write_text("snapshotneedle in a saved run output\n")
        (self.run_dir / "report.html").write_text("<p>existing saved report</p>")
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,'partial',?,1)",
                        (self.run_id, APP_VERSION, now))
        self.db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,run_dir) VALUES(?,'example.test','fixture','partial',?,?)",
                        (self.run_id, now, str(self.run_dir)))
        for number in range(205):
            self.db.execute("INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) VALUES('example.test',?,'url','katana',?,?,?)",
                            (f"https://example.test/literal_%/snapshotneedle/{number:04}", now, now, self.run_id))
        self.store = ContentAddressedStore(self.source, self.db)
        self.digest, self.blob, _ = self.store.put(b"const snapshotneedle = true;", content_type="application/javascript")
        self.store.set_reference("javascript", "example.test/app.js", self.digest)
        self.db.execute("INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_run_id) VALUES('example.test','https://example.test/app.js',?,?,?,?,?,?,?)",
                        (self.digest, self.digest, str(self.blob), self.blob.stat().st_size, now, now, self.run_id))
        self.db.execute("INSERT INTO asset_edges(target,source_type,source_value,relation,destination_type,destination_value,metadata_json,first_seen,last_seen,last_run_id) VALUES('example.test','javascript','fixture','contains','evidence','fixture',?,?,?,?)",
                        (json.dumps({"blob_path": str(self.blob), "object_hash": self.digest}), now, now, self.run_id))
        create_user(self.source, "installed-admin", "source-only-password-12345", "admin")
        self.destination = self.root / "snapshot"

    def fingerprint_source(self):
        return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in
                (self.source.db, self.source.db.with_name(self.source.db.name + "-wal"), self.source.config, self.blob)}

    def test_wal_snapshot_keeps_every_table_and_leaves_installation_unchanged(self):
        before = self.fingerprint_source()
        counts = review._counts(self.db.conn)
        report = review.prepare_review(self.source.root, self.destination)
        self.assertEqual(report["snapshot_table_counts"], counts)
        self.assertTrue(report["all_table_counts_preserved"])
        self.assertEqual(report["source_open_mode"], "ro")
        self.assertEqual(report["verified_referenced_files"], 1)
        self.assertEqual(before, self.fingerprint_source())
        clone = Database(AppPaths.from_root(self.destination).db)
        self.addCleanup(clone.close)
        self.assertEqual(review._counts(clone.conn), counts)
        self.assertEqual(clone.one("SELECT COUNT(*) n FROM urls")["n"], 205)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.destination / "state/recon-v2.db").stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.destination / "state/run.lock").exists())
        self.assertFalse((self.destination / "state/dashboard.pid").exists())

    def test_file_text_and_reports_use_only_copied_artifacts_after_source_is_gone(self):
        review.prepare_review(self.source.root, self.destination)
        paths = AppPaths.from_root(self.destination)
        clone = Database(paths.db)
        self.addCleanup(clone.close)
        blob = Path(clone.one("SELECT blob_path FROM js_files")["blob_path"])
        metadata = json.loads(clone.one("SELECT metadata_json FROM asset_edges")["metadata_json"])
        directory = Path(clone.one("SELECT run_dir FROM run_targets")["run_dir"])
        self.assertTrue(blob.is_relative_to(self.destination))
        self.assertEqual(metadata["blob_path"], str(blob))
        self.assertTrue(directory.is_relative_to(paths.output))
        # Destroy only synthetic originals, so following an old absolute path fails.
        self.blob.unlink()
        (self.run_dir / "urls.txt").unlink()
        (self.run_dir / "report.html").unlink()
        matches, unavailable = search_artifact_text(clone, paths, "snapshotneedle", target="example.test", run_id=self.run_id)
        self.assertEqual(unavailable, 0)
        self.assertEqual(len(matches), 2)
        self.assertIn("existing saved report", (directory / "report.html").read_text())

    def test_installed_credentials_are_disabled_only_in_copy_and_environment_is_ignored(self):
        review.prepare_review(self.source.root, self.destination)
        paths = AppPaths.from_root(self.destination)
        clone = Database(paths.db)
        self.addCleanup(clone.close)
        self.assertEqual(clone.one("SELECT enabled FROM users WHERE username='installed-admin'")["enabled"], 0)
        self.assertEqual(self.db.one("SELECT enabled FROM users WHERE username='installed-admin'")["enabled"], 1)
        self.assertNotIn("installed-secret", paths.config.read_text())
        with patch.dict(os.environ, {"I_HAVE_AUTHORIZATION": "yes", "TELEGRAM_ENABLED": "yes", "TELEGRAM_BOT_TOKEN": "ambient-secret"}):
            config = review.review_config(paths)
        self.assertFalse(config.authorized)
        self.assertFalse(config.bool("TELEGRAM_ENABLED"))
        self.assertFalse(config.get("TELEGRAM_BOT_TOKEN"))

    def test_missing_or_changed_referenced_artifact_fails_without_partial_review(self):
        before = self.fingerprint_source()
        self.blob.write_bytes(b"different content")
        with self.assertRaisesRegex(ReconError, "hash mismatch"):
            review.prepare_review(self.source.root, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(before[self.source.db], self.fingerprint_source()[self.source.db])
        self.blob.unlink()
        with self.assertRaisesRegex(ReconError, "artifact missing"):
            review.prepare_review(self.source.root, self.destination)
        self.assertFalse(self.destination.exists())

    def test_symlink_in_unreferenced_output_is_rejected_without_following_it(self):
        unrelated = self.root / "private.txt"
        unrelated.write_text("not part of this installation")
        (self.run_dir / "linked.txt").symlink_to(unrelated)
        with self.assertRaisesRegex(ReconError, "symlinks"):
            review.prepare_review(self.source.root, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(unrelated.read_text(), "not part of this installation")

    def test_app_generated_run_pointers_preserve_runs_and_original_aliases(self):
        orchestrator = Orchestrator.__new__(Orchestrator)
        orchestrator.paths = self.source
        orchestrator.logger = review.Logger(self.source, verbose=False)
        # Use the actual volume's case detection, then exercise the macOS layout
        # even on a case-sensitive CI volume. Never force the unsafe reverse.
        orchestrator._update_latest_pointers("example.test", self.run_dir)
        with patch.object(Orchestrator, "_pointer_names_collide", return_value=True):
            orchestrator._update_latest_pointers("example.test", self.run_dir)
        target_dir = self.run_dir.parent.parent
        aliases = {path: os.readlink(path) for path in target_dir.iterdir() if path.is_symlink()}
        self.assertIn(target_dir / "latest-run", aliases)
        latest_text = (target_dir / "LATEST").read_bytes()
        before = self.fingerprint_source()
        counts = review._counts(self.db.conn)

        report = review.prepare_review(self.source.root, self.destination)

        self.assertEqual(report["snapshot_table_counts"], counts)
        self.assertEqual(before, self.fingerprint_source())
        self.assertEqual(latest_text, (target_dir / "LATEST").read_bytes())
        self.assertEqual(aliases, {path: os.readlink(path) for path in aliases})
        self.assertEqual({item["path"] for item in report["skipped_run_pointer_aliases"]},
                         {path.relative_to(self.source.root).as_posix() for path in aliases})
        self.assertTrue(all(item["run_directory_present"] for item in report["skipped_run_pointer_aliases"]))
        output = AppPaths.from_root(self.destination).output
        self.assertEqual({path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()},
                         {"example.test/LATEST", f"example.test/runs/{self.run_id}/urls.txt",
                          f"example.test/runs/{self.run_id}/report.html"})
        self.assertFalse(any(path.is_symlink() for path in self.destination.rglob("*")))

    def test_alias_based_database_references_resolve_to_independent_copied_runs(self):
        alias = self.run_dir.parent.parent / "latest-run"
        alias.symlink_to(self.run_dir.relative_to(alias.parent))
        run_blob = self.run_dir / "current" / "app.js"
        run_blob.parent.mkdir()
        run_blob.write_bytes(self.blob.read_bytes())
        relative_blob = "output/example.test/latest-run/current/app.js"
        absolute_blob = str(alias / "current" / "app.js")
        self.db.execute("UPDATE run_targets SET run_dir=?", (str(alias),))
        self.db.execute("UPDATE js_files SET blob_path=?", (relative_blob,))
        self.db.execute("UPDATE asset_edges SET metadata_json=?",
                        (json.dumps({"blob_path": absolute_blob, "object_hash": self.digest}),))
        before = self.fingerprint_source()

        report = review.prepare_review(self.source.root, self.destination)
        paths = AppPaths.from_root(self.destination)
        clone = Database(paths.db)
        self.addCleanup(clone.close)
        directory = paths.output / "example.test" / "runs" / self.run_id
        copied_blob = directory / "current" / "app.js"
        self.assertEqual(clone.one("SELECT run_dir FROM run_targets")["run_dir"], str(directory))
        self.assertEqual(clone.one("SELECT blob_path FROM js_files")["blob_path"], str(copied_blob))
        self.assertEqual(json.loads(clone.one("SELECT metadata_json FROM asset_edges")["metadata_json"])["blob_path"],
                         str(copied_blob))
        self.assertEqual(report["verified_referenced_files"], 2)
        self.assertEqual(before, self.fingerprint_source())
        self.assertEqual(self.db.one("SELECT run_dir FROM run_targets")["run_dir"], str(alias))
        self.assertEqual(self.db.one("SELECT blob_path FROM js_files")["blob_path"], relative_blob)
        self.assertEqual(json.loads(self.db.one("SELECT metadata_json FROM asset_edges")["metadata_json"])["blob_path"],
                         absolute_blob)
        self.assertFalse((paths.output / "example.test" / "latest-run").exists())
        # Removing only synthetic originals proves File text and reports cannot
        # silently fall back to the installed run or its aliases.
        run_blob.unlink()
        self.blob.unlink()
        (self.run_dir / "urls.txt").unlink()
        (self.run_dir / "report.html").unlink()
        matches, unavailable = search_artifact_text(clone, paths, "snapshotneedle", target="example.test", run_id=self.run_id)
        self.assertEqual(unavailable, 0)
        self.assertEqual(len(matches), 2)
        self.assertIn("existing saved report", (directory / "report.html").read_text())

    def test_dangling_run_alias_does_not_discard_available_historical_data(self):
        alias = self.run_dir.parent.parent / "latest-run"
        alias.symlink_to("runs/removed-run")
        before = self.fingerprint_source()
        report = review.prepare_review(self.source.root, self.destination)
        self.assertEqual(report["skipped_run_pointer_aliases"], [{
            "path": "output/example.test/latest-run", "canonical_run": "output/example.test/runs/removed-run",
            "run_directory_present": False,
        }])
        self.assertEqual(report["snapshot_table_counts"]["urls"], 205)
        self.assertTrue((self.destination / "output/example.test/runs" / self.run_id / "urls.txt").is_file())
        self.assertEqual(before, self.fingerprint_source())
        self.assertEqual(os.readlink(alias), "runs/removed-run")

    def test_missing_file_referenced_through_run_alias_still_fails_verification(self):
        alias = self.run_dir.parent.parent / "latest-run"
        alias.symlink_to(self.run_dir.relative_to(alias.parent))
        self.db.execute("UPDATE js_files SET blob_path=?", (str(alias / "missing.js"),))
        before = self.fingerprint_source()
        with self.assertRaisesRegex(ReconError, "artifact missing"):
            review.prepare_review(self.source.root, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(before, self.fingerprint_source())
        self.assertTrue(alias.is_symlink())

    def test_named_run_alias_cannot_escape_chain_or_point_to_a_file(self):
        outside = self.root / "private"
        outside.mkdir()
        private_file = outside / "keep.txt"
        private_file.write_text("not part of this installation")
        target_dir = self.run_dir.parent.parent
        linked_run = target_dir / "runs" / "linked-run"
        (target_dir / "runs" / "file-run").write_text("a file cannot be a Run directory")
        other_run = self.source.output / "other.test" / "runs" / "other-run"
        other_run.mkdir(parents=True)
        alias = target_dir / "latest-run"
        for link_target in (outside, other_run, "runs/linked-run", "runs/file-run", "latest-run",
                            "runs/../runs/" + self.run_id, "runs/" + self.run_id + "/urls.txt"):
            with self.subTest(link_target=str(link_target)):
                if link_target == "runs/linked-run":
                    linked_run.symlink_to(outside, target_is_directory=True)
                alias.symlink_to(link_target)
                before = self.fingerprint_source()
                try:
                    with self.assertRaises(ReconError) as raised:
                        review.prepare_review(self.source.root, self.destination)
                    self.assertIn(f"symlinks: {alias}", str(raised.exception))
                    self.assertFalse(self.destination.exists())
                    self.assertEqual(before, self.fingerprint_source())
                    self.assertEqual(private_file.read_text(), "not part of this installation")
                finally:
                    alias.unlink()
                    if linked_run.is_symlink():
                        linked_run.unlink()

    def test_existing_and_overlapping_destinations_are_never_overwritten(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep.txt"
        sentinel.write_text("existing data")
        with self.assertRaisesRegex(ReconError, "already exists"):
            review.prepare_review(self.source.root, self.destination)
        self.assertEqual(sentinel.read_text(), "existing data")
        for destination in (self.source.root / "review", review.ROOT / "review-regression-never-created"):
            with self.assertRaisesRegex(ReconError, "separate"):
                review.prepare_review(self.source.root, destination)
            self.assertFalse(destination.exists())

    def test_old_schema_is_rejected_without_migrating_source(self):
        self.db.execute("UPDATE schema_meta SET value='17' WHERE key='schema_version'")
        before = self.fingerprint_source()
        with self.assertRaisesRegex(ReconError, "requires schema"):
            review.prepare_review(self.source.root, self.destination)
        self.assertEqual(self.db.one("SELECT value FROM schema_meta WHERE key='schema_version'")["value"], "17")
        self.assertEqual(before, self.fingerprint_source())
        self.assertFalse(self.destination.exists())

    def test_real_http_login_filters_pagination_and_all_operational_posts_are_blocked(self):
        before = self.fingerprint_source()
        review.prepare_review(self.source.root, self.destination)
        paths = AppPaths.from_root(self.destination)
        create_user(paths, "test-review", "review-password-12345", "viewer")
        server = review.make_server(paths)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with review.loopback_only():
                checks = review.probe_pages(server, paths, "test-review", "review-password-12345")
                self.assertEqual(len(checks), 12)
                self.assertTrue(all(item["passed"] for item in checks), checks)
                cookies = http.cookiejar.CookieJar()
                cookies.set_cookie(http.cookiejar.Cookie(
                    version=0, name="recon_session", value="installed-browser-session",
                    port=None, port_specified=False, domain="127.0.0.1", domain_specified=False,
                    domain_initial_dot=False, path="/", path_specified=True, secure=False,
                    expires=None, discard=True, comment=None, comment_url=None, rest={},
                ))
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))
                base = f"http://127.0.0.1:{server.server_address[1]}"
                with client.open(base + "/login", data=urllib.parse.urlencode({"username": "test-review", "password": "review-password-12345"}).encode()) as response:
                    self.assertIn("Snapshot review", response.read().decode())
                session_cookies = {cookie.name: cookie.value for cookie in cookies}
                self.assertEqual(session_cookies["recon_session"], "installed-browser-session")
                self.assertIn("recon_review_session", session_cookies)
                query = urllib.parse.urlencode({"q": "snapshotneedle", "target": "example.test", "run": self.run_id, "group": "URLs", "days": 0, "page": 3})
                with client.open(base + "/search?" + query) as response:
                    self.assertIn("5 shown · 205 matching records", response.read().decode())
                for path in ("/run-control", "/workspace/platform-sync", "/workspace/report", "/retention"):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        client.open(base + path, data=b"confirm=yes")
                    self.assertEqual(raised.exception.code, 403)
                    raised.exception.close()
                with client.open(base + "/logout") as response:
                    self.assertEqual(urllib.parse.urlsplit(response.geturl()).path, "/login")
                    response.read()
                self.assertEqual({cookie.name: cookie.value for cookie in cookies}, {"recon_session": "installed-browser-session"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(before, self.fingerprint_source())

    def test_guard_rejects_remote_dns_and_both_connect_methods_before_network_io(self):
        with review.loopback_only():
            with self.assertRaises(PermissionError):
                socket.getaddrinfo("example.test", 443)
            with socket.socket() as connection:
                for method in (connection.connect, connection.connect_ex):
                    with self.assertRaises(PermissionError):
                        method(("203.0.113.1", 443))

    def test_prepare_only_cli_writes_complete_report_and_stops(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = review.main(["--source", str(self.source.root), "--destination", str(self.destination),
                                  "--port", str(port), "--prepare-only"])
        self.assertEqual(status, 0, output.getvalue())
        report = json.loads((self.destination / "review-report.json").read_text())
        self.assertTrue(report["all_table_counts_preserved"])
        self.assertTrue(report["http_checks_passed"])
        self.assertEqual(len(report["http_checks"]), 12)
        self.assertNotIn("Password:", output.getvalue())
        with socket.socket() as connection:
            self.assertNotEqual(connection.connect_ex(("127.0.0.1", port)), 0)

    def test_prepare_only_accepts_empty_url_inventory_without_calling_it_an_error(self):
        self.db.execute("DELETE FROM urls")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with contextlib.redirect_stdout(io.StringIO()):
            status = review.main(["--source", str(self.source.root), "--destination", str(self.destination),
                                  "--port", str(port), "--prepare-only"])
        report = json.loads((self.destination / "review-report.json").read_text())
        self.assertEqual(status, 0)
        self.assertEqual(report["snapshot_table_counts"]["urls"], 0)
        self.assertTrue(report["http_checks_passed"])

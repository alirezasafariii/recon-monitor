#!/usr/bin/env python3
"""Review the feature-branch dashboard against a private copy of local data.

The installed database is opened with SQLite mode=ro and copied with the online
backup API. This runner never starts collectors, workers, services or migrations
on the source installation. The review server accepts login POSTs only.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import sqlite3
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import recon_monitor  # noqa: E402,F401 -- install the actual CLI's dashboard hooks
from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, Logger, ReconError, utc_now  # noqa: E402
from dashboard import DashboardHandler  # noqa: E402
from operations import BackupManager, sha256_file  # noqa: E402
from session_auth import create_user  # noqa: E402

ARTIFACT_TREES = ("output", "reports", "state/blobs", "state/objects")
PATH_COLUMNS = (
    ("run_targets", "run_dir"), ("js_files", "blob_path"),
    ("js_diffs", "diff_path"), ("fingerprints", "screenshot_path"),
    ("evidence_records", "source_artifact"),
)
SAFE_CONFIG = {
    "I_HAVE_AUTHORIZATION": "no", "ENABLE_ACTIVE_MODULES": "no",
    "TELEGRAM_ENABLED": "no", "USE_MACOS_KEYCHAIN": "no",
    "DASHBOARD_AUTH_ENABLED": "yes", "DASHBOARD_AUTH_MODE": "session",
    "DASHBOARD_ALLOW_REMOTE": "no", "DASHBOARD_TRUST_PROXY_HEADERS": "no",
}


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = [str(row[0]) for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {name: int(conn.execute(f"SELECT COUNT(*) FROM {_quote(name)}").fetchone()[0]) for name in tables}


def _regular_file(path: Path, root: Path) -> None:
    try:
        relative = path.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ReconError(f"Review does not follow symlinks: {path}")
        if not stat.S_ISREG(path.stat().st_mode):
            raise ReconError(f"Review requires a regular file: {path}")
    except (OSError, ValueError) as exc:
        raise ReconError(f"Cannot read review input: {path}") from exc


def _run_pointer_target(path: Path, root: Path) -> Path | None:
    """Recognize the app's redundant latest/latest-run alias without walking it."""
    relative = path.relative_to(root)
    if len(relative.parts) != 3 or relative.parts[0] != "output" or relative.name not in {"latest", "latest-run"}:
        return None
    raw = Path(os.readlink(path))
    if ".." in raw.parts:
        return None
    target = raw if raw.is_absolute() else path.parent / raw
    try:
        leaf = target.relative_to(path.parent / "runs")
        if len(leaf.parts) != 1:
            return None
        current = root
        for part in target.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                return None
        if target.exists() and not target.is_dir():
            return None
    except (OSError, ValueError):
        return None
    return target


def _copy_tree(source: Path, destination: Path, root: Path, run_aliases: list[dict]) -> tuple[int, int]:
    if not source.exists() and not source.is_symlink():
        return 0, 0
    if source.is_symlink() or not source.is_dir():
        raise ReconError(f"Review requires a real artifact directory: {source}")
    files = size = 0

    def skip_run_pointer(path: Path) -> bool:
        if not path.is_symlink():
            return False
        target = _run_pointer_target(path, root)
        if target is None:
            raise ReconError(f"Review does not follow symlinks: {path}")
        run_aliases.append({"path": path.relative_to(root).as_posix(),
                            "canonical_run": target.relative_to(root).as_posix(),
                            "run_directory_present": target.is_dir()})
        return True

    for current, directories, names in os.walk(source, followlinks=False):
        current_path = Path(current)
        directories[:] = [name for name in directories if not skip_run_pointer(current_path / name)]
        target = destination / current_path.relative_to(source)
        target.mkdir(parents=True, exist_ok=True)
        for name in names:
            original = current_path / name
            if skip_run_pointer(original):
                continue
            _regular_file(original, root)
            copied = target / name
            shutil.copyfile(original, copied)
            copied.chmod(0o600)
            files += 1
            size += copied.stat().st_size
    return files, size


def _map_path(value: str, source: Path, destination: Path) -> str:
    candidate = Path(value)
    try:
        relative = candidate.relative_to(source) if candidate.is_absolute() else candidate
        if ".." not in relative.parts and any(
            relative == Path(tree) or Path(tree) in relative.parents for tree in ARTIFACT_TREES
        ):
            if len(relative.parts) >= 3 and relative.parts[0] == "output" and relative.parts[2] in {"latest", "latest-run"}:
                pointer = source / Path(*relative.parts[:3])
                if pointer.is_symlink():
                    canonical = _run_pointer_target(pointer, source)
                    if canonical is None:
                        raise ReconError(f"Review does not follow symlinks: {pointer}")
                    relative = canonical.relative_to(source) / Path(*relative.parts[3:])
            return str(destination / relative)
    except ValueError:
        pass
    return value


def _rebase_paths(conn: sqlite3.Connection, source: Path, destination: Path) -> None:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, column in PATH_COLUMNS:
        if table not in tables:
            continue
        for rowid, value in conn.execute(
            f"SELECT rowid,{_quote(column)} FROM {_quote(table)} WHERE COALESCE({_quote(column)},'')<>''"
        ).fetchall():
            rewritten = _map_path(str(value), source, destination)
            if rewritten != value:
                conn.execute(f"UPDATE {_quote(table)} SET {_quote(column)}=? WHERE rowid=?", (rewritten, rowid))
    if "asset_edges" in tables:
        for rowid, encoded in conn.execute(
            "SELECT rowid,metadata_json FROM asset_edges WHERE metadata_json LIKE '%blob_path%'"
        ).fetchall():
            metadata = json.loads(encoded)
            if not isinstance(metadata, dict) or not isinstance(metadata.get("blob_path"), str):
                continue
            original = metadata["blob_path"]
            metadata["blob_path"] = _map_path(original, source, destination)
            if metadata["blob_path"] != original:
                conn.execute("UPDATE asset_edges SET metadata_json=? WHERE rowid=?", (json.dumps(metadata), rowid))


def prepare_review(source: Path, destination: Path) -> dict:
    source = source.expanduser().resolve(strict=True)
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ReconError("Review destination already exists; choose a new directory")
    destination = destination.resolve()
    if any(destination.is_relative_to(root) or root.is_relative_to(destination) for root in (source, ROOT)):
        raise ReconError("Review data must be separate from the installation and code checkout")
    source_paths = AppPaths.from_root(source)
    _regular_file(source_paths.db, source)
    if not source_paths.policy.is_file() and not source_paths.legacy_targets.is_file():
        raise ReconError("Source installation has no target policy")
    destination.mkdir(mode=0o700, parents=True)
    paths = AppPaths.from_root(destination)
    try:
        paths.ensure()
        started = time.monotonic()
        # Do not open the installed database through Database(): it migrates.
        original = sqlite3.connect(source_paths.db.as_uri() + "?mode=ro", uri=True, timeout=10)
        snapshot = sqlite3.connect(paths.db)
        try:
            original.execute("PRAGMA query_only=ON")

            def progress(_status, _remaining, _total):
                if time.monotonic() - started > 300:
                    raise ReconError("SQLite snapshot could not finish within five minutes")

            original.backup(snapshot, pages=256, progress=progress)
            captured_at = utc_now()
            schema = snapshot.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            if not schema or int(schema[0]) != SCHEMA_VERSION:
                raise ReconError(f"Review requires schema {SCHEMA_VERSION}; update the installation first")
            before = _counts(snapshot)
            quick = snapshot.execute("PRAGMA quick_check").fetchall()
            violations = snapshot.execute("PRAGMA foreign_key_check").fetchall()
            if quick != [("ok",)] or violations:
                raise ReconError("Snapshot failed database integrity/foreign-key checks")
        finally:
            snapshot.close()
            original.close()
        paths.db.chmod(0o600)
        paths.config.write_text("".join(f'{key}="{value}"\n' for key, value in SAFE_CONFIG.items()), encoding="utf-8")
        paths.config.chmod(0o600)
        for original_policy, copied_policy in (
            (source_paths.policy, paths.policy), (source_paths.legacy_targets, paths.legacy_targets),
        ):
            if original_policy.exists() or original_policy.is_symlink():
                _regular_file(original_policy, source)
                shutil.copyfile(original_policy, copied_policy)
                copied_policy.chmod(0o600)

        db = Database(paths.db)
        try:
            logger = Logger(paths, verbose=False)
            # Normalize alias-based references in the snapshot only. The source
            # manifest must inspect canonical artifacts before paths are rebased.
            _rebase_paths(db.conn, source, source)
            source_manager = BackupManager(source_paths, db, logger)
            inventory = source_manager._materialize_reference_manifest(paths.db, strict=True)
            for relative in inventory["required_files"]:
                if not any(Path(tree) in Path(relative).parents for tree in ARTIFACT_TREES):
                    raise ReconError(f"Referenced file is outside managed artifact directories: {relative}")
            file_count = byte_count = 0
            run_aliases: list[dict] = []
            for tree in ARTIFACT_TREES:
                count, size = _copy_tree(source / tree, destination / tree, source, run_aliases)
                file_count += count
                byte_count += size
            _rebase_paths(db.conn, source, destination)
            review_manager = BackupManager(paths, db, logger)
            rebase = review_manager._rebase_restored_artifact_references(paths.db)
            if not rebase["ok"]:
                raise ReconError("Could not rebase artifact references: " + "; ".join(rebase["issues"][:5]))
            copied_inventory = review_manager._materialize_reference_manifest(paths.db, strict=True)
            for relative, metadata in inventory["required_files"].items():
                if sha256_file(destination / relative) != metadata["sha256"]:
                    raise ReconError(f"Artifact changed while preparing the review: {relative}")
            after = _counts(db.conn)
            if before != after:
                raise ReconError("Review preparation changed database record counts")
            # Preserve the records, but invalidate installed credentials in the copy.
            db.execute("UPDATE users SET enabled=0,auth_epoch=auth_epoch+1")
            db.execute("UPDATE api_tokens SET revoked_at=? WHERE revoked_at IS NULL", (utc_now(),))
        finally:
            db.close()
        report = {
            "version": APP_VERSION, "schema": SCHEMA_VERSION, "snapshot_at": captured_at,
            "source_open_mode": "ro", "database_quick_check": "ok", "foreign_key_violations": 0,
            "all_table_counts_preserved": True, "snapshot_table_counts": before,
            "copied_files": file_count, "copied_bytes": byte_count,
            "verified_referenced_files": copied_inventory["required_count"],
            "skipped_run_pointer_aliases": run_aliases,
            "snapshot_seconds": round(time.monotonic() - started, 3),
        }
        (destination / "review-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report
    except BaseException:
        # Only the fresh directory created by this call may be removed.
        shutil.rmtree(destination)
        raise


def review_config(paths: AppPaths) -> Config:
    config = Config(paths)
    # Ambient Telegram/authorization environment variables must not override isolation.
    config.values = dict(SAFE_CONFIG)
    return config


def make_server(paths: AppPaths, port: int = 0) -> ThreadingHTTPServer:
    class ReviewHandler(DashboardHandler):
        def parse_request(self):
            if not super().parse_request():
                return False
            # Cookies are scoped by host/path, not port. Keep a review login from
            # replacing the installed dashboard's recon_session browser cookie.
            cookies = SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
            except Exception:
                pass
            if "Cookie" in self.headers:
                del self.headers["Cookie"]
            own = cookies.get("recon_review_session")
            if own:
                self.headers["Cookie"] = "recon_session=" + own.value
            return True

        def send_header(self, keyword, value):
            if keyword.lower() == "set-cookie" and value.startswith("recon_session="):
                value = value.replace("recon_session=", "recon_review_session=", 1)
            super().send_header(keyword, value)

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path != "/login":
                self.send_html("Review is read-only", "<h1>Operations are disabled in this snapshot review.</h1>", 403)
                return
            super().do_POST()

        def send_html(self, title, body, status=200):
            banner = ("<aside class='callout' role='note'><strong>Snapshot review · read-only account</strong>"
                      "<span>This is a local copy. Running-state records describe the snapshot; "
                      "collectors and operational actions are disabled.</span></aside>")
            super().send_html(title, banner + body, status)

        def report(self, run_id):
            db = self.db()
            try:
                row = db.one("SELECT run_dir FROM run_targets WHERE run_id=? LIMIT 1", (run_id,))
            finally:
                db.close()
            if row and not Path(str(row["run_dir"])).resolve().is_relative_to(paths.output.resolve()):
                self.send_html("Unavailable in snapshot", "<h1>Report path is outside this snapshot.</h1>", 404)
                return
            super().report(run_id)

    ReviewHandler.paths = paths
    ReviewHandler.db_path = paths.db
    ReviewHandler.config = review_config(paths)
    ReviewHandler.logger = Logger(paths, verbose=False)
    return ThreadingHTTPServer(("127.0.0.1", port), ReviewHandler)


@contextlib.contextmanager
def loopback_only():
    connect, connect_ex, getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
    allowed = {"127.0.0.1", "::1", "localhost"}

    def checked(address):
        if isinstance(address, tuple) and address[0] not in allowed:
            raise PermissionError("Snapshot review refuses non-loopback connections")

    def local_connect(sock, address):
        checked(address)
        return connect(sock, address)

    def local_connect_ex(sock, address):
        checked(address)
        return connect_ex(sock, address)

    def local_lookup(host, *args, **kwargs):
        if host is not None and host not in allowed:
            raise PermissionError("Snapshot review refuses non-loopback DNS lookups")
        return getaddrinfo(host, *args, **kwargs)

    with patch.object(socket.socket, "connect", local_connect), patch.object(socket.socket, "connect_ex", local_connect_ex), patch.object(socket, "getaddrinfo", local_lookup):
        yield


def probe_pages(server: ThreadingHTTPServer, paths: AppPaths, username: str, password: str) -> list[dict]:
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base = f"http://127.0.0.1:{server.server_address[1]}"
    login = urllib.parse.urlencode({"username": username, "password": password}).encode()
    with client.open(base + "/login", data=login, timeout=60) as response:
        if urllib.parse.urlsplit(response.geturl()).path != "/":
            raise ReconError("Review viewer login failed")
        response.read()
    db = Database(paths.db)
    try:
        sample = db.one("SELECT target,url,last_run_id FROM urls ORDER BY rowid DESC LIMIT 1")
        params = {"q": sample["url"] if sample else "*", "group": "URLs", "days": "0"}
        if sample:
            params.update(target=sample["target"], run=sample["last_run_id"] or "")
            escaped = str(sample["url"]).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where, values = "target=? AND url LIKE ? ESCAPE '\\'", [sample["target"], "%" + escaped + "%"]
            if sample["last_run_id"]:
                where += " AND last_run_id=?"
                values.append(sample["last_run_id"])
            expected = int(db.one("SELECT COUNT(*) count FROM urls WHERE " + where, values)["count"])
        else:
            expected = 0
        run = db.one("SELECT id FROM runs ORDER BY started_at DESC LIMIT 1")
    finally:
        db.close()
    routes = [("Home", "/"), ("Recon", "/recon"), ("Runs", "/runs"), ("Analysis", "/analysis"),
              ("Search with combined filters", "/search?" + urllib.parse.urlencode(params))]
    if run:
        routes.append(("Latest run review", "/run-review?" + urllib.parse.urlencode({"id": run["id"]})))
    checks = []
    for name, path in routes:
        for attempt in ("first", "repeat"):
            started = time.monotonic()
            try:
                with client.open(base + path, timeout=60) as response:
                    status, body = response.status, response.read().decode("utf-8")
                ok = status == 200 and urllib.parse.urlsplit(response.geturl()).path != "/login"
                if name.startswith("Search"):
                    ok = ok and (f"{expected} matching records" in body if expected else "No matching records" in body)
                checks.append({"page": name, "attempt": attempt, "status": status, "passed": ok,
                               "seconds": round(time.monotonic() - started, 3)})
            except (OSError, urllib.error.URLError) as exc:
                checks.append({"page": name, "attempt": attempt, "passed": False,
                               "error_type": type(exc).__name__, "seconds": round(time.monotonic() - started, 3)})
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Installed recon-monitor directory")
    parser.add_argument("--destination", type=Path, help="New private snapshot directory; never overwritten")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--open", action="store_true", help="Open the local review URL in the default browser")
    parser.add_argument("--prepare-only", action="store_true", help="Prepare and probe, then stop without keeping the server open")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = args.destination or args.source.expanduser().resolve().parent / f"recon-dashboard-review-{stamp}-{uuid.uuid4().hex[:6]}"
    print("Preparing an isolated database/artifact snapshot…", flush=True)
    report = prepare_review(args.source, destination)
    paths = AppPaths.from_root(destination)
    username, password = "review-" + secrets.token_hex(4), secrets.token_urlsafe(24)
    create_user(paths, username, password, "viewer")
    server = make_server(paths, args.port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with loopback_only():
            report["http_checks"] = probe_pages(server, paths, username, password)
            report["http_checks_passed"] = all(item["passed"] for item in report["http_checks"])
            (paths.root / "review-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"All table counts preserved: {report['all_table_counts_preserved']}")
            print(f"Copied files: {report['copied_files']}; verified references: {report['verified_referenced_files']}")
            print(f"Skipped redundant run pointer aliases: {len(report['skipped_run_pointer_aliases'])}")
            print(f"HTTP checks passed: {report['http_checks_passed']}")
            for check in report["http_checks"]:
                result = "OK" if check["passed"] else "FAIL"
                print(f"{check['page']} ({check['attempt']}): {check['seconds']}s · {result}")
            print(f"Report: {paths.root / 'review-report.json'}")
            if args.prepare_only:
                return 0 if report["http_checks_passed"] else 1
            url = f"http://127.0.0.1:{args.port}"
            print(f"\nSnapshot dashboard: {url}\nUsername: {username}\nPassword: {password}")
            print("Keep this terminal open. Ctrl+C stops this review server only.", flush=True)
            if args.open:
                from dashboard_service import open_dashboard
                open_dashboard("127.0.0.1", args.port)
            while thread.is_alive():
                thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\nSnapshot review stopped.")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReconError, OSError, sqlite3.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

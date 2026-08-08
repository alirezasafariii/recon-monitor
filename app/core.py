from __future__ import annotations

import contextlib
import copy
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

APP_VERSION = "8.1.0"
SCHEMA_VERSION = 16
UTC = dt.timezone.utc


def utc_now() -> str:
    return dt.datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def json_dumps(value: Any, *, pretty: bool = False) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )


def safe_json_loads(value: Any, default: Any, *, expected_type: type | tuple[type, ...] | None = None) -> Any:
    """Decode legacy or partially-corrupt JSON without crashing callers.

    Database rows produced by older Recon Monitor versions can contain NULL,
    blank strings, scalars where containers are expected, or malformed JSON
    left by interrupted writes.  This helper centralizes defensive decoding and
    always returns an independent copy of ``default`` on failure.
    """
    if value is None:
        return copy.deepcopy(default)
    if isinstance(value, (dict, list, tuple, str, int, float, bool)) and not isinstance(value, str):
        decoded = value
    else:
        text = str(value).strip()
        if not text:
            return copy.deepcopy(default)
        try:
            decoded = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return copy.deepcopy(default)
    required = expected_type
    if required is None and default is not None:
        required = type(default)
    if required is not None and not isinstance(decoded, required):
        return copy.deepcopy(default)
    return decoded


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def parse_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        result = int(str(value).strip())
    except (ValueError, TypeError):
        result = default
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(text, encoding="utf-8")
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def atomic_write_bytes(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_bytes(data)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def safe_filename(value: str, max_len: int = 120) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    if not cleaned:
        cleaned = sha256_text(value)[:16]
    return cleaned[:max_len]


def normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def valid_domain(value: str) -> bool:
    value = normalize_host(value)
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is not None
        for label in labels
    )


def normalize_url(value: str, *, drop_tracking: bool = True) -> str | None:
    """Canonicalize an HTTP(S) URL for stable comparison.

    The normalizer removes fragments/default ports, normalizes host/path, sorts
    query parameters, and optionally removes common tracking/cache-busting keys.
    """
    value = value.strip()
    if not value:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = normalize_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = urllib.parse.unquote(parsed.path or "/", errors="replace")
    path = re.sub(r"/{2,}", "/", path)
    # Re-quote while preserving URL path delimiters.
    path = urllib.parse.quote(path, safe="/%:@-._~!$&'()*+,;=")
    tracking = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "gclid", "fbclid", "msclkid", "dclid", "yclid", "mc_cid", "mc_eid",
        "_ga", "_gl", "ref", "source", "spm", "cachebust", "cache_bust", "cb",
    }
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if drop_tracking:
        pairs = [(k, v) for k, v in pairs if k.lower() not in tracking and not k.lower().startswith("utm_")]
    pairs.sort(key=lambda item: (item[0], item[1]))
    query = urllib.parse.urlencode(pairs, doseq=True)
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


class ReconError(RuntimeError):
    pass


class StageError(ReconError):
    def __init__(self, message: str, *, exit_code: int = 1, retryable: bool = True):
        super().__init__(message)
        self.exit_code = exit_code
        self.retryable = retryable


@dataclasses.dataclass(slots=True)
class AppPaths:
    root: Path
    app: Path
    config: Path
    policy: Path
    legacy_targets: Path
    db: Path
    output: Path
    state: Path
    logs: Path
    lock: Path
    blobs: Path
    backups: Path
    reports: Path
    objects: Path
    plugins: Path
    audit_log: Path
    sessions: Path
    releases: Path

    @classmethod
    def from_root(cls, root: Path) -> "AppPaths":
        root = root.resolve()
        state = root / "state"
        return cls(
            root=root,
            app=root / "app",
            config=root / "config.env",
            policy=root / "policies" / "targets.json",
            legacy_targets=root / "targets.txt",
            db=state / "recon-v2.db",
            output=root / "output",
            state=state,
            logs=root / "logs",
            lock=state / "run.lock",
            blobs=state / "blobs",
            backups=state / "backups",
            reports=root / "reports",
            objects=state / "objects" / "sha256",
            plugins=root / "plugins",
            audit_log=state / "audit.jsonl",
            sessions=state / "sessions",
            releases=state / "releases",
        )

    def ensure(self) -> None:
        for path in (self.output, self.state, self.logs, self.blobs, self.backups, self.reports, self.policy.parent, self.objects, self.plugins, self.sessions, self.releases):
            path.mkdir(parents=True, exist_ok=True)


class Config:
    def __init__(self, paths: AppPaths):
        self.paths = paths
        self.values = parse_env_file(paths.config)
        for key, value in os.environ.items():
            if key.startswith("RECON_") or key in {
                "I_HAVE_AUTHORIZATION",
                "TELEGRAM_ENABLED",
                "TELEGRAM_BOT_TOKEN",
                "TELEGRAM_CHAT_ID",
            }:
                self.values[key] = value

    def get(self, key: str, default: str = "") -> str:
        value = self.values.get(key, default)
        keychain_map = {
            "TELEGRAM_BOT_TOKEN": "telegram-token",
            "GITHUB_TOKEN": "github-token",
            "NOTIFY_WEBHOOK": "notify-webhook",
            "DASHBOARD_SECRET": "dashboard-secret",
        }
        reference = str(value).strip()
        secret_name = reference.split(":", 1)[1] if reference.startswith("keychain:") else keychain_map.get(key, "") if parse_bool(self.values.get("USE_MACOS_KEYCHAIN"), False) and not reference else ""
        if secret_name and sys.platform == "darwin" and shutil.which("security"):
            result = subprocess.run(
                ["security", "find-generic-password", "-a", os.environ.get("USER", "recon-monitor"), "-s", f"recon-monitor-{secret_name}", "-w"],
                text=True, capture_output=True, timeout=5, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        return value

    def bool(self, key: str, default: bool = False) -> bool:
        return parse_bool(self.values.get(key), default)

    def int(self, key: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
        return parse_int(self.values.get(key), default, minimum, maximum)

    @property
    def authorized(self) -> bool:
        return self.get("I_HAVE_AUTHORIZATION").strip().lower() == "yes"

    @property
    def active_globally_enabled(self) -> bool:
        return self.get("ENABLE_ACTIVE_MODULES").strip().lower() == "yes"

    def secret_is_set(self, key: str) -> bool:
        value = self.get(key)
        return bool(value and not value.startswith("CHANGE_") and "YOUR_" not in value)


class Logger:
    def __init__(self, paths: AppPaths, verbose: bool = True):
        paths.logs.mkdir(parents=True, exist_ok=True)
        self.text_path = paths.logs / "recon.log"
        self.jsonl_path = paths.logs / "events.jsonl"
        self.verbose = verbose
        self._lock = threading.Lock()

    def event(self, level: str, message: str, **fields: Any) -> None:
        record = {"ts": utc_now(), "level": level.upper(), "message": message, **fields}
        line = f"[{local_now()}] [{level.upper()}] {message}"
        with self._lock:
            with self.text_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json_dumps(record) + "\n")
        if self.verbose:
            stream = sys.stderr if level.upper() in {"WARN", "ERROR"} else sys.stdout
            print(line, file=stream, flush=True)

    def info(self, message: str, **fields: Any) -> None:
        self.event("INFO", message, **fields)

    def warn(self, message: str, **fields: Any) -> None:
        self.event("WARN", message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self.event("ERROR", message, **fields)


@dataclasses.dataclass(slots=True)
class Limits:
    request_rate: int = 3
    dns_rate: int = 100
    timeout_seconds: int = 600
    retries: int = 1
    crawl_depth: int = 2
    max_urls: int = 10000
    max_js_files: int = 200
    max_js_bytes: int = 5_000_000
    http_threads: int = 20
    naabu_rate: int = 50
    nuclei_rate: int = 3
    max_runtime_minutes: int = 120
    max_http_requests: int = 10000
    max_dns_queries: int = 5000
    max_download_mb: int = 500
    max_new_assets: int = 5000
    dns_workers: int = 10
    http_workers: int = 20
    js_workers: int = 5
    screenshot_workers: int = 2


@dataclasses.dataclass(slots=True)
class TargetPolicy:
    name: str
    roots: list[str]
    include: list[str]
    exclude: list[str]
    modules: dict[str, bool]
    limits: Limits
    headers: dict[str, str]
    active: dict[str, Any]
    alert: dict[str, Any]
    analysis: dict[str, Any]
    tags: list[str]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], defaults: Mapping[str, Any] | None = None) -> "TargetPolicy":
        merged: dict[str, Any] = {}
        if defaults:
            merged.update(json.loads(json.dumps(defaults)))
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value

        roots = [normalize_host(str(x)) for x in merged.get("roots", []) if str(x).strip()]
        if not roots and merged.get("domain"):
            roots = [normalize_host(str(merged["domain"]))]
        name = str(merged.get("name") or (roots[0] if roots else "unnamed"))
        include = [str(x) for x in merged.get("include", [])]
        if not include:
            include = [rf"(^|\.){re.escape(root)}$" for root in roots]
        exclude = [str(x) for x in merged.get("exclude", [])]
        modules = {
            "subdomains": True,
            "dns": True,
            "urls": True,
            "javascript": True,
            "endpoint_validation": False,
            "fingerprint": True,
            "screenshots": False,
            "ports": False,
            "nuclei": False,
            **{str(k): parse_bool(v) for k, v in dict(merged.get("modules", {})).items()},
        }
        raw_limits = dict(merged.get("limits", {}))
        limits = Limits(
            request_rate=parse_int(raw_limits.get("request_rate"), 3, 1, 50),
            dns_rate=parse_int(raw_limits.get("dns_rate"), 100, 1, 1000),
            timeout_seconds=parse_int(raw_limits.get("timeout_seconds"), 600, 30, 7200),
            retries=parse_int(raw_limits.get("retries"), 1, 0, 5),
            crawl_depth=parse_int(raw_limits.get("crawl_depth"), 2, 1, 5),
            max_urls=parse_int(raw_limits.get("max_urls"), 10000, 100, 200000),
            max_js_files=parse_int(raw_limits.get("max_js_files"), 200, 1, 5000),
            max_js_bytes=parse_int(raw_limits.get("max_js_bytes"), 5_000_000, 10_000, 50_000_000),
            http_threads=parse_int(raw_limits.get("http_threads"), 20, 1, 100),
            naabu_rate=parse_int(raw_limits.get("naabu_rate"), 50, 1, 500),
            nuclei_rate=parse_int(raw_limits.get("nuclei_rate"), 3, 1, 50),
            max_runtime_minutes=parse_int(raw_limits.get("max_runtime_minutes"), 120, 5, 1440),
            max_http_requests=parse_int(raw_limits.get("max_http_requests"), 10000, 100, 1000000),
            max_dns_queries=parse_int(raw_limits.get("max_dns_queries"), 5000, 100, 1000000),
            max_download_mb=parse_int(raw_limits.get("max_download_mb"), 500, 10, 100000),
            max_new_assets=parse_int(raw_limits.get("max_new_assets"), 5000, 10, 1000000),
            dns_workers=parse_int(raw_limits.get("dns_workers"), 10, 1, 100),
            http_workers=parse_int(raw_limits.get("http_workers"), 20, 1, 100),
            js_workers=parse_int(raw_limits.get("js_workers"), 5, 1, 50),
            screenshot_workers=parse_int(raw_limits.get("screenshot_workers"), 2, 1, 10),
        )
        policy = cls(
            name=name,
            roots=roots,
            include=include,
            exclude=exclude,
            modules=modules,
            limits=limits,
            headers={str(k): str(v) for k, v in dict(merged.get("headers", {})).items()},
            active=dict(merged.get("active", {})),
            alert=dict(merged.get("alert", {})),
            analysis=dict(merged.get("analysis", {})),
            tags=[str(x) for x in merged.get("tags", [])],
            raw=merged,
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        if not self.roots:
            raise ReconError(f"Target policy {self.name!r} has no roots")
        for root in self.roots:
            if not valid_domain(root):
                raise ReconError(f"Invalid root domain in {self.name}: {root}")
        for pattern in self.include + self.exclude:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ReconError(f"Invalid scope regex in {self.name}: {pattern}: {exc}") from exc
        ports = str(self.active.get("naabu_ports", "80,443,8080,8443"))
        if not re.fullmatch(r"[0-9,\-]+", ports):
            raise ReconError(f"Invalid naabu_ports in {self.name}: {ports}")

    def host_in_scope(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if any(re.search(pattern, host, re.IGNORECASE) for pattern in self.exclude):
            return False
        return any(re.search(pattern, host, re.IGNORECASE) for pattern in self.include)

    def url_in_scope(self, url: str) -> bool:
        normalized = normalize_url(url)
        if not normalized:
            return False
        host = urllib.parse.urlsplit(normalized).hostname or ""
        return self.host_in_scope(host)

    @property
    def active_confirmed(self) -> bool:
        return self.active.get("confirmation") == "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"

    def active_allowed(self, config: Config, cli_allow_active: bool) -> bool:
        return config.authorized and config.active_globally_enabled and cli_allow_active and self.active_confirmed

    def policy_hash(self) -> str:
        return sha256_text(json_dumps(self.raw))


class PolicySet:
    def __init__(self, defaults: Mapping[str, Any], targets: Sequence[TargetPolicy], source: Path):
        self.defaults = dict(defaults)
        self.targets = list(targets)
        self.source = source

    @classmethod
    def load(cls, paths: AppPaths) -> "PolicySet":
        if paths.policy.exists():
            try:
                data = json.loads(paths.policy.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ReconError(f"Invalid JSON in {paths.policy}: {exc}") from exc
            defaults = dict(data.get("defaults", {}))
            targets = [TargetPolicy.from_dict(item, defaults) for item in data.get("targets", [])]
            if not targets:
                raise ReconError(f"No targets configured in {paths.policy}")
            return cls(defaults, targets, paths.policy)

        if paths.legacy_targets.exists():
            roots: list[str] = []
            for raw in paths.legacy_targets.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.split("#", 1)[0].strip()
                if line:
                    roots.append(normalize_host(line))
            targets = [TargetPolicy.from_dict({"name": root, "roots": [root]}) for root in roots if valid_domain(root)]
            if targets:
                return cls({}, targets, paths.legacy_targets)
        raise ReconError("No policy file or valid legacy targets.txt found. Run init.")

    def select(self, selector: str | None) -> list[TargetPolicy]:
        if not selector:
            return list(self.targets)
        selector = selector.lower()
        matches = [
            target
            for target in self.targets
            if target.name.lower() == selector or selector in {root.lower() for root in target.roots}
        ]
        if not matches:
            raise ReconError(f"Target not found in policy: {selector}")
        return matches


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self._lock = threading.RLock()
        self.migrate()

    def close(self) -> None:
        self.conn.close()

    def migrate(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY,
              version TEXT NOT NULL,
              status TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              target_selector TEXT,
              target_count INTEGER NOT NULL DEFAULT 0,
              resumed_from TEXT,
              config_hash TEXT,
              error TEXT
            );
            CREATE TABLE IF NOT EXISTS run_targets (
              run_id TEXT NOT NULL,
              target TEXT NOT NULL,
              policy_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              current_stage TEXT,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              run_dir TEXT NOT NULL,
              baseline INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(run_id,target),
              FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS stage_runs (
              run_id TEXT NOT NULL,
              target TEXT NOT NULL,
              stage TEXT NOT NULL,
              status TEXT NOT NULL,
              attempt INTEGER NOT NULL DEFAULT 1,
              started_at TEXT,
              finished_at TEXT,
              heartbeat_at TEXT,
              exit_code INTEGER,
              duration_seconds REAL,
              metrics_json TEXT,
              error TEXT,
              PRIMARY KEY(run_id,target,stage),
              FOREIGN KEY(run_id,target) REFERENCES run_targets(run_id,target) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS assets (
              target TEXT NOT NULL,
              host TEXT NOT NULL,
              sources_json TEXT NOT NULL DEFAULT '[]',
              confidence INTEGER NOT NULL DEFAULT 0,
              wildcard INTEGER NOT NULL DEFAULT 0,
              resolved INTEGER NOT NULL DEFAULT 0,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,host)
            );
            CREATE TABLE IF NOT EXISTS dns_records (
              target TEXT NOT NULL,
              host TEXT NOT NULL,
              rrtype TEXT NOT NULL,
              value TEXT NOT NULL,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              is_current INTEGER NOT NULL DEFAULT 1,
              PRIMARY KEY(target,host,rrtype,value)
            );
            CREATE TABLE IF NOT EXISTS urls (
              target TEXT NOT NULL,
              url TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT 'url',
              source TEXT,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,url)
            );
            CREATE TABLE IF NOT EXISTS js_files (
              target TEXT NOT NULL,
              url TEXT NOT NULL,
              raw_hash TEXT NOT NULL,
              semantic_hash TEXT NOT NULL,
              blob_path TEXT NOT NULL,
              content_length INTEGER NOT NULL,
              etag TEXT,
              last_modified TEXT,
              source_map_url TEXT,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_changed TEXT,
              last_run_id TEXT,
              PRIMARY KEY(target,url)
            );
            CREATE TABLE IF NOT EXISTS js_indicators (
              target TEXT NOT NULL,
              js_url TEXT NOT NULL,
              kind TEXT NOT NULL,
              value TEXT NOT NULL,
              redacted INTEGER NOT NULL DEFAULT 0,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,js_url,kind,value)
            );
            CREATE TABLE IF NOT EXISTS fingerprints (
              target TEXT NOT NULL,
              url TEXT NOT NULL,
              fingerprint_hash TEXT NOT NULL,
              status_code INTEGER,
              title TEXT,
              webserver TEXT,
              technologies_json TEXT NOT NULL DEFAULT '[]',
              content_type TEXT,
              content_length INTEGER,
              body_hash TEXT,
              favicon_hash TEXT,
              jarm TEXT,
              ip TEXT,
              cname TEXT,
              cdn TEXT,
              final_url TEXT,
              redirect_chain_json TEXT NOT NULL DEFAULT '[]',
              http2 INTEGER,
              tls_issuer TEXT,
              tls_expiry TEXT,
              tls_sans_json TEXT NOT NULL DEFAULT '[]',
              tls_serial TEXT,
              screenshot_path TEXT,
              screenshot_hash TEXT,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_changed TEXT,
              last_run_id TEXT,
              PRIMARY KEY(target,url)
            );
            CREATE TABLE IF NOT EXISTS ports (
              target TEXT NOT NULL,
              host TEXT NOT NULL,
              ip TEXT,
              port INTEGER NOT NULL,
              protocol TEXT NOT NULL DEFAULT 'tcp',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              is_current INTEGER NOT NULL DEFAULT 1,
              PRIMARY KEY(target,host,port,protocol)
            );
            CREATE TABLE IF NOT EXISTS findings (
              target TEXT NOT NULL,
              dedup_key TEXT NOT NULL,
              template_id TEXT,
              name TEXT,
              severity TEXT,
              matched_at TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,dedup_key)
            );
            CREATE TABLE IF NOT EXISTS alerts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              target TEXT NOT NULL,
              dedup_key TEXT NOT NULL,
              category TEXT NOT NULL,
              severity TEXT NOT NULL,
              risk_score INTEGER NOT NULL,
              title TEXT NOT NULL,
              item TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              status TEXT NOT NULL DEFAULT 'new',
              occurrences INTEGER NOT NULL DEFAULT 1,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_notified TEXT,
              last_run_id TEXT,
              UNIQUE(target,dedup_key)
            );
            CREATE TABLE IF NOT EXISTS asset_edges (
              target TEXT NOT NULL,
              source_type TEXT NOT NULL,
              source_value TEXT NOT NULL,
              relation TEXT NOT NULL,
              destination_type TEXT NOT NULL,
              destination_value TEXT NOT NULL,
              metadata_json TEXT NOT NULL DEFAULT '{}',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,source_type,source_value,relation,destination_type,destination_value)
            );
            CREATE TABLE IF NOT EXISTS event_observations (
              target TEXT NOT NULL,
              dedup_key TEXT NOT NULL,
              category TEXT NOT NULL,
              item TEXT NOT NULL,
              change_class TEXT NOT NULL,
              occurrences INTEGER NOT NULL DEFAULT 1,
              confirmation_state TEXT NOT NULL DEFAULT 'observed',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              PRIMARY KEY(target,dedup_key)
            );
            CREATE TABLE IF NOT EXISTS investigation_notes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              target TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_value TEXT NOT NULL,
              note TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entity_tags (
              target TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_value TEXT NOT NULL,
              tag TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY(target,entity_type,entity_value,tag)
            );
            CREATE TABLE IF NOT EXISTS alert_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              alert_id INTEGER NOT NULL,
              action TEXT NOT NULL,
              old_value TEXT,
              new_value TEXT,
              note TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS js_diffs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              target TEXT NOT NULL,
              js_url TEXT NOT NULL,
              old_raw_hash TEXT,
              new_raw_hash TEXT NOT NULL,
              old_semantic_hash TEXT,
              new_semantic_hash TEXT NOT NULL,
              summary_json TEXT NOT NULL DEFAULT '{}',
              diff_text TEXT NOT NULL DEFAULT '',
              diff_path TEXT,
              created_at TEXT NOT NULL,
              UNIQUE(run_id,target,js_url)
            );
            CREATE TABLE IF NOT EXISTS endpoint_intelligence (
              target TEXT NOT NULL,
              endpoint TEXT NOT NULL,
              kind TEXT NOT NULL,
              primary_category TEXT NOT NULL,
              confidence INTEGER NOT NULL,
              categories_json TEXT NOT NULL DEFAULT '[]',
              reasons_json TEXT NOT NULL DEFAULT '[]',
              sources_json TEXT NOT NULL DEFAULT '[]',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              PRIMARY KEY(target,endpoint,kind)
            );
            CREATE TABLE IF NOT EXISTS technology_observations (
              target TEXT NOT NULL,
              url TEXT NOT NULL,
              technology TEXT NOT NULL,
              confidence INTEGER NOT NULL,
              confidence_label TEXT NOT NULL,
              evidence_json TEXT NOT NULL DEFAULT '[]',
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              last_run_id TEXT,
              is_current INTEGER NOT NULL DEFAULT 1,
              PRIMARY KEY(target,url,technology)
            );
            CREATE TABLE IF NOT EXISTS work_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL, target TEXT NOT NULL, stage TEXT NOT NULL,
              item_key TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}',
              status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
              worker_id TEXT, result_json TEXT NOT NULL DEFAULT '{}', error TEXT,
              created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, heartbeat_at TEXT,
              UNIQUE(run_id,target,stage,item_key)
            );
            CREATE TABLE IF NOT EXISTS run_budgets (
              run_id TEXT NOT NULL, target TEXT NOT NULL, metric TEXT NOT NULL,
              used INTEGER NOT NULL DEFAULT 0, limit_value INTEGER NOT NULL, updated_at TEXT NOT NULL,
              PRIMARY KEY(run_id,target,metric)
            );
            CREATE TABLE IF NOT EXISTS ignore_rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL DEFAULT '*',
              rule_type TEXT NOT NULL, pattern TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
              note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS change_incidents (
              id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, correlation_key TEXT NOT NULL,
              title TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
              event_count INTEGER NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              last_run_id TEXT, details_json TEXT NOT NULL DEFAULT '{}', UNIQUE(target,correlation_key)
            );
            CREATE TABLE IF NOT EXISTS incident_events (
              incident_id INTEGER NOT NULL, event_key TEXT NOT NULL, category TEXT NOT NULL, item TEXT NOT NULL,
              created_at TEXT NOT NULL, PRIMARY KEY(incident_id,event_key),
              FOREIGN KEY(incident_id) REFERENCES change_incidents(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS asset_lifecycle (
              target TEXT NOT NULL, host TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new',
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, inactive_since TEXT, reappeared_at TEXT,
              transitions INTEGER NOT NULL DEFAULT 0, last_run_id TEXT, PRIMARY KEY(target,host)
            );
            CREATE TABLE IF NOT EXISTS endpoint_validations (
              target TEXT NOT NULL, endpoint TEXT NOT NULL, resolved_url TEXT NOT NULL,
              method TEXT NOT NULL, status_code INTEGER, content_type TEXT, reachable INTEGER NOT NULL DEFAULT 0,
              confidence INTEGER NOT NULL DEFAULT 0, checked_at TEXT NOT NULL, last_run_id TEXT, error TEXT,
              PRIMARY KEY(target,endpoint,resolved_url)
            );
            CREATE TABLE IF NOT EXISTS object_store (
              sha256 TEXT PRIMARY KEY, relative_path TEXT NOT NULL, size INTEGER NOT NULL,
              content_type TEXT NOT NULL DEFAULT 'application/octet-stream', reference_count INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, last_accessed TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_manifests (
              id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, entity_type TEXT NOT NULL, entity_value TEXT NOT NULL,
              manifest_sha256 TEXT NOT NULL, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
              target TEXT, entity_type TEXT, entity_value TEXT, details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS saved_views (
              id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL DEFAULT 'admin', name TEXT NOT NULL,
              view_type TEXT NOT NULL, query_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              UNIQUE(owner,name)
            );
            CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
              password_iterations INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'admin', enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_tokens (
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
              role TEXT NOT NULL DEFAULT 'viewer', created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS remote_workers (
              worker_id TEXT PRIMARY KEY, name TEXT NOT NULL, capabilities_json TEXT NOT NULL DEFAULT '[]',
              status TEXT NOT NULL DEFAULT 'registered', registered_at TEXT NOT NULL, last_heartbeat TEXT, metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS plugin_registry (
              name TEXT PRIMARY KEY, version TEXT NOT NULL, category TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
              path TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', last_health TEXT, health_status TEXT
            );
            CREATE TABLE IF NOT EXISTS backup_catalog (
              backup_id TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
              created_at TEXT NOT NULL, verified_at TEXT, metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS tool_versions (
              run_id TEXT NOT NULL,
              tool TEXT NOT NULL,
              version TEXT,
              path TEXT,
              PRIMARY KEY(run_id,tool),
              FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS analysis_runs (
              id TEXT PRIMARY KEY, source_run_id TEXT NOT NULL, target TEXT NOT NULL DEFAULT '*',
              engine_version TEXT NOT NULL, rule_version TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'analysis',
              status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, summary_json TEXT NOT NULL DEFAULT '{}', error TEXT
            );
            CREATE TABLE IF NOT EXISTS analysis_rules (
              rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, category TEXT NOT NULL, weight INTEGER NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1, description TEXT NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(rule_id,rule_version)
            );
            CREATE TABLE IF NOT EXISTS analysis_results (
              analysis_id TEXT NOT NULL, alert_id INTEGER NOT NULL, target TEXT NOT NULL, source_run_id TEXT NOT NULL,
              category TEXT NOT NULL, original_score INTEGER NOT NULL, adjusted_score INTEGER NOT NULL, confidence INTEGER NOT NULL,
              hypothesis TEXT NOT NULL, next_action TEXT NOT NULL, playbook_id TEXT NOT NULL, business_context TEXT NOT NULL,
              evidence_for_json TEXT NOT NULL DEFAULT '[]', evidence_against_json TEXT NOT NULL DEFAULT '[]',
              anomaly_score REAL NOT NULL DEFAULT 0, baseline_json TEXT NOT NULL DEFAULT '{}', feedback_json TEXT NOT NULL DEFAULT '{}',
              duplicate_cluster TEXT NOT NULL, rule_ids_json TEXT NOT NULL DEFAULT '[]', temporal_json TEXT NOT NULL DEFAULT '{}',
              endpoint_schema_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,alert_id), FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS analysis_clusters (
              analysis_id TEXT NOT NULL, cluster_key TEXT NOT NULL, primary_alert_id INTEGER NOT NULL, member_count INTEGER NOT NULL,
              members_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,cluster_key)
            );
            CREATE TABLE IF NOT EXISTS analysis_quality_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, target TEXT NOT NULL, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analysis_replays (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, previous_analysis_id TEXT, source_run_id TEXT NOT NULL,
              comparison_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoint_schemas (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, source_run_id TEXT NOT NULL, alert_id INTEGER NOT NULL, endpoint TEXT NOT NULL,
              method TEXT NOT NULL, path_parameters_json TEXT NOT NULL DEFAULT '[]', query_parameters_json TEXT NOT NULL DEFAULT '[]',
              body_fields_json TEXT NOT NULL DEFAULT '[]', object_identifiers_json TEXT NOT NULL DEFAULT '[]', auth_hints_json TEXT NOT NULL DEFAULT '[]',
              content_type TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,alert_id)
            );
            CREATE TABLE IF NOT EXISTS js_dataflows (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL, source_kind TEXT NOT NULL, sink_kind TEXT NOT NULL,
              confidence INTEGER NOT NULL, snippet TEXT NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,js_url,source_kind,sink_kind,snippet)
            );
            CREATE TABLE IF NOT EXISTS source_map_intelligence (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL, source_map_url TEXT NOT NULL,
              source_count INTEGER NOT NULL, internal_source_count INTEGER NOT NULL, evidence_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,js_url)
            );
            CREATE TABLE IF NOT EXISTS secret_intelligence (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL, secret_kind TEXT NOT NULL,
              value_fingerprint TEXT NOT NULL, confidence INTEGER NOT NULL, assessment TEXT NOT NULL, reasons_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,js_url,secret_kind,value_fingerprint)
            );
            CREATE TABLE IF NOT EXISTS graphql_intelligence (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL, operation_name TEXT NOT NULL,
              operation_type TEXT NOT NULL, identifiers_json TEXT NOT NULL DEFAULT '[]', sensitive_fields_json TEXT NOT NULL DEFAULT '[]',
              confidence INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,js_url,operation_name)
            );
            CREATE TABLE IF NOT EXISTS api_relationships (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, source_endpoint TEXT NOT NULL, relation TEXT NOT NULL,
              destination_endpoint TEXT NOT NULL, confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,source_endpoint,relation,destination_endpoint)
            );
            CREATE TABLE IF NOT EXISTS business_contexts (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, entity_type TEXT NOT NULL, entity_value TEXT NOT NULL, context TEXT NOT NULL,
              adjustment INTEGER NOT NULL, reasons_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,entity_type,entity_value)
            );
            CREATE TABLE IF NOT EXISTS deployment_signatures (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, incident_id INTEGER NOT NULL, signature TEXT NOT NULL,
              affected_items_json TEXT NOT NULL DEFAULT '[]', change_summary_json TEXT NOT NULL DEFAULT '{}', confidence INTEGER NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,incident_id)
            );
            CREATE TABLE IF NOT EXISTS bug_candidates (
              candidate_id TEXT PRIMARY KEY, candidate_fingerprint TEXT NOT NULL, analysis_id TEXT NOT NULL, source_run_id TEXT NOT NULL,
              alert_id INTEGER, target TEXT NOT NULL, asset TEXT NOT NULL DEFAULT '', endpoint TEXT NOT NULL DEFAULT '', source_ref TEXT NOT NULL DEFAULT '',
              bug_family TEXT NOT NULL, bug_variant TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL,
              likelihood_score INTEGER NOT NULL, evidence_strength INTEGER NOT NULL, impact_potential INTEGER NOT NULL, priority_score INTEGER NOT NULL,
              observation_quality INTEGER NOT NULL DEFAULT 50, investigation_value INTEGER NOT NULL DEFAULT 0,
              novelty_score INTEGER NOT NULL DEFAULT 100, historical_noise INTEGER NOT NULL DEFAULT 0,
              candidate_state TEXT NOT NULL, lifecycle_state TEXT NOT NULL DEFAULT 'observed', analysis_profile TEXT NOT NULL DEFAULT 'balanced',
              supporting_evidence_json TEXT NOT NULL DEFAULT '[]', contradicting_evidence_json TEXT NOT NULL DEFAULT '[]',
              missing_evidence_json TEXT NOT NULL DEFAULT '[]', evidence_groups_json TEXT NOT NULL DEFAULT '{}', quality_explanation_json TEXT NOT NULL DEFAULT '{}',
              safe_next_action TEXT NOT NULL, rule_ids_json TEXT NOT NULL DEFAULT '[]', rule_version TEXT NOT NULL,
              analyst_decision TEXT NOT NULL DEFAULT 'unreviewed', analyst_note TEXT NOT NULL DEFAULT '', feedback_reason TEXT NOT NULL DEFAULT '',
              bundle_id TEXT NOT NULL DEFAULT '', first_observed_at TEXT, last_observed_at TEXT, seen_count INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              UNIQUE(analysis_id,candidate_fingerprint), FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS authentication_boundaries (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, boundary TEXT NOT NULL,
              confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,endpoint)
            );
            CREATE TABLE IF NOT EXISTS response_shape_fingerprints (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, status_code INTEGER,
              shape_hash TEXT NOT NULL, keys_json TEXT NOT NULL DEFAULT '[]', types_json TEXT NOT NULL DEFAULT '{}',
              sensitive_keys_json TEXT NOT NULL DEFAULT '[]', confidence INTEGER NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,endpoint,shape_hash)
            );
            CREATE TABLE IF NOT EXISTS semantic_js_units (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL,
              unit_type TEXT NOT NULL, unit_key TEXT NOT NULL, value_json TEXT NOT NULL DEFAULT '{}', confidence INTEGER NOT NULL,
              created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,js_url,unit_type,unit_key)
            );
            CREATE TABLE IF NOT EXISTS feature_flags (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, run_id TEXT NOT NULL, js_url TEXT NOT NULL,
              flag_name TEXT NOT NULL, observed_value TEXT NOT NULL, confidence INTEGER NOT NULL,
              related_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,js_url,flag_name)
            );
            CREATE TABLE IF NOT EXISTS endpoint_contracts (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, source_run_id TEXT NOT NULL, alert_id INTEGER NOT NULL,
              endpoint TEXT NOT NULL, method TEXT NOT NULL, input_fields_json TEXT NOT NULL DEFAULT '{}', output_fields_json TEXT NOT NULL DEFAULT '[]',
              auth_boundary TEXT NOT NULL DEFAULT 'unknown', object_relations_json TEXT NOT NULL DEFAULT '[]', confidence INTEGER NOT NULL,
              created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,alert_id)
            );
            CREATE TABLE IF NOT EXISTS parameter_relationships (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, parent_parameter TEXT NOT NULL,
              child_parameter TEXT NOT NULL, relation TEXT NOT NULL, confidence INTEGER NOT NULL,
              evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,endpoint,parent_parameter,child_parameter,relation)
            );
            CREATE TABLE IF NOT EXISTS candidate_bundles (
              bundle_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, target TEXT NOT NULL, bundle_key TEXT NOT NULL,
              title TEXT NOT NULL, summary TEXT NOT NULL, primary_family TEXT NOT NULL, members_json TEXT NOT NULL DEFAULT '[]',
              priority_score INTEGER NOT NULL, created_at TEXT NOT NULL, UNIQUE(analysis_id,bundle_key)
            );
            CREATE TABLE IF NOT EXISTS candidate_feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_fingerprint TEXT NOT NULL, candidate_id TEXT NOT NULL,
              analysis_id TEXT NOT NULL, decision TEXT NOT NULL, reason_code TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
              actor TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidate_gold_labels (
              id INTEGER PRIMARY KEY AUTOINCREMENT, source_run_id TEXT NOT NULL, target TEXT NOT NULL,
              candidate_fingerprint TEXT NOT NULL, expected_family TEXT NOT NULL, label TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidate_evaluations (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, profile TEXT NOT NULL,
              metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS behavioral_observations (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, context TEXT NOT NULL,
              auth_state TEXT NOT NULL DEFAULT 'unknown', status_code INTEGER, shape_hash TEXT NOT NULL DEFAULT '',
              headers_json TEXT NOT NULL DEFAULT '{}', source_ref TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL,
              created_at TEXT NOT NULL, PRIMARY KEY(analysis_id,target,endpoint,context,source_ref)
            );
            CREATE TABLE IF NOT EXISTS authentication_boundary_diffs (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, previous_analysis_id TEXT NOT NULL,
              previous_boundary TEXT NOT NULL, current_boundary TEXT NOT NULL, transition TEXT NOT NULL, confidence INTEGER NOT NULL,
              severity TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,endpoint,previous_analysis_id)
            );
            CREATE TABLE IF NOT EXISTS response_shape_diffs (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL, previous_analysis_id TEXT NOT NULL,
              previous_shape_hash TEXT NOT NULL, current_shape_hash TEXT NOT NULL, previous_status_code INTEGER, current_status_code INTEGER,
              added_keys_json TEXT NOT NULL DEFAULT '[]', removed_keys_json TEXT NOT NULL DEFAULT '[]',
              type_changes_json TEXT NOT NULL DEFAULT '[]', sensitive_added_json TEXT NOT NULL DEFAULT '[]',
              transition TEXT NOT NULL, confidence INTEGER NOT NULL, severity TEXT NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,endpoint,previous_analysis_id,current_shape_hash)
            );
            CREATE TABLE IF NOT EXISTS protocol_findings (
              finding_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, target TEXT NOT NULL, protocol TEXT NOT NULL,
              entity TEXT NOT NULL, kind TEXT NOT NULL, confidence INTEGER NOT NULL, severity TEXT NOT NULL,
              summary TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              UNIQUE(analysis_id,target,protocol,entity,kind)
            );
            CREATE TABLE IF NOT EXISTS identity_entities (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, entity_type TEXT NOT NULL, entity_value TEXT NOT NULL,
              confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,entity_type,entity_value)
            );
            CREATE TABLE IF NOT EXISTS identity_relations (
              analysis_id TEXT NOT NULL, target TEXT NOT NULL, source_type TEXT NOT NULL, source_value TEXT NOT NULL,
              relation TEXT NOT NULL, destination_type TEXT NOT NULL, destination_value TEXT NOT NULL, confidence INTEGER NOT NULL,
              evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(analysis_id,target,source_type,source_value,relation,destination_type,destination_value)
            );
            CREATE TABLE IF NOT EXISTS evidence_records (
              evidence_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, source_run_id TEXT NOT NULL, target TEXT NOT NULL,
              evidence_type TEXT NOT NULL, polarity TEXT NOT NULL, source_kind TEXT NOT NULL, source_tool TEXT NOT NULL DEFAULT '',
              source_artifact TEXT NOT NULL DEFAULT '', parser_name TEXT NOT NULL, parser_version TEXT NOT NULL,
              source_group TEXT NOT NULL, root_fingerprint TEXT NOT NULL, trust_score INTEGER NOT NULL, observation_quality INTEGER NOT NULL,
              directness TEXT NOT NULL, summary TEXT NOT NULL, raw_reference TEXT NOT NULL DEFAULT '', integrity_hash TEXT NOT NULL,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(analysis_id,root_fingerprint,polarity)
            );
            CREATE TABLE IF NOT EXISTS candidate_evidence_links (
              candidate_id TEXT NOT NULL, evidence_id TEXT NOT NULL, polarity TEXT NOT NULL, weight INTEGER NOT NULL,
              relation TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(candidate_id,evidence_id,polarity),
              FOREIGN KEY(candidate_id) REFERENCES bug_candidates(candidate_id) ON DELETE CASCADE,
              FOREIGN KEY(evidence_id) REFERENCES evidence_records(evidence_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS family_rankings (
              analysis_id TEXT NOT NULL, candidate_id TEXT NOT NULL, rank INTEGER NOT NULL, bug_family TEXT NOT NULL,
              score INTEGER NOT NULL, reason_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(candidate_id,rank), FOREIGN KEY(candidate_id) REFERENCES bug_candidates(candidate_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS candidate_reasoning_traces (
              candidate_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, trace_json TEXT NOT NULL DEFAULT '{}',
              engine_version TEXT NOT NULL, rule_version TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(candidate_id) REFERENCES bug_candidates(candidate_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS shadow_rule_results (
              analysis_id TEXT NOT NULL, candidate_id TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version TEXT NOT NULL,
              matched INTEGER NOT NULL, confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(candidate_id,rule_id,rule_version), FOREIGN KEY(candidate_id) REFERENCES bug_candidates(candidate_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS family_calibration (
              target TEXT NOT NULL, bug_family TEXT NOT NULL, sample_count INTEGER NOT NULL, positive_count INTEGER NOT NULL,
              negative_count INTEGER NOT NULL, average_predicted REAL NOT NULL, observed_rate REAL NOT NULL, calibration_gap REAL NOT NULL,
              status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(target,bug_family)
            );
            CREATE TABLE IF NOT EXISTS reasoning_evaluations (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reasoning_regression_gates (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, baseline_analysis_id TEXT NOT NULL DEFAULT '',
              passed INTEGER NOT NULL, checks_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS engine_quality_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL, target TEXT NOT NULL DEFAULT '*',
              health_score INTEGER NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rule_governance (
              rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, bug_family TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'draft',
              owner TEXT NOT NULL DEFAULT 'core', description TEXT NOT NULL DEFAULT '', known_noise_json TEXT NOT NULL DEFAULT '[]',
              activation_metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              PRIMARY KEY(rule_id,rule_version)
            );
            CREATE TABLE IF NOT EXISTS rule_noise_budgets (
              target TEXT NOT NULL DEFAULT '*', profile TEXT NOT NULL, maximum_candidates INTEGER NOT NULL,
              maximum_noise_rate REAL NOT NULL DEFAULT 0.5, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              PRIMARY KEY(target,profile)
            );
            CREATE TABLE IF NOT EXISTS target_learning_profiles (
              target TEXT PRIMARY KEY, baseline_json TEXT NOT NULL DEFAULT '{}', known_noise_json TEXT NOT NULL DEFAULT '[]',
              confidence INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_cases (
              case_id TEXT PRIMARY KEY, case_key TEXT NOT NULL, analysis_id TEXT NOT NULL, source_run_id TEXT NOT NULL, target TEXT NOT NULL,
              title TEXT NOT NULL, summary TEXT NOT NULL, primary_family TEXT NOT NULL, priority_score INTEGER NOT NULL DEFAULT 0,
              state TEXT NOT NULL DEFAULT 'new', assigned_to TEXT NOT NULL DEFAULT '', scope_status TEXT NOT NULL DEFAULT 'unknown',
              report_readiness INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(target,case_key)
            );
            CREATE TABLE IF NOT EXISTS security_case_members (
              case_id TEXT NOT NULL, member_type TEXT NOT NULL, member_id TEXT NOT NULL, relation TEXT NOT NULL,
              metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, PRIMARY KEY(case_id,member_type,member_id,relation),
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_case_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'system',
              details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_stories (
              story_id TEXT PRIMARY KEY, story_key TEXT NOT NULL, analysis_id TEXT NOT NULL, target TEXT NOT NULL, title TEXT NOT NULL,
              summary TEXT NOT NULL, priority_score INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'open',
              timeline_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(target,story_key)
            );
            CREATE TABLE IF NOT EXISTS validation_packages (
              package_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, package_json TEXT NOT NULL DEFAULT '{}', created_by TEXT NOT NULL,
              created_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS validation_plans (
              plan_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, target TEXT NOT NULL, level TEXT NOT NULL, status TEXT NOT NULL,
              plan_json TEXT NOT NULL DEFAULT '{}', approval_phrase_hash TEXT NOT NULL DEFAULT '', approved_by TEXT, approved_at TEXT,
              created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS validation_approvals (
              id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL, actor TEXT NOT NULL, confirmation_hash TEXT NOT NULL,
              created_at TEXT NOT NULL, FOREIGN KEY(plan_id) REFERENCES validation_plans(plan_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS validation_runs (
              run_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, case_id TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
              result TEXT NOT NULL DEFAULT '', summary_json TEXT NOT NULL DEFAULT '{}', started_at TEXT NOT NULL, finished_at TEXT,
              executed_by TEXT NOT NULL, FOREIGN KEY(plan_id) REFERENCES validation_plans(plan_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS validation_observations (
              run_id TEXT NOT NULL, sequence INTEGER NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, status_code INTEGER,
              observation_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, PRIMARY KEY(run_id,sequence),
              FOREIGN KEY(run_id) REFERENCES validation_runs(run_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS validation_feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, case_id TEXT NOT NULL, decision TEXT NOT NULL,
              reason_code TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(run_id) REFERENCES validation_runs(run_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS imported_http_evidence (
              observation_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, target TEXT NOT NULL, source_type TEXT NOT NULL,
              source_file TEXT NOT NULL, observation_json TEXT NOT NULL DEFAULT '{}', imported_by TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS report_drafts (
              draft_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, title TEXT NOT NULL, body_json TEXT NOT NULL DEFAULT '{}',
              status TEXT NOT NULL DEFAULT 'draft', readiness_score INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS run_completeness (
              run_id TEXT PRIMARY KEY, score INTEGER NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS scope_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, policy_hash TEXT NOT NULL, scope_json TEXT NOT NULL DEFAULT '{}',
              authorization_status TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schedule_policies (
              target TEXT PRIMARY KEY, cadence TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, max_runtime_minutes INTEGER NOT NULL DEFAULT 120,
              request_budget INTEGER NOT NULL DEFAULT 10000, quiet_hours TEXT NOT NULL DEFAULT '', last_run_at TEXT, next_run_at TEXT,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_policies (
              target TEXT NOT NULL DEFAULT '*', event_type TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'digest', minimum_score INTEGER NOT NULL DEFAULT 70,
              enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(target,event_type)
            );
            CREATE TABLE IF NOT EXISTS storage_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incremental_checkpoints (
              analysis_id TEXT PRIMARY KEY, source_run_id TEXT NOT NULL, target TEXT NOT NULL, fingerprint TEXT NOT NULL,
              metrics_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incremental_reasoning_cache (
              candidate_fingerprint TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, rule_version TEXT NOT NULL,
              result_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL,
              PRIMARY KEY(candidate_fingerprint,evidence_fingerprint,rule_version)
            );
            CREATE TABLE IF NOT EXISTS plugin_health_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT, plugin_name TEXT NOT NULL, version TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
              details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS validation_intelligence (
              validation_run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, overall_confidence INTEGER NOT NULL DEFAULT 0,
              test_reliability INTEGER NOT NULL DEFAULT 0, context_coverage INTEGER NOT NULL DEFAULT 0,
              response_comparability INTEGER NOT NULL DEFAULT 0, identity_confidence INTEGER NOT NULL DEFAULT 0,
              scope_confidence INTEGER NOT NULL DEFAULT 0, freshness INTEGER NOT NULL DEFAULT 0,
              baseline_delta_json TEXT NOT NULL DEFAULT '{}', limitations_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              FOREIGN KEY(validation_run_id) REFERENCES validation_runs(run_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS revalidation_policies (
              case_id TEXT PRIMARY KEY, trigger TEXT NOT NULL, interval_days INTEGER NOT NULL DEFAULT 7, enabled INTEGER NOT NULL DEFAULT 1,
              last_run_at TEXT, next_due_at TEXT, created_by TEXT NOT NULL DEFAULT 'system', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS data_quality_snapshots (
              run_id TEXT NOT NULL, target TEXT NOT NULL DEFAULT '*', score INTEGER NOT NULL DEFAULT 0,
              metrics_json TEXT NOT NULL DEFAULT '{}', blind_spots_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              PRIMARY KEY(run_id,target), FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS review_rankings (
              case_id TEXT PRIMARY KEY, review_value INTEGER NOT NULL DEFAULT 0, analyst_effort INTEGER NOT NULL DEFAULT 0,
              information_gain INTEGER NOT NULL DEFAULT 0, required_contexts_json TEXT NOT NULL DEFAULT '[]',
              explanation_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS burp_roundtrip_packages (
              package_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, target TEXT NOT NULL, export_path TEXT NOT NULL, sha256 TEXT NOT NULL,
              package_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'exported', created_by TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS burp_roundtrip_results (
              result_id TEXT PRIMARY KEY, package_id TEXT NOT NULL, case_id TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}',
              decision TEXT NOT NULL, reason_code TEXT NOT NULL, imported_by TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(package_id) REFERENCES burp_roundtrip_packages(package_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS story_correlation_links (
              story_id TEXT NOT NULL, member_type TEXT NOT NULL, member_id TEXT NOT NULL, relation TEXT NOT NULL,
              metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
              PRIMARY KEY(story_id,member_type,member_id,relation), FOREIGN KEY(story_id) REFERENCES security_stories(story_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS schedule_jobs (
              target TEXT PRIMARY KEY, label TEXT NOT NULL, generated_path TEXT NOT NULL, applied_path TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'generated', last_error TEXT NOT NULL DEFAULT '', last_synced_at TEXT,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_events (
              event_id TEXT PRIMARY KEY, target TEXT NOT NULL DEFAULT '*', event_type TEXT NOT NULL, mode TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0,
              fingerprint TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'queued',
              occurrences INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, delivered_at TEXT
            );
            CREATE TABLE IF NOT EXISTS notification_deliveries (
              id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, channel TEXT NOT NULL, status TEXT NOT NULL,
              error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, FOREIGN KEY(event_id) REFERENCES notification_events(event_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS retention_policies (
              category TEXT PRIMARY KEY, retention_days INTEGER NOT NULL DEFAULT 90, keep_count INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1, protected INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS retention_previews (
              preview_id TEXT PRIMARY KEY, files_count INTEGER NOT NULL DEFAULT 0, bytes_count INTEGER NOT NULL DEFAULT 0,
              protected_count INTEGER NOT NULL DEFAULT 0, preview_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS retention_executions (
              execution_id TEXT PRIMARY KEY, preview_id TEXT NOT NULL, deleted_count INTEGER NOT NULL DEFAULT 0,
              freed_bytes INTEGER NOT NULL DEFAULT 0, errors_json TEXT NOT NULL DEFAULT '[]', executed_by TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(preview_id) REFERENCES retention_previews(preview_id) ON DELETE RESTRICT
            );
            CREATE TABLE IF NOT EXISTS performance_samples (
              id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, name TEXT NOT NULL, duration_ms REAL NOT NULL,
              cache_hit INTEGER NOT NULL DEFAULT 0, details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS target_template_applications (
              application_id TEXT PRIMARY KEY, target TEXT NOT NULL, template_id TEXT NOT NULL, template_json TEXT NOT NULL DEFAULT '{}',
              applied_by TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_quality_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, draft_id TEXT NOT NULL, case_id TEXT NOT NULL, quality_score INTEGER NOT NULL DEFAULT 0,
              checks_json TEXT NOT NULL DEFAULT '[]', missing_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              FOREIGN KEY(draft_id) REFERENCES report_drafts(draft_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_posture_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, score INTEGER NOT NULL DEFAULT 0, checks_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_integrity (
              audit_id INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL DEFAULT '', event_hash TEXT NOT NULL, event_json TEXT NOT NULL,
              created_at TEXT NOT NULL, FOREIGN KEY(audit_id) REFERENCES audit_log(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS evidence_gap_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, coverage INTEGER NOT NULL DEFAULT 0,
              requirements_json TEXT NOT NULL DEFAULT '[]', next_actions_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS case_autopilot_tasks (
              task_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, task_type TEXT NOT NULL, title TEXT NOT NULL, rank INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'open', details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS auth_context_profiles (
              target TEXT NOT NULL, context_id TEXT NOT NULL, label TEXT NOT NULL, auth_state TEXT NOT NULL DEFAULT 'unknown',
              endpoint_count INTEGER NOT NULL DEFAULT 0, response_shape_count INTEGER NOT NULL DEFAULT 0, confidence INTEGER NOT NULL DEFAULT 0,
              sources_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL, PRIMARY KEY(target,context_id)
            );
            CREATE TABLE IF NOT EXISTS differential_findings (
              diff_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, target TEXT NOT NULL, endpoint TEXT NOT NULL DEFAULT '', diff_kind TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT 'info', details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recon_coverage_snapshots (
              run_id TEXT NOT NULL, target TEXT NOT NULL, overall INTEGER NOT NULL DEFAULT 0, components_json TEXT NOT NULL DEFAULT '{}',
              blind_spots_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, PRIMARY KEY(run_id,target),
              FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS change_intelligence_snapshots (
              run_id TEXT NOT NULL, target TEXT NOT NULL, previous_run_id TEXT NOT NULL DEFAULT '', summary_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL, PRIMARY KEY(run_id,target),
              FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS target_memory (
              target TEXT PRIMARY KEY, memory_json TEXT NOT NULL DEFAULT '{}', confidence INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS false_positive_learning (
              target TEXT NOT NULL, bug_family TEXT NOT NULL, total INTEGER NOT NULL DEFAULT 0, confirmed INTEGER NOT NULL DEFAULT 0,
              rejected INTEGER NOT NULL DEFAULT 0, needs_more INTEGER NOT NULL DEFAULT 0, precision REAL NOT NULL DEFAULT 0,
              recommendation TEXT NOT NULL DEFAULT 'keep', updated_at TEXT NOT NULL, PRIMARY KEY(target,bug_family)
            );
            CREATE TABLE IF NOT EXISTS smart_recon_plans (
              plan_id TEXT PRIMARY KEY, target TEXT NOT NULL, plan_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'proposed', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_claims (
              claim_id TEXT PRIMARY KEY, draft_id TEXT NOT NULL, case_id TEXT NOT NULL, claim TEXT NOT NULL, supported INTEGER NOT NULL DEFAULT 0,
              evidence_refs_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
              FOREIGN KEY(draft_id) REFERENCES report_drafts(draft_id) ON DELETE CASCADE,
              FOREIGN KEY(case_id) REFERENCES security_cases(case_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS browser_capture_events (
              event_id TEXT PRIMARY KEY, target TEXT NOT NULL, context_label TEXT NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET',
              status_code INTEGER, content_type TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}', source_file TEXT NOT NULL DEFAULT '',
              imported_by TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operator_diagnostics (
              diag_id TEXT PRIMARY KEY, overall TEXT NOT NULL, checks_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS error_events (
              error_id TEXT PRIMARY KEY, component TEXT NOT NULL, error_code TEXT NOT NULL, summary TEXT NOT NULL, safe_details_json TEXT NOT NULL DEFAULT '{}',
              resolved INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS recovery_actions (
              action_id TEXT PRIMARY KEY, action_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'preview', details_json TEXT NOT NULL DEFAULT '{}',
              created_by TEXT NOT NULL DEFAULT 'system', created_at TEXT NOT NULL, executed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(target,last_seen);
            CREATE INDEX IF NOT EXISTS idx_urls_last_seen ON urls(target,last_seen);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status,severity,last_seen);
            CREATE INDEX IF NOT EXISTS idx_stage_status ON stage_runs(status,heartbeat_at);
            CREATE INDEX IF NOT EXISTS idx_edges_source ON asset_edges(target,source_type,source_value);
            CREATE INDEX IF NOT EXISTS idx_edges_destination ON asset_edges(target,destination_type,destination_value);
            CREATE INDEX IF NOT EXISTS idx_notes_entity ON investigation_notes(target,entity_type,entity_value);
            CREATE INDEX IF NOT EXISTS idx_tags_entity ON entity_tags(target,entity_type,entity_value);
            CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_history(alert_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_js_diffs_target ON js_diffs(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_endpoint_category ON endpoint_intelligence(target,primary_category,confidence);
            CREATE INDEX IF NOT EXISTS idx_technology_confidence ON technology_observations(target,technology,confidence);
            CREATE INDEX IF NOT EXISTS idx_work_items_status ON work_items(run_id,target,stage,status);
            CREATE INDEX IF NOT EXISTS idx_ignore_rules_type ON ignore_rules(target,rule_type,enabled);
            CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON change_incidents(target,status,last_seen);
            CREATE INDEX IF NOT EXISTS idx_lifecycle_state ON asset_lifecycle(target,state,last_seen);
            CREATE INDEX IF NOT EXISTS idx_endpoint_validation ON endpoint_validations(target,reachable,status_code);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at,action);
            CREATE INDEX IF NOT EXISTS idx_bug_candidates_analysis ON bug_candidates(analysis_id,priority_score,candidate_state);
            CREATE INDEX IF NOT EXISTS idx_bug_candidates_target ON bug_candidates(target,bug_family,candidate_state);
            CREATE INDEX IF NOT EXISTS idx_bug_candidates_alert ON bug_candidates(alert_id,analysis_id);
            CREATE INDEX IF NOT EXISTS idx_bug_candidates_fingerprint ON bug_candidates(candidate_fingerprint,updated_at);
            CREATE INDEX IF NOT EXISTS idx_candidate_feedback_fingerprint ON candidate_feedback(candidate_fingerprint,created_at);
            CREATE INDEX IF NOT EXISTS idx_semantic_units_analysis ON semantic_js_units(analysis_id,unit_type,confidence);
            CREATE INDEX IF NOT EXISTS idx_feature_flags_analysis ON feature_flags(analysis_id,target,confidence);
            CREATE INDEX IF NOT EXISTS idx_candidate_bundles_analysis ON candidate_bundles(analysis_id,priority_score);
            CREATE INDEX IF NOT EXISTS idx_behavioral_observations_analysis ON behavioral_observations(analysis_id,target,endpoint,context);
            CREATE INDEX IF NOT EXISTS idx_boundary_diffs_analysis ON authentication_boundary_diffs(analysis_id,severity,confidence);
            CREATE INDEX IF NOT EXISTS idx_shape_diffs_analysis ON response_shape_diffs(analysis_id,severity,confidence);
            CREATE INDEX IF NOT EXISTS idx_protocol_findings_analysis ON protocol_findings(analysis_id,protocol,severity,confidence);
            CREATE INDEX IF NOT EXISTS idx_identity_relations_analysis ON identity_relations(analysis_id,target,source_type,relation);
            CREATE INDEX IF NOT EXISTS idx_evidence_analysis ON evidence_records(analysis_id,target,polarity,trust_score);
            CREATE INDEX IF NOT EXISTS idx_evidence_root ON evidence_records(root_fingerprint,source_kind);
            CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate ON candidate_evidence_links(candidate_id,polarity);
            CREATE INDEX IF NOT EXISTS idx_family_rankings_analysis ON family_rankings(analysis_id,bug_family,score);
            CREATE INDEX IF NOT EXISTS idx_shadow_rules_analysis ON shadow_rule_results(analysis_id,rule_id,matched);
            CREATE INDEX IF NOT EXISTS idx_reasoning_evaluations_analysis ON reasoning_evaluations(analysis_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_reasoning_regression_analysis ON reasoning_regression_gates(analysis_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_runs_status_started ON runs(status,started_at);
            CREATE INDEX IF NOT EXISTS idx_run_targets_status_started ON run_targets(status,started_at);
            CREATE INDEX IF NOT EXISTS idx_analysis_runs_status_finished ON analysis_runs(status,finished_at,source_run_id);
            CREATE INDEX IF NOT EXISTS idx_work_items_status_heartbeat ON work_items(status,heartbeat_at,run_id);
            CREATE INDEX IF NOT EXISTS idx_backup_catalog_created ON backup_catalog(created_at);
            CREATE INDEX IF NOT EXISTS idx_engine_quality_analysis ON engine_quality_snapshots(analysis_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_rule_governance_state ON rule_governance(state,bug_family,updated_at);
            CREATE INDEX IF NOT EXISTS idx_security_cases_queue ON security_cases(state,priority_score,updated_at);
            CREATE INDEX IF NOT EXISTS idx_security_cases_target ON security_cases(target,state,updated_at);
            CREATE INDEX IF NOT EXISTS idx_case_members_case ON security_case_members(case_id,member_type);
            CREATE INDEX IF NOT EXISTS idx_case_events_case ON security_case_events(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_security_stories_queue ON security_stories(status,priority_score,updated_at);
            CREATE INDEX IF NOT EXISTS idx_scope_snapshots_target ON scope_snapshots(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_storage_snapshots_created ON storage_snapshots(created_at);
            CREATE INDEX IF NOT EXISTS idx_plugin_health_name ON plugin_health_history(plugin_name,created_at);
            CREATE INDEX IF NOT EXISTS idx_reasoning_cache_updated ON incremental_reasoning_cache(updated_at);
            CREATE INDEX IF NOT EXISTS idx_validation_plans_case ON validation_plans(case_id,status,updated_at);
            CREATE INDEX IF NOT EXISTS idx_validation_runs_case ON validation_runs(case_id,started_at);
            CREATE INDEX IF NOT EXISTS idx_validation_runs_plan ON validation_runs(plan_id,started_at);
            CREATE INDEX IF NOT EXISTS idx_validation_feedback_case ON validation_feedback(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_imported_http_case ON imported_http_evidence(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_validation_intelligence_case ON validation_intelligence(case_id,overall_confidence,created_at);
            CREATE INDEX IF NOT EXISTS idx_revalidation_due ON revalidation_policies(enabled,next_due_at);
            CREATE INDEX IF NOT EXISTS idx_data_quality_target ON data_quality_snapshots(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_review_rankings_value ON review_rankings(review_value,analyst_effort,updated_at);
            CREATE INDEX IF NOT EXISTS idx_burp_roundtrip_case ON burp_roundtrip_packages(case_id,status,created_at);
            CREATE INDEX IF NOT EXISTS idx_story_correlation_member ON story_correlation_links(member_type,member_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_fingerprint_time ON notification_events(fingerprint,created_at);
            CREATE INDEX IF NOT EXISTS idx_notification_queue ON notification_events(status,mode,score,created_at);
            CREATE INDEX IF NOT EXISTS idx_performance_duration ON performance_samples(duration_ms,created_at);
            CREATE INDEX IF NOT EXISTS idx_report_quality_case ON report_quality_snapshots(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_evidence_gap_case ON evidence_gap_snapshots(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_autopilot_case ON case_autopilot_tasks(case_id,status,rank);
            CREATE INDEX IF NOT EXISTS idx_auth_context_target ON auth_context_profiles(target,confidence,updated_at);
            CREATE INDEX IF NOT EXISTS idx_diff_findings_target ON differential_findings(target,confidence,created_at);
            CREATE INDEX IF NOT EXISTS idx_recon_coverage_target ON recon_coverage_snapshots(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_change_intelligence_target ON change_intelligence_snapshots(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_fp_learning_precision ON false_positive_learning(precision,updated_at);
            CREATE INDEX IF NOT EXISTS idx_smart_recon_target ON smart_recon_plans(target,created_at);
            CREATE INDEX IF NOT EXISTS idx_report_claims_case ON report_claims(case_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_browser_capture_target ON browser_capture_events(target,context_label,created_at);
            CREATE INDEX IF NOT EXISTS idx_error_events_created ON error_events(resolved,created_at);
            """
        )
        # Additive migrations for databases created by earlier 2.x previews.
        existing_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(fingerprints)")}
        for column, declaration in {
            "tls_issuer": "TEXT",
            "tls_expiry": "TEXT",
            "tls_sans_json": "TEXT NOT NULL DEFAULT '[]'",
            "tls_serial": "TEXT",
            "screenshot_hash": "TEXT",
        }.items():
            if column not in existing_columns:
                self.conn.execute(f"ALTER TABLE fingerprints ADD COLUMN {column} {declaration}")
        alert_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(alerts)")}
        for column, declaration in {
            "priority": "TEXT NOT NULL DEFAULT 'normal'",
            "assignee": "TEXT NOT NULL DEFAULT ''",
            "workflow_note": "TEXT NOT NULL DEFAULT ''",
            "updated_at": "TEXT",
        }.items():
            if column not in alert_columns:
                self.conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {declaration}")
        self.conn.execute("UPDATE alerts SET updated_at=COALESCE(updated_at,last_seen)")

        candidate_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(bug_candidates)")}
        for column, declaration in {
            "observation_quality": "INTEGER NOT NULL DEFAULT 50",
            "investigation_value": "INTEGER NOT NULL DEFAULT 0",
            "novelty_score": "INTEGER NOT NULL DEFAULT 100",
            "historical_noise": "INTEGER NOT NULL DEFAULT 0",
            "lifecycle_state": "TEXT NOT NULL DEFAULT 'observed'",
            "analysis_profile": "TEXT NOT NULL DEFAULT 'balanced'",
            "evidence_groups_json": "TEXT NOT NULL DEFAULT '{}'",
            "quality_explanation_json": "TEXT NOT NULL DEFAULT '{}'",
            "feedback_reason": "TEXT NOT NULL DEFAULT ''",
            "bundle_id": "TEXT NOT NULL DEFAULT ''",
            "first_observed_at": "TEXT",
            "last_observed_at": "TEXT",
            "seen_count": "INTEGER NOT NULL DEFAULT 1",
            "calibrated_likelihood": "INTEGER NOT NULL DEFAULT 0",
            "exploitability_confidence": "INTEGER NOT NULL DEFAULT 0",
            "evidence_coverage": "INTEGER NOT NULL DEFAULT 0",
            "precondition_state": "TEXT NOT NULL DEFAULT 'unknown'",
            "reachability_state": "TEXT NOT NULL DEFAULT 'unknown'",
            "unknowns_json": "TEXT NOT NULL DEFAULT '[]'",
            "alternative_families_json": "TEXT NOT NULL DEFAULT '[]'",
            "reasoning_trace_json": "TEXT NOT NULL DEFAULT '{}'",
        }.items():
            if column not in candidate_columns:
                self.conn.execute(f"ALTER TABLE bug_candidates ADD COLUMN {column} {declaration}")
        self.conn.execute("UPDATE bug_candidates SET investigation_value=CASE WHEN investigation_value=0 THEN priority_score ELSE investigation_value END")
        self.conn.execute("UPDATE bug_candidates SET first_observed_at=COALESCE(first_observed_at,created_at),last_observed_at=COALESCE(last_observed_at,updated_at)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_bug_candidates_quality ON bug_candidates(analysis_id,investigation_value,observation_quality)")
        self.conn.execute("UPDATE bug_candidates SET calibrated_likelihood=CASE WHEN calibrated_likelihood=0 THEN likelihood_score ELSE calibrated_likelihood END")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_bug_candidates_reasoning ON bug_candidates(analysis_id,calibrated_likelihood,exploitability_confidence,evidence_coverage)")

        case_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(security_cases)")}
        for column, declaration in {
            "validation_state": "TEXT NOT NULL DEFAULT 'not_started'",
            "validation_summary": "TEXT NOT NULL DEFAULT ''",
            "last_validation_at": "TEXT",
        }.items():
            if column not in case_columns:
                self.conn.execute(f"ALTER TABLE security_cases ADD COLUMN {column} {declaration}")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_security_cases_validation ON security_cases(validation_state,last_validation_at)")
        current_case_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(security_cases)")}
        for column, declaration in {
            "evidence_gap_score": "INTEGER NOT NULL DEFAULT 100",
            "autopilot_score": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if column not in current_case_columns:
                self.conn.execute(f"ALTER TABLE security_cases ADD COLUMN {column} {declaration}")
        for column, declaration in {
            "review_value": "INTEGER NOT NULL DEFAULT 0",
            "analyst_effort": "INTEGER NOT NULL DEFAULT 0",
            "information_gain": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if column not in {row[1] for row in self.conn.execute("PRAGMA table_info(security_cases)")}:
                self.conn.execute(f"ALTER TABLE security_cases ADD COLUMN {column} {declaration}")
        story_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(security_stories)")}
        if "correlation_json" not in story_columns:
            self.conn.execute("ALTER TABLE security_stories ADD COLUMN correlation_json TEXT NOT NULL DEFAULT '{}'")
        token_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(api_tokens)")}
        for column, declaration in {
            "scopes_json": "TEXT NOT NULL DEFAULT '[]'",
            "expires_at": "TEXT",
        }.items():
            if column not in token_columns:
                self.conn.execute(f"ALTER TABLE api_tokens ADD COLUMN {column} {declaration}")
        user_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(users)")}
        for column, declaration in {
            "last_login_at": "TEXT",
            "failed_login_count": "INTEGER NOT NULL DEFAULT 0",
            "locked_until": "TEXT",
        }.items():
            if column not in user_columns:
                self.conn.execute(f"ALTER TABLE users ADD COLUMN {column} {declaration}")

        self.conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    def one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(sql, params).fetchall())

    def audit(self, action: str, *, actor: str = "system", target: str = "", entity_type: str = "", entity_value: str = "", details: Mapping[str, Any] | None = None) -> None:
        created = utc_now()
        record = {"created_at": created, "actor": actor, "action": action, "target": target, "entity_type": entity_type, "entity_value": entity_value, "details": dict(details or {})}
        cursor = self.execute(
            "INSERT INTO audit_log(actor,action,target,entity_type,entity_value,details_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (actor, action, target or None, entity_type or None, entity_value or None, json_dumps(details or {}), created),
        )
        audit_id = int(cursor.lastrowid or 0)
        event_json = json_dumps(record)
        previous_row = self.one("SELECT event_hash FROM audit_integrity ORDER BY audit_id DESC LIMIT 1")
        previous_hash = str(previous_row["event_hash"]) if previous_row else ""
        event_hash = sha256_text(previous_hash + "|" + event_json)
        self.execute(
            "INSERT OR REPLACE INTO audit_integrity(audit_id,previous_hash,event_hash,event_json,created_at) VALUES(?,?,?,?,?)",
            (audit_id, previous_hash, event_hash, event_json, created),
        )
        audit_path = self.path.parent / "audit.jsonl"
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(event_json + "\n")

    def budget_init(self, run_id: str, target: str, limits: Mapping[str, int]) -> None:
        now = utc_now()
        for metric, limit_value in limits.items():
            self.execute(
                "INSERT INTO run_budgets(run_id,target,metric,used,limit_value,updated_at) VALUES(?,?,?,0,?,?) "
                "ON CONFLICT(run_id,target,metric) DO UPDATE SET limit_value=excluded.limit_value,updated_at=excluded.updated_at",
                (run_id, target, metric, int(limit_value), now),
            )

    def budget_consume(self, run_id: str, target: str, metric: str, amount: int) -> tuple[int, int, bool]:
        amount = max(0, int(amount))
        with self.transaction():
            row = self.one("SELECT used,limit_value FROM run_budgets WHERE run_id=? AND target=? AND metric=?", (run_id,target,metric))
            if not row:
                return amount, 0, True
            used = int(row["used"]) + amount
            limit_value = int(row["limit_value"])
            self.execute("UPDATE run_budgets SET used=?,updated_at=? WHERE run_id=? AND target=? AND metric=?", (used,utc_now(),run_id,target,metric))
        return used, limit_value, used <= limit_value

    def enqueue_work(self, run_id: str, target: str, stage: str, item_key: str, payload: Mapping[str, Any] | None = None) -> int:
        now = utc_now()
        self.execute(
            "INSERT INTO work_items(run_id,target,stage,item_key,payload_json,status,created_at) VALUES(?,?,?,?,?,'queued',?) "
            "ON CONFLICT(run_id,target,stage,item_key) DO NOTHING",
            (run_id,target,stage,item_key,json_dumps(payload or {}),now),
        )
        row = self.one("SELECT id FROM work_items WHERE run_id=? AND target=? AND stage=? AND item_key=?", (run_id,target,stage,item_key))
        return int(row["id"]) if row else 0

    def work_status(self, run_id: str, target: str, stage: str, item_key: str) -> str | None:
        row = self.one("SELECT status FROM work_items WHERE run_id=? AND target=? AND stage=? AND item_key=?", (run_id,target,stage,item_key))
        return str(row["status"]) if row else None

    def work_start(self, work_id: int, worker_id: str = "local") -> None:
        self.execute("UPDATE work_items SET status='running',attempts=attempts+1,worker_id=?,started_at=?,heartbeat_at=?,error=NULL WHERE id=?", (worker_id,utc_now(),utc_now(),work_id))

    def work_finish(self, work_id: int, result: Mapping[str, Any] | None = None) -> None:
        self.execute("UPDATE work_items SET status='completed',result_json=?,finished_at=?,heartbeat_at=? WHERE id=?", (json_dumps(result or {}),utc_now(),utc_now(),work_id))

    def work_fail(self, work_id: int, error: str, retry: bool = True) -> None:
        self.execute("UPDATE work_items SET status=?,error=?,finished_at=?,heartbeat_at=? WHERE id=?", ('retry_pending' if retry else 'failed',error,utc_now(),utc_now(),work_id))

    def add_ignore_rule(self, target: str, rule_type: str, pattern: str, note: str = "") -> int:
        now=utc_now()
        cur=self.execute("INSERT INTO ignore_rules(target,rule_type,pattern,note,created_at,updated_at) VALUES(?,?,?,?,?,?)", (target or '*',rule_type,pattern,note,now,now))
        self.audit('ignore_rule_added', target=target, entity_type=rule_type, entity_value=pattern, details={'id':cur.lastrowid,'note':note})
        return int(cur.lastrowid)

    def ignore_match(self, target: str, rule_type: str, value: str) -> int | None:
        rows=self.all("SELECT id,pattern FROM ignore_rules WHERE enabled=1 AND rule_type IN (?, 'any') AND target IN (?, '*') ORDER BY id", (rule_type,target))
        for row in rows:
            try:
                if re.search(str(row['pattern']), value, re.IGNORECASE):
                    return int(row['id'])
            except re.error:
                continue
        return None

    def correlate_event(self, target: str, event_key: str, category: str, item: str, title: str, severity: str, risk_score: int, run_id: str, details: Mapping[str, Any] | None = None) -> int:
        host = normalize_host(urllib.parse.urlsplit(item).hostname or item.split('/',1)[0]) if '://' in item else normalize_host(item.split('/',1)[0])
        bucket = dt.datetime.now(UTC).strftime('%Y%m%d%H')
        correlation_key = sha256_text(json_dumps([host or item[:100], bucket]))[:32]
        now=utc_now()
        row=self.one("SELECT id,event_count,risk_score FROM change_incidents WHERE target=? AND correlation_key=?", (target,correlation_key))
        if row:
            incident_id=int(row['id'])
            self.execute("UPDATE change_incidents SET event_count=event_count+1,last_seen=?,last_run_id=?,risk_score=MAX(risk_score,?),severity=CASE WHEN ? > risk_score THEN ? ELSE severity END WHERE id=?", (now,run_id,risk_score,risk_score,severity,incident_id))
        else:
            cur=self.execute("INSERT INTO change_incidents(target,correlation_key,title,severity,risk_score,event_count,first_seen,last_seen,last_run_id,details_json) VALUES(?,?,?,?,?,1,?,?,?,?)", (target,correlation_key,title,severity,risk_score,now,now,run_id,json_dumps(details or {})))
            incident_id=int(cur.lastrowid)
        self.execute("INSERT OR IGNORE INTO incident_events(incident_id,event_key,category,item,created_at) VALUES(?,?,?,?,?)", (incident_id,event_key,category,item,now))
        return incident_id

    def refresh_asset_lifecycle(self, target: str, run_id: str) -> dict[str, int]:
        now=utc_now(); counts={'new':0,'active':0,'inactive':0,'reappeared':0}
        assets=self.all("SELECT host,first_seen,last_seen,last_run_id FROM assets WHERE target=?", (target,))
        seen={str(r['host']) for r in assets if str(r['last_run_id'] or '')==run_id}
        for row in assets:
            host=str(row['host']); prior=self.one("SELECT state,inactive_since FROM asset_lifecycle WHERE target=? AND host=?", (target,host))
            if host in seen:
                if not prior: state='new'; counts['new']+=1; reappeared=None; transitions=0
                elif str(prior['state']) in {'inactive','retired'}: state='reappeared'; counts['reappeared']+=1; reappeared=now; transitions=1
                else: state='active'; counts['active']+=1; reappeared=None; transitions=0
                self.execute("INSERT INTO asset_lifecycle(target,host,state,first_seen,last_seen,inactive_since,reappeared_at,transitions,last_run_id) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(target,host) DO UPDATE SET state=excluded.state,last_seen=excluded.last_seen,inactive_since=NULL,reappeared_at=COALESCE(excluded.reappeared_at,asset_lifecycle.reappeared_at),transitions=asset_lifecycle.transitions+?,last_run_id=excluded.last_run_id", (target,host,state,str(row['first_seen']),now,None,reappeared,transitions,run_id,transitions))
            elif prior and str(prior['state']) not in {'inactive','retired'}:
                self.execute("UPDATE asset_lifecycle SET state='inactive',inactive_since=?,transitions=transitions+1,last_run_id=? WHERE target=? AND host=?", (now,run_id,target,host)); counts['inactive']+=1
        return counts

    def create_run(self, target_selector: str | None, target_count: int, config_hash: str, resumed_from: str | None = None) -> str:
        run_id = f"{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.execute(
            "INSERT INTO runs(id,version,status,started_at,target_selector,target_count,resumed_from,config_hash) VALUES(?,?,?,?,?,?,?,?)",
            (run_id, APP_VERSION, "running", utc_now(), target_selector, target_count, resumed_from, config_hash),
        )
        return run_id

    def finish_run(self, run_id: str, status: str, error: str | None = None) -> None:
        self.execute(
            "UPDATE runs SET status=?,finished_at=?,error=? WHERE id=?",
            (status, utc_now(), error, run_id),
        )

    def create_run_target(self, run_id: str, policy: TargetPolicy, run_dir: Path, baseline: bool) -> None:
        self.execute(
            """
            INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,run_dir,baseline)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id,target) DO UPDATE SET status='running',current_stage=NULL,finished_at=NULL
            """,
            (run_id, policy.name, policy.policy_hash(), "running", None, utc_now(), str(run_dir), int(baseline)),
        )

    def finish_run_target(self, run_id: str, target: str, status: str) -> None:
        self.execute(
            "UPDATE run_targets SET status=?,finished_at=?,current_stage=NULL WHERE run_id=? AND target=?",
            (status, utc_now(), run_id, target),
        )

    def stage_begin(self, run_id: str, target: str, stage: str, attempt: int) -> None:
        now = utc_now()
        self.execute(
            """
            INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,heartbeat_at)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(run_id,target,stage) DO UPDATE SET
              status='running',attempt=excluded.attempt,started_at=excluded.started_at,
              finished_at=NULL,heartbeat_at=excluded.heartbeat_at,exit_code=NULL,error=NULL
            """,
            (run_id, target, stage, "running", attempt, now, now),
        )
        self.execute(
            "UPDATE run_targets SET current_stage=? WHERE run_id=? AND target=?",
            (stage, run_id, target),
        )

    def stage_heartbeat(self, run_id: str, target: str, stage: str) -> None:
        # Heartbeats are emitted by CommandRunner's watchdog thread.  A sqlite3
        # connection is thread-affine by default, so never reuse the main
        # Database connection here.  A short-lived WAL connection keeps this
        # update safe on Python 3.10+ (including Python 3.14) and avoids sharing
        # cursors or transaction state across threads.
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute(
                "UPDATE stage_runs SET heartbeat_at=? WHERE run_id=? AND target=? AND stage=?",
                (utc_now(), run_id, target, stage),
            )
        finally:
            conn.close()

    def stage_finish(
        self,
        run_id: str,
        target: str,
        stage: str,
        status: str,
        *,
        exit_code: int = 0,
        duration: float = 0,
        metrics: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.execute(
            """
            UPDATE stage_runs SET status=?,finished_at=?,heartbeat_at=?,exit_code=?,duration_seconds=?,metrics_json=?,error=?
            WHERE run_id=? AND target=? AND stage=?
            """,
            (status, utc_now(), utc_now(), exit_code, duration, json_dumps(metrics or {}), error, run_id, target, stage),
        )

    def stage_status(self, run_id: str, target: str, stage: str) -> str | None:
        row = self.one("SELECT status FROM stage_runs WHERE run_id=? AND target=? AND stage=?", (run_id, target, stage))
        return str(row["status"]) if row else None

    def target_has_history(self, target: str) -> bool:
        for table in ("assets", "urls", "js_files", "fingerprints"):
            row = self.one(f"SELECT 1 FROM {table} WHERE target=? LIMIT 1", (target,))
            if row:
                return True
        return False

    def upsert_asset(self, target: str, host: str, sources: Iterable[str], run_id: str, *, wildcard: bool = False, resolved: bool = False) -> bool:
        now = utc_now()
        row = self.one("SELECT sources_json FROM assets WHERE target=? AND host=?", (target, host))
        old_sources = set(safe_json_loads(row["sources_json"], [], expected_type=list)) if row else set()
        merged = sorted(old_sources | {str(x) for x in sources if x})
        source_weights = {"root": 100, "dns": 30, "http": 25, "subfinder": 22, "assetfinder": 18, "certificate": 20, "wayback": 10, "v1-import": 10}
        confidence = min(100, sum(source_weights.get(src.lower(), 15) for src in merged) + (20 if resolved else 0))
        self.execute(
            """
            INSERT INTO assets(target,host,sources_json,confidence,wildcard,resolved,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,host) DO UPDATE SET
              sources_json=excluded.sources_json,confidence=excluded.confidence,
              wildcard=MAX(assets.wildcard,excluded.wildcard),resolved=MAX(assets.resolved,excluded.resolved),
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id
            """,
            (target, host, json_dumps(merged), confidence, int(wildcard), int(resolved), now, now, run_id),
        )
        return row is None

    def mark_asset_resolved(self, target: str, host: str, run_id: str, resolved: bool = True) -> None:
        self.execute(
            "UPDATE assets SET resolved=?,last_seen=?,last_run_id=? WHERE target=? AND host=?",
            (int(resolved), utc_now(), run_id, target, host),
        )

    def upsert_dns(self, target: str, host: str, rrtype: str, value: str, run_id: str) -> bool:
        now = utc_now()
        row = self.one(
            "SELECT 1 FROM dns_records WHERE target=? AND host=? AND rrtype=? AND value=?",
            (target, host, rrtype, value),
        )
        self.execute(
            """
            INSERT INTO dns_records(target,host,rrtype,value,first_seen,last_seen,last_run_id,is_current)
            VALUES(?,?,?,?,?,?,?,1)
            ON CONFLICT(target,host,rrtype,value) DO UPDATE SET
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,is_current=1
            """,
            (target, host, rrtype, value, now, now, run_id),
        )
        return row is None

    def finalize_dns_current(self, target: str, run_id: str, rrtypes: Iterable[str] | None = None) -> None:
        types = sorted({str(x).upper() for x in (rrtypes or [])})
        if types:
            placeholders = ",".join("?" for _ in types)
            self.execute(
                f"UPDATE dns_records SET is_current=0 WHERE target=? AND rrtype IN ({placeholders}) AND COALESCE(last_run_id,'')<>?",
                (target, *types, run_id),
            )
        else:
            self.execute(
                "UPDATE dns_records SET is_current=0 WHERE target=? AND COALESCE(last_run_id,'')<>?",
                (target, run_id),
            )

    def upsert_url(self, target: str, url: str, kind: str, source: str, run_id: str) -> bool:
        now = utc_now()
        row = self.one("SELECT 1 FROM urls WHERE target=? AND url=?", (target, url))
        self.execute(
            """
            INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(target,url) DO UPDATE SET kind=excluded.kind,source=COALESCE(urls.source,excluded.source),last_seen=excluded.last_seen,last_run_id=excluded.last_run_id
            """,
            (target, url, kind, source, now, now, run_id),
        )
        return row is None

    def upsert_js(
        self,
        target: str,
        url: str,
        raw_hash: str,
        semantic_hash: str,
        blob_path: str,
        content_length: int,
        run_id: str,
        *,
        etag: str = "",
        last_modified: str = "",
        source_map_url: str = "",
    ) -> tuple[bool, bool, bool]:
        now = utc_now()
        row = self.one("SELECT raw_hash,semantic_hash FROM js_files WHERE target=? AND url=?", (target, url))
        is_new = row is None
        raw_changed = bool(row and row["raw_hash"] != raw_hash)
        semantic_changed = bool(row and row["semantic_hash"] != semantic_hash)
        self.execute(
            """
            INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,etag,last_modified,source_map_url,first_seen,last_seen,last_changed,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,url) DO UPDATE SET
              raw_hash=excluded.raw_hash,semantic_hash=excluded.semantic_hash,blob_path=excluded.blob_path,
              content_length=excluded.content_length,etag=excluded.etag,last_modified=excluded.last_modified,
              source_map_url=excluded.source_map_url,last_seen=excluded.last_seen,
              last_changed=CASE WHEN js_files.semantic_hash<>excluded.semantic_hash THEN excluded.last_seen ELSE js_files.last_changed END,
              last_run_id=excluded.last_run_id
            """,
            (
                target, url, raw_hash, semantic_hash, blob_path, content_length, etag, last_modified, source_map_url,
                now, now, now if semantic_changed else None, run_id,
            ),
        )
        return is_new, raw_changed, semantic_changed

    def upsert_js_indicator(self, target: str, js_url: str, kind: str, value: str, redacted: bool, run_id: str) -> bool:
        now = utc_now()
        row = self.one(
            "SELECT 1 FROM js_indicators WHERE target=? AND js_url=? AND kind=? AND value=?",
            (target, js_url, kind, value),
        )
        self.execute(
            """
            INSERT INTO js_indicators(target,js_url,kind,value,redacted,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(target,js_url,kind,value) DO UPDATE SET last_seen=excluded.last_seen,last_run_id=excluded.last_run_id
            """,
            (target, js_url, kind, value, int(redacted), now, now, run_id),
        )
        return row is None

    def upsert_fingerprint(self, target: str, url: str, record: Mapping[str, Any], fp_hash: str, run_id: str) -> tuple[bool, bool, dict[str, Any] | None]:
        now = utc_now()
        row = self.one("SELECT * FROM fingerprints WHERE target=? AND url=?", (target, url))
        is_new = row is None
        changed = bool(row and row["fingerprint_hash"] != fp_hash)
        old = dict(row) if row else None
        self.execute(
            """
            INSERT INTO fingerprints(
              target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,
              body_hash,favicon_hash,jarm,ip,cname,cdn,final_url,redirect_chain_json,http2,
              tls_issuer,tls_expiry,tls_sans_json,tls_serial,screenshot_path,screenshot_hash,
              first_seen,last_seen,last_changed,last_run_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,url) DO UPDATE SET
              fingerprint_hash=excluded.fingerprint_hash,status_code=excluded.status_code,title=excluded.title,
              webserver=excluded.webserver,technologies_json=excluded.technologies_json,content_type=excluded.content_type,
              content_length=excluded.content_length,body_hash=excluded.body_hash,favicon_hash=excluded.favicon_hash,
              jarm=excluded.jarm,ip=excluded.ip,cname=excluded.cname,cdn=excluded.cdn,final_url=excluded.final_url,
              redirect_chain_json=excluded.redirect_chain_json,http2=excluded.http2,
              tls_issuer=excluded.tls_issuer,tls_expiry=excluded.tls_expiry,tls_sans_json=excluded.tls_sans_json,
              tls_serial=excluded.tls_serial,screenshot_path=COALESCE(excluded.screenshot_path,fingerprints.screenshot_path),
              screenshot_hash=COALESCE(excluded.screenshot_hash,fingerprints.screenshot_hash),last_seen=excluded.last_seen,
              last_changed=CASE WHEN fingerprints.fingerprint_hash<>excluded.fingerprint_hash THEN excluded.last_seen ELSE fingerprints.last_changed END,
              last_run_id=excluded.last_run_id
            """,
            (
                target, url, fp_hash, record.get("status_code"), record.get("title", ""), record.get("webserver", ""),
                json_dumps(record.get("technologies", [])), record.get("content_type", ""), record.get("content_length", 0),
                record.get("body_hash", ""), record.get("favicon_hash", ""), record.get("jarm", ""), record.get("ip", ""),
                record.get("cname", ""), record.get("cdn", ""), record.get("final_url", url),
                json_dumps(record.get("redirect_chain", [])), int(bool(record.get("http2"))),
                record.get("tls_issuer", ""), record.get("tls_expiry", ""), json_dumps(record.get("tls_sans", [])),
                record.get("tls_serial", ""), record.get("screenshot_path"), record.get("screenshot_hash"),
                now, now, now if changed else None, run_id,
            ),
        )
        return is_new, changed, old

    def upsert_port(self, target: str, host: str, ip: str, port: int, protocol: str, run_id: str) -> bool:
        now = utc_now()
        row = self.one(
            "SELECT 1 FROM ports WHERE target=? AND host=? AND port=? AND protocol=?",
            (target, host, port, protocol),
        )
        self.execute(
            """
            INSERT INTO ports(target,host,ip,port,protocol,first_seen,last_seen,last_run_id,is_current)
            VALUES(?,?,?,?,?,?,?,?,1)
            ON CONFLICT(target,host,port,protocol) DO UPDATE SET ip=excluded.ip,last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,is_current=1
            """,
            (target, host, ip, port, protocol, now, now, run_id),
        )
        return row is None

    def finalize_ports_current(self, target: str, run_id: str) -> None:
        self.execute("UPDATE ports SET is_current=0 WHERE target=? AND COALESCE(last_run_id,'')<>?", (target, run_id))

    def upsert_finding(self, target: str, dedup_key: str, record: Mapping[str, Any], run_id: str) -> bool:
        now = utc_now()
        row = self.one("SELECT 1 FROM findings WHERE target=? AND dedup_key=?", (target, dedup_key))
        self.execute(
            """
            INSERT INTO findings(target,dedup_key,template_id,name,severity,matched_at,details_json,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,dedup_key) DO UPDATE SET last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,details_json=excluded.details_json
            """,
            (
                target, dedup_key, record.get("template_id", ""), record.get("name", ""), record.get("severity", "info"),
                record.get("matched_at", ""), json_dumps(record), now, now, run_id,
            ),
        )
        return row is None

    def upsert_alert(
        self,
        target: str,
        dedup_key: str,
        category: str,
        severity: str,
        risk_score: int,
        title: str,
        item: str,
        details: Mapping[str, Any],
        run_id: str,
    ) -> tuple[int, bool, sqlite3.Row | None]:
        now = utc_now()
        old = self.one("SELECT * FROM alerts WHERE target=? AND dedup_key=?", (target, dedup_key))
        self.execute(
            """
            INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id,updated_at)
            VALUES(?,?,?,?,?,?,?,?, 'new',1,?,?,?,?)
            ON CONFLICT(target,dedup_key) DO UPDATE SET
              severity=excluded.severity,risk_score=MAX(alerts.risk_score,excluded.risk_score),title=excluded.title,
              item=excluded.item,details_json=excluded.details_json,occurrences=alerts.occurrences+1,
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,updated_at=excluded.updated_at,
              status=CASE WHEN alerts.status='resolved' THEN 'new' ELSE alerts.status END
            """,
            (target, dedup_key, category, severity, risk_score, title, item, json_dumps(details), now, now, run_id, now),
        )
        row = self.one("SELECT id FROM alerts WHERE target=? AND dedup_key=?", (target, dedup_key))
        assert row is not None
        return int(row["id"]), old is None, old

    def mark_alert_notified(self, alert_id: int) -> None:
        self.execute("UPDATE alerts SET last_notified=? WHERE id=?", (utc_now(), alert_id))

    def set_alert_status(self, alert_id: int, status: str, note: str = "") -> None:
        allowed = {"new", "triaged", "acknowledged", "investigating", "interesting", "reported", "resolved", "ignored", "false_positive", "out_of_scope"}
        if status not in allowed:
            raise ReconError(f"Invalid alert status: {status}")
        row = self.one("SELECT status FROM alerts WHERE id=?", (alert_id,))
        if not row:
            raise ReconError(f"Alert not found: {alert_id}")
        old = str(row["status"] or "")
        now = utc_now()
        self.execute("UPDATE alerts SET status=?,updated_at=? WHERE id=?", (status, now, alert_id))
        if old != status or note.strip():
            self.execute(
                "INSERT INTO alert_history(alert_id,action,old_value,new_value,note,created_at) VALUES(?,?,?,?,?,?)",
                (alert_id, "status", old, status, note.strip()[:2000], now),
            )

    def update_alert_workflow(self, alert_id: int, *, priority: str | None = None, assignee: str | None = None, note: str | None = None) -> None:
        row = self.one("SELECT priority,assignee,workflow_note FROM alerts WHERE id=?", (alert_id,))
        if not row:
            raise ReconError(f"Alert not found: {alert_id}")
        allowed_priorities = {"low", "normal", "high", "urgent"}
        updates: list[str] = []
        params: list[Any] = []
        history: list[tuple[str, str, str, str]] = []
        if priority is not None:
            if priority not in allowed_priorities:
                raise ReconError(f"Invalid priority: {priority}")
            updates.append("priority=?"); params.append(priority)
            history.append(("priority", str(row["priority"] or "normal"), priority, ""))
        if assignee is not None:
            value = assignee.strip()[:200]
            updates.append("assignee=?"); params.append(value)
            history.append(("assignee", str(row["assignee"] or ""), value, ""))
        if note is not None:
            value = note.strip()[:5000]
            updates.append("workflow_note=?"); params.append(value)
            history.append(("workflow_note", str(row["workflow_note"] or ""), value, value))
        if not updates:
            return
        now = utc_now()
        updates.append("updated_at=?"); params.append(now); params.append(alert_id)
        self.execute(f"UPDATE alerts SET {','.join(updates)} WHERE id=?", params)
        for action, old_value, new_value, history_note in history:
            if old_value != new_value:
                self.execute(
                    "INSERT INTO alert_history(alert_id,action,old_value,new_value,note,created_at) VALUES(?,?,?,?,?,?)",
                    (alert_id, action, old_value, new_value, history_note, now),
                )

    def add_tag(self, target: str, entity_type: str, entity_value: str, tag: str) -> None:
        tag = re.sub(r"[^A-Za-z0-9_.:-]+", "-", tag.strip().lower()).strip("-")[:80]
        if not tag:
            raise ReconError("Tag cannot be empty")
        self.execute(
            "INSERT OR IGNORE INTO entity_tags(target,entity_type,entity_value,tag,created_at) VALUES(?,?,?,?,?)",
            (target, entity_type, entity_value, tag, utc_now()),
        )

    def remove_tag(self, target: str, entity_type: str, entity_value: str, tag: str) -> None:
        self.execute(
            "DELETE FROM entity_tags WHERE target=? AND entity_type=? AND entity_value=? AND tag=?",
            (target, entity_type, entity_value, tag),
        )

    def record_js_diff(
        self, run_id: str, target: str, js_url: str, old_raw_hash: str, new_raw_hash: str,
        old_semantic_hash: str, new_semantic_hash: str, summary: Mapping[str, Any], diff_text: str, diff_path: str,
    ) -> int:
        now = utc_now()
        self.execute(
            """
            INSERT INTO js_diffs(run_id,target,js_url,old_raw_hash,new_raw_hash,old_semantic_hash,new_semantic_hash,summary_json,diff_text,diff_path,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id,target,js_url) DO UPDATE SET
              old_raw_hash=excluded.old_raw_hash,new_raw_hash=excluded.new_raw_hash,
              old_semantic_hash=excluded.old_semantic_hash,new_semantic_hash=excluded.new_semantic_hash,
              summary_json=excluded.summary_json,diff_text=excluded.diff_text,diff_path=excluded.diff_path,created_at=excluded.created_at
            """,
            (run_id,target,js_url,old_raw_hash,new_raw_hash,old_semantic_hash,new_semantic_hash,json_dumps(summary),diff_text[:500000],diff_path,now),
        )
        row = self.one("SELECT id FROM js_diffs WHERE run_id=? AND target=? AND js_url=?", (run_id,target,js_url))
        return int(row["id"]) if row else 0

    def upsert_endpoint_intelligence(self, target: str, endpoint: str, kind: str, classification: Mapping[str, Any], source: str, run_id: str) -> bool:
        now = utc_now()
        row = self.one("SELECT sources_json FROM endpoint_intelligence WHERE target=? AND endpoint=? AND kind=?", (target,endpoint,kind))
        sources = set(safe_json_loads(row["sources_json"], [], expected_type=list)) if row else set()
        if source:
            sources.add(source)
        self.execute(
            """
            INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,endpoint,kind) DO UPDATE SET
              primary_category=excluded.primary_category,confidence=MAX(endpoint_intelligence.confidence,excluded.confidence),
              categories_json=excluded.categories_json,reasons_json=excluded.reasons_json,sources_json=excluded.sources_json,
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id
            """,
            (target,endpoint,kind,str(classification.get("primary_category","general")),int(classification.get("confidence",0)),
             json_dumps(classification.get("categories",[])),json_dumps(classification.get("reasons",[])),json_dumps(sorted(sources)),now,now,run_id),
        )
        return row is None

    def upsert_technology_observation(self, target: str, url: str, technology: str, observation: Mapping[str, Any], run_id: str) -> None:
        now = utc_now()
        self.execute(
            """
            INSERT INTO technology_observations(target,url,technology,confidence,confidence_label,evidence_json,first_seen,last_seen,last_run_id,is_current)
            VALUES(?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(target,url,technology) DO UPDATE SET
              confidence=excluded.confidence,confidence_label=excluded.confidence_label,evidence_json=excluded.evidence_json,
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,is_current=1
            """,
            (target,url,technology,int(observation.get("confidence",0)),str(observation.get("confidence_label","low")),
             json_dumps(observation.get("reasons",[])),now,now,run_id),
        )

    def finalize_technology_observations(self, target: str, url: str, run_id: str) -> None:
        self.execute(
            "UPDATE technology_observations SET is_current=0 WHERE target=? AND url=? AND COALESCE(last_run_id,'')<>?",
            (target,url,run_id),
        )

    def upsert_edge(
        self,
        target: str,
        source_type: str,
        source_value: str,
        relation: str,
        destination_type: str,
        destination_value: str,
        run_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if not source_value or not destination_value or source_value == destination_value:
            return
        now = utc_now()
        self.execute(
            """
            INSERT INTO asset_edges(target,source_type,source_value,relation,destination_type,destination_value,metadata_json,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,source_type,source_value,relation,destination_type,destination_value) DO UPDATE SET
              metadata_json=excluded.metadata_json,last_seen=excluded.last_seen,last_run_id=excluded.last_run_id
            """,
            (target, source_type, source_value, relation, destination_type, destination_value, json_dumps(metadata or {}), now, now, run_id),
        )

    def observe_event(
        self,
        target: str,
        dedup_key: str,
        category: str,
        item: str,
        change_class: str,
        run_id: str,
        details: Mapping[str, Any] | None = None,
        confirmations: int = 2,
        immediately_confirmed: bool = False,
    ) -> tuple[int, str]:
        now = utc_now()
        old = self.one("SELECT occurrences,last_run_id,confirmation_state FROM event_observations WHERE target=? AND dedup_key=?", (target, dedup_key))
        occurrence = int(old["occurrences"] if old else 0)
        if not old or str(old["last_run_id"] or "") != run_id:
            occurrence += 1
        state = "confirmed" if immediately_confirmed or occurrence >= max(1, confirmations) else "observed"
        self.execute(
            """
            INSERT INTO event_observations(target,dedup_key,category,item,change_class,occurrences,confirmation_state,first_seen,last_seen,last_run_id,details_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target,dedup_key) DO UPDATE SET
              category=excluded.category,item=excluded.item,change_class=excluded.change_class,
              occurrences=excluded.occurrences,confirmation_state=excluded.confirmation_state,
              last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,details_json=excluded.details_json
            """,
            (target, dedup_key, category, item, change_class, occurrence, state, now, now, run_id, json_dumps(details or {})),
        )
        return occurrence, state

    def add_note(self, target: str, entity_type: str, entity_value: str, note: str) -> int:
        note = note.strip()
        if not note:
            raise ReconError("Note cannot be empty")
        now = utc_now()
        cursor = self.execute(
            "INSERT INTO investigation_notes(target,entity_type,entity_value,note,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (target, entity_type, entity_value, note[:5000], now, now),
        )
        return int(cursor.lastrowid)

    def delete_note(self, note_id: int) -> None:
        self.execute("DELETE FROM investigation_notes WHERE id=?", (note_id,))

    def record_tool_version(self, run_id: str, tool: str, version: str, path: str) -> None:
        self.execute(
            "INSERT INTO tool_versions(run_id,tool,version,path) VALUES(?,?,?,?) ON CONFLICT(run_id,tool) DO UPDATE SET version=excluded.version,path=excluded.path",
            (run_id, tool, version, path),
        )

    def meta_get(self, key: str, default: str = "") -> str:
        row = self.one("SELECT value FROM schema_meta WHERE key=?", (key,))
        return str(row["value"]) if row else default

    def meta_set(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO schema_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def integrity(self) -> str:
        row = self.one("PRAGMA integrity_check")
        return str(row[0]) if row else "unknown"

    def quick_check(self) -> str:
        row = self.one("PRAGMA quick_check")
        return str(row[0]) if row else "unknown"

    def optimize(self) -> dict[str, Any]:
        before = self.one("PRAGMA page_count")
        self.execute("PRAGMA optimize")
        self.execute("PRAGMA wal_checkpoint(PASSIVE)")
        after = self.one("PRAGMA page_count")
        return {"page_count_before": int(before[0]) if before else 0, "page_count_after": int(after[0]) if after else 0}

    def foreign_key_violations(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.all("PRAGMA foreign_key_check")]

    @staticmethod
    def _age_hours(value: Any, now: dt.datetime | None = None) -> float | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        current = now or dt.datetime.now(UTC)
        return max(0.0, (current - parsed.astimezone(UTC)).total_seconds() / 3600.0)

    def stale_state_report(self, max_age_hours: int = 24) -> dict[str, Any]:
        threshold = max(1, int(max_age_hours))
        now = dt.datetime.now(UTC)
        analyses = []
        for row in self.all("SELECT id,source_run_id,target,started_at FROM analysis_runs WHERE status='running'"):
            age = self._age_hours(row["started_at"], now)
            if age is None or age >= threshold:
                analyses.append({**dict(row), "age_hours": None if age is None else round(age, 2)})
        stages = []
        for row in self.all("SELECT run_id,target,stage,started_at,heartbeat_at FROM stage_runs WHERE status='running'"):
            age = self._age_hours(row["heartbeat_at"] or row["started_at"], now)
            if age is None or age >= threshold:
                stages.append({**dict(row), "age_hours": None if age is None else round(age, 2)})
        work_items = []
        for row in self.all("SELECT id,run_id,target,stage,started_at,heartbeat_at FROM work_items WHERE status='running'"):
            age = self._age_hours(row["heartbeat_at"] or row["started_at"], now)
            if age is None or age >= threshold:
                work_items.append({**dict(row), "age_hours": None if age is None else round(age, 2)})
        runs = []
        for row in self.all("SELECT id,started_at FROM runs WHERE status='running'"):
            age = self._age_hours(row["started_at"], now)
            if age is None or age >= threshold:
                runs.append({**dict(row), "age_hours": None if age is None else round(age, 2)})
        return {
            "max_age_hours": threshold,
            "analysis_runs": analyses,
            "stage_runs": stages,
            "work_items": work_items,
            "runs": runs,
            "count": len(analyses) + len(stages) + len(work_items) + len(runs),
        }

    def repair_stale_state(self, max_age_hours: int = 24, *, dry_run: bool = False) -> dict[str, Any]:
        report = self.stale_state_report(max_age_hours)
        if dry_run or not report["count"]:
            return {**report, "dry_run": dry_run, "repaired": 0}
        now = utc_now()
        repaired = 0
        with self.transaction():
            for row in report["analysis_runs"]:
                self.conn.execute(
                    "UPDATE analysis_runs SET status='failed',finished_at=?,error=COALESCE(NULLIF(error,''),'Recovered stale analysis state') WHERE id=? AND status='running'",
                    (now, row["id"]),
                )
                repaired += 1
            for row in report["stage_runs"]:
                self.conn.execute(
                    "UPDATE stage_runs SET status='failed',finished_at=?,error=COALESCE(NULLIF(error,''),'Recovered stale stage state') WHERE run_id=? AND target=? AND stage=? AND status='running'",
                    (now, row["run_id"], row["target"], row["stage"]),
                )
                repaired += 1
            for row in report["work_items"]:
                self.conn.execute(
                    "UPDATE work_items SET status='retry_pending',started_at=NULL,worker_id=NULL,error=COALESCE(NULLIF(error,''),'Recovered stale work item'),heartbeat_at=? WHERE id=? AND status='running'",
                    (now, row["id"]),
                )
                repaired += 1
            for row in report["runs"]:
                active = self.conn.execute(
                    "SELECT 1 FROM stage_runs WHERE run_id=? AND status='running' LIMIT 1", (row["id"],)
                ).fetchone()
                if active:
                    continue
                self.conn.execute(
                    "UPDATE runs SET status='failed',finished_at=?,error=COALESCE(NULLIF(error,''),'Recovered stale run state') WHERE id=? AND status='running'",
                    (now, row["id"]),
                )
                self.conn.execute(
                    "UPDATE run_targets SET status='failed',finished_at=? WHERE run_id=? AND status='running'",
                    (now, row["id"]),
                )
                repaired += 1
        return {**report, "dry_run": False, "repaired": repaired}

    def json_health(self, sample_limit: int = 10000) -> dict[str, Any]:
        checks = {
            "alerts.details_json": ("alerts", "id", "details_json", dict),
            "stage_runs.metrics_json": ("stage_runs", "rowid", "metrics_json", dict),
            "analysis_runs.summary_json": ("analysis_runs", "id", "summary_json", dict),
            "analysis_results.evidence_for_json": ("analysis_results", "rowid", "evidence_for_json", list),
            "analysis_results.evidence_against_json": ("analysis_results", "rowid", "evidence_against_json", list),
            "bug_candidates.supporting_evidence_json": ("bug_candidates", "candidate_id", "supporting_evidence_json", list),
            "bug_candidates.contradicting_evidence_json": ("bug_candidates", "candidate_id", "contradicting_evidence_json", list),
            "bug_candidates.missing_evidence_json": ("bug_candidates", "candidate_id", "missing_evidence_json", list),
        }
        malformed: list[dict[str, Any]] = []
        scanned = 0
        for label, (table, key_column, column, expected) in checks.items():
            try:
                rows = self.all(f"SELECT {key_column} AS row_key,{column} AS payload FROM {table} WHERE {column} IS NOT NULL LIMIT ?", (sample_limit,))
            except sqlite3.Error:
                continue
            for row in rows:
                scanned += 1
                payload = row["payload"]
                try:
                    decoded = json.loads(str(payload))
                    valid = isinstance(decoded, expected)
                except (json.JSONDecodeError, TypeError, ValueError):
                    valid = False
                if not valid:
                    malformed.append({"field": label, "row": str(row["row_key"])})
                    if len(malformed) >= 100:
                        return {"scanned": scanned, "malformed_count": len(malformed), "malformed": malformed, "truncated": True}
        return {"scanned": scanned, "malformed_count": len(malformed), "malformed": malformed, "truncated": False}


class RunLock:
    def __init__(self, path: Path, logger: Logger):
        self.path = path
        self.logger = logger
        self.owned = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            pid = parse_int(data.get("pid"), 0)
            if pid and process_alive(pid):
                raise ReconError(f"Another Recon Monitor run is active (PID {pid}).")
            self.logger.warn("Removing stale run lock", lock=str(self.path), stale_pid=pid)
            self.path.unlink(missing_ok=True)
        payload = {"pid": os.getpid(), "created_at": utc_now(), "command": sys.argv}
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ReconError("Run lock appeared concurrently; another run may be starting.") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        self.owned = True

    def release(self) -> None:
        if not self.owned:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        except Exception:
            data = {}
        if parse_int(data.get("pid"), 0) in {0, os.getpid()}:
            self.path.unlink(missing_ok=True)
        self.owned = False

    def __enter__(self) -> "RunLock":
        self.acquire()
        return self

    def __exit__(self, *_: Any) -> None:
        self.release()


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


@dataclasses.dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    duration: float
    lines: int
    timed_out: bool
    output_path: Path | None


class CommandRunner:
    def __init__(self, logger: Logger, db: Database | None = None):
        self.logger = logger
        self.db = db
        self._active: subprocess.Popen[str] | None = None
        self._stop = threading.Event()

    def terminate_active(self) -> None:
        self._stop.set()
        proc = self._active
        if proc and proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 600,
        output_path: Path | None = None,
        line_callback: Callable[[str, int], None] | None = None,
        heartbeat: Callable[[], None] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        if not args:
            raise ValueError("Empty command")
        started = time.monotonic()
        lines = 0
        timed_out = False
        output_handle = None
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_handle = output_path.open("w", encoding="utf-8")
        proc_env = os.environ.copy()
        if env:
            proc_env.update({str(k): str(v) for k, v in env.items()})
        self.logger.info("Executing tool", command=" ".join(args), cwd=str(cwd or Path.cwd()))
        proc = subprocess.Popen(
            list(args),
            cwd=str(cwd) if cwd else None,
            env=proc_env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        self._active = proc
        if input_text is not None and proc.stdin:
            proc.stdin.write(input_text)
            proc.stdin.close()

        def watchdog() -> None:
            nonlocal timed_out
            heartbeat_interval = 5.0
            next_heartbeat = time.monotonic()
            while proc.poll() is None and not self._stop.wait(0.5):
                now = time.monotonic()
                if heartbeat and now >= next_heartbeat:
                    try:
                        heartbeat()
                    except Exception as exc:  # Heartbeat failure must not kill timeout supervision.
                        self.logger.warn(
                            "Stage heartbeat failed",
                            command=" ".join(args),
                            error=str(exc),
                        )
                    next_heartbeat = now + heartbeat_interval
                if now - started > timeout:
                    timed_out = True
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGTERM)
                    time.sleep(1)
                    if proc.poll() is None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                    break

        watcher = threading.Thread(target=watchdog, daemon=True)
        watcher.start()
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                lines += 1
                if output_handle:
                    output_handle.write(raw)
                if line_callback:
                    line_callback(raw.rstrip("\n"), lines)
                if self._stop.is_set():
                    break
            returncode = proc.wait()
        finally:
            watcher.join(timeout=1)
            if output_handle:
                output_handle.close()
            self._active = None
            self._stop.clear()
        duration = time.monotonic() - started
        if timed_out:
            returncode = 124
        self.logger.info(
            "Tool finished",
            command=" ".join(args),
            returncode=returncode,
            duration_seconds=round(duration, 3),
            lines=lines,
            timed_out=timed_out,
        )
        return CommandResult(list(args), returncode, duration, lines, timed_out, output_path)


class Progress:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()
        self.started = time.monotonic()
        self.target_index = 1
        self.target_total = 1
        self.stage_index = 1
        self.stage_total = 1
        self.label = ""
        self.current = 0
        self.total = 0
        self.extra = ""
        self._last_len = 0
        self._lock = threading.Lock()

    def configure(self, target_index: int, target_total: int, stage_index: int, stage_total: int, label: str) -> None:
        with self._lock:
            self.target_index = target_index
            self.target_total = target_total
            self.stage_index = stage_index
            self.stage_total = stage_total
            self.label = label
            self.current = 0
            self.total = 0
            self.extra = ""
            self.draw()

    def update(self, current: int | None = None, total: int | None = None, extra: str | None = None) -> None:
        with self._lock:
            if current is not None:
                self.current = current
            if total is not None:
                self.total = total
            if extra is not None:
                self.extra = extra
            self.draw()

    def draw(self) -> None:
        if not self.enabled:
            return
        stage_fraction = 0.0
        unit = ""
        if self.total > 0:
            stage_fraction = min(1.0, self.current / self.total)
            unit = f" {self.current}/{self.total}"
        global_units = (self.target_index - 1) * self.stage_total + (self.stage_index - 1) + stage_fraction
        total_units = max(1, self.target_total * self.stage_total)
        percent = int(global_units * 100 / total_units)
        width = 24
        filled = int(width * percent / 100)
        bar = "#" * filled + "-" * (width - filled)
        elapsed = int(time.monotonic() - self.started)
        elapsed_text = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        text = (
            f"[{bar}] {percent:3d}% | Target {self.target_index}/{self.target_total} | "
            f"Stage {self.stage_index}/{self.stage_total} | {self.label}{unit} | {elapsed_text}"
        )
        if self.extra:
            text += f" | {self.extra}"
        padding = " " * max(0, self._last_len - len(text))
        sys.stdout.write("\r" + text + padding)
        sys.stdout.flush()
        self._last_len = len(text)

    def finish_stage(self, status: str, metrics: Mapping[str, Any] | None = None) -> None:
        if self.enabled:
            self.update(self.total or 1, self.total or 1)
            sys.stdout.write("\n")
            self._last_len = 0
        summary = ", ".join(f"{k}={v}" for k, v in (metrics or {}).items() if isinstance(v, (str, int, float, bool)))
        print(f"  [{status.upper()}] {self.label}" + (f" — {summary}" if summary else ""), flush=True)

    def message(self, text: str) -> None:
        if self.enabled and self._last_len:
            sys.stdout.write("\r" + " " * self._last_len + "\r")
            self._last_len = 0
        print(text, flush=True)


class TelegramNotifier:
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger

    @property
    def ready(self) -> bool:
        return (
            self.config.bool("TELEGRAM_ENABLED", False)
            and self.config.secret_is_set("TELEGRAM_BOT_TOKEN")
            and self.config.secret_is_set("TELEGRAM_CHAT_ID")
        )

    def api(self, method: str, fields: Mapping[str, str], timeout: int = 25) -> dict[str, Any]:
        token = self.config.get("TELEGRAM_BOT_TOKEN")
        url = f"https://api.telegram.org/bot{token}/{method}"
        data = urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(url, data=data, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise ReconError(f"Telegram HTTP {exc.code}: {body[:300]}") from exc
        except OSError as exc:
            raise ReconError(f"Telegram connection failed: {exc}") from exc
        if not payload.get("ok"):
            raise ReconError(f"Telegram API error: {payload}")
        return payload

    def send(self, message: str) -> bool:
        if not self.ready:
            self.logger.warn("Telegram disabled or incomplete")
            return False
        chunks = split_message(message, 3900)
        for chunk in chunks:
            self.api(
                "sendMessage",
                {
                    "chat_id": self.config.get("TELEGRAM_CHAT_ID"),
                    "text": chunk,
                    "disable_web_page_preview": "true",
                },
            )
        return True

    def test(self) -> bool:
        return self.send(f"✅ Recon Monitor {APP_VERSION} connection is working.\nTime: {local_now()}")

    def get_me(self) -> dict[str, Any]:
        return self.api("getMe", {})


def split_message(text: str, limit: int) -> list[str]:
    if len(text) <= limit:
        return [text]
    result: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > limit and current:
            result.append(current.rstrip())
            current = ""
        if len(line) > limit:
            while len(line) > limit:
                result.append(line[:limit])
                line = line[limit:]
        current += line
    if current:
        result.append(current.rstrip())
    return result


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def tool_version(name: str) -> tuple[str, str]:
    path = tool_path(name)
    if not path:
        return "", ""
    candidates = ([path, "-version"], [path, "--version"], [path, "version"])
    for args in candidates:
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = proc.stdout.strip().replace("\n", " | ")
        if output:
            return path, output[:500]
    return path, "installed"


def collect_tool_versions(names: Iterable[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in names:
        path, version = tool_version(name)
        result[name] = {"path": path, "version": version}
    return result


def semantic_js_normalize(text: str) -> str:
    # Conservative normalization: remove comments, source-map trailer, volatile build
    # timestamps and whitespace while preserving strings and identifiers as much as possible.
    text = re.sub(r"(?m)^\s*//#\s*sourceMappingURL=.*$", "", text)
    text = re.sub(r"(?m)^\s*//[@#]\s*sourceURL=.*$", "", text)
    text = re.sub(r"/\*![\s\S]*?\*/", "", text)
    text = re.sub(r"/\*(?!\!)[\s\S]*?\*/", "", text)
    text = re.sub(r"(?m)(?<!:)//[^\n\r]*", "", text)
    text = re.sub(r"\b(?:buildTime|buildTimestamp|compiledAt)\s*[:=]\s*[\"']?\d{10,13}[\"']?", "VOLATILE_BUILD_TIME", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s*([=,:;{}()\[\]])\s*", r"\1", text)
    return text


def extract_js_indicators(text: str) -> list[tuple[str, str, bool]]:
    indicators: set[tuple[str, str, bool]] = set()
    absolute = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
    endpoint = re.compile(
        r"[\"'`](?P<path>/(?:api|graphql|admin|auth|oauth|internal|debug|v\d+|upload|download|export|import|webhook|socket|ws)[^\"'`\s<>]{0,450})[\"'`]",
        re.IGNORECASE,
    )
    parameter = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,63})=")
    graphql_op = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for value in absolute.findall(text):
        value = value.rstrip(".,);]}\"")[:500]
        with contextlib.suppress(ValueError):
            if urllib.parse.urlsplit(value).hostname:
                indicators.add(("absolute_url", value, False))
    for match in endpoint.finditer(text):
        indicators.add(("endpoint", match.group("path")[:500], False))
    for value in parameter.findall(text):
        indicators.add(("parameter", value[:100], False))
    for value in graphql_op.findall(text):
        indicators.add(("graphql_operation", value[:200], False))
    lower = text.lower()
    if "new websocket" in lower or "websocket(" in lower:
        indicators.add(("technology_hint", "websocket", False))
    if "graphql" in lower:
        indicators.add(("technology_hint", "graphql", False))
    secret_patterns = {
        "aws_access_key_pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "private_key_marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "jwt_like_token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
        "sensitive_assignment": re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]"),
    }
    for label, pattern in secret_patterns.items():
        count = len(pattern.findall(text))
        if count:
            indicators.add(("sensitive_marker", f"{label}:count={count}", True))
    return sorted(indicators)


def classify_url(url: str) -> str:
    path = urllib.parse.urlsplit(url).path.lower()
    if re.search(r"\.m?js$", path):
        return "javascript"
    if path.endswith(".map"):
        return "source_map"
    if re.search(r"\.(?:json|xml|yaml|yml)$", path):
        return "data"
    if re.search(r"/(?:api|graphql|v\d+)(?:/|$)", path):
        return "api"
    return "url"


def classify_change(category: str, item: str, details: Mapping[str, Any] | None = None) -> str:
    details = details or {}
    text = f"{category} {item} {json_dumps(details)}".lower()
    if category == "nuclei_finding" or details.get("kind") == "sensitive_marker":
        return "sensitive"
    if re.search(r"(^|[./_?-])(auth|oauth|sso|login|token|session|password)([./_?=&-]|$)", text):
        return "authentication"
    if category in {"js_indicator", "new_url"} and re.search(r"/(api|graphql|v\d+)(/|$)", text):
        return "api"
    if category in {"dns_change", "new_subdomain", "new_port"}:
        return "infrastructure"
    if category in {"fingerprint_change", "new_live_http"}:
        return "application"
    if category in {"changed_js", "new_js"}:
        return "application"
    return "asset"


def explain_risk(category: str, item: str, details: Mapping[str, Any] | None = None) -> tuple[int, str, list[str], str]:
    details = details or {}
    base = {
        "new_subdomain": 20,
        "new_url": 10,
        "new_js": 15,
        "changed_js": 22,
        "js_indicator": 18,
        "endpoint_added": 24,
        "fingerprint_change": 20,
        "new_live_http": 25,
        "new_port": 35,
        "nuclei_finding": 50,
        "dns_change": 15,
    }.get(category, 10)
    score = base
    reasons = [f"Base score for {category}: +{base}"]
    change_class = classify_change(category, item, details)

    sensitive = re.compile(
        r"(^|[./_?-])(admin|internal|debug|dev|staging|stage|uat|preprod|vpn|sso|auth|oauth|api|graphql|export|backup)([./_?=&-]|$)",
        re.I,
    )
    if sensitive.search(item):
        score += 25
        reasons.append("Sensitive asset or path keyword: +25")

    endpoint_classification = details.get("endpoint_classification")
    if not isinstance(endpoint_classification, Mapping):
        diff_summary = details.get("diff_summary")
        if isinstance(diff_summary, Mapping):
            added = diff_summary.get("added_endpoints")
            if isinstance(added, list) and added:
                endpoint_classification = max(
                    (x for x in added if isinstance(x, Mapping)),
                    key=lambda x: int(x.get("confidence", 0)),
                    default=None,
                )
    if isinstance(endpoint_classification, Mapping):
        endpoint_category = str(endpoint_classification.get("primary_category") or "general")
        confidence = parse_int(endpoint_classification.get("confidence"), 0, 0, 100)
        maximum = {
            "sensitive": 35,
            "admin": 30,
            "authentication": 27,
            "authorization": 27,
            "debug": 25,
            "payment": 25,
            "internal": 23,
            "export": 19,
            "upload": 17,
            "personal_data": 16,
            "graphql": 15,
            "websocket": 12,
            "webhook": 12,
            "api": 8,
        }.get(endpoint_category, 0)
        bonus = round(maximum * confidence / 100)
        if bonus:
            score += bonus
            reasons.append(f"Endpoint classification {endpoint_category} ({confidence}% confidence): +{bonus}")
        if endpoint_category in {"authentication", "authorization"}:
            change_class = "authentication"
        elif endpoint_category in {"api", "graphql", "websocket", "webhook", "admin", "debug", "payment", "upload", "export", "personal_data", "internal"}:
            change_class = "api"

    if category == "js_indicator" and details.get("kind") == "sensitive_marker":
        score += 40
        reasons.append("Redacted sensitive marker in JavaScript: +40")
        change_class = "sensitive"

    if category == "changed_js":
        semantic_changed = bool(details.get("semantic_changed"))
        diff_summary = details.get("diff_summary") if isinstance(details.get("diff_summary"), Mapping) else {}
        added_endpoints = diff_summary.get("added_endpoints") if isinstance(diff_summary, Mapping) else []
        removed_endpoints = diff_summary.get("removed_endpoints") if isinstance(diff_summary, Mapping) else []
        if not semantic_changed:
            score = max(0, score - 12)
            reasons.append("Raw-only JavaScript change with no semantic change: -12")
        if isinstance(added_endpoints, list) and added_endpoints:
            bonus = min(25, 8 + len(added_endpoints) * 4)
            score += bonus
            reasons.append(f"New endpoints in JavaScript diff ({len(added_endpoints)}): +{bonus}")
        if isinstance(removed_endpoints, list) and removed_endpoints and not added_endpoints:
            score = max(0, score - 5)
            reasons.append("Only endpoint removals were observed: -5")

    if category == "nuclei_finding":
        finding_severity = str(details.get("severity", "info")).lower()
        addition = {"critical": 50, "high": 35, "medium": 20, "low": 5}.get(finding_severity, 0)
        score += addition
        if addition:
            reasons.append(f"Allowlisted finding severity {finding_severity}: +{addition}")

    if category == "new_port" and str(details.get("port")) in {"22", "2375", "3306", "5432", "6379", "9200", "27017"}:
        score += 30
        reasons.append("Sensitive service port: +30")

    sources = details.get("sources")
    if isinstance(sources, list) and len(sources) >= 2:
        bonus = min(15, len(sources) * 5)
        score += bonus
        reasons.append(f"Confirmed by multiple discovery sources: +{bonus}")

    status_code = details.get("status_code")
    if isinstance(details.get("new"), Mapping):
        status_code = details.get("new", {}).get("status_code")
    if status_code == 200:
        score += 10
        reasons.append("Public HTTP 200 response: +10")

    tech_confidence = details.get("technology_confidence")
    if isinstance(tech_confidence, list) and tech_confidence:
        highest = max((parse_int(x.get("confidence"), 0) for x in tech_confidence if isinstance(x, Mapping)), default=0)
        if highest >= 85:
            score += 4
            reasons.append(f"High-confidence technology fingerprint ({highest}%): +4")

    score = max(0, min(100, score))
    severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW" if score >= 20 else "INFO"
    reasons.append(f"Final score: {score}/100 ({severity})")
    return score, severity, reasons, change_class


def risk_score(category: str, item: str, details: Mapping[str, Any] | None = None) -> tuple[int, str]:
    score, severity, _reasons, _change_class = explain_risk(category, item, details)
    return score, severity


def header_args(headers: Mapping[str, str]) -> list[str]:
    args: list[str] = []
    for key, value in headers.items():
        if "\n" in key or "\n" in value or "\r" in key or "\r" in value:
            continue
        args.extend(["-H", f"{key}: {value}"])
    return args


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, "".join(json_dumps(dict(row)) + "\n" for row in rows))


def query_host_records_fallback(host: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {"A": set(), "AAAA": set()}
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            value = sockaddr[0]
            if family == socket.AF_INET:
                result["A"].add(value)
            elif family == socket.AF_INET6:
                result["AAAA"].add(value)
    except socket.gaierror:
        pass
    return result


def config_hash(config: Config, policies: PolicySet) -> str:
    safe_values = {k: v for k, v in config.values.items() if "TOKEN" not in k and "SECRET" not in k and "PASSWORD" not in k}
    return sha256_text(json_dumps({"config": safe_values, "policy": [target.raw for target in policies.targets]}))

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core import (
    APP_VERSION,
    SCHEMA_VERSION,
    AppPaths,
    Config,
    Database,
    Logger,
    PolicySet,
    ReconError,
    TelegramNotifier,
    collect_tool_versions,
    parse_int,
    process_alive,
)
from service import service_status
from dashboard_service import dashboard_status
from dashboard_auth import auth_status
from plugins import PluginManager
from secrets_manager import keychain_available, known_secret_names
from api_server import api_status
from postgres_mirror import status as postgres_status


@dataclass(slots=True)
class Check:
    level: str
    name: str
    detail: str


REQUIRED_TOOLS = ["bash", "sqlite3", "curl", "python3"]
PASSIVE_TOOLS = ["subfinder", "assetfinder", "dnsx", "waybackurls", "katana", "httpx"]
OPTIONAL_TOOLS = ["notify", "naabu", "nuclei"]


def _tool_help_has(tool: str, tokens: list[str]) -> tuple[bool, str]:
    path = shutil.which(tool)
    if not path:
        return False, "not installed"
    try:
        proc = subprocess.run([path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    missing = [token for token in tokens if token not in proc.stdout]
    return not missing, "missing flags: " + ", ".join(missing) if missing else "compatible flags detected"


def run_doctor(paths: AppPaths, config: Config, logger: Logger, *, network: bool = True) -> list[Check]:
    checks: list[Check] = []

    def add(level: str, name: str, detail: str) -> None:
        checks.append(Check(level, name, detail))

    add("OK" if config.authorized else "FAIL", "Authorization", "I_HAVE_AUTHORIZATION=yes" if config.authorized else "Set I_HAVE_AUTHORIZATION=yes only after verifying all targets")
    try:
        policies = PolicySet.load(paths)
        add("OK", "Target policy", f"{len(policies.targets)} target(s) loaded from {policies.source}")
        for policy in policies.targets:
            active = policy.modules.get("ports") or policy.modules.get("nuclei")
            if active and not policy.active_confirmed:
                add("WARN", f"Active gate: {policy.name}", "Active module enabled but target confirmation string is absent")
            elif active and not config.active_globally_enabled:
                add("WARN", f"Active gate: {policy.name}", "Target permits active checks but ENABLE_ACTIVE_MODULES is not yes")
            else:
                add("OK", f"Scope: {policy.name}", f"roots={','.join(policy.roots)} include={len(policy.include)} exclude={len(policy.exclude)}")
    except ReconError as exc:
        add("FAIL", "Target policy", str(exc))
        policies = None

    import sys
    add("OK" if sys.version_info >= (3, 10) else "FAIL", "Python version", sys.version.split()[0] + " (requires 3.10+)")
    for tool in REQUIRED_TOOLS:
        path = shutil.which(tool)
        add("OK" if path else "FAIL", f"Tool: {tool}", path or "missing")
    for tool in PASSIVE_TOOLS:
        path = shutil.which(tool)
        add("OK" if path else "WARN", f"Passive tool: {tool}", path or "missing; related module will degrade or skip")
    for tool in OPTIONAL_TOOLS:
        path = shutil.which(tool)
        add("OK" if path else "INFO", f"Optional tool: {tool}", path or "not installed")

    compatibility = {
        "subfinder": ["-oJ", "-cs", "-rl"],
        "dnsx": ["-json", "-wd", "-rl"],
        "katana": ["-jc", "-rl"],
        "httpx": ["-json", "-hash", "-jarm", "-include-chain"],
        "naabu": ["-json", "-rate"],
        "nuclei": ["-jsonl", "-id", "-dut", "-rl"],
    }
    for tool, flags in compatibility.items():
        if shutil.which(tool):
            ok, detail = _tool_help_has(tool, flags)
            add("OK" if ok else "WARN", f"Compatibility: {tool}", detail)

    try:
        db = Database(paths.db)
        integrity = db.integrity()
        add("OK" if integrity == "ok" else "FAIL", "Database integrity", integrity)
        row = db.one("SELECT value FROM schema_meta WHERE key='schema_version'")
        add("OK" if row and str(row[0]) == str(SCHEMA_VERSION) else "WARN", "Database schema", f"{str(row[0]) if row else 'unknown'} (expected {SCHEMA_VERSION})")
        quick = db.quick_check()
        add("OK" if quick == "ok" else "FAIL", "Database quick check", quick)
        foreign_keys = db.foreign_key_violations()
        add("OK" if not foreign_keys else "FAIL", "Database foreign keys", "no violations" if not foreign_keys else f"{len(foreign_keys)} violation(s)")
        stale = db.stale_state_report(config.int("STALE_STATE_HOURS", 24, 1, 720))
        add("WARN" if stale["count"] else "OK", "Stale execution state", f"{stale['count']} stale row(s); run `recon-monitor repair --dry-run`" if stale["count"] else "none")
        json_health = db.json_health(sample_limit=2000)
        add("WARN" if json_health["malformed_count"] else "OK", "Stored JSON health", f"{json_health['malformed_count']} malformed sampled field(s)" if json_health["malformed_count"] else f"{json_health['scanned']} field(s) sampled")
        plugin_health = PluginManager(paths, db).health()
        degraded = [item["name"] for item in plugin_health if not item["ok"]]
        add("WARN" if degraded else "OK", "Plugin registry", "degraded: " + ", ".join(degraded) if degraded else f"{len(plugin_health)} plugin(s) healthy")
        db.close()
    except (sqlite3.Error, OSError) as exc:
        add("FAIL", "Database", str(exc))

    try:
        usage = shutil.disk_usage(paths.root)
        free_gb = usage.free / (1024 ** 3)
        minimum = config.int("MIN_FREE_DISK_GB", 2, 0, 100)
        add("OK" if free_gb >= minimum else "WARN", "Disk space", f"{free_gb:.2f} GiB free; minimum configured {minimum} GiB")
    except OSError as exc:
        add("WARN", "Disk space", str(exc))

    if paths.lock.exists():
        try:
            data = json.loads(paths.lock.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        pid = parse_int(data.get("pid"), 0)
        add("INFO" if pid and process_alive(pid) else "WARN", "Run lock", f"pid={pid}; {'active' if pid and process_alive(pid) else 'stale'}")
    else:
        add("OK", "Run lock", "No active lock")

    telegram = TelegramNotifier(config, logger)
    if telegram.ready and network:
        try:
            result = telegram.get_me().get("result", {})
            add("OK", "Telegram", f"bot=@{result.get('username','unknown')}")
        except ReconError as exc:
            add("FAIL", "Telegram", str(exc))
    elif telegram.ready:
        add("INFO", "Telegram", "configured; network test skipped")
    else:
        add("WARN", "Telegram", "disabled or incomplete")

    dashboard_active, dashboard_detail = dashboard_status(paths)
    add("OK" if dashboard_active else "INFO", "Dashboard service", dashboard_detail)
    auth_enabled, auth_detail = auth_status(config)
    remote_enabled = config.bool("DASHBOARD_ALLOW_REMOTE", False)
    if remote_enabled and not auth_enabled:
        add("FAIL", "Dashboard authentication", "Remote dashboard access is enabled without valid authentication")
    else:
        add("OK" if auth_enabled else "INFO", "Dashboard authentication", auth_detail)

    api_active, api_detail = api_status(paths)
    add("OK" if api_active else "INFO", "Local API", api_detail)
    if keychain_available():
        add("OK", "macOS Keychain", f"available; {len(known_secret_names(paths))} registered secret name(s)")
    else:
        add("INFO", "macOS Keychain", "unavailable on this platform")
    if config.get("POSTGRES_DSN"):
        pg = postgres_status(config)
        add("OK" if pg.get("ok") else "WARN", "PostgreSQL mirror", str(pg.get("server") or pg.get("error")))
    else:
        add("INFO", "PostgreSQL mirror", "not configured")

    if os.uname().sysname == "Darwin":
        active, detail = service_status()
        add("OK" if active else "INFO", "LaunchAgent", "installed and loaded" if active else "not installed")
    else:
        add("INFO", "LaunchAgent", "macOS only")

    if config.get("NOTIFY_PROVIDER_CONFIG"):
        notify_path = Path(config.get("NOTIFY_PROVIDER_CONFIG")).expanduser()
        add("OK" if notify_path.exists() and shutil.which("notify") else "WARN", "Multi-channel notify", str(notify_path))
    else:
        add("INFO", "Multi-channel notify", "not configured")

    print(f"Recon Monitor doctor {APP_VERSION}\n")
    for check in checks:
        print(f"[{check.level:4}] {check.name}: {check.detail}")
    failures = sum(1 for check in checks if check.level == "FAIL")
    warnings = sum(1 for check in checks if check.level == "WARN")
    print(f"\nSummary: {failures} failure(s), {warnings} warning(s), {len(checks)} checks")
    return checks

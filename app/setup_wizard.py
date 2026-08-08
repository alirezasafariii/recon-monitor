from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable

from core import AppPaths, ReconError, atomic_write_text, json_dumps, normalize_host, parse_bool, valid_domain

PASSIVE_MODULES = [
    ("subdomains", "Subdomain discovery", True),
    ("dns", "DNS resolution and history", True),
    ("urls", "Historical URL collection and authorized crawling", True),
    ("javascript", "JavaScript and source-map analysis", True),
    ("endpoint_validation", "Safe in-scope endpoint validation", False),
    ("fingerprint", "HTTP/TLS fingerprinting", True),
    ("screenshots", "Screenshots for live web services", False),
]
ACTIVE_MODULES = [
    ("ports", "Restricted port monitoring with Naabu", False),
    ("nuclei", "Allowlisted Nuclei checks", False),
]


def _prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in {None, ""} else ""
    try:
        value = input(f"{text}{suffix}: ").strip()
    except EOFError as exc:
        raise ReconError("Interactive setup requires a terminal") from exc
    return value if value else (default or "")


def _yes_no(text: str, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    while True:
        value = _prompt(f"{text} ({marker})").lower()
        if not value:
            return default
        if value in {"y", "yes", "1", "true", "on"}:
            return True
        if value in {"n", "no", "0", "false", "off"}:
            return False
        print("Please answer y or n.")


def _int_prompt(text: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = _prompt(text, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("Enter a number.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"Enter a value between {minimum} and {maximum}.")


def _read_policy(paths: AppPaths) -> dict[str, Any]:
    if not paths.policy.exists():
        return {}
    try:
        value = json.loads(paths.policy.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _existing_targets(payload: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for item in payload.get("targets", []):
        if not isinstance(item, dict):
            continue
        roots = item.get("roots") or []
        if roots:
            value = normalize_host(str(roots[0]))
            if valid_domain(value):
                result.append(value)
    return result


def _parse_target_tokens(values: Iterable[str]) -> list[str]:
    targets: list[str] = []
    for value in values:
        for token in re.split(r"[\s,;]+", value.strip()):
            host = normalize_host(token)
            if not host:
                continue
            if not valid_domain(host):
                print(f"Skipped invalid domain: {token}")
                continue
            if host not in targets:
                targets.append(host)
    return targets


def collect_targets(existing: list[str] | None = None) -> list[str]:
    existing = existing or []
    print("\nStage 1/2 — Authorized targets")
    print("Enter one or more root domains. Separate them with spaces/commas, or enter one per line.")
    print("Only add assets that you own or are explicitly authorized to assess.")
    if existing:
        print("Current targets:")
        for item in existing:
            print(f"  - {item}")
        mode = _prompt("Keep, add, or replace targets?", "keep").lower()
        if mode in {"keep", "k"}:
            return existing
        base = existing if mode in {"add", "a"} else []
    else:
        base = []

    lines: list[str] = []
    print("Enter targets. Press Enter on an empty line when finished:")
    while True:
        value = _prompt("target")
        if not value:
            break
        lines.append(value)
    targets = base + [item for item in _parse_target_tokens(lines) if item not in base]
    if not targets:
        raise ReconError("At least one valid target is required")
    return targets


def _module_defaults(payload: dict[str, Any]) -> dict[str, bool]:
    defaults = payload.get("defaults", {}) if isinstance(payload.get("defaults"), dict) else {}
    configured = defaults.get("modules", {}) if isinstance(defaults.get("modules"), dict) else {}
    values: dict[str, bool] = {}
    for key, _label, default in PASSIVE_MODULES + ACTIVE_MODULES:
        values[key] = parse_bool(configured.get(key), default)
    return values


def collect_settings(payload: dict[str, Any]) -> tuple[dict[str, bool], dict[str, Any], dict[str, Any], dict[str, Any]]:
    print("\nStage 2/2 — Modules and analysis settings")
    defaults = _module_defaults(payload)
    modules: dict[str, bool] = {}
    for key, label, default in PASSIVE_MODULES:
        modules[key] = _yes_no(f"Enable {label}?", defaults.get(key, default))

    print("\nActive modules can generate direct traffic. They remain protected by three authorization gates.")
    active_requested = False
    for key, label, default in ACTIVE_MODULES:
        enabled = _yes_no(f"Enable {label}?", defaults.get(key, default))
        modules[key] = enabled
        active_requested = active_requested or enabled

    active: dict[str, Any] = {"naabu_ports": "80,443,8080,8443", "nuclei_template_ids": []}
    if active_requested:
        phrase = _prompt("Type I_AM_AUTHORIZED_FOR_ACTIVE_TESTING to confirm explicit authorization")
        if phrase != "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING":
            print("Authorization phrase did not match. Active modules were disabled.")
            modules["ports"] = False
            modules["nuclei"] = False
        else:
            active["confirmation"] = phrase
            if modules["ports"]:
                active["naabu_ports"] = _prompt("Allowed ports", "80,443,8080,8443")
            if modules["nuclei"]:
                print("Enter allowlisted Nuclei template IDs separated by commas. Blank disables Nuclei.")
                raw_ids = _prompt("Template IDs")
                ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
                active["nuclei_template_ids"] = ids
                if not ids:
                    modules["nuclei"] = False

    analysis = {
        "asset_graph": _yes_no("Build and update the asset relationship graph?", True),
        "detailed_js_diff": True,
        "endpoint_classification": True,
        "technology_confidence": True,
        "semantic_change_classification": _yes_no("Classify changes semantically?", True),
        "explainable_risk": _yes_no("Store explainable risk reasons?", True),
        "track_confirmation_state": _yes_no("Track observed/confirmed change state?", True),
        "stable_confirmations": _int_prompt("Observations required to confirm volatile changes", 2, 1, 5),
    }
    alert = {
        "minimum_score": _int_prompt("Minimum score for immediate notification", 70, 0, 100),
        "cooldown_hours": _int_prompt("Alert cooldown in hours", 24, 0, 720),
        "confirmed_only": _yes_no("Notify only confirmed volatile changes?", False),
    }
    limits = {
        "request_rate": _int_prompt("Maximum HTTP requests per second", 3, 1, 20),
        "dns_rate": _int_prompt("Maximum DNS queries per second", 100, 1, 500),
        "timeout_seconds": _int_prompt("Maximum stage runtime in seconds", 900, 60, 7200),
        "retries": _int_prompt("Stage retries", 1, 0, 5),
        "crawl_depth": _int_prompt("Crawler depth", 2, 1, 5),
        "max_urls": _int_prompt("Maximum URLs per target", 10000, 100, 200000),
        "max_js_files": _int_prompt("Maximum JavaScript files per target", 200, 1, 5000),
        "max_js_bytes": 5_000_000,
        "http_threads": _int_prompt("HTTP fingerprint worker count", 20, 1, 50),
        "naabu_rate": 50,
        "nuclei_rate": 3,
        "max_runtime_minutes": _int_prompt("Maximum total runtime per target in minutes", 120, 5, 1440),
        "max_http_requests": _int_prompt("Maximum HTTP requests per target", 10000, 100, 1000000),
        "max_dns_queries": _int_prompt("Maximum DNS queries per target", 5000, 100, 1000000),
        "max_download_mb": _int_prompt("Maximum downloaded data in MiB", 500, 10, 100000),
        "max_new_assets": _int_prompt("Maximum new assets per run", 5000, 10, 1000000),
        "dns_workers": 10,
        "http_workers": 20,
        "js_workers": _int_prompt("JavaScript download workers", 5, 1, 50),
        "screenshot_workers": 2,
    }
    return modules, analysis, alert, {"active": active, "limits": limits}


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    import datetime as dt

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.backup-{stamp}")
    shutil.copy2(path, backup)
    return backup


def _update_env(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    remaining = dict(updates)
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                output.append(f'{key}="{remaining.pop(key)}"')
                continue
        output.append(line)
    if remaining:
        if output and output[-1] != "":
            output.append("")
        output.append("# Interactive setup")
        for key, value in remaining.items():
            output.append(f'{key}="{value}"')
    atomic_write_text(path, "\n".join(output).rstrip() + "\n", mode=0o600)


def run_setup_wizard(paths: AppPaths) -> dict[str, Any]:
    if not sys.stdin.isatty():
        raise ReconError("The setup wizard requires an interactive terminal")
    print("Recon Monitor setup wizard")
    if not _yes_no("Do you confirm that every target you add is explicitly authorized?", False):
        raise ReconError("Authorization was not confirmed; setup cancelled")
    payload = _read_policy(paths)
    targets = collect_targets(_existing_targets(payload))
    modules, analysis, alert, extra = collect_settings(payload)
    defaults = {
        "modules": modules,
        "limits": extra["limits"],
        "analysis": analysis,
        "alert": alert,
    }
    target_items = []
    for target in targets:
        item: dict[str, Any] = {"name": target, "roots": [target]}
        if modules.get("ports") or modules.get("nuclei"):
            item["active"] = extra["active"]
        target_items.append(item)
    new_payload = {"schema": 2, "defaults": defaults, "targets": target_items}
    backup = _backup(paths.policy)
    atomic_write_text(paths.policy, json_dumps(new_payload, pretty=True) + "\n")
    _update_env(
        paths.config,
        {
            "I_HAVE_AUTHORIZATION": "yes",
            "ENABLE_ACTIVE_MODULES": "yes" if (modules.get("ports") or modules.get("nuclei")) else "no",
            "ALERT_MIN_SCORE": str(alert["minimum_score"]),
            "ALERT_COOLDOWN_HOURS": str(alert["cooldown_hours"]),
            "ALERT_CONFIRMED_ONLY": "true" if alert["confirmed_only"] else "false",
            "DASHBOARD_HOST": "127.0.0.1",
            "DASHBOARD_PORT": "8787",
        },
    )
    print("\nSetup completed.")
    print(f"Targets: {', '.join(targets)}")
    enabled = [key for key, value in modules.items() if value]
    disabled = [key for key, value in modules.items() if not value]
    print(f"Enabled modules: {', '.join(enabled) or 'none'}")
    print(f"Disabled modules: {', '.join(disabled) or 'none'}")
    if backup:
        print(f"Policy backup: {backup}")
    print("Next: ./recon-monitor.sh doctor")
    return {"targets": targets, "modules": modules, "analysis": analysis, "policy": str(paths.policy), "backup": str(backup or "")}


def list_targets(paths: AppPaths) -> list[str]:
    return _existing_targets(_read_policy(paths))


def add_targets(paths: AppPaths, values: Iterable[str]) -> list[str]:
    payload = _read_policy(paths)
    current_items = [item for item in payload.get("targets", []) if isinstance(item, dict)]
    current = _existing_targets(payload)
    additions = _parse_target_tokens(values)
    for value in additions:
        if value not in current:
            current_items.append({"name": value, "roots": [value]})
            current.append(value)
    if not current:
        raise ReconError("No valid targets supplied")
    payload = {
        "schema": max(2, int(payload.get("schema", 1) or 1)),
        "defaults": payload.get("defaults", {}),
        "targets": current_items,
    }
    _backup(paths.policy)
    atomic_write_text(paths.policy, json_dumps(payload, pretty=True) + "\n")
    return current


def remove_target(paths: AppPaths, value: str) -> list[str]:
    payload = _read_policy(paths)
    normalized = normalize_host(value)
    targets = []
    for item in payload.get("targets", []):
        name = normalize_host(str(item.get("name", ""))) if isinstance(item, dict) else ""
        roots = [normalize_host(str(x)) for x in item.get("roots", [])] if isinstance(item, dict) else []
        if normalized == name or normalized in roots:
            continue
        targets.append(item)
    if not targets:
        raise ReconError("Refusing to remove the last target; run setup to replace it")
    payload["targets"] = targets
    _backup(paths.policy)
    atomic_write_text(paths.policy, json_dumps(payload, pretty=True) + "\n")
    return _existing_targets(payload)


def module_status(paths: AppPaths) -> dict[str, bool]:
    payload = _read_policy(paths)
    return _module_defaults(payload)


def interactive_main_menu(paths: AppPaths) -> list[str]:
    print("Recon Monitor interactive menu")
    print("1) Setup targets and modules")
    print("2) Run all targets")
    print("3) Run one target")
    print("4) Start/open dashboard")
    print("5) Doctor")
    print("6) Dashboard status")
    print("7) LaunchAgent status")
    print("0) Exit")
    choice = _prompt("Select", "2")
    if choice == "1":
        return ["setup"]
    if choice == "2":
        return ["run"]
    if choice == "3":
        targets = list_targets(paths)
        if not targets:
            return ["setup"]
        for index, target in enumerate(targets, 1):
            print(f"{index}) {target}")
        selected = _int_prompt("Target number", 1, 1, len(targets))
        return ["run", "--target", targets[selected - 1]]
    if choice == "4":
        return ["dashboard", "start", "--open"]
    if choice == "5":
        return ["doctor"]
    if choice == "6":
        return ["dashboard", "status"]
    if choice == "7":
        return ["service", "status"]
    raise SystemExit(0)

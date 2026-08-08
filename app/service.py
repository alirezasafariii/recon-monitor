from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import Any

from core import AppPaths, Config, Logger, ReconError, parse_int

LABEL = "com.reconmonitor.agent"


def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _interval_seconds(spec: str) -> int:
    spec = spec.strip().lower()
    mapping = {
        "30m": 1800,
        "1h": 3600,
        "2h": 7200,
        "3h": 10800,
        "4h": 14400,
        "6h": 21600,
        "8h": 28800,
        "12h": 43200,
        "daily": 86400,
    }
    if spec in mapping:
        return mapping[spec]
    if spec.endswith("m") and spec[:-1].isdigit():
        return max(900, int(spec[:-1]) * 60)
    if spec.endswith("h") and spec[:-1].isdigit():
        return max(3600, int(spec[:-1]) * 3600)
    raise ReconError(f"Unsupported interval: {spec}. Use 30m, 1h, 2h, 3h, 4h, 6h, 8h, 12h, or daily.")


def _calendar_interval(spec: str) -> dict[str, int] | None:
    spec = spec.strip().lower()
    if not spec.startswith("daily@"):
        return None
    raw = spec.split("@", 1)[1]
    parts = raw.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ReconError(f"Invalid daily schedule: {spec}")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ReconError(f"Invalid daily schedule: {spec}")
    return {"Hour": hour, "Minute": minute}


def install_service(paths: AppPaths, config: Config, logger: Logger, interval: str = "3h") -> Path:
    if os.uname().sysname != "Darwin":
        raise ReconError("LaunchAgent service installation is available only on macOS")
    plist_path = _plist_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    calendar = _calendar_interval(interval)
    seconds = _interval_seconds(interval) if calendar is None else 0
    wrapper = paths.root / "recon-monitor.sh"
    if not wrapper.exists():
        raise ReconError(f"Wrapper not found: {wrapper}")
    environment = {
        "PATH": ":".join(
            x
            for x in [
                "/usr/local/bin",
                "/opt/homebrew/bin",
                str(Path.home() / "go" / "bin"),
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
            if x
        )
    }
    payload: dict[str, Any] = {
        "Label": LABEL,
        "ProgramArguments": [str(wrapper), "run", "--no-progress"],
        "WorkingDirectory": str(paths.root),
        "RunAtLoad": False,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "StandardOutPath": str(paths.logs / "launchd.out.log"),
        "StandardErrorPath": str(paths.logs / "launchd.err.log"),
        "EnvironmentVariables": environment,
    }
    if calendar is not None:
        payload["StartCalendarInterval"] = calendar
    else:
        payload["StartInterval"] = seconds
    with plist_path.open("wb") as handle:
        plistlib.dump(payload, handle)
    os.chmod(plist_path, 0o600)
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc = subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise ReconError(f"launchctl bootstrap failed: {proc.stdout.strip()}")
    subprocess.run(["launchctl", "enable", f"gui/{os.getuid()}/{LABEL}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.info("LaunchAgent installed", path=str(plist_path), interval=interval, interval_seconds=seconds)
    return plist_path


def uninstall_service(logger: Logger) -> None:
    plist_path = _plist_path()
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    plist_path.unlink(missing_ok=True)
    logger.info("LaunchAgent removed", path=str(plist_path))


def service_status() -> tuple[bool, str]:
    proc = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc.returncode == 0, proc.stdout.strip()


def restart_service(logger: Logger) -> None:
    proc = subprocess.run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{LABEL}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise ReconError(f"LaunchAgent restart failed: {proc.stdout.strip()}")
    logger.info("LaunchAgent restarted")


def print_service_logs(paths: AppPaths, lines: int = 100) -> None:
    lines = parse_int(lines, 100, 1, 5000)
    for path in (paths.logs / "launchd.out.log", paths.logs / "launchd.err.log"):
        print(f"\n==> {path} <==")
        if not path.exists():
            print("(not created yet)")
            continue
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        print("\n".join(content[-lines:]))

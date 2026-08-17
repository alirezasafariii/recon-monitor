from __future__ import annotations

import contextlib
import os
import signal
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from core import AppPaths, Config, Logger, ReconError, atomic_write_text


def _pid_path(paths: AppPaths) -> Path:
    return paths.state / "dashboard.pid"


def _log_path(paths: AppPaths) -> Path:
    return paths.logs / "dashboard.log"


def _read_pid(paths: AppPaths) -> int | None:
    try:
        return int(_pid_path(paths).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int | None) -> bool:
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _dashboard_process_info(paths: AppPaths, pid: int | None) -> dict[str, Any] | None:
    """Validate that a PID-file process is this checkout's dashboard foreground process."""
    if not _alive(pid):
        return None
    assert pid is not None
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    command = result.stdout.strip()
    if not command:
        return None
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    expected_script = str((paths.app / "recon_monitor.py").resolve())
    script_indexes = [index for index, value in enumerate(parts) if value == expected_script]
    if not script_indexes:
        return None
    index = script_indexes[-1]
    tail = parts[index + 1:]
    if len(tail) < 2 or tail[0:2] != ["dashboard", "foreground"]:
        return None

    def option(name: str, default: str) -> str:
        try:
            option_index = tail.index(name)
            return tail[option_index + 1]
        except (ValueError, IndexError):
            return default

    host = option("--host", "127.0.0.1")
    try:
        port = int(option("--port", "8787"))
    except ValueError:
        port = 8787
    return {"pid": pid, "host": host, "port": port, "command": command}


def _tracked_dashboard(paths: AppPaths) -> dict[str, Any] | None:
    pid = _read_pid(paths)
    info = _dashboard_process_info(paths, pid)
    if info is not None:
        return info
    # A live but unrelated/reused PID must never be trusted or signalled.
    with contextlib.suppress(OSError):
        _pid_path(paths).unlink()
    return None


def dashboard_status(paths: AppPaths) -> tuple[bool, str]:
    info = _tracked_dashboard(paths)
    if info is None:
        return False, "Dashboard is not running"
    ready = _dashboard_listener_ready(str(info["host"]), int(info["port"]), timeout=0.2)
    suffix = "" if ready else " (process alive, listener unavailable)"
    return True, (
        f"Dashboard running (PID {info['pid']}) at "
        f"http://{info['host']}:{info['port']}{suffix}"
    )


def _dashboard_listener_ready(host: str, port: int, timeout: float = 0.5) -> bool:
    """Return True once the spawned dashboard is accepting TCP connections.

    Readiness stays independent from /health because that page intentionally
    performs operator diagnostics, including database integrity work.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _port_listener_details(host: str, port: int) -> dict[str, Any] | None:
    """Return a best-effort description when a TCP listener already owns the dashboard port.

    Detect occupancy with a bind probe instead of opening a client connection. This avoids
    consuming a listener's accept backlog and keeps repeated preflight checks reliable.
    """
    occupied = False
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        infos = []
    for family, socktype, proto, _canonname, sockaddr in infos:
        probe = socket.socket(family, socktype, proto)
        try:
            probe.bind(sockaddr)
        except OSError:
            occupied = True
            break
        finally:
            probe.close()
    if not occupied:
        return None

    details: dict[str, Any] = {
        "host": host,
        "port": port,
        "pid": None,
        "command": "",
        "cwd": "",
    }
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 2 and parts[1].isdigit():
                pid = int(parts[1])
                details["pid"] = pid
                ps = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "command="],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                details["command"] = ps.stdout.strip()
                cwd = subprocess.run(
                    ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                for line in cwd.stdout.splitlines():
                    if line.startswith("n"):
                        details["cwd"] = line[1:].strip()
                        break
    except (OSError, subprocess.SubprocessError):
        pass
    return details


def _recent_dashboard_log(paths: AppPaths, lines: int = 12) -> str:
    path = _log_path(paths)
    try:
        content = [
            line
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return ""
    return "\n".join(content[-max(1, lines):])


def start_dashboard(
    paths: AppPaths,
    config: Config,
    logger: Logger,
    host: str,
    port: int,
    allow_remote: bool,
    open_browser: bool = False,
) -> int:
    existing = _tracked_dashboard(paths)
    if existing is not None:
        existing_host = str(existing["host"])
        existing_port = int(existing["port"])
        existing_pid = int(existing["pid"])
        if existing_host != host or existing_port != port:
            raise ReconError(
                f"Dashboard is already running (PID {existing_pid}) at "
                f"http://{existing_host}:{existing_port}; requested http://{host}:{port}. "
                "Stop or restart the existing dashboard before changing host/port."
            )
        if not _dashboard_listener_ready(host, port, timeout=0.5):
            raise ReconError(
                f"Dashboard process PID {existing_pid} exists for http://{host}:{port} "
                "but is not accepting connections. Run dashboard stop, then start it again."
            )
        print(f"Dashboard running (PID {existing_pid}) at http://{host}:{port}")
        if open_browser:
            open_dashboard(host, port)
        return existing_pid

    listener = _port_listener_details(host, port)
    if listener:
        owner = f"PID {listener['pid']}" if listener.get("pid") else "another process"
        command = f"\nCommand: {listener['command']}" if listener.get("command") else ""
        cwd = f"\nWorking directory: {listener['cwd']}" if listener.get("cwd") else ""
        hint = (
            f"\nIf this is an older Recon Monitor instance, stop it there first. "
            f"Otherwise choose another port with: "
            f"./recon-monitor.sh dashboard start --port {port + 1} --open"
        )
        raise ReconError(
            f"Dashboard cannot start because {host}:{port} is already in use by {owner}."
            f"{command}{cwd}{hint}"
        )

    paths.logs.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(paths.app / "recon_monitor.py"),
        "dashboard",
        "foreground",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if allow_remote:
        command.append("--allow-remote")

    log_handle = _log_path(paths).open("a", encoding="utf-8")
    kwargs: dict[str, Any] = {
        "cwd": str(paths.root),
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "start_new_session": True,
    }
    process = subprocess.Popen(command, **kwargs)
    log_handle.close()
    atomic_write_text(_pid_path(paths), f"{process.pid}\n")

    deadline = time.time() + 20
    ready = False
    while time.time() < deadline:
        if process.poll() is not None:
            with contextlib.suppress(OSError):
                _pid_path(paths).unlink()
            tail = _recent_dashboard_log(paths)
            suffix = (
                f"\nLast dashboard log lines:\n{tail}"
                if tail
                else f"\nInspect {_log_path(paths)}"
            )
            raise ReconError(
                f"Dashboard exited early with code {process.returncode}.{suffix}"
            )
        if _dashboard_listener_ready(host, port):
            ready = True
            break
        time.sleep(0.2)

    if not ready:
        with contextlib.suppress(OSError):
            process.terminate()
        with contextlib.suppress(OSError):
            _pid_path(paths).unlink()
        tail = _recent_dashboard_log(paths)
        suffix = (
            f"\nLast dashboard log lines:\n{tail}"
            if tail
            else f"\nInspect {_log_path(paths)}"
        )
        raise ReconError(
            f"Dashboard process started but did not become ready on {host}:{port} "
            f"within the startup window.{suffix}"
        )

    logger.info(
        "Dashboard background service started",
        pid=process.pid,
        url=f"http://{host}:{port}",
    )
    print(f"Dashboard started: http://{host}:{port} (PID {process.pid})")
    if open_browser:
        open_dashboard(host, port)
    return process.pid


def stop_dashboard(paths: AppPaths, logger: Logger) -> bool:
    pid = _read_pid(paths)
    info = _dashboard_process_info(paths, pid)
    if info is None:
        with contextlib.suppress(OSError):
            _pid_path(paths).unlink()
        print("Dashboard is not running")
        return False
    assert pid is not None
    os.kill(pid, signal.SIGTERM)
    deadline = time.time() + 8
    while time.time() < deadline and _alive(pid):
        time.sleep(0.2)
    if _alive(pid):
        os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        _pid_path(paths).unlink()
    logger.info("Dashboard background service stopped", pid=pid)
    print("Dashboard stopped")
    return True


def restart_dashboard(
    paths: AppPaths,
    config: Config,
    logger: Logger,
    host: str,
    port: int,
    allow_remote: bool,
    open_browser: bool = False,
) -> int:
    stop_dashboard(paths, logger)
    return start_dashboard(paths, config, logger, host, port, allow_remote, open_browser)


def open_dashboard(host: str, port: int) -> None:
    url = f"http://{host}:{port}"
    if sys.platform == "darwin":
        subprocess.run(["open", url], check=False)
    elif sys.platform.startswith("linux"):
        subprocess.run(["xdg-open", url], check=False)
    else:
        print(url)


def print_dashboard_logs(paths: AppPaths, lines: int = 100) -> None:
    path = _log_path(paths)
    if not path.exists():
        print("No dashboard log exists")
        return
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    print("\n".join(content[-max(1, lines):]))

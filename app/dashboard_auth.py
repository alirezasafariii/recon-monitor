from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from core import AppPaths, Config, ReconError, atomic_write_text, parse_int

DEFAULT_ITERATIONS = 310_000


def hash_password(password: str, *, salt: bytes | None = None, iterations: int = DEFAULT_ITERATIONS) -> tuple[str, str, int]:
    if len(password) < 10:
        raise ReconError("Dashboard password must contain at least 10 characters")
    salt = salt or os.urandom(18)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return base64.urlsafe_b64encode(salt).decode("ascii"), base64.urlsafe_b64encode(digest).decode("ascii"), iterations


def verify_password(password: str, salt_b64: str, hash_b64: str, iterations: int) -> bool:
    try:
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(hash_b64.encode("ascii"))
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


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
    if output and output[-1].strip():
        output.append("")
    output.extend(f'{key}="{value}"' for key, value in remaining.items())
    atomic_write_text(path, "\n".join(output).rstrip() + "\n", 0o600)


def configure_auth(paths: AppPaths, username: str, password: str) -> None:
    username = username.strip()
    if not username or len(username) > 100 or any(ch in username for ch in ":\r\n"):
        raise ReconError("Dashboard username is invalid")
    salt, digest, iterations = hash_password(password)
    _update_env(
        paths.config,
        {
            "DASHBOARD_AUTH_ENABLED": "yes",
            "DASHBOARD_AUTH_USERNAME": username,
            "DASHBOARD_AUTH_SALT": salt,
            "DASHBOARD_AUTH_HASH": digest,
            "DASHBOARD_AUTH_ITERATIONS": str(iterations),
        },
    )


def disable_auth(paths: AppPaths) -> None:
    _update_env(
        paths.config,
        {
            "DASHBOARD_AUTH_ENABLED": "no",
            "DASHBOARD_AUTH_USERNAME": "",
            "DASHBOARD_AUTH_SALT": "",
            "DASHBOARD_AUTH_HASH": "",
        },
    )


def auth_status(config: Config) -> tuple[bool, str]:
    enabled = config.bool("DASHBOARD_AUTH_ENABLED", False)
    username = config.get("DASHBOARD_AUTH_USERNAME")
    configured = bool(username and config.get("DASHBOARD_AUTH_SALT") and config.get("DASHBOARD_AUTH_HASH"))
    if enabled and configured:
        return True, f"Dashboard authentication enabled for user: {username}"
    if enabled:
        return False, "Dashboard authentication is enabled but credentials are incomplete"
    return False, "Dashboard authentication is disabled"


def verify_basic_header(config: Config, header: str) -> bool:
    if not config.bool("DASHBOARD_AUTH_ENABLED", False):
        return True
    if not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        username, password = raw.split(":", 1)
    except Exception:
        return False
    expected_user = config.get("DASHBOARD_AUTH_USERNAME")
    user_ok = hmac.compare_digest(username.encode("utf-8"), expected_user.encode("utf-8"))
    password_ok = verify_password(
        password,
        config.get("DASHBOARD_AUTH_SALT"),
        config.get("DASHBOARD_AUTH_HASH"),
        parse_int(config.get("DASHBOARD_AUTH_ITERATIONS"), DEFAULT_ITERATIONS, 100_000, 2_000_000),
    )
    return user_ok and password_ok

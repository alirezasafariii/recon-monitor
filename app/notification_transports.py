from __future__ import annotations

"""Public notification transport interface.

Transport delivery is deliberately separate from Candidate/Admission state.  The
functions in this module may perform outbound notification delivery, but they do
not collect target-side evidence and never mutate security findings directly.
"""

import subprocess
from pathlib import Path
from typing import Any

from core import TelegramNotifier, tool_path


NOTIFICATION_TRANSPORTS_VERSION = "1.0.0"


def send_telegram(config: Any, logger: Any, message: str) -> tuple[bool, str]:
    try:
        notifier = TelegramNotifier(config, logger)
        if not notifier.ready:
            return False, "telegram_not_configured"
        return (True, "") if notifier.send(message) else (False, "telegram_delivery_failed")
    except Exception as exc:  # transport failures must not escape into Admission
        logger.warn("Telegram notification transport failed", error=str(exc))
        return False, str(exc)


def send_notify_cli(config: Any, logger: Any, message: str) -> tuple[bool, str]:
    provider_config = str(config.get("NOTIFY_PROVIDER_CONFIG") or "").strip()
    if not provider_config or not tool_path("notify"):
        return False, "notify_not_configured"
    path = Path(provider_config).expanduser()
    if not path.exists():
        logger.warn("Notify provider config not found", path=str(path))
        return False, "notify_provider_config_not_found"
    try:
        proc = subprocess.run(
            ["notify", "-silent", "-bulk", "-char-limit", "3500", "-provider-config", str(path)],
            input=message,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warn("Notify CLI failed", error=str(exc))
        return False, str(exc)
    if proc.returncode != 0:
        output = str(proc.stdout or "")[-500:]
        logger.warn("Notify CLI returned an error", output=output)
        return False, output or f"notify_exit_{proc.returncode}"
    return True, ""


def deliver_notification_message(config: Any, logger: Any, message: str) -> dict[str, Any]:
    """Attempt configured transports once and return a transport-neutral result."""

    telegram_ok, telegram_error = send_telegram(config, logger, message)
    notify_ok, notify_error = send_notify_cli(config, logger, message)
    channels = []
    if telegram_ok:
        channels.append("telegram")
    if notify_ok:
        channels.append("notify")
    errors = [
        value
        for value in (telegram_error, notify_error)
        if value and value not in {"telegram_not_configured", "notify_not_configured"}
    ]
    configured = not (
        telegram_error == "telegram_not_configured"
        and notify_error == "notify_not_configured"
    )
    if not channels and not errors and not configured:
        errors.append("no_configured_notification_transport")
    return {
        "version": NOTIFICATION_TRANSPORTS_VERSION,
        "delivered": bool(channels),
        "channels": channels,
        "channel": "+".join(channels),
        "error": "; ".join(errors),
    }

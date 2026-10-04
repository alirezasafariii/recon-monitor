"""Local, instance-bound API shutdown; no public endpoint or PID signals."""
from __future__ import annotations

import json
import os
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from core import AppPaths, ReconError, atomic_write_text, json_dumps


def valid_control_instance(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


class APIProcessControl:
    def __init__(self, paths: AppPaths, instance: str):
        if not valid_control_instance(instance):
            raise ReconError("Invalid API control instance")
        self.instance = instance
        self.path = paths.state / f"api-stop-{instance}.json"

    def _read(self) -> dict[str, Any]:
        try:
            with self.path.open(encoding="utf-8") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                return {}
            record = json.loads(raw)
        except (OSError, UnicodeError, ValueError):
            return {}
        if not isinstance(record, dict) or record.get("control_instance") != self.instance:
            return {}
        return record

    def request_stop(self, pid: int) -> None:
        # A retry must not overwrite an acknowledgement already written after
        # the listener closed, even if the process has since exited.
        if not self.is_stopped(pid):
            self._write({"action": "stop", "pid": pid})

    def stop_requested(self) -> bool:
        record = self._read()
        return record.get("action") == "stop" and self._matches_pid(record, os.getpid())

    def acknowledge_stop(self) -> None:
        self._write({"status": "stopped", "pid": os.getpid()})

    def is_stopped(self, pid: int) -> bool:
        record = self._read()
        return record.get("status") == "stopped" and self._matches_pid(record, pid)

    @staticmethod
    def _matches_pid(record: dict[str, Any], pid: int) -> bool:
        value = record.get("pid")
        return type(value) is int and value == pid

    def _write(self, record: dict[str, Any]) -> None:
        atomic_write_text(
            self.path,
            json_dumps({"control_instance": self.instance, **record}) + "\n",
            mode=0o600,
        )


class ControlledAPIHTTPServer(ThreadingHTTPServer):
    def __init__(self, address, handler, control: APIProcessControl | None = None):
        self.control = control
        self.control_stop_requested = False
        super().__init__(address, handler)

    def service_actions(self) -> None:
        if self.control and not self.control_stop_requested and self.control.stop_requested():
            self.control_stop_requested = True
            # BaseServer.shutdown() waits for serve_forever to finish, so it
            # must run outside the thread executing this service_actions hook.
            threading.Thread(target=self.shutdown, daemon=True).start()

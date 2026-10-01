from __future__ import annotations

import json
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server_core as api
from core import AppPaths


class APIIdentityRegressionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.pid_path, _ = api.api_paths(self.paths)
        self.pid_path.write_text("42424242\n")
        for name in ("socket.getaddrinfo", "socket.socket.connect", "subprocess.Popen"):
            guard = patch(name, side_effect=AssertionError("PID regression attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_status_does_not_trust_a_live_unrelated_pid(self):
        unrelated = subprocess.CompletedProcess([], 0, stdout="/usr/bin/python unrelated.py", stderr="")
        with patch("api_server_core.os.kill"), patch("api_server_core.subprocess.run", return_value=unrelated):
            active, detail = api.api_status(self.paths)
        self.assertFalse(active, detail)

    def test_legacy_plain_pid_file_is_still_checked_by_command_identity(self):
        self.pid_path.write_text("42424242\n", encoding="utf-8")
        command = (
            f"/usr/bin/python {self.paths.app / 'recon_monitor.py'} "
            "api foreground --host 127.0.0.1 --port 8790"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=command, stderr="")
        with patch("api_server_core.os.kill"), patch("api_server_core.subprocess.run", return_value=completed):
            active, detail = api.api_status(self.paths)
        self.assertTrue(active, detail)
        self.assertIn(":8790", detail)

    def test_stop_does_not_signal_a_live_unrelated_pid(self):
        unrelated = subprocess.CompletedProcess([], 0, stdout="/usr/bin/python unrelated.py", stderr="")
        with patch("api_server_core.os.kill") as kill, patch("api_server_core.subprocess.run", return_value=unrelated), patch("api_server_core.time.sleep"):
            stopped = api.stop_api(self.paths)
        self.assertFalse(stopped)
        self.assertFalse(any(call.args[1] == signal.SIGTERM for call in kill.call_args_list))

    def test_status_accepts_only_this_checkout_api_foreground_command(self):
        self.pid_path.write_text(
            '{"pid": 42424242, "start_token": "boot-start-1"}\n',
            encoding="utf-8",
        )
        command = (
            f"/usr/bin/python {self.paths.app / 'recon_monitor.py'} "
            "api foreground --host 127.0.0.1 --port 9090"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=command, stderr="")
        with patch("api_server_core.os.kill"), \
             patch("api_server_core._process_start_token", return_value="boot-start-1"), \
             patch("api_server_core.subprocess.run", return_value=completed):
            active, detail = api.api_status(self.paths)
        self.assertTrue(active, detail)
        self.assertIn("PID 42424242", detail)
        self.assertIn(":9090", detail)

    def test_start_token_mismatch_refuses_same_command_after_pid_reuse(self):
        self.pid_path.write_text(
            '{"pid": 42424242, "start_token": "old-process"}\n',
            encoding="utf-8",
        )
        command = (
            f"/usr/bin/python {self.paths.app / 'recon_monitor.py'} "
            "api foreground --host 127.0.0.1 --port 9090"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=command, stderr="")
        with patch("api_server_core.os.kill") as kill, \
             patch("api_server_core._process_start_token", return_value="new-process"), \
             patch("api_server_core.subprocess.run", return_value=completed):
            stopped = api.stop_api(self.paths)
        self.assertFalse(stopped)
        self.assertFalse(any(call.args[1] in {signal.SIGTERM, signal.SIGKILL} for call in kill.call_args_list))

    def test_start_writes_json_process_identity_record(self):
        process = subprocess.CompletedProcess([], 0)
        process.pid = 4242
        with patch("api_server_core.subprocess.Popen", return_value=process), \
             patch("api_server_core._process_start_token", return_value="start-4242"), \
             patch("api_server_core.time.sleep"):
            self.assertEqual(api.start_api(self.paths, "127.0.0.1", 9090), 4242)
        record = json.loads(self.pid_path.read_text(encoding="utf-8"))
        self.assertEqual(record["pid"], 4242)
        self.assertEqual(record["start_token"], "start-4242")


if __name__ == "__main__":
    unittest.main()

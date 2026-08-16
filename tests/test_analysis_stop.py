from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP_DIR = Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import analysis_engine
from core import AppPaths, ReconError
from progress_tracking import ProgressRecord, _health, stop_analysis


class InterruptDB:
    def __init__(self):
        self.executed = []
        self.audits = []

    def one(self, sql, params=()):
        if "FROM analysis_runs" in sql:
            return {"id": "analysis-int"}
        return None

    def execute(self, sql, params=()):
        self.executed.append((sql, params))

    def audit(self, event, **kwargs):
        self.audits.append((event, kwargs))


class StopDB:
    def __init__(self):
        self.row = {
            "id": "analysis-stop",
            "source_run_id": "run-stop",
            "target": "example.com",
            "status": "running",
            "started_at": "2026-08-17T00:00:00Z",
        }
        self.executed = []
        self.audits = []

    def one(self, sql, params=()):
        if "FROM analysis_runs" in sql:
            return self.row
        return None

    def execute(self, sql, params=()):
        self.executed.append((sql, params))

    def audit(self, event, **kwargs):
        self.audits.append((event, kwargs))


class AnalysisStopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()

    def tearDown(self):
        self.temp.cleanup()

    def test_keyboard_interrupt_finalizes_analysis_row(self):
        db = InterruptDB()
        with patch.object(analysis_engine, "_run_analysis_impl", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                analysis_engine.run_analysis(self.paths, db, "run-int", "example.com")
        self.assertTrue(any("status='interrupted'" in sql for sql, _ in db.executed))
        self.assertTrue(any(event == "analysis_interrupted" for event, _ in db.audits))

    def test_progress_record_persists_pid_and_interruption_is_cancelled_health(self):
        record = ProgressRecord(self.paths, "analysis", "run-pid", "example.com")
        record.start(phase="initializing", label="Initializing")
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["pid"], os.getpid())
        record.finish(status="interrupted", error="operator stop")
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "interrupted")
        self.assertEqual(payload["phase"], "interrupted")
        self.assertEqual(_health("interrupted", payload["heartbeat_at"])[0], "cancelled")

    def test_stop_analysis_sends_sigint_and_repairs_state_after_exit(self):
        db = StopDB()
        record = ProgressRecord(self.paths, "analysis", "run-stop", "example.com")
        record.start(phase="security_reasoning", label="Security reasoning", percent=82)
        record.bind_analysis_id("analysis-stop")
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        payload["pid"] = 4242
        record.path.write_text(json.dumps(payload), encoding="utf-8")
        command = "/usr/bin/python /tmp/recon-monitor/app/recon_monitor.py analyze --run run-stop --target example.com"
        with patch("progress_tracking.process_alive", side_effect=[True, False]), \
             patch("progress_tracking._analysis_process_command", return_value=command), \
             patch("progress_tracking.os.kill") as kill_process:
            result = stop_analysis(self.paths, db, analysis_id="analysis-stop")
        kill_process.assert_called_once_with(4242, signal.SIGINT)
        self.assertTrue(result["stopped"])
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["signals_sent"], ["SIGINT"])
        self.assertTrue(any("status='interrupted'" in sql for sql, _ in db.executed))

    def test_stop_analysis_refuses_pid_identity_mismatch(self):
        db = StopDB()
        record = ProgressRecord(self.paths, "analysis", "run-stop", "example.com")
        record.start(phase="security_reasoning", label="Security reasoning", percent=82)
        record.bind_analysis_id("analysis-stop")
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        payload["pid"] = 4242
        record.path.write_text(json.dumps(payload), encoding="utf-8")
        with patch("progress_tracking.process_alive", return_value=True), \
             patch("progress_tracking._analysis_process_command", return_value="/usr/bin/python unrelated.py"), \
             patch("progress_tracking.os.kill") as kill_process:
            with self.assertRaises(ReconError):
                stop_analysis(self.paths, db, analysis_id="analysis-stop")
        kill_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()

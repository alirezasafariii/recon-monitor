from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core import AppPaths
from progress_tracking import (
    ANALYSIS_PHASES,
    AnalysisProgress,
    ProgressRecord,
    _health,
    _progress_panel,
    analysis_progress_snapshot,
    recon_progress_snapshot,
)


def _paths(root: Path) -> AppPaths:
    paths = AppPaths.from_root(root)
    paths.ensure()
    return paths


class FakeDB:
    def __init__(self, *, analysis=None, alerts=0, results=0, activity="", recon=None, stages=None):
        self.analysis = analysis
        self.alerts = alerts
        self.results = results
        self.activity = activity
        self.recon = recon
        self.stages = list(stages or [])

    def one(self, sql, params=()):
        if "FROM analysis_runs" in sql:
            return self.analysis
        if "MAX(" in sql:
            return {"value": self.activity} if self.activity else {"value": None}
        if "COUNT(*) count FROM alerts" in sql:
            return {"count": self.alerts}
        if "COUNT(*) count FROM analysis_results" in sql:
            return {"count": self.results}
        if "FROM run_targets rt JOIN runs" in sql:
            return self.recon
        return None

    def all(self, sql, params=()):
        if "FROM stage_runs" in sql:
            return self.stages
        return []


class ProgressTrackingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = _paths(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_progress_record_persists_monotonic_percent_and_completion(self):
        record = ProgressRecord(self.paths, "analysis", "run-1", "example.com")
        record.start(phase="initializing", label="Initializing", percent=1)
        record.update(phase="work", label="Work", percent=40, current=4, total=10)
        record.update(percent=20, current=5, total=10)
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["estimated_percent"], 40.0)
        self.assertEqual(payload["current"], 5)
        self.assertEqual(payload["total"], 10)
        self.assertEqual(payload["status"], "running")
        record.finish(status="success")
        payload = json.loads(record.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["estimated_percent"], 100.0)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["phase"], "completed")

    def test_health_distinguishes_live_waiting_and_stalled(self):
        now = dt.datetime.now(dt.timezone.utc)
        fresh = (now - dt.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
        waiting = (now - dt.timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
        stale = (now - dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        self.assertEqual(_health("running", fresh)[0], "progressing")
        self.assertEqual(_health("running", waiting)[0], "waiting")
        self.assertEqual(_health("running", stale)[0], "stalled")
        self.assertEqual(_health("failed", fresh)[0], "failed")
        self.assertEqual(_health("success", fresh)[0], "completed")

    def test_analysis_phase_weights_cover_full_pipeline_without_time_claims(self):
        self.assertEqual(ANALYSIS_PHASES[0][2], 0.0)
        self.assertEqual(ANALYSIS_PHASES[-1][3], 100.0)
        previous_end = 0.0
        for _name, _label, start, end in ANALYSIS_PHASES:
            self.assertEqual(start, previous_end)
            self.assertGreaterEqual(end, start)
            previous_end = end

    def test_analysis_progress_uses_real_alert_counter_inside_first_heavy_phase(self):
        db = FakeDB(alerts=10)
        tracker = AnalysisProgress(self.paths, db, "run-1", "example.com")
        tracker.start()
        tracker.set_targets(2)
        for _ in range(5):
            tracker.advance_alert()
        payload = json.loads(tracker.record.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["phase"], "alert_enrichment")
        self.assertEqual(payload["phase_percent"], 50.0)
        self.assertEqual(payload["estimated_percent"], 12.0)
        tracker.record.stop_heartbeat()

    def test_analysis_snapshot_reports_live_heartbeat_and_phase(self):
        analysis = {
            "id": "analysis-1", "source_run_id": "run-1", "target": "example.com",
            "status": "running", "started_at": "2026-08-16T20:00:00Z",
            "finished_at": None, "error": None,
        }
        db = FakeDB(analysis=analysis, alerts=10, results=3)
        record = ProgressRecord(self.paths, "analysis", "run-1", "example.com")
        record.start(phase="semantic_intelligence", label="Semantic intelligence", percent=45)
        record.bind_analysis_id("analysis-1")
        snapshot = analysis_progress_snapshot(self.paths, db, "example.com")
        self.assertEqual(snapshot["visibility"], "live")
        self.assertEqual(snapshot["health"], "progressing")
        self.assertEqual(snapshot["estimated_percent"], 45.0)
        self.assertEqual(snapshot["phase"], "semantic_intelligence")

    def test_legacy_running_analysis_never_invents_late_phase_percentage(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        analysis = {
            "id": "analysis-old", "source_run_id": "run-old", "target": "example.com",
            "status": "running", "started_at": "2026-08-16T20:00:00Z",
            "finished_at": None, "error": None,
        }
        db = FakeDB(analysis=analysis, alerts=10, results=10, activity=now)
        snapshot = analysis_progress_snapshot(self.paths, db, "example.com")
        self.assertEqual(snapshot["visibility"], "legacy")
        self.assertIsNone(snapshot["estimated_percent"])
        self.assertEqual(snapshot["health"], "progressing")
        self.assertIn("precise heartbeat is unavailable", snapshot["health_detail"])

    def test_legacy_alert_loop_can_show_counter_backed_progress(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        analysis = {
            "id": "analysis-old", "source_run_id": "run-old", "target": "example.com",
            "status": "running", "started_at": "2026-08-16T20:00:00Z",
            "finished_at": None, "error": None,
        }
        db = FakeDB(analysis=analysis, alerts=20, results=5, activity=now)
        snapshot = analysis_progress_snapshot(self.paths, db, "example.com")
        self.assertEqual(snapshot["phase"], "alert_enrichment")
        self.assertEqual(snapshot["phase_percent"], 25.0)
        self.assertEqual(snapshot["estimated_percent"], 7.0)

    def test_recon_snapshot_combines_stage_heartbeat_and_counter_progress(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        recon = {
            "run_id": "run-r", "target": "example.com", "status": "running",
            "started_at": "2026-08-16T20:00:00Z", "finished_at": None,
            "current_stage": "dns", "run_dir": "/tmp/run", "run_status": "running",
        }
        stages = [
            {"stage": "subdomains", "status": "success", "started_at": now, "finished_at": now, "heartbeat_at": now, "duration_seconds": 12, "metrics_json": "{}", "error": None},
            {"stage": "dns", "status": "running", "started_at": now, "finished_at": None, "heartbeat_at": now, "duration_seconds": None, "metrics_json": "{}", "error": None},
        ]
        record = ProgressRecord(self.paths, "recon", "run-r", "example.com")
        record.start(phase="dns", label="DNS resolution", percent=11.1)
        record.update(phase="dns", label="DNS resolution", percent=16.7, phase_percent=50, current=50, total=100)
        db = FakeDB(recon=recon, stages=stages)
        snapshot = recon_progress_snapshot(self.paths, db, "example.com")
        self.assertEqual(snapshot["health"], "progressing")
        self.assertEqual(snapshot["phase"], "dns")
        self.assertEqual(snapshot["phase_percent"], 50.0)
        self.assertEqual(snapshot["current"], 50)
        self.assertEqual(snapshot["total"], 100)
        self.assertEqual(snapshot["stages"][0]["status"], "success")
        self.assertEqual(snapshot["stages"][1]["status"], "running")

    def test_progress_panel_labels_estimate_and_auto_refresh_for_running(self):
        base = SimpleNamespace(_esc=lambda value: str(value), _pill=lambda value, tone="": f"[{value}:{tone}]")
        html = _progress_panel(base, {
            "status": "running", "health": "progressing", "estimated_percent": 42.5,
            "phase_label": "Security reasoning", "current": 0, "total": 0,
            "elapsed_seconds": 7200, "heartbeat_age_seconds": 4, "progress_age_seconds": 90,
            "health_detail": "Heartbeat is fresh", "message": "Security reasoning",
            "visibility": "live", "stages": [],
        }, "Live Analysis Progress")
        self.assertIn("42.5%", html)
        self.assertIn("work completion, not time remaining", html)
        self.assertIn("location.reload", html)
        self.assertIn("Security reasoning", html)

    def test_progress_panel_does_not_auto_refresh_completed_operation(self):
        base = SimpleNamespace(_esc=lambda value: str(value), _pill=lambda value, tone="": f"[{value}:{tone}]")
        html = _progress_panel(base, {
            "status": "success", "health": "completed", "estimated_percent": 100,
            "phase_label": "Completed", "elapsed_seconds": 12,
            "health_detail": "Completed successfully", "message": "", "stages": [],
        }, "Live Recon Progress")
        self.assertIn("100.0%", html)
        self.assertNotIn("location.reload", html)


if __name__ == "__main__":
    unittest.main()

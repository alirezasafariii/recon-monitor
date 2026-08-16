from __future__ import annotations

import datetime as dt
import json
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


def _paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths.from_root(tmp_path)
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


def test_progress_record_persists_monotonic_percent_and_completion(tmp_path):
    paths = _paths(tmp_path)
    record = ProgressRecord(paths, "analysis", "run-1", "example.com")
    record.start(phase="initializing", label="Initializing", percent=1)
    record.update(phase="work", label="Work", percent=40, current=4, total=10)
    record.update(percent=20, current=5, total=10)

    payload = json.loads(record.path.read_text(encoding="utf-8"))
    assert payload["estimated_percent"] == 40.0
    assert payload["current"] == 5
    assert payload["total"] == 10
    assert payload["status"] == "running"

    record.finish(status="success")
    payload = json.loads(record.path.read_text(encoding="utf-8"))
    assert payload["estimated_percent"] == 100.0
    assert payload["status"] == "success"
    assert payload["phase"] == "completed"


def test_health_distinguishes_live_waiting_and_stalled():
    now = dt.datetime.now(dt.timezone.utc)
    fresh = (now - dt.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    waiting = (now - dt.timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    stale = (now - dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")

    assert _health("running", fresh)[0] == "progressing"
    assert _health("running", waiting)[0] == "waiting"
    assert _health("running", stale)[0] == "stalled"
    assert _health("failed", fresh)[0] == "failed"
    assert _health("success", fresh)[0] == "completed"


def test_analysis_phase_weights_cover_full_pipeline_without_time_claims():
    assert ANALYSIS_PHASES[0][2] == 0.0
    assert ANALYSIS_PHASES[-1][3] == 100.0
    previous_end = 0.0
    for _name, _label, start, end in ANALYSIS_PHASES:
        assert start == previous_end
        assert end >= start
        previous_end = end


def test_analysis_progress_uses_real_alert_counter_inside_first_heavy_phase(tmp_path):
    paths = _paths(tmp_path)
    db = FakeDB(alerts=10)
    tracker = AnalysisProgress(paths, db, "run-1", "example.com")
    tracker.start()
    tracker.set_targets(2)
    for _ in range(5):
        tracker.advance_alert()

    payload = json.loads(tracker.record.path.read_text(encoding="utf-8"))
    assert payload["phase"] == "alert_enrichment"
    assert payload["phase_percent"] == 50.0
    assert payload["estimated_percent"] == 12.0
    tracker.record.stop_heartbeat()


def test_analysis_snapshot_reports_live_heartbeat_and_phase(tmp_path):
    paths = _paths(tmp_path)
    analysis = {
        "id": "analysis-1", "source_run_id": "run-1", "target": "example.com",
        "status": "running", "started_at": "2026-08-16T20:00:00Z",
        "finished_at": None, "error": None,
    }
    db = FakeDB(analysis=analysis, alerts=10, results=3)
    record = ProgressRecord(paths, "analysis", "run-1", "example.com")
    record.start(phase="semantic_intelligence", label="Semantic intelligence", percent=45)
    record.bind_analysis_id("analysis-1")

    snapshot = analysis_progress_snapshot(paths, db, "example.com")
    assert snapshot["visibility"] == "live"
    assert snapshot["health"] == "progressing"
    assert snapshot["estimated_percent"] == 45.0
    assert snapshot["phase"] == "semantic_intelligence"


def test_legacy_running_analysis_never_invents_late_phase_percentage(tmp_path):
    paths = _paths(tmp_path)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    analysis = {
        "id": "analysis-old", "source_run_id": "run-old", "target": "example.com",
        "status": "running", "started_at": "2026-08-16T20:00:00Z",
        "finished_at": None, "error": None,
    }
    db = FakeDB(analysis=analysis, alerts=10, results=10, activity=now)

    snapshot = analysis_progress_snapshot(paths, db, "example.com")
    assert snapshot["visibility"] == "legacy"
    assert snapshot["estimated_percent"] is None
    assert snapshot["health"] == "progressing"
    assert "precise heartbeat is unavailable" in snapshot["health_detail"]


def test_legacy_alert_loop_can_show_counter_backed_progress(tmp_path):
    paths = _paths(tmp_path)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    analysis = {
        "id": "analysis-old", "source_run_id": "run-old", "target": "example.com",
        "status": "running", "started_at": "2026-08-16T20:00:00Z",
        "finished_at": None, "error": None,
    }
    db = FakeDB(analysis=analysis, alerts=20, results=5, activity=now)

    snapshot = analysis_progress_snapshot(paths, db, "example.com")
    assert snapshot["phase"] == "alert_enrichment"
    assert snapshot["phase_percent"] == 25.0
    assert snapshot["estimated_percent"] == 7.0


def test_recon_snapshot_combines_stage_heartbeat_and_counter_progress(tmp_path):
    paths = _paths(tmp_path)
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
    record = ProgressRecord(paths, "recon", "run-r", "example.com")
    record.start(phase="dns", label="DNS resolution", percent=11.1)
    record.update(phase="dns", label="DNS resolution", percent=16.7, phase_percent=50, current=50, total=100)
    db = FakeDB(recon=recon, stages=stages)

    snapshot = recon_progress_snapshot(paths, db, "example.com")
    assert snapshot["health"] == "progressing"
    assert snapshot["phase"] == "dns"
    assert snapshot["phase_percent"] == 50.0
    assert snapshot["current"] == 50
    assert snapshot["total"] == 100
    assert snapshot["stages"][0]["status"] == "success"
    assert snapshot["stages"][1]["status"] == "running"


def test_progress_panel_labels_estimate_and_auto_refresh_for_running():
    base = SimpleNamespace(
        _esc=lambda value: str(value),
        _pill=lambda value, tone="": f"[{value}:{tone}]",
    )
    html = _progress_panel(base, {
        "status": "running", "health": "progressing", "estimated_percent": 42.5,
        "phase_label": "Security reasoning", "current": 0, "total": 0,
        "elapsed_seconds": 7200, "heartbeat_age_seconds": 4, "progress_age_seconds": 90,
        "health_detail": "Heartbeat is fresh", "message": "Security reasoning",
        "visibility": "live", "stages": [],
    }, "Live Analysis Progress")
    assert "42.5%" in html
    assert "work completion, not time remaining" in html
    assert "location.reload" in html
    assert "Security reasoning" in html


def test_progress_panel_does_not_auto_refresh_completed_operation():
    base = SimpleNamespace(
        _esc=lambda value: str(value),
        _pill=lambda value, tone="": f"[{value}:{tone}]",
    )
    html = _progress_panel(base, {
        "status": "success", "health": "completed", "estimated_percent": 100,
        "phase_label": "Completed", "elapsed_seconds": 12,
        "health_detail": "Completed successfully", "message": "", "stages": [],
    }, "Live Recon Progress")
    assert "100.0%" in html
    assert "location.reload" not in html

from __future__ import annotations

"""Live progress and liveness tracking for Recon and Analysis operations.

This module is intentionally observational. It does not change Recon output,
Analysis evidence, Admission, Candidate promotion, or validation behavior.
Progress percentages are either based on concrete work counters or documented
pipeline phase weights and are therefore estimates, not time-remaining claims.
"""

import contextlib
import datetime as dt
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from core import AppPaths, ReconError, atomic_write_text, json_dumps, process_alive, safe_filename, utc_now

PROGRESS_TRACKING_VERSION = "1.0.0"
PROGRESS_TRACKING_RULE_VERSION = "2026.08.17.2"
HEARTBEAT_INTERVAL_SECONDS = 10
HEALTH_ACTIVE_SECONDS = 35
HEALTH_WAITING_SECONDS = 120

RECON_STAGES: tuple[tuple[str, str], ...] = (
    ("subdomains", "Subdomain discovery"),
    ("dns", "DNS resolution"),
    ("urls", "URL collection"),
    ("javascript", "JavaScript analysis"),
    ("endpoint_validation", "Endpoint validation"),
    ("fingerprint", "HTTP fingerprinting"),
    ("ports", "Port monitoring"),
    ("nuclei", "Allowlisted active checks"),
    ("report", "Reporting and analysis"),
)
RECON_STAGE_INDEX = {name: index for index, (name, _label) in enumerate(RECON_STAGES, 1)}
RECON_STAGE_LABEL = dict(RECON_STAGES)

# Work-share estimates, not duration estimates. Fine-grained counters override
# phase interpolation whenever a real denominator is available.
ANALYSIS_PHASES: tuple[tuple[str, str, float, float], ...] = (
    ("initializing", "Initializing analysis", 0.0, 2.0),
    ("alert_enrichment", "Alert and endpoint enrichment", 2.0, 22.0),
    ("static_intelligence", "Static target intelligence", 22.0, 42.0),
    ("semantic_intelligence", "Semantic intelligence", 42.0, 50.0),
    ("behavioral_intelligence", "Behavioral intelligence", 50.0, 58.0),
    ("candidate_generation", "Potential finding generation", 58.0, 68.0),
    ("behavioral_candidates", "Behavioral candidate reconciliation", 68.0, 72.0),
    ("candidate_reliability", "Candidate reliability", 72.0, 78.0),
    ("security_reasoning", "Security reasoning", 78.0, 88.0),
    ("candidate_bundles", "Evidence bundle construction", 88.0, 91.0),
    ("platform_sync", "Platform synchronization", 91.0, 94.0),
    ("workspace_sync", "Workspace synchronization", 94.0, 97.0),
    ("quality_snapshot", "Quality snapshot", 97.0, 99.0),
    ("finalizing", "Finalizing analysis", 99.0, 100.0),
)
ANALYSIS_PHASE_MAP = {name: (label, start, end) for name, label, start, end in ANALYSIS_PHASES}

_INSTALL_LOCK = threading.Lock()
_INSTALLED = False
_CURRENT_ANALYSIS = threading.local()


def _progress_dir(paths: AppPaths) -> Path:
    path = paths.state / "progress"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _progress_path(paths: AppPaths, kind: str, run_id: str, target: str) -> Path:
    return _progress_dir(paths) / f"{safe_filename(kind)}-{safe_filename(run_id)}-{safe_filename(target or 'all')}.json"


def _parse_time(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _age_seconds(value: Any) -> float | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return max(0.0, (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds())


def _elapsed_seconds(started_at: Any, finished_at: Any = None) -> float | None:
    started = _parse_time(started_at)
    if started is None:
        return None
    finished = _parse_time(finished_at) or dt.datetime.now(dt.timezone.utc)
    return max(0.0, (finished - started).total_seconds())


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _health(status: str, heartbeat_at: Any, *, heartbeat_available: bool = True) -> tuple[str, str]:
    normalized = str(status or "").lower()
    if normalized == "success":
        return "completed", "Completed successfully"
    if normalized in {"interrupted", "cancelled"}:
        return "cancelled", "Operation was stopped before completion"
    if normalized == "failed":
        return "failed", "Operation stopped with an error"
    if normalized == "stale":
        return "stale", "Stored Analysis state says running, but no matching live process could be verified"
    if normalized != "running":
        return "unknown", "No active operation"
    if not heartbeat_available:
        return "unknown", "This run started without live heartbeat instrumentation"
    age = _age_seconds(heartbeat_at)
    if age is None:
        return "unknown", "No heartbeat has been recorded yet"
    if age <= HEALTH_ACTIVE_SECONDS:
        return "progressing", "Heartbeat is fresh; the process is alive"
    if age <= HEALTH_WAITING_SECONDS:
        return "waiting", "Heartbeat is delayed; the process may be in a blocking operation"
    return "stalled", "Heartbeat is stale; inspect logs/process state"


def _format_seconds(value: float | None) -> str:
    if value is None:
        return "—"
    seconds = int(max(0, value))
    hours, rem = divmod(seconds, 3600)
    minutes, sec = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


class ProgressRecord:
    def __init__(self, paths: AppPaths, kind: str, run_id: str, target: str):
        self.paths = paths
        self.kind = str(kind)
        self.run_id = str(run_id)
        self.target = str(target or "*")
        self.path = _progress_path(paths, self.kind, self.run_id, self.target)
        self._lock = threading.RLock()
        self._data = _load_json(self.path)
        self._heartbeat_stop: threading.Event | None = None
        self._heartbeat_thread: threading.Thread | None = None

    @property
    def data(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)

    def _write(self) -> None:
        atomic_write_text(self.path, json_dumps(self._data, pretty=True) + "\n")

    def start(self, *, phase: str, label: str, percent: float = 0.0, message: str = "") -> None:
        with self._lock:
            now = utc_now()
            self._data = {
                "version": PROGRESS_TRACKING_VERSION,
                "rule_version": PROGRESS_TRACKING_RULE_VERSION,
                "kind": self.kind,
                "run_id": self.run_id,
                "target": self.target,
                "analysis_id": "",
                "pid": os.getpid(),
                "process_group_id": os.getpgrp() if hasattr(os, "getpgrp") else None,
                "status": "running",
                "phase": phase,
                "phase_label": label,
                "estimated_percent": round(max(0.0, min(100.0, float(percent))), 1),
                "phase_percent": None,
                "current": None,
                "total": None,
                "message": message,
                "started_at": now,
                "updated_at": now,
                "heartbeat_at": now,
                "last_progress_at": now,
                "finished_at": None,
                "error": "",
                "percent_semantics": "estimated_work_completion_not_time_remaining",
            }
            self._write()

    def bind_analysis_id(self, analysis_id: str) -> None:
        if not analysis_id:
            return
        with self._lock:
            if self._data.get("analysis_id") == analysis_id:
                return
            self._data["analysis_id"] = str(analysis_id)
            self._data["updated_at"] = utc_now()
            self._write()

    def update(
        self,
        *,
        phase: str | None = None,
        label: str | None = None,
        percent: float | None = None,
        phase_percent: float | None = None,
        current: int | None = None,
        total: int | None = None,
        message: str | None = None,
        progress_changed: bool = True,
    ) -> None:
        with self._lock:
            now = utc_now()
            before = (
                self._data.get("phase"), self._data.get("estimated_percent"),
                self._data.get("current"), self._data.get("total"), self._data.get("message"),
            )
            if phase is not None:
                self._data["phase"] = phase
            if label is not None:
                self._data["phase_label"] = label
            if percent is not None:
                previous = float(self._data.get("estimated_percent") or 0.0)
                self._data["estimated_percent"] = round(max(previous, min(100.0, float(percent))), 1)
            if phase_percent is not None:
                self._data["phase_percent"] = round(max(0.0, min(100.0, float(phase_percent))), 1)
            elif phase is not None:
                self._data["phase_percent"] = None
            if current is not None:
                self._data["current"] = int(current)
            if total is not None:
                self._data["total"] = int(total)
            if message is not None:
                self._data["message"] = str(message)[:500]
            self._data["status"] = "running"
            self._data["updated_at"] = now
            self._data["heartbeat_at"] = now
            after = (
                self._data.get("phase"), self._data.get("estimated_percent"),
                self._data.get("current"), self._data.get("total"), self._data.get("message"),
            )
            if progress_changed and after != before:
                self._data["last_progress_at"] = now
            self._write()

    def heartbeat(self) -> None:
        with self._lock:
            if self._data.get("status") != "running":
                return
            now = utc_now()
            self._data["heartbeat_at"] = now
            self._data["updated_at"] = now
            self._write()

    def finish(self, *, status: str = "success", error: str = "") -> None:
        with self._lock:
            now = utc_now()
            normalized = str(status or "success")
            self._data["status"] = normalized
            if normalized == "success":
                self._data["estimated_percent"] = 100.0
                self._data["phase_percent"] = 100.0
                self._data["phase"] = "completed"
                self._data["phase_label"] = "Completed"
            elif normalized in {"interrupted", "cancelled"}:
                self._data["phase"] = "interrupted"
                self._data["phase_label"] = "Stopped"
                self._data["message"] = "Stopped before completion"
            self._data["error"] = str(error or "")[:4000]
            self._data["heartbeat_at"] = now
            self._data["updated_at"] = now
            self._data["finished_at"] = now
            self._write()

    def start_heartbeat(self) -> None:
        with self._lock:
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                return
            stop = threading.Event()
            self._heartbeat_stop = stop

            def worker() -> None:
                while not stop.wait(HEARTBEAT_INTERVAL_SECONDS):
                    with contextlib.suppress(Exception):
                        self.heartbeat()

            self._heartbeat_thread = threading.Thread(
                target=worker,
                name=f"recon-monitor-{self.kind}-heartbeat",
                daemon=True,
            )
            self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        with self._lock:
            stop = self._heartbeat_stop
            thread = self._heartbeat_thread
            self._heartbeat_stop = None
            self._heartbeat_thread = None
        if stop:
            stop.set()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=1.0)


class AnalysisProgress:
    def __init__(self, paths: AppPaths, db: Any, run_id: str, target: str | None):
        self.paths = paths
        self.db = db
        self.run_id = str(run_id)
        self.target = str(target or "*")
        self.record = ProgressRecord(paths, "analysis", self.run_id, self.target)
        self.alert_total = 0
        self.alert_current = 0
        self.target_total = 0
        self.target_current = 0

    def start(self) -> None:
        if self.target != "*":
            row = self.db.one("SELECT COUNT(*) count FROM alerts WHERE last_run_id=? AND target=?", (self.run_id, self.target))
        else:
            row = self.db.one("SELECT COUNT(*) count FROM alerts WHERE last_run_id=?", (self.run_id,))
        self.alert_total = int(row["count"] if row else 0)
        self.record.start(
            phase="initializing",
            label=ANALYSIS_PHASE_MAP["initializing"][0],
            percent=0.5,
            message="Creating analysis run and resolving source targets",
        )
        self.record.start_heartbeat()

    def bind_analysis_id(self) -> None:
        row = self.db.one(
            "SELECT id FROM analysis_runs WHERE source_run_id=? AND target=? AND status='running' ORDER BY started_at DESC LIMIT 1",
            (self.run_id, self.target),
        )
        if row:
            self.record.bind_analysis_id(str(row["id"]))

    def set_targets(self, count: int) -> None:
        self.target_total = max(0, int(count))
        self.bind_analysis_id()
        if self.alert_total <= 0:
            self.phase("static_intelligence", current=0, total=self.target_total, message="No alert rows; analyzing raw target surfaces")
        else:
            self.phase("alert_enrichment", current=0, total=self.alert_total)

    def _phase_bounds(self, phase: str) -> tuple[str, float, float]:
        return ANALYSIS_PHASE_MAP.get(phase, (phase.replace("_", " ").title(), 0.0, 100.0))

    def phase(
        self,
        phase: str,
        *,
        current: int | None = None,
        total: int | None = None,
        message: str = "",
        completed: bool = False,
    ) -> None:
        label, start, end = self._phase_bounds(phase)
        fraction: float | None = None
        if total is not None and total > 0 and current is not None:
            fraction = max(0.0, min(1.0, float(current) / float(total)))
        elif completed:
            fraction = 1.0
        percent = end if completed else start + (end - start) * fraction if fraction is not None else start
        self.record.update(
            phase=phase,
            label=label,
            percent=percent,
            phase_percent=(fraction * 100.0) if fraction is not None else None,
            current=0 if current is None else current,
            total=0 if total is None else total,
            message=message or label,
        )

    def advance_alert(self) -> None:
        self.alert_current += 1
        self.phase("alert_enrichment", current=self.alert_current, total=self.alert_total)

    def advance_static(self) -> None:
        self.target_current += 1
        self.phase("static_intelligence", current=self.target_current, total=self.target_total)

    def complete(self) -> None:
        self.phase("finalizing", completed=True, message="Analysis completed")
        self.record.finish(status="success")
        self.record.stop_heartbeat()

    def interrupt(self, exc: BaseException | None = None) -> None:
        detail = "Analysis interrupted by operator"
        if exc is not None and str(exc):
            detail = f"{type(exc).__name__}: {exc}"
        self.record.finish(status="interrupted", error=detail)
        self.record.stop_heartbeat()

    def fail(self, exc: BaseException) -> None:
        self.record.finish(status="failed", error=f"{type(exc).__name__}: {exc}")
        self.record.stop_heartbeat()


def _current_analysis() -> AnalysisProgress | None:
    return getattr(_CURRENT_ANALYSIS, "tracker", None)


def _set_current_analysis(value: AnalysisProgress | None) -> None:
    _CURRENT_ANALYSIS.tracker = value


def _analysis_process_command(pid: int) -> str:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(int(pid)), "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    if completed.returncode != 0:
        return ""
    return str(completed.stdout or "").strip()


def _analysis_process_matches(command: str, run_id: str, target: str) -> bool:
    rendered = f" {str(command or '').strip()} "
    if "recon_monitor.py" not in rendered:
        return False
    if " analyze " not in rendered and " analysis replay " not in rendered:
        return False
    if run_id and run_id not in rendered:
        return False
    if target not in {"", "*"} and target not in rendered:
        return False
    return True


def _wait_analysis_exit(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return True
        time.sleep(0.1)
    return not process_alive(pid)


def _mark_analysis_interrupted(
    paths: AppPaths,
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    target: str,
    reason: str,
) -> None:
    now = utc_now()
    db.execute(
        "UPDATE analysis_runs SET status='interrupted',finished_at=?,error=? "
        "WHERE id=? AND status='running'",
        (now, reason[:4000], analysis_id),
    )
    with contextlib.suppress(Exception):
        db.audit(
            "analysis_interrupted",
            target=target,
            entity_type="run",
            entity_value=run_id,
            details={"analysis_id": analysis_id, "reason": reason},
        )
    record = ProgressRecord(paths, "analysis", run_id, target)
    data = record.data
    if data and str(data.get("analysis_id") or "") in {"", analysis_id}:
        record.bind_analysis_id(analysis_id)
        record.finish(status="interrupted", error=reason)


def stop_analysis(
    paths: AppPaths,
    db: Any,
    *,
    analysis_id: str = "",
    run_id: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Stop one running Analysis process after validating its persisted PID."""

    clauses = ["status='running'"]
    params: list[Any] = []
    if str(analysis_id or "").strip():
        clauses.append("id=?")
        params.append(str(analysis_id).strip())
    if str(run_id or "").strip():
        clauses.append("source_run_id=?")
        params.append(str(run_id).strip())
    if str(target or "").strip():
        clauses.append("target=?")
        params.append(str(target).strip())
    row = db.one(
        "SELECT id,source_run_id,target,status,started_at FROM analysis_runs WHERE "
        + " AND ".join(clauses)
        + " ORDER BY started_at DESC LIMIT 1",
        tuple(params),
    )
    if not row:
        raise ReconError("No running Analysis matches the requested selector")

    selected = dict(row)
    selected_id = str(selected["id"])
    selected_run = str(selected["source_run_id"])
    selected_target = str(selected["target"] or "*")
    stored = _load_json(_progress_path(paths, "analysis", selected_run, selected_target))
    if not stored:
        raise ReconError(
            "This Analysis has no PID metadata (legacy/pre-stop-control run). "
            "Inspect the process explicitly before stopping it."
        )
    bound_analysis = str(stored.get("analysis_id") or "")
    if bound_analysis and bound_analysis != selected_id:
        raise ReconError("Progress PID belongs to a different Analysis run; refusing to signal it")
    try:
        pid = int(stored.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid <= 1:
        raise ReconError("Running Analysis progress record does not contain a valid PID")

    if not process_alive(pid):
        reason = "Analysis process was already gone; stale running state repaired by stop command"
        _mark_analysis_interrupted(
            paths, db, analysis_id=selected_id, run_id=selected_run,
            target=selected_target, reason=reason,
        )
        return {
            "analysis_id": selected_id,
            "run_id": selected_run,
            "target": selected_target,
            "pid": pid,
            "signals_sent": [],
            "stopped": True,
            "status": "interrupted",
            "already_exited": True,
        }

    command = _analysis_process_command(pid)
    if not _analysis_process_matches(command, selected_run, selected_target):
        raise ReconError(
            f"Refusing to stop PID {pid}: process identity does not match the selected Analysis"
        )

    signals_sent: list[str] = []
    try:
        os.kill(pid, signal.SIGINT)
        signals_sent.append("SIGINT")
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        raise ReconError(f"Permission denied while signaling Analysis PID {pid}") from exc

    stopped = _wait_analysis_exit(pid, 1.5)
    if not stopped:
        try:
            os.kill(pid, signal.SIGTERM)
            signals_sent.append("SIGTERM")
        except ProcessLookupError:
            stopped = True
        except PermissionError as exc:
            raise ReconError(f"Permission denied while terminating Analysis PID {pid}") from exc
        if not stopped:
            stopped = _wait_analysis_exit(pid, 2.5)

    if stopped:
        reason = "Analysis stopped by operator via " + (" -> ".join(signals_sent) or "process exit")
        _mark_analysis_interrupted(
            paths, db, analysis_id=selected_id, run_id=selected_run,
            target=selected_target, reason=reason,
        )

    return {
        "analysis_id": selected_id,
        "run_id": selected_run,
        "target": selected_target,
        "pid": pid,
        "signals_sent": signals_sent,
        "stopped": bool(stopped),
        "status": "interrupted" if stopped else "stop_requested",
        "command": command,
    }


def _wrap_analysis_phase(module: Any, name: str, phase: str, *, advance_static: bool = False) -> None:
    original = getattr(module, name, None)
    if not callable(original) or getattr(original, "_rm_progress_wrapped", False):
        return

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        tracker = _current_analysis()
        if tracker:
            if advance_static:
                tracker.phase("static_intelligence", current=tracker.target_current, total=tracker.target_total)
            else:
                tracker.phase(phase)
        result = original(*args, **kwargs)
        tracker = _current_analysis()
        if tracker:
            if advance_static:
                tracker.advance_static()
            else:
                tracker.phase(phase, completed=True)
        return result

    wrapped._rm_progress_wrapped = True  # type: ignore[attr-defined]
    setattr(module, name, wrapped)


def _install_analysis_tracking(base: Any) -> None:
    import analysis_engine as engine

    if getattr(engine, "_RM_PROGRESS_INSTALLED", False):
        base.run_analysis = engine.run_analysis
        return

    original_targets = engine._analysis_targets
    original_evidence = engine._evidence
    original_run_analysis = engine.run_analysis

    def tracked_targets(db: Any, run_id: str, target: str | None) -> list[str]:
        targets = original_targets(db, run_id, target)
        tracker = _current_analysis()
        if tracker:
            tracker.set_targets(len(targets))
        return targets

    def tracked_evidence(*args: Any, **kwargs: Any) -> Any:
        result = original_evidence(*args, **kwargs)
        tracker = _current_analysis()
        if tracker:
            tracker.advance_alert()
        return result

    engine._analysis_targets = tracked_targets
    engine._evidence = tracked_evidence
    _wrap_analysis_phase(engine, "_scan_js_intelligence", "static_intelligence", advance_static=True)
    _wrap_analysis_phase(engine, "generate_semantic_intelligence", "semantic_intelligence")
    _wrap_analysis_phase(engine, "generate_behavioral_intelligence", "behavioral_intelligence")
    _wrap_analysis_phase(engine, "generate_bug_candidates", "candidate_generation")
    _wrap_analysis_phase(engine, "generate_behavioral_candidates", "behavioral_candidates")
    _wrap_analysis_phase(engine, "enhance_candidates", "candidate_reliability")
    _wrap_analysis_phase(engine, "apply_security_reasoning", "security_reasoning")
    _wrap_analysis_phase(engine, "reasoning_regression_gate", "security_reasoning")
    _wrap_analysis_phase(engine, "build_candidate_bundles", "candidate_bundles")
    _wrap_analysis_phase(engine, "platform_sync", "platform_sync")
    _wrap_analysis_phase(engine, "_quality_snapshot", "quality_snapshot")

    with contextlib.suppress(Exception):
        import workspace_v7
        _wrap_analysis_phase(workspace_v7, "workspace_v7_sync", "workspace_sync")

    def tracked_run_analysis(paths: AppPaths, db: Any, run_id: str, target: str | None = None, **kwargs: Any) -> dict[str, Any]:
        tracker = AnalysisProgress(paths, db, run_id, target)
        previous = _current_analysis()
        _set_current_analysis(tracker)
        tracker.start()
        try:
            result = original_run_analysis(paths, db, run_id, target, **kwargs)
            tracker.complete()
            return result
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                tracker.interrupt(exc)
            else:
                tracker.fail(exc)
            raise
        finally:
            _set_current_analysis(previous)

    tracked_run_analysis._rm_progress_wrapped = True  # type: ignore[attr-defined]
    engine.run_analysis = tracked_run_analysis
    engine._RM_PROGRESS_INSTALLED = True
    base.run_analysis = tracked_run_analysis

    # reporting imported run_analysis by value, so update that binding as well.
    with contextlib.suppress(Exception):
        import reporting
        reporting.run_analysis = tracked_run_analysis


def _install_recon_tracking(base: Any) -> None:
    original_progress = base.Progress
    if getattr(original_progress, "_rm_persistent_progress", False):
        return

    class PersistentProgress(original_progress):
        _rm_persistent_progress = True

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self._rm_record: ProgressRecord | None = None
            self._rm_stage_name = ""
            self._rm_stage_index = 0
            self._rm_stage_total = len(RECON_STAGES)

        def bind_recon(self, paths: AppPaths, run_id: str, target: str, stage: str, stage_index: int, stage_total: int, label: str) -> None:
            record = ProgressRecord(paths, "recon", run_id, target)
            data = record.data
            if not data or data.get("status") in {"success", "failed", "interrupted"}:
                record.start(phase=stage, label=label, percent=max(0.0, (stage_index - 1) * 100.0 / max(1, stage_total)))
            self._rm_record = record
            self._rm_stage_name = stage
            self._rm_stage_index = stage_index
            self._rm_stage_total = max(1, stage_total)
            record.update(
                phase=stage,
                label=label,
                percent=(stage_index - 1) * 100.0 / self._rm_stage_total,
                message=f"Stage {stage_index}/{self._rm_stage_total}",
            )
            record.start_heartbeat()

        def unbind_recon(self) -> None:
            if self._rm_record:
                self._rm_record.stop_heartbeat()
            self._rm_record = None

        def update(self, current: int | None = None, total: int | None = None, extra: str | None = None) -> None:
            super().update(current, total, extra)
            record = self._rm_record
            if not record:
                return
            fraction = None
            if total is not None and total > 0 and current is not None:
                fraction = max(0.0, min(1.0, float(current) / float(total)))
            base_percent = (self._rm_stage_index - 1) * 100.0 / self._rm_stage_total
            span = 100.0 / self._rm_stage_total
            record.update(
                phase=self._rm_stage_name,
                label=RECON_STAGE_LABEL.get(self._rm_stage_name, self._rm_stage_name.replace("_", " ").title()),
                percent=base_percent + (span * fraction if fraction is not None else 0.0),
                phase_percent=(fraction * 100.0) if fraction is not None else None,
                current=current,
                total=total,
                message=extra if extra is not None else None,
            )

    base.Progress = PersistentProgress

    original_run_stage = base.Orchestrator._run_stage
    if getattr(original_run_stage, "_rm_progress_wrapped", False):
        return

    def tracked_run_stage(
        self: Any,
        ctx: Any,
        stage_name: str,
        label: str,
        stage_index: int,
        stage_total: int,
        target_index: int,
        target_total: int,
        baseline: bool,
        resume: bool,
    ) -> tuple[str, dict[str, Any]]:
        progress = self.progress
        if hasattr(progress, "bind_recon"):
            progress.bind_recon(self.paths, ctx.run_id, ctx.policy.name, stage_name, stage_index, stage_total, label)
        record = getattr(progress, "_rm_record", None)
        try:
            status, metrics = original_run_stage(
                self, ctx, stage_name, label, stage_index, stage_total,
                target_index, target_total, baseline, resume,
            )
            if record:
                if status == "success":
                    record.update(
                        phase=stage_name,
                        label=label,
                        percent=stage_index * 100.0 / max(1, stage_total),
                        phase_percent=100.0,
                        message="Stage complete",
                    )
                    if stage_index >= stage_total:
                        record.finish(status="success")
                else:
                    record.finish(status=status, error=str(metrics.get("error") or ""))
            return status, metrics
        except BaseException as exc:
            if record:
                record.finish(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            if hasattr(progress, "unbind_recon"):
                progress.unbind_recon()

    tracked_run_stage._rm_progress_wrapped = True  # type: ignore[attr-defined]
    base.Orchestrator._run_stage = tracked_run_stage


def _latest_analysis_activity(db: Any, analysis_id: str) -> str:
    candidates: list[str] = []
    for sql in (
        "SELECT MAX(created_at) value FROM analysis_results WHERE analysis_id=?",
        "SELECT MAX(updated_at) value FROM analysis_hypotheses WHERE analysis_id=?",
        "SELECT MAX(updated_at) value FROM bug_candidates WHERE analysis_id=?",
        "SELECT MAX(created_at) value FROM reasoning_evaluations WHERE analysis_id=?",
    ):
        try:
            row = db.one(sql, (analysis_id,))
        except Exception:
            continue
        if row and row["value"]:
            candidates.append(str(row["value"]))
    if not candidates:
        return ""
    return max(candidates, key=lambda value: _parse_time(value) or dt.datetime.min.replace(tzinfo=dt.timezone.utc))


def analysis_progress_snapshot(paths: AppPaths, db: Any, target: str = "", *, dashboard_fast: bool = False) -> dict[str, Any]:
    params: tuple[Any, ...] = ()
    where = ""
    if target:
        where = "WHERE target=?"
        params = (target,)

    stored: dict[str, Any] = {}
    live_running = False
    row = None
    if dashboard_fast:
        running_where = "WHERE status='running'"
        running_params: tuple[Any, ...] = ()
        if target:
            running_where += " AND target=?"
            running_params = (target,)
        running_row = db.one(
            f"SELECT id,source_run_id,target,status,started_at,finished_at,error FROM analysis_runs {running_where} "
            "ORDER BY started_at DESC LIMIT 1",
            running_params,
        )
        if running_row:
            running_value = dict(running_row)
            running_run = str(running_value["source_run_id"])
            running_target = str(running_value["target"] or "*")
            candidate = _load_json(_progress_path(paths, "analysis", running_run, running_target))
            bound = str(candidate.get("analysis_id") or "") == str(running_value["id"])
            try:
                pid = int(candidate.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            live_running = bool(
                bound
                and str(candidate.get("status") or "").lower() == "running"
                and pid > 1
                and process_alive(pid)
            )
            if live_running:
                row = running_row
                stored = candidate

        if row is None:
            row = db.one(
                f"SELECT id,source_run_id,target,status,started_at,finished_at,error FROM analysis_runs {where} "
                "ORDER BY started_at DESC LIMIT 1",
                params,
            )
            if row:
                latest = dict(row)
                stored = _load_json(
                    _progress_path(paths, "analysis", str(latest["source_run_id"]), str(latest["target"] or "*"))
                )
    else:
        row = db.one(
            f"SELECT id,source_run_id,target,status,started_at,finished_at,error FROM analysis_runs {where} "
            "ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, COALESCE(finished_at,started_at) DESC LIMIT 1",
            params,
        )
        if row:
            selected = dict(row)
            stored = _load_json(
                _progress_path(paths, "analysis", str(selected["source_run_id"]), str(selected["target"] or "*"))
            )

    if not row:
        return {"kind": "analysis", "status": "not_run", "health": "unknown", "estimated_percent": None}
    value = dict(row)
    run_id = str(value["source_run_id"])
    row_target = str(value["target"] or "*")

    if dashboard_fast and str(value.get("status") or "").lower() == "running" and not live_running:
        exact_progress = str(stored.get("analysis_id") or "") == str(value["id"])
        progress_status = str(stored.get("status") or "").lower() if exact_progress else ""
        if progress_status in {"success", "failed", "interrupted", "cancelled"}:
            value["status"] = progress_status
        else:
            value["status"] = "stale"
            if not value.get("error"):
                value["error"] = "Stored Analysis row is marked running, but no matching live Analysis process was verified"

    heartbeat_available = bool(stored and str(stored.get("analysis_id") or "") in {"", str(value["id"])})
    payload = {
        "kind": "analysis",
        "analysis_id": str(value["id"]),
        "run_id": run_id,
        "target": row_target,
        "status": str(value["status"]),
        "started_at": str(value["started_at"] or ""),
        "finished_at": str(value["finished_at"] or ""),
        "error": str(value["error"] or ""),
        "estimated_percent": stored.get("estimated_percent") if heartbeat_available else None,
        "phase_percent": stored.get("phase_percent") if heartbeat_available else None,
        "phase": stored.get("phase") if heartbeat_available else "legacy_run",
        "phase_label": stored.get("phase_label") if heartbeat_available else "Legacy analysis run",
        "current": stored.get("current") if heartbeat_available else None,
        "total": stored.get("total") if heartbeat_available else None,
        "message": stored.get("message") if heartbeat_available else "Live progress was not enabled when this analysis started",
        "heartbeat_at": stored.get("heartbeat_at") if heartbeat_available else None,
        "last_progress_at": stored.get("last_progress_at") if heartbeat_available else None,
        "visibility": "live" if heartbeat_available else "legacy",
    }
    if not heartbeat_available and payload["status"] == "running" and not dashboard_fast:
        activity = _latest_analysis_activity(db, str(value["id"]))
        payload["last_progress_at"] = activity or None
        payload["activity_age_seconds"] = _age_seconds(activity)
        if row_target != "*":
            total_row = db.one("SELECT COUNT(*) count FROM alerts WHERE last_run_id=? AND target=?", (run_id, row_target))
        else:
            total_row = db.one("SELECT COUNT(*) count FROM alerts WHERE last_run_id=?", (run_id,))
        result_row = db.one("SELECT COUNT(*) count FROM analysis_results WHERE analysis_id=?", (str(value["id"]),))
        alert_total = int(total_row["count"] if total_row else 0)
        alert_current = int(result_row["count"] if result_row else 0)
        if alert_total > 0 and alert_current < alert_total:
            payload["phase"] = "alert_enrichment"
            payload["phase_label"] = ANALYSIS_PHASE_MAP["alert_enrichment"][0]
            payload["current"] = alert_current
            payload["total"] = alert_total
            payload["phase_percent"] = round(alert_current * 100.0 / alert_total, 1)
            payload["estimated_percent"] = round(2.0 + 20.0 * alert_current / alert_total, 1)
            if activity and (_age_seconds(activity) or 999999) <= HEALTH_WAITING_SECONDS:
                payload["message"] = "Legacy run is still writing analysis results"
    health, health_detail = _health(payload["status"], payload.get("heartbeat_at"), heartbeat_available=heartbeat_available)
    if not heartbeat_available and payload["status"] == "running" and payload.get("activity_age_seconds") is not None:
        if float(payload["activity_age_seconds"]) <= HEALTH_ACTIVE_SECONDS:
            health, health_detail = "progressing", "Recent database activity detected; precise heartbeat is unavailable for this legacy run"
        elif float(payload["activity_age_seconds"]) <= HEALTH_WAITING_SECONDS:
            health, health_detail = "waiting", "Recent database activity exists, but precise heartbeat is unavailable"
    payload["health"] = health
    payload["health_detail"] = health_detail
    payload["heartbeat_age_seconds"] = _age_seconds(payload.get("heartbeat_at"))
    payload["progress_age_seconds"] = _age_seconds(payload.get("last_progress_at"))
    payload["elapsed_seconds"] = _elapsed_seconds(payload["started_at"], payload["finished_at"] if payload["status"] != "running" else None)
    return payload


def recon_progress_snapshot(paths: AppPaths, db: Any, target: str = "") -> dict[str, Any]:
    params: tuple[Any, ...] = ()
    where = ""
    if target:
        where = "WHERE rt.target=?"
        params = (target,)
    row = db.one(
        "SELECT rt.run_id,rt.target,rt.status,rt.started_at,rt.finished_at,rt.current_stage,rt.run_dir,r.status run_status "
        "FROM run_targets rt JOIN runs r ON r.id=rt.run_id " + where +
        " ORDER BY CASE rt.status WHEN 'running' THEN 0 ELSE 1 END, COALESCE(rt.finished_at,rt.started_at) DESC LIMIT 1",
        params,
    )
    if not row:
        return {"kind": "recon", "status": "not_run", "health": "unknown", "estimated_percent": None, "stages": []}
    value = dict(row)
    run_id = str(value["run_id"])
    row_target = str(value["target"])
    stored = _load_json(_progress_path(paths, "recon", run_id, row_target))
    rows = db.all(
        "SELECT stage,status,started_at,finished_at,heartbeat_at,duration_seconds,metrics_json,error FROM stage_runs "
        "WHERE run_id=? AND target=? ORDER BY rowid",
        (run_id, row_target),
    )
    by_stage = {str(item["stage"]): dict(item) for item in rows}
    current_stage = str(value.get("current_stage") or stored.get("phase") or "")
    current_row = by_stage.get(current_stage, {})
    heartbeat_candidates = [stored.get("heartbeat_at"), current_row.get("heartbeat_at")]
    heartbeat = max(
        (str(v) for v in heartbeat_candidates if _parse_time(v)),
        key=lambda v: _parse_time(v) or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        default="",
    )
    status = str(value["status"] or value["run_status"] or "")
    stage_index = RECON_STAGE_INDEX.get(current_stage, 0)
    estimated_percent: float | None = stored.get("estimated_percent") if stored else None
    if status == "success":
        estimated_percent = 100.0
    elif estimated_percent is None and stage_index:
        estimated_percent = round((stage_index - 1) * 100.0 / len(RECON_STAGES), 1)
    stages: list[dict[str, Any]] = []
    for index, (name, label) in enumerate(RECON_STAGES, 1):
        stage_row = by_stage.get(name, {})
        stage_status = str(stage_row.get("status") or ("pending" if index >= stage_index else "unknown"))
        phase_percent = None
        current = total = None
        if name == current_stage and stored:
            phase_percent = stored.get("phase_percent")
            current = stored.get("current")
            total = stored.get("total")
        stages.append({
            "stage": name,
            "label": label,
            "status": stage_status,
            "phase_percent": phase_percent,
            "current": current,
            "total": total,
            "heartbeat_at": stage_row.get("heartbeat_at"),
            "duration_seconds": stage_row.get("duration_seconds"),
            "error": str(stage_row.get("error") or ""),
        })
    heartbeat_available = bool(heartbeat)
    health, health_detail = _health(status, heartbeat, heartbeat_available=heartbeat_available)
    return {
        "kind": "recon",
        "run_id": run_id,
        "target": row_target,
        "status": status,
        "health": health,
        "health_detail": health_detail,
        "estimated_percent": estimated_percent,
        "phase_percent": stored.get("phase_percent") if stored else None,
        "phase": current_stage,
        "phase_label": RECON_STAGE_LABEL.get(current_stage, current_stage.replace("_", " ").title() if current_stage else "—"),
        "current": stored.get("current") if stored else None,
        "total": stored.get("total") if stored else None,
        "message": stored.get("message") if stored else "",
        "heartbeat_at": heartbeat or None,
        "heartbeat_age_seconds": _age_seconds(heartbeat),
        "last_progress_at": stored.get("last_progress_at") if stored else None,
        "progress_age_seconds": _age_seconds(stored.get("last_progress_at")) if stored else None,
        "started_at": str(value.get("started_at") or ""),
        "finished_at": str(value.get("finished_at") or ""),
        "elapsed_seconds": _elapsed_seconds(value.get("started_at"), value.get("finished_at") if status != "running" else None),
        "error": str(current_row.get("error") or ""),
        "visibility": "live" if stored else "stage_heartbeat_only",
        "stages": stages,
    }


def _progress_tone(health: str) -> str:
    return {
        "progressing": "success",
        "waiting": "amber",
        "stalled": "danger",
        "failed": "danger",
        "cancelled": "amber",
        "completed": "success",
        "stale": "amber",
    }.get(str(health), "neutral")


def _progress_panel(base: Any, snapshot: Mapping[str, Any], title: str) -> str:
    status = str(snapshot.get("status") or "not_run")
    health = str(snapshot.get("health") or "unknown")
    percent = snapshot.get("estimated_percent")
    percent_text = f"{float(percent):.1f}%" if isinstance(percent, (int, float)) else "—"
    width = max(0.0, min(100.0, float(percent or 0.0)))
    current = snapshot.get("current")
    total = snapshot.get("total")
    work = f"{current}/{total}" if isinstance(current, int) and isinstance(total, int) and total > 0 else "total unknown"
    heartbeat_age = _format_seconds(snapshot.get("heartbeat_age_seconds"))
    progress_age = _format_seconds(snapshot.get("progress_age_seconds"))
    elapsed = _format_seconds(snapshot.get("elapsed_seconds"))
    error = str(snapshot.get("error") or "")
    error_html = (
        f"<div class='callout' style='margin-top:12px'><strong>Latest error</strong><span>{base._esc(error)}</span></div>"
        if error else ""
    )
    visibility = str(snapshot.get("visibility") or "")
    legacy = (
        "<div class='callout' style='margin-top:12px'><strong>Limited visibility for this existing run</strong>"
        "<span>This operation started before live progress tracking was installed. Recon Monitor will not invent a percentage. "
        "Recent database activity is used when available; restart/re-run with this version for precise heartbeat and phase progress.</span></div>"
        if visibility == "legacy" and status == "running" else ""
    )
    stage_rows = ""
    for stage in snapshot.get("stages", []) if isinstance(snapshot.get("stages"), list) else []:
        stage_percent = stage.get("phase_percent")
        stage_work = ""
        if isinstance(stage.get("current"), int) and isinstance(stage.get("total"), int) and stage.get("total") > 0:
            stage_work = f"{stage['current']}/{stage['total']}"
        progress_cell = f"{float(stage_percent):.1f}%" if isinstance(stage_percent, (int, float)) else stage_work or "—"
        stage_rows += (
            f"<tr><td>{base._esc(stage.get('label'))}</td><td>{base._pill(stage.get('status'))}</td>"
            f"<td>{base._esc(progress_cell)}</td><td>{base._esc(_format_seconds(stage.get('duration_seconds')))}</td>"
            f"<td class='muted small'>{base._esc(stage.get('error') or '')}</td></tr>"
        )
    stages_html = (
        "<div class='table-wrap' style='margin-top:14px'><table><thead><tr><th>Stage</th><th>Status</th><th>Progress</th><th>Duration</th><th>Error</th></tr></thead><tbody>"
        + stage_rows + "</tbody></table></div>"
        if stage_rows else ""
    )
    refresh = ""
    return (
        f"<section class='panel' id='live-progress' style='margin-top:16px'><div class='panel-head'><div><h3>{base._esc(title)}</h3>"
        f"<span class='muted small'>Progress Tracking {PROGRESS_TRACKING_VERSION} · auto-refresh while running</span></div>"
        + base._pill(health, _progress_tone(health)) + "</div><div class='panel-body'>"
        "<div class='attention-grid'>"
        f"<div class='attention-card'><span>Estimated progress</span><strong>{base._esc(percent_text)}</strong><small>work completion, not time remaining</small></div>"
        f"<div class='attention-card'><span>Current phase</span><strong>{base._esc(snapshot.get('phase_label') or '—')}</strong><small>{base._esc(work)}</small></div>"
        f"<div class='attention-card'><span>Elapsed</span><strong>{base._esc(elapsed)}</strong><small>since operation start</small></div>"
        f"<div class='attention-card'><span>Heartbeat age</span><strong>{base._esc(heartbeat_age)}</strong><small>last measurable progress {base._esc(progress_age)} ago</small></div>"
        "</div>"
        f"<div style='height:12px;background:rgba(127,127,127,.18);border-radius:999px;overflow:hidden;margin-top:14px'><div style='height:100%;width:{width:.1f}%;background:currentColor;border-radius:999px'></div></div>"
        f"<div class='callout' style='margin-top:12px'><strong>{base._esc(snapshot.get('health_detail') or health)}</strong><span>{base._esc(snapshot.get('message') or '')}</span></div>"
        + error_html + legacy + stages_html + "</div></section>" + refresh
    )


def _capture_dashboard_html(self: Any, renderer: Callable[[Any], None]) -> tuple[str, str, int]:
    captured: dict[str, Any] = {}
    had_send = "send_html" in getattr(self, "__dict__", {})
    previous = getattr(self, "__dict__", {}).get("send_html")
    self.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
    try:
        renderer(self)
    finally:
        if had_send:
            self.send_html = previous
        else:
            self.__dict__.pop("send_html", None)
    return str(captured.get("title") or "Recon Monitor"), str(captured.get("body") or ""), int(captured.get("status") or 200)


def _analysis_dashboard_renderer(dash: Any, default_renderer: Callable[[Any], None], snapshot: Mapping[str, Any]) -> tuple[Callable[[Any], None], bool]:
    """Use the lightweight Analysis renderer while live progress is active."""
    if str(snapshot.get("status") or "").lower() == "running":
        lightweight = getattr(dash, "_ORIGINAL_ANALYSIS_ENGINE", None)
        if callable(lightweight):
            return lightweight, True
    return default_renderer, False


def _install_dashboard_tracking() -> None:
    import dashboard as dash

    handler = dash.DashboardHandler
    if getattr(handler, "_rm_progress_installed", False):
        return
    original_analysis = handler.analysis_engine
    original_recon = handler.recon_workspace
    original_do_get = handler.do_GET

    def analysis_with_progress(self: Any) -> None:
        params = self.query()
        target = str((params.get("target") or [""])[0]).strip()
        db = self.db()
        try:
            # Dashboard navigation must never perform legacy progress reconstruction
            # or invoke the historical Analysis renderer. Those paths can aggregate
            # large evidence/candidate tables on populated databases.
            snapshot = analysis_progress_snapshot(self.paths, db, target, dashboard_fast=True)
        finally:
            db.close()

        panel = _progress_panel(dash, snapshot, "Live Analysis Progress")
        analysis_id = str(snapshot.get("analysis_id") or "")
        run_id = str(snapshot.get("run_id") or "")
        row_target = str(snapshot.get("target") or target or "*")
        status = str(snapshot.get("status") or "not_run")
        summary = (
            "<section class='panel' id='analysis-fast-summary' style='margin-top:16px'>"
            "<div class='panel-head'><div><h3>Analysis workspace</h3>"
            "<span class='muted small'>Fast status surface · deep summaries are on demand</span></div>"
            + dash._pill(status)
            + "</div><div class='panel-body'>"
            "<div class='attention-grid'>"
            f"<div class='attention-card'><span>Analysis</span><strong>{dash._esc(analysis_id or '—')}</strong><small>latest tracked analysis</small></div>"
            f"<div class='attention-card'><span>Source run</span><strong>{dash._esc(run_id or '—')}</strong><small>recon evidence source</small></div>"
            f"<div class='attention-card'><span>Target</span><strong>{dash._esc(row_target)}</strong><small>analysis scope</small></div>"
            f"<div class='attention-card'><span>Status</span><strong>{dash._esc(status)}</strong><small>current analysis state</small></div>"
            "</div>"
            "<div class='callout' style='margin-top:14px'><strong>Fast Analysis view</strong>"
            "<span>Deep vulnerability-intelligence correlation is deferred. Evidence totals, candidate aggregation, quality metrics and deep reasoning are intentionally loaded only when you open their dedicated views.</span></div>"
            "<div class='page-actions' style='margin-top:14px'>"
            "<a class='button' href='/potential-findings'>Potential Findings</a>"
            "<a class='button secondary' href='/analysis-quality'>Analysis Quality</a>"
            "<a class='button secondary' href='/security-reasoning'>Security Reasoning</a>"
            "<a class='button secondary' href='/candidate-quality'>Candidate Quality</a>"
            "</div></div></section>"
        )
        self.send_html("Analysis", panel + summary)

    def recon_with_progress(self: Any) -> None:
        title, body, status = _capture_dashboard_html(self, original_recon)
        params = self.query()
        target = str((params.get("target") or [""])[0]).strip()
        db = self.db()
        try:
            snapshot = recon_progress_snapshot(self.paths, db, target)
        finally:
            db.close()
        panel = _progress_panel(dash, snapshot, "Live Recon Progress")
        self.send_html(title, panel + body, status)

    def do_get_with_live_progress(self: Any) -> None:
        path = self.path.split("?", 1)[0]

        if path != "/api/live-progress":
            return original_do_get(self)

        if not self._require_auth("viewer"):
            return

        params = self.query()
        kind = str((params.get("kind") or [""])[0]).strip().lower()
        target = str((params.get("target") or [""])[0]).strip()

        if kind not in {"recon", "analysis"}:
            self.send_json(
                {"error": "kind must be recon or analysis"},
                status=400,
            )
            return

        db = self.db()
        try:
            if kind == "analysis":
                snapshot = analysis_progress_snapshot(
                    self.paths,
                    db,
                    target,
                    dashboard_fast=True,
                )
                title = "Live Analysis Progress"
            else:
                snapshot = recon_progress_snapshot(
                    self.paths,
                    db,
                    target,
                )
                title = "Live Recon Progress"
        finally:
            db.close()

        self.send_json({
            "kind": kind,
            "target": target,
            "status": str(snapshot.get("status") or ""),
            "health": str(snapshot.get("health") or ""),
            "estimated_percent": snapshot.get("estimated_percent"),
            "phase": snapshot.get("phase"),
            "html": _progress_panel(dash, snapshot, title),
        })

    handler.analysis_engine = analysis_with_progress
    handler.recon_workspace = recon_with_progress
    handler.do_GET = do_get_with_live_progress
    handler._rm_progress_installed = True


def install_progress_tracking(base: Any) -> None:
    """Install additive runtime hooks into the compatibility CLI/dashboard."""
    global _INSTALLED
    with _INSTALL_LOCK:
        if _INSTALLED:
            return
        _install_recon_tracking(base)
        _install_analysis_tracking(base)
        _install_dashboard_tracking()
        _INSTALLED = True

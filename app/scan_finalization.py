"""Refresh diagnostic projections after terminal execution states are durable.

No collection, analysis, notification, baseline promotion or target requests are
performed here. Historical stage outcomes and comparison snapshots stay intact.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from core import ReconError, atomic_write_text, json_dumps, safe_json_loads, utc_now, read_jsonl
from scan_coverage import COVERAGE_VERSION, metrics_dict, origin_probe_coverage, stage_coverage


def _audit_legacy_origins(paths: Any, db: Any, run_id: str) -> None:
    """Annotate old omissions using retained local evidence, not fresh traffic."""
    for target in db.all("SELECT target,run_dir FROM run_targets WHERE run_id=?", (run_id,)):
        directory = Path(str(target["run_dir"]))
        if not directory.resolve().is_relative_to(paths.output.resolve()):
            raise ReconError("Run output directory is outside the configured output root")
        row = db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND target=? AND stage='urls'", (run_id, target["target"]))
        metrics = metrics_dict(row["metrics_json"]) if row else {}
        proof = directory / "current" / "origin-probe.jsonl"
        if (row and "origin_probe_coverage_version" not in metrics and "coverage_audit" not in metrics
                and proof.is_file()):
            if not proof.resolve().is_relative_to(directory.resolve()) or proof.stat().st_size > 16 * 1024 * 1024:
                raise ReconError("Retained origin-probe evidence is outside its run or exceeds the audit limit")
            audit = origin_probe_coverage(list(read_jsonl(proof)))
            audit.update(diagnostic_only=True, provenance="retained_origin_probe", historical_outcome_unchanged=True)
            metrics["coverage_audit"] = audit
            db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND target=? AND stage='urls'",
                       (json_dumps(metrics), run_id, target["target"]))


def finalize_run_diagnostics(paths: Any, db: Any, run_id: str) -> dict[str, Any]:
    from product_platform import invalidate_platform_cache, run_completeness
    from platform_v6 import data_quality_snapshot
    from reporting import _stage_metrics, render_report_html
    from workspace_v7 import recon_coverage
    from collection_quality import snapshot_collection_quality

    run = db.one("SELECT status FROM runs WHERE id=?", (run_id,))
    if not run:
        raise ReconError("Run not found: " + run_id)
    if run["status"] == "running" or db.one(
        "SELECT 1 FROM stage_runs WHERE run_id=? AND status='running' LIMIT 1", (run_id,),
    ):
        raise ReconError("Cannot finalize diagnostics for a running scan")
    _audit_legacy_origins(paths, db, run_id)
    invalidate_platform_cache()
    completeness = run_completeness(db, run_id, persist=True)
    quality = data_quality_snapshot(db, run_id, persist=True)
    finalized = []
    for target_row in db.all("SELECT target,run_dir FROM run_targets WHERE run_id=?", (run_id,)):
        target = str(target_row["target"])
        run_dir = Path(str(target_row["run_dir"]))
        if not run_dir.resolve().is_relative_to(paths.output.resolve()):
            raise ReconError("Run output directory is outside the configured output root")
        coverage = recon_coverage(db, target=target, run_id=run_id, persist=True)
        lifecycle_row = db.one("SELECT * FROM target_run_lifecycle WHERE run_id=? AND target=?", (run_id, target))
        lifecycle = dict(lifecycle_row) if lifecycle_row else {}
        finalization = {"coverage_version": COVERAGE_VERSION, "run_id": run_id, "target": target,
                        "run_status": run["status"], "lifecycle": lifecycle, "generated_at": utc_now()}
        report_stage = db.one("SELECT metrics_json FROM stage_runs WHERE run_id=? AND target=? AND stage='report'", (run_id, target))
        report_metrics = safe_json_loads(report_stage["metrics_json"], {}, expected_type=dict) if report_stage else {}
        observations = {str(row["stage"]): stage_coverage(str(row["stage"]), dict(row)) for row in db.all(
            "SELECT stage,status,metrics_json FROM stage_runs WHERE run_id=? AND target=?", (run_id, target),
        )}
        finalization["collection_visibility"] = observations
        finalization["baseline_review_required"] = bool(lifecycle.get("baseline_eligible") and any(
            value["status"] in {"access_restricted", "partial"} for value in observations.values()
        ))
        old_quality = metrics_dict(report_metrics.get("collection_quality"))
        dimensions = metrics_dict(old_quality.get("dimensions"))
        stage_rows = db.all("SELECT stage,metrics_json FROM stage_runs WHERE run_id=? AND target=?", (run_id, target))
        modules = {str(row["stage"]): not bool(metrics_dict(row["metrics_json"]).get("skipped")) for row in stage_rows}
        policy = SimpleNamespace(name=target, modules=modules, limits=SimpleNamespace(
            max_urls=metrics_dict(dimensions.get("urls")).get("limit", 0),
            max_js_files=metrics_dict(dimensions.get("javascript")).get("limit", 0)))
        collection_quality = snapshot_collection_quality(SimpleNamespace(
            db=db, run_id=run_id, policy=policy, run_dir=run_dir), persist=True)
        report_metrics["collection_quality"] = collection_quality

        # Update only operational projections, never candidate scores or evidence.
        for analysis in db.all("SELECT id,summary_json FROM analysis_runs WHERE source_run_id=? AND target=?", (run_id, target)):
            summary = safe_json_loads(analysis["summary_json"], {}, expected_type=dict)
            candidates = summary.get("bug_candidates")
            if isinstance(candidates, dict):
                platform = candidates.get("product_platform")
                if isinstance(platform, dict):
                    platform["run_completeness"] = completeness
                    suite = platform.get("suite_v6")
                    if isinstance(suite, dict):
                        suite["data_quality"] = quality
                workspace = candidates.get("workspace_v7")
                if isinstance(workspace, dict):
                    entry = workspace.get("targets", {}).get(target)
                    if isinstance(entry, dict):
                        entry["coverage"] = coverage
                        entry["analysis_id"] = analysis["id"]
                    diagnostics = workspace.get("diagnostics")
                    if isinstance(diagnostics, dict):
                        running_count = db.one("SELECT COUNT(*) c FROM runs WHERE status='running'")["c"]
                        for check in diagnostics.get("checks", []):
                            if check.get("id") == "RUN-STATE":
                                check.update(status="warn" if running_count else "ok",
                                             detail=f"{running_count} run(s) marked running")
                        diagnostics["overall"] = ("error" if any(c.get("status") == "error" for c in diagnostics.get("checks", []))
                                                   else "warn" if any(c.get("status") == "warn" for c in diagnostics.get("checks", [])) else "ok")
            summary["diagnostics_finalization"] = finalization
            db.execute("UPDATE analysis_runs SET summary_json=? WHERE id=?", (json_dumps(summary), analysis["id"]))
            if report_metrics.get("analysis", {}).get("analysis_id") == analysis["id"]:
                report_metrics["analysis"].update(summary)
        report_metrics["diagnostics_finalization"] = finalization
        if report_stage:
            db.execute("UPDATE stage_runs SET metrics_json=? WHERE run_id=? AND target=? AND stage='report'",
                       (json_dumps(report_metrics), run_id, target))

        report_path = run_dir / "report.json"
        if report_path.is_file():
            report = safe_json_loads(report_path.read_text(encoding="utf-8"), {}, expected_type=dict)
            if report.get("run_id") != run_id or report.get("target") != target:
                raise ReconError("Report identity does not match its recorded run and target")
            ctx = SimpleNamespace(db=db, run_id=run_id, policy=SimpleNamespace(name=target))
            report["stages"] = _stage_metrics(ctx)
            report["diagnostics_finalization"] = finalization
            report["run_completeness"] = completeness
            report["lifecycle"] = lifecycle
            report["collection_quality"] = collection_quality
            html = render_report_html(report)
            atomic_write_text(report_path, json_dumps(report, pretty=True) + "\n")
            atomic_write_text(run_dir / "report.html", html)
            target_reports = paths.reports / target
            target_reports.mkdir(parents=True, exist_ok=True)
            atomic_write_text(target_reports / (run_id + ".html"), html)
            latest = paths.output / target / "LATEST"
            if latest.is_file() and latest.read_text().strip() == str(run_dir):
                atomic_write_text(target_reports / "latest.html", html)
            manifest_path = run_dir / "run-manifest.json"
            if manifest_path.is_file():
                manifest = safe_json_loads(manifest_path.read_text(), {}, expected_type=dict)
                if manifest.get("run_id") != run_id or manifest.get("target") != target:
                    raise ReconError("Manifest identity does not match its recorded run and target")
                manifest.update(stages=report["stages"], diagnostics_finalization=finalization,
                                lifecycle=lifecycle, run_completeness=completeness, collection_quality=collection_quality)
                atomic_write_text(manifest_path, json_dumps(manifest, pretty=True) + "\n")
        finalized.append(target)
    invalidate_platform_cache()
    return {"run_id": run_id, "targets": finalized, "run_completeness": completeness,
            "collection_or_baseline_changed": False, "network_requests": 0}

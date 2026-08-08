#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import getpass
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from core import (  # noqa: E402
    APP_VERSION,
    AppPaths,
    atomic_write_text,
    CommandRunner,
    Config,
    Database,
    Logger,
    PolicySet,
    Progress,
    process_alive,
    ReconError,
    RunLock,
    TargetPolicy,
    TelegramNotifier,
    collect_tool_versions,
    config_hash,
    json_dumps,
    local_now,
    parse_bool,
    read_jsonl,
    safe_json_loads,
    utc_now,
)
from dashboard import serve_dashboard  # noqa: E402
from dashboard_auth import auth_status, configure_auth, disable_auth  # noqa: E402
from dashboard_service import (  # noqa: E402
    dashboard_status,
    open_dashboard,
    print_dashboard_logs,
    restart_dashboard,
    start_dashboard,
    stop_dashboard,
)
from analysis import compare_runs, format_comparison  # noqa: E402
from analysis_engine import run_analysis, replay_analysis, analysis_quality, calibration_report, feedback_report  # noqa: E402
from bug_candidates import ANALYST_DECISIONS, FEEDBACK_REASON_CODES, get_bug_candidate, list_bug_candidates, set_bug_candidate_decision  # noqa: E402
from candidate_intelligence import PROFILES, candidate_calibration, candidate_evaluation, set_gold_label  # noqa: E402
from behavioral_intelligence import behavioral_summary  # noqa: E402
from security_reasoning import evidence_trace, evaluate_reasoning, family_calibration_report, reasoning_regression_gate, reasoning_summary, shadow_rule_report  # noqa: E402
from safe_validation import (  # noqa: E402
    FEEDBACK_DECISIONS as VALIDATION_FEEDBACK_DECISIONS, FEEDBACK_REASONS as VALIDATION_FEEDBACK_REASONS,
    VALIDATION_LEVELS, approve_validation_plan, create_validation_plan, execute_validation_plan, import_burp_xml,
    import_har, record_validation_feedback, validation_detail, validation_eligibility,
)
from product_platform import (  # noqa: E402
    CASE_STATES, RULE_STATES, NOTIFICATION_MODES, build_report_draft, build_validation_package,
    case_detail, engine_quality, incremental_checkpoint, learn_target_profile, list_cases, list_stories, noise_budget_status, operations_center,
    platform_sync, rule_governance, run_completeness, scope_center, set_case_state, set_notification_policy,
    set_rule_state, set_schedule_policy, storage_health, sync_security_cases, sync_security_stories, target_learning_profiles,
)
from platform_v6 import (  # noqa: E402
    PLATFORM_V6_VERSION, TARGET_TEMPLATES, apply_retention, apply_target_template, build_burp_roundtrip_package,
    correlate_security_stories, data_quality_snapshot, deliver_notifications, due_revalidations, generate_schedule_job,
    import_burp_roundtrip_result, list_target_templates, performance_diagnostics, platform_v6_sync, process_due_revalidations, queue_notification,
    run_scheduled_workflow,
    rank_review_queue, report_quality, retention_preview, review_value_for_case, security_posture,
    set_revalidation_policy, set_retention_policy, validation_intelligence, verify_audit_chain,
)
from workspace_v7 import (  # noqa: E402
    WORKSPACE_V7_VERSION, attack_surface_graph, authentication_contexts, browser_compatibility, build_evidence_linked_report,
    case_autopilot, case_autopilot_queue, change_intelligence, cockpit, differential_intelligence, evidence_gap_for_case,
    false_positive_learning, import_browser_capture, operator_diagnostics, recent_error_events, recon_coverage, safe_repair,
    safety_center, smart_recon_plan, stage_value_analysis, target_memory, universal_search, workspace_v7_sync,
)
from execution import BudgetManager, DatabaseWriter  # noqa: E402
from planning import build_plan, format_plan  # noqa: E402
from plugins import PluginManager  # noqa: E402
from operations import BackupManager, UpdateManager, benchmark  # noqa: E402
from secrets_manager import set_secret, delete_secret, known_secret_names, register_secret_name, unregister_secret_name  # noqa: E402
from api_server import serve_api, start_api, stop_api, api_status, create_token  # noqa: E402
from session_auth import create_user, disable_user, list_users  # noqa: E402
from postgres_mirror import status as postgres_status, initialize as postgres_init, sync as postgres_sync  # noqa: E402
from remote_worker import run_worker  # noqa: E402
from doctor import run_doctor  # noqa: E402
from maintenance import (  # noqa: E402
    backup_state,
    initialize_project,
    migrate_targets_txt,
    migrate_v1_database,
    record_versions_snapshot,
    retention,
)
from reporting import send_daily_digest, stage_report  # noqa: E402
from service import (  # noqa: E402
    install_service,
    print_service_logs,
    restart_service,
    service_status,
    uninstall_service,
)
from stages import STAGE_FUNCTIONS, StageContext  # noqa: E402
from setup_wizard import (  # noqa: E402
    add_targets,
    interactive_main_menu,
    list_targets,
    module_status,
    remove_target,
    run_setup_wizard,
)

STAGES = [
    ("subdomains", "Subdomain discovery and source attribution"),
    ("dns", "DNS resolution, wildcard filtering, and history"),
    ("urls", "Historical URLs and authorized crawling"),
    ("javascript", "JavaScript and source-map analysis"),
    ("endpoint_validation", "Safe in-scope endpoint validation"),
    ("fingerprint", "HTTP, TLS-adjacent, and content fingerprinting"),
    ("ports", "Optional authorized port monitoring"),
    ("nuclei", "Optional allowlisted active checks"),
    ("report", "Risk scoring, reports, retention state, and notifications"),
]
TOOLS = ["python3", "sqlite3", "subfinder", "assetfinder", "dnsx", "waybackurls", "katana", "httpx", "notify", "naabu", "nuclei"]


class Orchestrator:
    def __init__(self, paths: AppPaths, config: Config, logger: Logger, db: Database, *, progress: bool, allow_active: bool):
        self.paths = paths
        self.config = config
        self.logger = logger
        self.db = db
        self.progress = Progress(progress)
        self.runner = CommandRunner(logger, db)
        self.allow_active = allow_active
        self.db_writer = DatabaseWriter(paths.db)
        self.interrupted = False
        self.current_run_id = ""
        self.current_target = ""

    @staticmethod
    def _move_conflicting_pointer(path: Path) -> Path | None:
        """Preserve a legacy directory that conflicts with a pointer path.

        Older Recon Monitor layouts could leave a pointer path as a real
        directory. Never delete such a directory: move it aside with a
        timestamp so its contents remain recoverable. Files and symlinks are
        replaceable pointer objects and are removed before recreation.
        """
        if not path.exists() and not path.is_symlink():
            return None
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
            return None
        stamp = time.strftime("%Y%m%d-%H%M%S")
        candidate = path.with_name(f"{path.name}.legacy-{stamp}")
        index = 1
        while candidate.exists() or candidate.is_symlink():
            candidate = path.with_name(f"{path.name}.legacy-{stamp}-{index}")
            index += 1
        path.rename(candidate)
        return candidate

    @staticmethod
    def _pointer_names_collide(latest_file: Path, latest_link: Path) -> bool:
        """Return True when two differently-cased names address one object.

        Default macOS volumes are commonly case-insensitive. On such a volume
        ``LATEST`` and ``latest`` cannot simultaneously be a text file and a
        symlink. The check is performed after ``LATEST`` exists so ``samefile``
        can reliably detect the alias without making assumptions about the
        operating system or volume format.
        """
        if not latest_file.exists() or not latest_link.exists():
            return False
        try:
            return os.path.samefile(latest_file, latest_link)
        except OSError:
            return False

    def _update_latest_pointers(self, target_name: str, run_dir: Path) -> None:
        target_dir = self.paths.output / target_name
        target_dir.mkdir(parents=True, exist_ok=True)

        # LATEST is the authoritative, portable text pointer.
        latest_file = target_dir / "LATEST"
        moved_latest = self._move_conflicting_pointer(latest_file)
        if moved_latest is not None:
            self.logger.warn(
                "Preserved legacy LATEST directory",
                target=target_name,
                moved_to=str(moved_latest),
            )
        atomic_write_text(latest_file, str(run_dir) + "\n")

        # On case-sensitive filesystems we keep the historical ``latest``
        # symlink. On case-insensitive macOS filesystems that name aliases the
        # LATEST file, so use the unambiguous ``latest-run`` name instead.
        conventional_link = target_dir / "latest"
        names_collide = self._pointer_names_collide(latest_file, conventional_link)
        latest_link = target_dir / ("latest-run" if names_collide else "latest")
        if names_collide:
            self.logger.info(
                "Using latest-run symlink on case-insensitive filesystem",
                target=target_name,
            )

        moved_link = self._move_conflicting_pointer(latest_link)
        if moved_link is not None:
            self.logger.warn(
                "Preserved legacy latest pointer directory",
                target=target_name,
                moved_to=str(moved_link),
            )
        try:
            latest_link.symlink_to(run_dir.relative_to(target_dir))
        except OSError as exc:
            # The text pointer remains authoritative even when symlinks are
            # unavailable (for example, on a restricted filesystem).
            self.logger.warn(
                "Could not create latest-run symlink",
                target=target_name,
                pointer=str(latest_link),
                error=str(exc),
            )

    def install_signal_handlers(self) -> None:
        def handler(signum: int, _frame: Any) -> None:
            self.interrupted = True
            self.logger.warn("Interrupted by signal", signal=signum, run_id=self.current_run_id, target=self.current_target)
            self.runner.terminate_active()
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _record_versions(self, run_id: str) -> None:
        versions = collect_tool_versions(TOOLS)
        for tool, info in versions.items():
            self.db.record_tool_version(run_id, tool, info.get("version", ""), info.get("path", ""))
        record_versions_snapshot(self.paths)

    def _run_stage(
        self,
        ctx: StageContext,
        stage_name: str,
        label: str,
        stage_index: int,
        stage_total: int,
        target_index: int,
        target_total: int,
        baseline: bool,
        resume: bool,
    ) -> tuple[str, dict[str, Any]]:
        self.progress.configure(target_index, target_total, stage_index, stage_total, label)
        prior = self.db.stage_status(ctx.run_id, ctx.policy.name, stage_name)
        if resume and prior == "success":
            metrics_row = self.db.one(
                "SELECT metrics_json FROM stage_runs WHERE run_id=? AND target=? AND stage=?",
                (ctx.run_id, ctx.policy.name, stage_name),
            )
            metrics = safe_json_loads(metrics_row["metrics_json"], {}, expected_type=dict) if metrics_row else {}
            self.progress.finish_stage("resume-skip", metrics)
            return "success", metrics

        module_enabled = True
        if stage_name in {"subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "ports", "nuclei"}:
            module_enabled = bool(ctx.policy.modules.get(stage_name, True))
        if not module_enabled:
            metrics = {"skipped": "disabled by target policy"}
            self.db.stage_begin(ctx.run_id, ctx.policy.name, stage_name, 1)
            self.db.stage_finish(ctx.run_id, ctx.policy.name, stage_name, "success", metrics=metrics)
            self.progress.finish_stage("skip", metrics)
            return "success", metrics

        attempts = max(1, ctx.policy.limits.retries + 1)
        last_error = ""
        for attempt in range(1, attempts + 1):
            self.db.stage_begin(ctx.run_id, ctx.policy.name, stage_name, attempt)
            started = time.monotonic()
            try:
                if stage_name == "report":
                    metrics = stage_report(ctx, baseline)
                else:
                    metrics = STAGE_FUNCTIONS[stage_name](ctx)
                duration = time.monotonic() - started
                self.db.stage_finish(
                    ctx.run_id,
                    ctx.policy.name,
                    stage_name,
                    "success",
                    duration=duration,
                    metrics=metrics,
                )
                self.progress.finish_stage("ok", metrics)
                return "success", metrics
            except KeyboardInterrupt:
                duration = time.monotonic() - started
                self.db.stage_finish(
                    ctx.run_id,
                    ctx.policy.name,
                    stage_name,
                    "interrupted",
                    exit_code=130,
                    duration=duration,
                    error="interrupted",
                )
                raise
            except Exception as exc:
                duration = time.monotonic() - started
                exit_code = int(getattr(exc, "exit_code", 1))
                retryable = bool(getattr(exc, "retryable", True))
                last_error = str(exc)
                self.db.stage_finish(
                    ctx.run_id,
                    ctx.policy.name,
                    stage_name,
                    "failed",
                    exit_code=exit_code,
                    duration=duration,
                    error=last_error,
                    metrics={"attempt": attempt},
                )
                self.logger.warn(
                    "Stage failed",
                    run_id=ctx.run_id,
                    target=ctx.policy.name,
                    stage=stage_name,
                    attempt=attempt,
                    error=last_error,
                )
                if attempt < attempts and retryable:
                    delay = min(30, 2 ** (attempt - 1))
                    self.progress.message(f"  Retrying {stage_name} in {delay}s ({attempt}/{attempts})…")
                    time.sleep(delay)
                    continue
                self.progress.finish_stage("failed", {"error": last_error, "attempt": attempt})
                return "failed", {"error": last_error, "attempt": attempt}
        return "failed", {"error": last_error}

    def run(self, policies: PolicySet, selector: str | None = None, resume_id: str | None = None) -> int:
        if not self.config.authorized:
            raise ReconError('Set I_HAVE_AUTHORIZATION="yes" only after confirming every configured target is authorized.')
        targets = policies.select(selector)
        run_id = resume_id or self.db.create_run(selector, len(targets), config_hash(self.config, policies))
        self.current_run_id = run_id
        if resume_id:
            row = self.db.one("SELECT id,status FROM runs WHERE id=?", (resume_id,))
            if not row:
                raise ReconError(f"Run not found for resume: {resume_id}")
            self.db.execute("UPDATE runs SET status='running',finished_at=NULL,error=NULL WHERE id=?", (run_id,))
        self._record_versions(run_id)
        self.install_signal_handlers()
        print(f"Recon Monitor {APP_VERSION} | Run: {run_id} | Targets: {len(targets)} | Started: {local_now()}\n")
        failures = 0
        try:
            for target_index, policy in enumerate(targets, 1):
                self.current_target = policy.name
                existing = self.db.one("SELECT run_dir,baseline FROM run_targets WHERE run_id=? AND target=?", (run_id, policy.name))
                if existing:
                    run_dir = Path(str(existing["run_dir"]))
                    baseline = bool(existing["baseline"])
                else:
                    run_dir = self.paths.output / policy.name / "runs" / run_id
                    baseline = not self.db.target_has_history(policy.name)
                    run_dir.mkdir(parents=True, exist_ok=True)
                    self.db.create_run_target(run_id, policy, run_dir, baseline)
                (run_dir / "current").mkdir(parents=True, exist_ok=True)
                (run_dir / "changes").mkdir(parents=True, exist_ok=True)
                print(f"Target {target_index}/{len(targets)}: {policy.name}" + (" (initial baseline)" if baseline else ""))
                ctx = StageContext(
                    self.paths,
                    self.config,
                    policy,
                    self.db,
                    self.logger,
                    self.runner,
                    self.progress,
                    run_id,
                    run_dir,
                    self.allow_active,
                    BudgetManager.create(self.db, run_id, policy.name, policy),
                    self.db_writer,
                )
                target_failed = False
                report_ran = False
                for stage_index, (stage_name, label) in enumerate(STAGES, 1):
                    if target_failed and stage_name != "report":
                        # Persist explicit skipped state so resume can continue at the failed stage.
                        continue
                    status, _metrics = self._run_stage(
                        ctx,
                        stage_name,
                        label,
                        stage_index,
                        len(STAGES),
                        target_index,
                        len(targets),
                        baseline,
                        bool(resume_id),
                    )
                    if stage_name == "report":
                        report_ran = True
                    if status != "success" and stage_name != "report":
                        target_failed = True
                if target_failed and not report_ran:
                    # Should not normally happen, but preserve partial reporting.
                    with contextlib.suppress(Exception):
                        self._run_stage(ctx, "report", STAGES[-1][1], len(STAGES), len(STAGES), target_index, len(targets), baseline, False)
                self.db.finish_run_target(run_id, policy.name, "failed" if target_failed else "success")
                failures += int(target_failed)
                self._update_latest_pointers(policy.name, run_dir)
                print(f"  Results: {run_dir}\n")
            status = "success" if failures == 0 else "partial"
            self.db.finish_run(run_id, status)
            if self.config.bool("AUTO_RETENTION", True):
                with contextlib.suppress(Exception):
                    retention(self.paths, self.config, self.db, self.logger, False)
            digest_hours = self.config.int("AUTO_DIGEST_HOURS", 24, 0, 720)
            if digest_hours > 0:
                import datetime as dt
                last_digest = self.db.meta_get("last_auto_digest_at")
                due = True
                if last_digest:
                    with contextlib.suppress(ValueError):
                        previous = dt.datetime.fromisoformat(last_digest.replace("Z", "+00:00"))
                        due = (dt.datetime.now(dt.timezone.utc) - previous).total_seconds() >= digest_hours * 3600
                if due:
                    with contextlib.suppress(Exception):
                        send_daily_digest(self.paths, self.config, self.db, self.logger, digest_hours)
                        self.db.meta_set("last_auto_digest_at", utc_now())
            print(f"Run completed: {status} | failures={failures} | {local_now()}")
            return 0 if failures == 0 else 2
        except KeyboardInterrupt:
            self.db.finish_run(run_id, "interrupted", "interrupted by signal")
            print("\nRun interrupted safely. Resume with:")
            print(f"  ./recon-monitor.sh run --resume {run_id}")
            return 130
        except Exception as exc:
            self.db.finish_run(run_id, "failed", str(exc))
            raise
        finally:
            self.runner.terminate_active()
            self.db_writer.close()
            self.current_target = ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-monitor", description="Authorized attack-surface change monitoring")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="Initialize configuration, policies, and database")
    init.add_argument("--no-wizard", action="store_true", help="Do not launch the interactive setup wizard")
    sub.add_parser("setup", help="Interactive target and module setup wizard")
    run = sub.add_parser("run", help="Run recon monitoring")
    run.add_argument("--target", help="Policy name or root domain")
    run.add_argument("--resume", help="Resume an interrupted/failed run ID")
    run.add_argument("--allow-active", action="store_true", help="Satisfy the CLI gate for already-authorized active modules")
    run.add_argument("--dry-run", action="store_true", help="Preview scope, modules, limits, and budgets without network requests")
    run.add_argument("--json-plan", action="store_true", help="Print dry-run plan as JSON")
    group = run.add_mutually_exclusive_group()
    group.add_argument("--progress", action="store_true", help="Force interactive progress")
    group.add_argument("--no-progress", action="store_true", help="Disable interactive progress")

    doctor = sub.add_parser("doctor", help="Run health and compatibility checks")
    doctor.add_argument("--no-network", action="store_true")

    dashboard = sub.add_parser("dashboard", help="Manage the local dashboard")
    dashboard.add_argument("action", nargs="?", default="foreground", choices=["foreground", "start", "stop", "restart", "status", "logs", "open", "auth-set", "auth-disable", "auth-status"])
    dashboard.add_argument("--host", default=None)
    dashboard.add_argument("--port", type=int, default=None)
    dashboard.add_argument("--allow-remote", action="store_true")
    dashboard.add_argument("--open", action="store_true", dest="open_browser")
    dashboard.add_argument("--lines", type=int, default=100)
    dashboard.add_argument("--username", default=None, help="Dashboard authentication username")

    targets = sub.add_parser("targets", help="Manage configured targets")
    targets.add_argument("action", choices=["list", "add", "remove"])
    targets.add_argument("values", nargs="*")

    modules = sub.add_parser("modules", help="Show or configure modules")
    modules.add_argument("action", choices=["status", "configure"], default="status", nargs="?")

    compare = sub.add_parser("compare", help="Compare two completed runs")
    compare.add_argument("old_run")
    compare.add_argument("new_run")
    compare.add_argument("--target")
    compare.add_argument("--json", action="store_true")

    service = sub.add_parser("service", help="Manage macOS LaunchAgent")
    service.add_argument("action", choices=["install", "uninstall", "status", "restart", "logs"])
    service.add_argument("--interval", default="3h")
    service.add_argument("--lines", type=int, default=100)

    digest = sub.add_parser("digest", help="Send alert digest")
    digest.add_argument("--hours", type=int, default=24)

    retain = sub.add_parser("retention", help="Apply retention and blob garbage collection")
    retain.add_argument("--dry-run", action="store_true")

    backup = sub.add_parser("backup", help="Create, list, verify, drill, or restore backups")
    backup.add_argument("action", nargs="?", default="create", choices=["create","list","verify","drill","restore"])
    backup.add_argument("backup_id", nargs="?", help="Backup ID or 'latest'")
    backup.add_argument("--include-objects", action="store_true")
    backup.add_argument("--force", action="store_true")

    repair = sub.add_parser("repair", help="Inspect or repair stale execution state")
    repair.add_argument("--dry-run", action="store_true")
    repair.add_argument("--max-age-hours", type=int, default=24)
    repair.add_argument("--json-health", action="store_true", help="Also sample stored JSON fields")
    repair.add_argument("--force", action="store_true", help="Allow repair while a live run lock exists")
    sub.add_parser("migrate-v1", help="Import legacy targets.txt and recon.db")
    sub.add_parser("test-telegram", help="Test Telegram configuration")
    sub.add_parser("versions", help="Capture tool versions")


    ignore = sub.add_parser("ignore", help="Manage alert/event ignore rules")
    ignore.add_argument("action", choices=["add","list","test","remove","enable","disable"])
    ignore.add_argument("--id", type=int)
    ignore.add_argument("--target", default="*")
    ignore.add_argument("--type", dest="rule_type", default="any")
    ignore.add_argument("--pattern", default="")
    ignore.add_argument("--value", default="")
    ignore.add_argument("--note", default="")

    plugins = sub.add_parser("plugins", help="List and health-check plugin SDK modules")
    plugins.add_argument("action", nargs="?", default="list", choices=["list","health"])

    secrets_cmd = sub.add_parser("secrets", help="Manage secrets in macOS Keychain")
    secrets_cmd.add_argument("action", choices=["set","list","delete"])
    secrets_cmd.add_argument("name", nargs="?")

    api = sub.add_parser("api", help="Manage local authenticated API")
    api.add_argument("action", nargs="?", default="foreground", choices=["foreground","start","stop","status","token-create","token-list","token-revoke"])
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8790)
    api.add_argument("--allow-remote", action="store_true")
    api.add_argument("--name", default="cli")
    api.add_argument("--role", choices=["viewer","analyst","worker","lead_analyst","admin"], default="viewer")
    api.add_argument("--scopes", default="", help="Comma-separated: read,write,validation,operations,admin,worker")
    api.add_argument("--expires-days", type=int, default=90)
    api.add_argument("--id", type=int)

    users = sub.add_parser("users", help="Manage dashboard RBAC users")
    users.add_argument("action", choices=["add","list","disable"])
    users.add_argument("username", nargs="?")
    users.add_argument("--role", choices=["viewer","analyst","lead_analyst","admin"], default="admin")

    update = sub.add_parser("update", help="Check, install, or rollback signed/checksummed releases")
    update.add_argument("action", choices=["check","install","rollback"])
    update.add_argument("--package")
    update.add_argument("--repo", default="", help="GitHub repository owner/name for automatic private-release updates")
    update.add_argument("--force", action="store_true", help="Install the latest release even when the version matches")
    update.add_argument("--sha256", default="")
    update.add_argument("--signature", default="")
    update.add_argument("--public-key", default="")

    postgres = sub.add_parser("postgres", help="Manage optional PostgreSQL analytics mirror")
    postgres.add_argument("action", choices=["status","init","sync"])

    sub.add_parser("benchmark", help="Run local performance benchmarks")

    worker = sub.add_parser("worker", help="Run a restricted remote worker agent")
    worker.add_argument("action", choices=["run"])
    worker.add_argument("--server", required=True)
    worker.add_argument("--token", default="")
    worker.add_argument("--worker-id", default="")
    worker.add_argument("--name", default="")
    worker.add_argument("--interval", type=int, default=5)
    worker.add_argument("--once", action="store_true")

    views = sub.add_parser("views", help="Manage saved dashboard/API views")
    views.add_argument("action", choices=["list","add","remove"])
    views.add_argument("--name", default="")
    views.add_argument("--type", dest="view_type", default="search")
    views.add_argument("--query", default="{}")
    views.add_argument("--owner", default="admin")

    alerts = sub.add_parser("alerts", help="Manage alert workflow status")
    alerts.add_argument("action", choices=["set-status", "list"])
    alerts.add_argument("--id", type=int)
    alerts.add_argument("--status", choices=["new", "triaged", "acknowledged", "investigating", "interesting", "reported", "resolved", "ignored", "false_positive", "out_of_scope"])
    alerts.add_argument("--limit", type=int, default=50)

    analyze = sub.add_parser("analyze", help="Run the evidence and hypothesis engine on a completed recon run")
    analyze.add_argument("--run", dest="run_id", required=True, help="Completed source run ID")
    analyze.add_argument("--target", default=None)
    analyze.add_argument("--rules", default="latest", help="Rule set selector; latest is currently supported")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--profile", choices=sorted(PROFILES), default="balanced")

    analysis_cmd = sub.add_parser("analysis", help="Replay and inspect analysis-engine quality and bug candidates")
    analysis_cmd.add_argument("action", choices=["replay", "quality", "calibration", "feedback", "list", "show", "candidates", "candidate-show", "candidate-set", "candidate-calibration", "candidate-evaluate", "candidate-label", "bundles", "semantic", "behavioral", "boundary-diffs", "response-diffs", "protocols", "identity-graph", "reasoning", "evidence-trace", "reasoning-evaluate", "family-calibration", "shadow-rules", "regression-gate"])
    analysis_cmd.add_argument("--run", dest="run_id", default="")
    analysis_cmd.add_argument("--target", default=None)
    analysis_cmd.add_argument("--id", dest="analysis_id", default="")
    analysis_cmd.add_argument("--candidate-id", default="")
    analysis_cmd.add_argument("--family", default="")
    analysis_cmd.add_argument("--state", default="")
    analysis_cmd.add_argument("--decision", choices=list(ANALYST_DECISIONS), default="")
    analysis_cmd.add_argument("--note", default="")
    analysis_cmd.add_argument("--reason", choices=list(FEEDBACK_REASON_CODES), default="")
    analysis_cmd.add_argument("--label", default="")
    analysis_cmd.add_argument("--expected-family", default="")
    analysis_cmd.add_argument("--profile", choices=sorted(PROFILES), default="balanced")
    analysis_cmd.add_argument("--limit", type=int, default=20)

    platform = sub.add_parser("platform", help="Manage the 5.0 quality, cases, operations, scope and production platform")
    platform.add_argument("action", choices=["sync","quality","cases","case-show","case-set","stories","scope","operations","storage","completeness","validation-package","report-draft","rules","rule-set","schedule-set","notification-set","incremental","learning","noise-budget"])
    platform.add_argument("--analysis-id", default="")
    platform.add_argument("--run", dest="run_id", default="")
    platform.add_argument("--target", default="")
    platform.add_argument("--case-id", default="")
    platform.add_argument("--state", default="")
    platform.add_argument("--assignee", default=None)
    platform.add_argument("--note", default="")
    platform.add_argument("--limit", type=int, default=100)
    platform.add_argument("--rule-id", default="")
    platform.add_argument("--rule-version", default="")
    platform.add_argument("--cadence", default="")
    platform.add_argument("--enabled", choices=["true","false"], default="true")
    platform.add_argument("--max-runtime", type=int, default=120)
    platform.add_argument("--request-budget", type=int, default=10000)
    platform.add_argument("--quiet-hours", default="")
    platform.add_argument("--event-type", default="")
    platform.add_argument("--mode", choices=NOTIFICATION_MODES, default="digest")
    platform.add_argument("--minimum-score", type=int, default=70)
    platform.add_argument("--profile", choices=["quiet","balanced","research"], default="balanced")

    suite = sub.add_parser("suite", help="Manage the compatibility intelligence, coverage, automation and hardening suite")
    suite.add_argument("action", choices=["sync","validation-intelligence","revalidation-set","revalidation-due","revalidation-process","scheduled-run","data-quality","review-value","review-queue","burp-export","burp-import","story-correlate","schedule-sync","notify-queue","notify-deliver","security-posture","audit-verify","retention-policy","retention-preview","retention-apply","performance","templates","template-apply","report-quality"])
    suite.add_argument("--run", dest="run_id", default="")
    suite.add_argument("--analysis-id", default="")
    suite.add_argument("--validation-run-id", default="")
    suite.add_argument("--case-id", default="")
    suite.add_argument("--draft-id", default="")
    suite.add_argument("--package-id", default="")
    suite.add_argument("--target", default="")
    suite.add_argument("--trigger", default="manual")
    suite.add_argument("--interval-days", type=int, default=7)
    suite.add_argument("--enabled", choices=["true","false"], default="true")
    suite.add_argument("--apply", action="store_true")
    suite.add_argument("--apply-permissions", action="store_true")
    suite.add_argument("--limit", type=int, default=100)
    suite.add_argument("--file", default="")
    suite.add_argument("--event", default="{}")
    suite.add_argument("--mode", default="immediate")
    suite.add_argument("--dry-run", action="store_true")
    suite.add_argument("--category", default="")
    suite.add_argument("--days", type=int, default=90)
    suite.add_argument("--keep-count", type=int, default=0)
    suite.add_argument("--preview-id", default="")
    suite.add_argument("--confirmation", default="")
    suite.add_argument("--template-id", default="")

    workspace = sub.add_parser("workspace", help="Manage the Recon Monitor 8.x unified security research workspace")
    workspace.add_argument("action", choices=["sync","diagnostics","repair","errors","evidence-gap","autopilot","autopilot-queue","contexts","differential","coverage","graph","changes","memory","learning","plan","stage-value","report","capture-import","safety","cockpit","search"])
    workspace.add_argument("--target", default="")
    workspace.add_argument("--run", dest="run_id", default="")
    workspace.add_argument("--analysis-id", default="")
    workspace.add_argument("--case-id", default="")
    workspace.add_argument("--file", default="")
    workspace.add_argument("--context", default="")
    workspace.add_argument("--query", default="")
    workspace.add_argument("--limit", type=int, default=100)
    workspace.add_argument("--apply", action="store_true", help="Apply the safe repair action after preview")
    workspace.add_argument("--max-age-hours", type=int, default=24)

    validation = sub.add_parser("validation", help="Plan and run bounded safe validation for security cases")
    validation.add_argument("action", choices=["eligibility","plan","approve","run","show","list","import-har","import-burp","feedback"])
    validation.add_argument("--case-id", default="")
    validation.add_argument("--plan-id", default="")
    validation.add_argument("--run-id", default="")
    validation.add_argument("--level", choices=VALIDATION_LEVELS, default="")
    validation.add_argument("--confirmation", default="")
    validation.add_argument("--allow-live", action="store_true")
    validation.add_argument("--file", default="")
    validation.add_argument("--decision", choices=VALIDATION_FEEDBACK_DECISIONS, default="")
    validation.add_argument("--reason", choices=VALIDATION_FEEDBACK_REASONS, default="")
    validation.add_argument("--note", default="")
    validation.add_argument("--limit", type=int, default=100)

    tests = sub.add_parser("test", help="Run bundled unit tests")
    tests.add_argument("--verbose", action="store_true")
    tests.add_argument("--integration", action="store_true", help="Run local end-to-end fixture tests")
    return parser


def translate_legacy_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] == "--once":
        return ["run", *argv[1:]]
    if argv[0] == "--init":
        return ["init", *argv[1:]]
    if argv[0] == "--test-telegram":
        return ["test-telegram", *argv[1:]]
    if argv[0] == "--schedule":
        interval = argv[1] if len(argv) > 1 else "3h"
        return ["service", "install", "--interval", interval]
    if argv[0] == "--unschedule":
        return ["service", "uninstall"]
    if argv[0] == "--status":
        return ["service", "status"]
    return argv


def list_alerts(db: Database, limit: int) -> None:
    rows = db.all(
        "SELECT id,target,severity,risk_score,status,title,item,last_seen FROM alerts ORDER BY risk_score DESC,last_seen DESC LIMIT ?",
        (max(1, min(1000, limit)),),
    )
    print("ID\tTARGET\tSEVERITY\tSCORE\tSTATUS\tTITLE\tITEM\tLAST_SEEN")
    for row in rows:
        print("\t".join(str(row[key] or "").replace("\t", " ") for key in row.keys()))


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    paths = AppPaths.from_root(ROOT_DIR)
    if not raw_argv and sys.stdin.isatty():
        raw_argv = interactive_main_menu(paths)
    argv = translate_legacy_args(raw_argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    paths.ensure()
    logger = Logger(paths, verbose=True)

    if args.command == "init":
        result = initialize_project(paths, logger)
        if (paths.root / "recon.db").exists():
            migrate_v1_database(paths, logger)
        print(json_dumps(result, pretty=True))
        if not args.no_wizard and sys.stdin.isatty():
            run_setup_wizard(paths)
        else:
            print("\nNext: run ./recon-monitor.sh setup, then ./recon-monitor.sh doctor")
        return 0

    if args.command == "setup":
        if not paths.config.exists():
            initialize_project(paths, logger)
        print(json_dumps(run_setup_wizard(paths), pretty=True))
        return 0

    if not paths.config.exists():
        raise ReconError("config.env not found. Run ./recon-monitor.sh init")
    config = Config(paths)

    if args.command == "doctor":
        checks = run_doctor(paths, config, logger, network=not args.no_network)
        return 1 if any(check.level == "FAIL" for check in checks) else 0

    if args.command == "dashboard":
        host = args.host or config.get("DASHBOARD_HOST", "127.0.0.1")
        port = args.port or config.int("DASHBOARD_PORT", 8787, 1, 65535)
        if args.action == "foreground":
            serve_dashboard(paths, config, logger, host, port, args.allow_remote)
        elif args.action == "start":
            start_dashboard(paths, config, logger, host, port, args.allow_remote, args.open_browser)
        elif args.action == "stop":
            stop_dashboard(paths, logger)
        elif args.action == "restart":
            restart_dashboard(paths, config, logger, host, port, args.allow_remote, args.open_browser)
        elif args.action == "status":
            active, detail = dashboard_status(paths)
            print(detail)
            return 0 if active else 1
        elif args.action == "logs":
            print_dashboard_logs(paths, args.lines)
        elif args.action == "open":
            open_dashboard(host, port)
        elif args.action == "auth-set":
            username = args.username or input("Dashboard username [admin]: ").strip() or "admin"
            password = getpass.getpass("Dashboard password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                raise ReconError("Dashboard passwords do not match")
            configure_auth(paths, username, password)
            create_user(paths, username, password, "admin")
            # Session authentication is the v3 default; Basic credentials remain
            # as a compatibility fallback for older clients.
            from dashboard_auth import _update_env
            _update_env(paths.config, {"DASHBOARD_AUTH_MODE": "session"})
            print(f"Dashboard session authentication enabled for admin user: {username}")
            print("Restart the dashboard if it is currently running.")
        elif args.action == "auth-disable":
            disable_auth(paths)
            print("Dashboard authentication disabled. Keep the dashboard bound to 127.0.0.1.")
            print("Restart the dashboard if it is currently running.")
        elif args.action == "auth-status":
            enabled, detail = auth_status(config)
            print(detail)
            return 0 if enabled else 1
        return 0

    if args.command == "service":
        if args.action == "install":
            path = install_service(paths, config, logger, args.interval)
            print(f"Installed: {path}")
        elif args.action == "uninstall":
            uninstall_service(logger)
            print("LaunchAgent removed")
        elif args.action == "status":
            active, detail = service_status()
            print(detail if active else "LaunchAgent is not installed or not loaded")
            return 0 if active else 1
        elif args.action == "restart":
            restart_service(logger)
            print("LaunchAgent restarted")
        elif args.action == "logs":
            print_service_logs(paths, args.lines)
        return 0

    if args.command == "targets":
        if args.action == "list":
            for target in list_targets(paths):
                print(target)
        elif args.action == "add":
            if not args.values:
                raise ReconError("targets add requires one or more domains")
            for target in add_targets(paths, args.values):
                print(target)
        elif args.action == "remove":
            if len(args.values) != 1:
                raise ReconError("targets remove requires exactly one target")
            for target in remove_target(paths, args.values[0]):
                print(target)
        return 0

    if args.command == "modules":
        if args.action == "configure":
            print(json_dumps(run_setup_wizard(paths), pretty=True))
        else:
            for key, enabled in module_status(paths).items():
                print(f"{key}={'enabled' if enabled else 'disabled'}")
        return 0

    db = Database(paths.db)
    try:
        if args.command == "compare":
            result = compare_runs(paths, db, args.old_run, args.new_run, args.target)
            print(json_dumps(result, pretty=True) if args.json else format_comparison(result))
            return 0

        if args.command == "analyze":
            if args.rules != "latest":
                raise ReconError("Only --rules latest is supported in this release")
            result = run_analysis(paths, db, args.run_id, args.target, profile=args.profile)
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "analysis":
            if args.action == "replay":
                if not args.run_id: raise ReconError("analysis replay requires --run RUN_ID")
                result = replay_analysis(paths, db, args.run_id, args.target, profile=args.profile)
            elif args.action == "quality":
                result = analysis_quality(db, args.target)
            elif args.action == "calibration":
                result = calibration_report(db, args.target)
            elif args.action == "feedback":
                result = feedback_report(db, args.target)
            elif args.action == "list":
                result = [dict(row) for row in db.all("SELECT id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json FROM analysis_runs ORDER BY started_at DESC LIMIT ?", (max(1,min(200,args.limit)),))]
            elif args.action == "candidates":
                result = list_bug_candidates(db, analysis_id=args.analysis_id, target=args.target or "", family=args.family, state=args.state, limit=args.limit)
            elif args.action == "candidate-show":
                if not args.candidate_id: raise ReconError("analysis candidate-show requires --candidate-id ID")
                result = get_bug_candidate(db, args.candidate_id)
            elif args.action == "candidate-set":
                if not args.candidate_id: raise ReconError("analysis candidate-set requires --candidate-id ID")
                if not args.decision: raise ReconError("analysis candidate-set requires --decision")
                result = set_bug_candidate_decision(db, args.candidate_id, args.decision, args.note, actor="cli", reason_code=args.reason)
            elif args.action == "candidate-calibration":
                result = candidate_calibration(db, args.target)
            elif args.action == "candidate-evaluate":
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                if not analysis_id: raise ReconError("No completed analysis available")
                result = candidate_evaluation(db, analysis_id, profile=args.profile)
            elif args.action == "candidate-label":
                if not args.candidate_id: raise ReconError("analysis candidate-label requires --candidate-id ID")
                if not args.label: raise ReconError("analysis candidate-label requires --label")
                result = set_gold_label(db, args.candidate_id, args.label, args.expected_family, args.note)
            elif args.action == "bundles":
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                result = [dict(row) for row in db.all("SELECT * FROM candidate_bundles WHERE analysis_id=? ORDER BY priority_score DESC LIMIT ?", (analysis_id,max(1,min(1000,args.limit))))] if analysis_id else []
            elif args.action == "semantic":
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                result = {"semantic_js_units":[dict(row) for row in db.all("SELECT * FROM semantic_js_units WHERE analysis_id=? ORDER BY confidence DESC LIMIT ?",(analysis_id,max(1,min(1000,args.limit))))],"feature_flags":[dict(row) for row in db.all("SELECT * FROM feature_flags WHERE analysis_id=? ORDER BY confidence DESC LIMIT ?",(analysis_id,max(1,min(1000,args.limit))))],"endpoint_contracts":[dict(row) for row in db.all("SELECT * FROM endpoint_contracts WHERE analysis_id=? ORDER BY confidence DESC LIMIT ?",(analysis_id,max(1,min(1000,args.limit))))]} if analysis_id else {}
            elif args.action == "reasoning":
                result = reasoning_summary(db, args.analysis_id or None)
            elif args.action == "evidence-trace":
                if not args.candidate_id: raise ReconError("analysis evidence-trace requires --candidate-id ID")
                result = evidence_trace(db, args.candidate_id)
            elif args.action == "reasoning-evaluate":
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                if not analysis_id: raise ReconError("No completed analysis available")
                result = evaluate_reasoning(db, analysis_id, persist=True)
            elif args.action == "family-calibration":
                result = family_calibration_report(db, args.target)
            elif args.action == "shadow-rules":
                result = shadow_rule_report(db, args.analysis_id or None)
            elif args.action == "regression-gate":
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                if not analysis_id: raise ReconError("No completed analysis available")
                result = reasoning_regression_gate(db, analysis_id, persist=True)
            elif args.action in {"behavioral", "boundary-diffs", "response-diffs", "protocols", "identity-graph"}:
                analysis_id = args.analysis_id
                if not analysis_id:
                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
                    analysis_id = str(latest["id"]) if latest else ""
                summary = behavioral_summary(db, analysis_id) if analysis_id else {}
                if args.action == "boundary-diffs": result = summary.get("boundary_diffs", [])[:max(1,min(1000,args.limit))]
                elif args.action == "response-diffs": result = summary.get("response_shape_diffs", [])[:max(1,min(1000,args.limit))]
                elif args.action == "protocols": result = summary.get("protocol_findings", [])[:max(1,min(1000,args.limit))]
                elif args.action == "identity-graph": result = {"entities":summary.get("identity_entities", [])[:max(1,min(1000,args.limit))],"relations":summary.get("identity_relations", [])[:max(1,min(1000,args.limit))]}
                else: result = summary
            else:
                if not args.analysis_id: raise ReconError("analysis show requires --id ANALYSIS_ID")
                run_row = db.one("SELECT * FROM analysis_runs WHERE id=?", (args.analysis_id,))
                if not run_row: raise ReconError(f"Analysis run not found: {args.analysis_id}")
                result = {"analysis":dict(run_row),"results":[dict(row) for row in db.all("SELECT * FROM analysis_results WHERE analysis_id=? ORDER BY adjusted_score DESC,confidence DESC",(args.analysis_id,))],"bug_candidates":[dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY priority_score DESC",(args.analysis_id,))]}
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "platform":
            if args.action == "sync":
                legacy = platform_sync(paths, db, args.analysis_id or None)
                workspace = workspace_v7_sync(paths, config, db, target=args.target or "", actor="cli-platform-sync")
                result = {"platform": legacy, "workspace_v7": workspace}
            elif args.action == "quality":
                result = engine_quality(db, args.analysis_id or None, args.target or None, persist=True)
            elif args.action == "cases":
                result = list_cases(db, state=args.state or None, target=args.target or None, limit=args.limit)
            elif args.action == "case-show":
                if not args.case_id: raise ReconError("platform case-show requires --case-id")
                result = case_detail(db, args.case_id)
            elif args.action == "case-set":
                if not args.case_id or not args.state: raise ReconError("platform case-set requires --case-id and --state")
                result = set_case_state(db, args.case_id, args.state, assigned_to=args.assignee, note=args.note, actor="cli")
            elif args.action == "stories":
                sync_security_stories(db, args.analysis_id or None); result = list_stories(db, args.limit)
            elif args.action == "scope":
                result = scope_center(paths, db)
            elif args.action == "operations":
                result = operations_center(paths, db)
            elif args.action == "storage":
                result = storage_health(paths, db, persist=True)
            elif args.action == "completeness":
                result = run_completeness(db, args.run_id or None, persist=True)
            elif args.action == "validation-package":
                if not args.case_id: raise ReconError("platform validation-package requires --case-id")
                result = build_validation_package(db, args.case_id, actor="cli")
            elif args.action == "report-draft":
                if not args.case_id: raise ReconError("platform report-draft requires --case-id")
                result = build_report_draft(db, args.case_id, actor="cli")
            elif args.action == "rules":
                result = rule_governance(db)
            elif args.action == "rule-set":
                if not args.rule_id or not args.rule_version or not args.state: raise ReconError("platform rule-set requires --rule-id --rule-version --state")
                result = set_rule_state(db, args.rule_id, args.rule_version, args.state, actor="cli", note=args.note)
            elif args.action == "schedule-set":
                if not args.target or not args.cadence: raise ReconError("platform schedule-set requires --target and --cadence")
                result = set_schedule_policy(db, args.target, args.cadence, enabled=args.enabled=="true", max_runtime_minutes=args.max_runtime, request_budget=args.request_budget, quiet_hours=args.quiet_hours, actor="cli")
            elif args.action == "notification-set":
                if not args.target or not args.event_type: raise ReconError("platform notification-set requires --target and --event-type")
                result = set_notification_policy(db, args.target, args.event_type, args.mode, minimum_score=args.minimum_score, actor="cli")
            elif args.action == "incremental":
                result = incremental_checkpoint(db, args.analysis_id or None)
            elif args.action == "learning":
                result = learn_target_profile(db, args.target, args.analysis_id or None, persist=True) if args.target else target_learning_profiles(db)
            elif args.action == "noise-budget":
                result = noise_budget_status(db, args.analysis_id or None, profile=args.profile, target=args.target or None)
            else:
                raise ReconError(f"Unsupported platform action: {args.action}")
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "suite":
            if args.action == "sync":
                legacy = platform_v6_sync(paths, db, run_id=args.run_id or None, analysis_id=args.analysis_id or None)
                workspace = workspace_v7_sync(paths, config, db, target=args.target or "", actor="cli-suite-sync")
                result = {"platform_v6": legacy, "workspace_v7": workspace}
            elif args.action == "validation-intelligence":
                if not args.validation_run_id: raise ReconError("suite validation-intelligence requires --validation-run-id")
                result = validation_intelligence(db, args.validation_run_id, persist=True)
            elif args.action == "revalidation-set":
                if not args.case_id: raise ReconError("suite revalidation-set requires --case-id")
                result = set_revalidation_policy(db, args.case_id, args.trigger, interval_days=args.interval_days, enabled=args.enabled=="true", actor="cli")
            elif args.action == "revalidation-due":
                result = due_revalidations(db, limit=args.limit)
            elif args.action == "revalidation-process":
                result = process_due_revalidations(paths, config, db, limit=args.limit, execute_offline=not args.dry_run, actor="cli")
            elif args.action == "scheduled-run":
                if not args.target: raise ReconError("suite scheduled-run requires --target")
                result = run_scheduled_workflow(paths, config, db, args.target, dry_run=args.dry_run, actor="scheduler")
            elif args.action == "data-quality":
                result = data_quality_snapshot(db, args.run_id or None, args.target or None, persist=True)
            elif args.action == "review-value":
                if not args.case_id: raise ReconError("suite review-value requires --case-id")
                result = review_value_for_case(db, args.case_id, persist=True)
            elif args.action == "review-queue":
                result = rank_review_queue(db, target=args.target or None, limit=args.limit, refresh=args.apply)
            elif args.action == "burp-export":
                if not args.case_id: raise ReconError("suite burp-export requires --case-id")
                result = build_burp_roundtrip_package(paths, db, args.case_id, actor="cli")
            elif args.action == "burp-import":
                if not args.package_id or not args.file: raise ReconError("suite burp-import requires --package-id and --file")
                result = import_burp_roundtrip_result(db, args.package_id, json.loads(Path(args.file).read_text(encoding="utf-8")), actor="cli")
            elif args.action == "story-correlate":
                result = correlate_security_stories(db, args.analysis_id or None, persist=True)
            elif args.action == "schedule-sync":
                if not args.target: raise ReconError("suite schedule-sync requires --target")
                result = generate_schedule_job(paths, db, args.target, apply=args.apply, actor="cli")
            elif args.action == "notify-queue":
                event = json.loads(args.event)
                result = queue_notification(db, event, target=args.target or "*", actor="cli")
            elif args.action == "notify-deliver":
                result = deliver_notifications(paths, config, db, mode=args.mode, limit=args.limit, dry_run=args.dry_run)
            elif args.action == "security-posture":
                result = security_posture(paths, config, db, persist=True, apply_safe_permissions=args.apply_permissions)
            elif args.action == "audit-verify":
                result = verify_audit_chain(db)
            elif args.action == "retention-policy":
                if not args.category: raise ReconError("suite retention-policy requires --category")
                result = set_retention_policy(db, args.category, args.days, enabled=args.enabled=="true", keep_count=args.keep_count, actor="cli")
            elif args.action == "retention-preview":
                result = retention_preview(paths, db, persist=True)
            elif args.action == "retention-apply":
                if not args.preview_id: raise ReconError("suite retention-apply requires --preview-id")
                result = apply_retention(paths, db, args.preview_id, actor="cli", confirmation=args.confirmation)
            elif args.action == "performance":
                result = performance_diagnostics(paths, db, limit=args.limit)
            elif args.action == "templates":
                result = list_target_templates()
            elif args.action == "template-apply":
                if not args.target or not args.template_id: raise ReconError("suite template-apply requires --target and --template-id")
                result = apply_target_template(paths, args.target, args.template_id, actor="cli", dry_run=not args.apply)
            elif args.action == "report-quality":
                result = report_quality(db, draft_id=args.draft_id or None, case_id=args.case_id or None, persist=True)
            else:
                raise ReconError(f"Unsupported suite action: {args.action}")
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "workspace":
            if args.action == "sync":
                result = workspace_v7_sync(paths, config, db, target=args.target, actor="cli")
            elif args.action == "diagnostics":
                result = operator_diagnostics(paths, config, db, persist=True)
            elif args.action == "repair":
                result = safe_repair(paths, db, dry_run=not args.apply, actor="cli", max_age_hours=args.max_age_hours)
            elif args.action == "errors":
                result = recent_error_events(db, limit=args.limit)
            elif args.action == "evidence-gap":
                if not args.case_id: raise ReconError("workspace evidence-gap requires --case-id")
                result = evidence_gap_for_case(db, args.case_id, persist=True)
            elif args.action == "autopilot":
                if not args.case_id: raise ReconError("workspace autopilot requires --case-id")
                result = case_autopilot(db, args.case_id, actor="cli", persist=True)
            elif args.action == "autopilot-queue":
                result = case_autopilot_queue(db, target=args.target, limit=args.limit, persist=True)
            elif args.action == "contexts":
                result = authentication_contexts(db, target=args.target, analysis_id=args.analysis_id, persist=True)
            elif args.action == "differential":
                result = differential_intelligence(db, target=args.target, analysis_id=args.analysis_id, limit=args.limit, persist=True)
            elif args.action == "coverage":
                if not args.target: raise ReconError("workspace coverage requires --target")
                result = recon_coverage(db, target=args.target, run_id=args.run_id, persist=True)
            elif args.action == "graph":
                if not args.target: raise ReconError("workspace graph requires --target")
                result = attack_surface_graph(db, target=args.target, limit=args.limit)
            elif args.action == "changes":
                if not args.target: raise ReconError("workspace changes requires --target")
                result = change_intelligence(db, target=args.target, run_id=args.run_id, persist=True)
            elif args.action == "memory":
                if not args.target: raise ReconError("workspace memory requires --target")
                result = target_memory(db, target=args.target, persist=True)
            elif args.action == "learning":
                result = false_positive_learning(db, target=args.target, persist=True)
            elif args.action == "plan":
                if not args.target: raise ReconError("workspace plan requires --target")
                result = smart_recon_plan(db, target=args.target, persist=True)
            elif args.action == "stage-value":
                result = stage_value_analysis(db, target=args.target, limit=args.limit)
            elif args.action == "report":
                if not args.case_id: raise ReconError("workspace report requires --case-id")
                result = build_evidence_linked_report(db, args.case_id, actor="cli", persist=True)
            elif args.action == "capture-import":
                if not args.target or not args.file or not args.context: raise ReconError("workspace capture-import requires --target --file --context")
                result = import_browser_capture(paths, db, target=args.target, file_path=args.file, context_label=args.context, actor="cli", limit=args.limit)
            elif args.action == "safety":
                result = safety_center(paths, config, db)
            elif args.action == "cockpit":
                result = cockpit(db, target=args.target)
            elif args.action == "search":
                if not args.query: raise ReconError("workspace search requires --query")
                result = universal_search(db, args.query, limit=args.limit)
            else:
                raise ReconError(f"Unsupported workspace action: {args.action}")
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "validation":
            if args.action == "eligibility":
                if not args.case_id: raise ReconError("validation eligibility requires --case-id")
                result = validation_eligibility(db, args.case_id)
            elif args.action == "plan":
                if not args.case_id: raise ReconError("validation plan requires --case-id")
                result = create_validation_plan(paths, db, args.case_id, requested_level=args.level, actor="cli")
            elif args.action == "approve":
                if not args.plan_id or not args.confirmation: raise ReconError("validation approve requires --plan-id and --confirmation")
                result = approve_validation_plan(db, args.plan_id, args.confirmation, actor="cli")
            elif args.action == "run":
                if not args.plan_id: raise ReconError("validation run requires --plan-id")
                result = execute_validation_plan(paths, config, db, args.plan_id, allow_live=args.allow_live, actor="cli")
            elif args.action == "show":
                if not args.case_id and not args.plan_id: raise ReconError("validation show requires --case-id or --plan-id")
                result = validation_detail(db, case_id=args.case_id, plan_id=args.plan_id, limit=args.limit)
            elif args.action == "list":
                result = validation_detail(db, limit=args.limit)
            elif args.action == "import-har":
                if not args.case_id or not args.file: raise ReconError("validation import-har requires --case-id and --file")
                result = import_har(paths, db, args.case_id, args.file, actor="cli", limit=args.limit)
            elif args.action == "import-burp":
                if not args.case_id or not args.file: raise ReconError("validation import-burp requires --case-id and --file")
                result = import_burp_xml(paths, db, args.case_id, args.file, actor="cli", limit=args.limit)
            elif args.action == "feedback":
                if not args.run_id or not args.decision or not args.reason: raise ReconError("validation feedback requires --run-id --decision --reason")
                result = record_validation_feedback(db, args.run_id, args.decision, args.reason, args.note, actor="cli")
            else:
                raise ReconError(f"Unsupported validation action: {args.action}")
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "run":
            policies = PolicySet.load(paths)
            if args.dry_run:
                plan = build_plan(policies, config, args.target, allow_active=args.allow_active)
                print(json_dumps(plan, pretty=True) if args.json_plan else format_plan(plan))
                return 0
            show_progress = args.progress or (not args.no_progress and sys.stdout.isatty())
            orchestrator = Orchestrator(paths, config, logger, db, progress=show_progress, allow_active=args.allow_active)
            with RunLock(paths.lock, logger):
                return orchestrator.run(policies, args.target, args.resume)

        if args.command == "digest":
            print(json_dumps(send_daily_digest(paths, config, db, logger, args.hours), pretty=True))
            return 0

        if args.command == "retention":
            print(json_dumps(retention(paths, config, db, logger, args.dry_run), pretty=True))
            return 0

        if args.command == "backup":
            manager = BackupManager(paths, db, logger)
            if args.action == "create": print(json_dumps(manager.create(include_objects=args.include_objects), pretty=True))
            elif args.action == "list": print(json_dumps(manager.list(), pretty=True))
            elif args.action == "verify":
                print(json_dumps(manager.verify(args.backup_id or "latest"), pretty=True))
            elif args.action == "drill":
                print(json_dumps(manager.drill(args.backup_id or "latest"), pretty=True))
            elif args.action == "restore":
                if not args.backup_id: raise ReconError("backup restore requires BACKUP_ID")
                print(json_dumps(manager.restore(args.backup_id, force=args.force), pretty=True))
            return 0

        if args.command == "repair":
            if not args.dry_run and paths.lock.exists() and not args.force:
                lock_data = safe_json_loads(paths.lock.read_text(encoding="utf-8", errors="replace"), {}, expected_type=dict)
                lock_pid = parse_int(lock_data.get("pid"), 0)
                if lock_pid and process_alive(lock_pid):
                    raise ReconError(f"A live recon run owns the lock (PID {lock_pid}); use --dry-run or stop the run first")
            result = db.repair_stale_state(args.max_age_hours, dry_run=args.dry_run)
            if args.json_health:
                result["json_health"] = db.json_health()
            if not args.dry_run:
                result["database_optimize"] = db.optimize()
            db.audit("state_repair" if not args.dry_run else "state_repair_preview", entity_type="database", entity_value=str(paths.db), details={"max_age_hours":args.max_age_hours,"repaired":result.get("repaired",0)})
            print(json_dumps(result, pretty=True))
            return 0

        if args.command == "migrate-v1":
            if paths.legacy_targets.exists() and not paths.policy.exists():
                migrate_targets_txt(paths, logger)
            print(json_dumps(migrate_v1_database(paths, logger), pretty=True))
            return 0

        if args.command == "test-telegram":
            notifier = TelegramNotifier(config, logger)
            if not notifier.ready:
                raise ReconError("Telegram is disabled or incomplete in config.env")
            notifier.test()
            print("Telegram test sent successfully")
            return 0

        if args.command == "versions":
            print(record_versions_snapshot(paths))
            return 0

        if args.command == "ignore":
            if args.action == "add":
                if not args.pattern: raise ReconError("ignore add requires --pattern")
                print(db.add_ignore_rule(args.target, args.rule_type, args.pattern, args.note))
            elif args.action == "list": print(json_dumps([dict(r) for r in db.all("SELECT * FROM ignore_rules ORDER BY id")], pretty=True))
            elif args.action == "test":
                if not args.value: raise ReconError("ignore test requires --value")
                print(json_dumps({"matched_rule":db.ignore_match(args.target,args.rule_type,args.value)},pretty=True))
            elif args.action == "remove":
                if not args.id: raise ReconError("ignore remove requires --id")
                db.execute("DELETE FROM ignore_rules WHERE id=?",(args.id,)); db.audit("ignore_rule_removed",entity_type="ignore_rule",entity_value=str(args.id))
            elif args.action in {"enable","disable"}:
                if not args.id: raise ReconError(f"ignore {args.action} requires --id")
                db.execute("UPDATE ignore_rules SET enabled=?,updated_at=? WHERE id=?",(1 if args.action=="enable" else 0,utc_now(),args.id))
            return 0

        if args.command == "plugins":
            manager=PluginManager(paths,db)
            print(json_dumps(manager.health() if args.action=="health" else manager.list(),pretty=True)); return 0

        if args.command == "secrets":
            if args.action == "list": print("\n".join(known_secret_names(paths))); return 0
            if not args.name: raise ReconError(f"secrets {args.action} requires NAME")
            if args.action == "set":
                value=getpass.getpass(f"Secret value for {args.name}: "); set_secret(args.name,value); register_secret_name(paths,args.name); db.audit("secret_set",entity_type="secret",entity_value=args.name)
            else: delete_secret(args.name); unregister_secret_name(paths,args.name); db.audit("secret_deleted",entity_type="secret",entity_value=args.name)
            return 0

        if args.command == "api":
            if args.action == "foreground": serve_api(paths,logger,args.host,args.port,args.allow_remote)
            elif args.action == "start": print(f"API PID: {start_api(paths,args.host,args.port,args.allow_remote)}")
            elif args.action == "stop": print("stopped" if stop_api(paths) else "not running")
            elif args.action == "status":
                active,detail=api_status(paths); print(detail); return 0 if active else 1
            elif args.action == "token-create": print(create_token(db,args.name,args.role,[x.strip() for x in args.scopes.split(",") if x.strip()] or None,args.expires_days))
            elif args.action == "token-list": print(json_dumps([dict(r) for r in db.all("SELECT id,name,role,scopes_json,expires_at,created_at,last_used_at,revoked_at FROM api_tokens ORDER BY id")],pretty=True))
            elif args.action == "token-revoke":
                if not args.id: raise ReconError("api token-revoke requires --id")
                db.execute("UPDATE api_tokens SET revoked_at=? WHERE id=?",(utc_now(),args.id))
            return 0

        if args.command == "users":
            if args.action == "list": print(json_dumps(list_users(paths),pretty=True))
            elif args.action == "add":
                if not args.username: raise ReconError("users add requires USERNAME")
                password=getpass.getpass("Password: "); confirm=getpass.getpass("Confirm password: ")
                if password!=confirm: raise ReconError("Passwords do not match")
                create_user(paths,args.username,password,args.role)
            else:
                if not args.username: raise ReconError("users disable requires USERNAME")
                disable_user(paths,args.username)
            return 0

        if args.command == "update":
            manager=UpdateManager(paths,config,db,logger)
            if args.action=="check":
                print(json_dumps(manager.check(args.repo),pretty=True))
            elif args.action=="install":
                if args.package:
                    result=manager.install(Path(args.package).expanduser(),args.sha256,Path(args.signature).expanduser() if args.signature else None,Path(args.public_key).expanduser() if args.public_key else None)
                else:
                    result=manager.install_latest(args.repo,force=args.force)
                print(json_dumps(result,pretty=True))
            else:
                print(json_dumps(manager.rollback(),pretty=True))
            return 0

        if args.command == "postgres":
            result=postgres_status(config) if args.action=="status" else postgres_init(config) if args.action=="init" else postgres_sync(config,db)
            print(json_dumps(result,pretty=True)); return 0

        if args.command == "benchmark": print(json_dumps(benchmark(paths,db),pretty=True)); return 0

        if args.command == "worker":
            token=args.token or config.get("REMOTE_WORKER_TOKEN","")
            if not token: raise ReconError("worker run requires --token or REMOTE_WORKER_TOKEN")
            worker_id=args.worker_id or f"{os.uname().nodename}-{os.getpid()}"
            return run_worker(args.server,token,worker_id,args.name,args.interval,args.once)

        if args.command == "views":
            if args.action=="list": print(json_dumps([dict(r) for r in db.all("SELECT * FROM saved_views ORDER BY owner,name")],pretty=True))
            elif args.action=="add":
                if not args.name: raise ReconError("views add requires --name")
                try: query=json.loads(args.query)
                except json.JSONDecodeError as exc: raise ReconError(f"Invalid --query JSON: {exc}")
                now=utc_now(); db.execute("INSERT INTO saved_views(owner,name,view_type,query_json,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(owner,name) DO UPDATE SET view_type=excluded.view_type,query_json=excluded.query_json,updated_at=excluded.updated_at",(args.owner,args.name,args.view_type,json_dumps(query),now,now))
            else:
                if not args.name: raise ReconError("views remove requires --name")
                db.execute("DELETE FROM saved_views WHERE owner=? AND name=?",(args.owner,args.name))
            return 0

        if args.command == "alerts":
            if args.action == "list":
                list_alerts(db, args.limit)
            elif args.action == "set-status":
                if not args.id or not args.status:
                    raise ReconError("alerts set-status requires --id and --status")
                db.set_alert_status(args.id, args.status)
                print(f"Alert {args.id} -> {args.status}")
            return 0

        if args.command == "test":
            if args.integration:
                command = [sys.executable, str(paths.root / "tests" / "integration_runner.py")]
                return subprocess.run(command, cwd=paths.root).returncode
            command = [sys.executable, "-m", "unittest", "discover", "-s", str(paths.root / "tests")]
            if args.verbose:
                command.append("-v")
            return subprocess.run(command, cwd=paths.root).returncode

        parser.print_help()
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

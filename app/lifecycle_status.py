from __future__ import annotations

"""Strict target/run lifecycle semantics for Recon Monitor.

This compatibility layer keeps the established orchestration flow intact while
fixing one narrow reliability invariant: a failed report stage is a target
failure, just like a failed collection stage. The successful-snapshot boundary
already refuses to promote a failed-report run; this layer makes the public
run_targets/runs status and process exit code agree with that same truth.
"""

import contextlib
from pathlib import Path
from typing import Any, Mapping


LIFECYCLE_STATUS_VERSION = "1.0.0"


def install_lifecycle_status_guard(namespace: Mapping[str, Any]) -> None:
    """Install the strict run lifecycle on the loaded recon core module."""

    orchestrator_cls = namespace["Orchestrator"]
    stages = namespace["STAGES"]
    ReconError = namespace["ReconError"]
    StageContext = namespace["StageContext"]
    BudgetManager = namespace["BudgetManager"]
    config_hash = namespace["config_hash"]
    local_now = namespace["local_now"]
    retention = namespace["retention"]
    send_daily_digest = namespace["send_daily_digest"]
    utc_now = namespace["utc_now"]
    app_version = namespace["APP_VERSION"]

    original_run = orchestrator_cls.run
    if getattr(original_run, "_strict_lifecycle_status", False):
        return

    def run(
        self: Any,
        policies: Any,
        selector: str | None = None,
        resume_id: str | None = None,
    ) -> int:
        if not self.config.authorized:
            raise ReconError(
                'Set I_HAVE_AUTHORIZATION="yes" only after confirming every configured target is authorized.'
            )
        targets = policies.select(selector)
        run_id = resume_id or self.db.create_run(
            selector,
            len(targets),
            config_hash(self.config, policies),
        )
        self.current_run_id = run_id
        if resume_id:
            row = self.db.one(
                "SELECT id,status FROM runs WHERE id=?",
                (resume_id,),
            )
            if not row:
                raise ReconError(f"Run not found for resume: {resume_id}")
            self.db.execute(
                "UPDATE runs SET status='running',finished_at=NULL,error=NULL WHERE id=?",
                (run_id,),
            )
        self._record_versions(run_id)
        self.install_signal_handlers()
        print(
            f"Recon Monitor {app_version} | Run: {run_id} | "
            f"Targets: {len(targets)} | Started: {local_now()}\n"
        )
        failures = 0
        try:
            for target_index, policy in enumerate(targets, 1):
                self.current_target = policy.name
                existing = self.db.one(
                    "SELECT run_dir,baseline FROM run_targets "
                    "WHERE run_id=? AND target=?",
                    (run_id, policy.name),
                )
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
                print(
                    f"Target {target_index}/{len(targets)}: {policy.name}"
                    + (" (initial baseline)" if baseline else "")
                )
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
                for stage_index, (stage_name, label) in enumerate(stages, 1):
                    if target_failed and stage_name != "report":
                        # Preserve the established partial-reporting behavior:
                        # after a collection failure skip later collection stages,
                        # but still attempt the report stage.
                        continue
                    status, _metrics = self._run_stage(
                        ctx,
                        stage_name,
                        label,
                        stage_index,
                        len(stages),
                        target_index,
                        len(targets),
                        baseline,
                        bool(resume_id),
                    )
                    if stage_name == "report":
                        report_ran = True

                    # Reliability invariant: no failed stage can yield a
                    # successful target. This intentionally includes report.
                    if status != "success":
                        target_failed = True

                if target_failed and not report_ran:
                    # Defensive fallback retained from the established flow.
                    # If normal iteration somehow did not reach report, attempt
                    # it for partial diagnostics without changing failure truth.
                    with contextlib.suppress(Exception):
                        self._run_stage(
                            ctx,
                            "report",
                            stages[-1][1],
                            len(stages),
                            len(stages),
                            target_index,
                            len(targets),
                            baseline,
                            False,
                        )

                target_status = "failed" if target_failed else "success"
                self.db.finish_run_target(run_id, policy.name, target_status)
                failures += int(target_failed)
                self._update_latest_pointers(policy.name, run_dir)
                print(f"  Results: {run_dir}\n")

            status = "success" if failures == 0 else "partial"
            self.db.finish_run(run_id, status)
            if self.config.bool("AUTO_RETENTION", True):
                with contextlib.suppress(Exception):
                    retention(
                        self.paths,
                        self.config,
                        self.db,
                        self.logger,
                        False,
                    )
            digest_hours = self.config.int(
                "AUTO_DIGEST_HOURS",
                24,
                0,
                720,
            )
            if digest_hours > 0:
                import datetime as dt

                last_digest = self.db.meta_get("last_auto_digest_at")
                due = True
                if last_digest:
                    with contextlib.suppress(ValueError):
                        previous = dt.datetime.fromisoformat(
                            last_digest.replace("Z", "+00:00")
                        )
                        due = (
                            dt.datetime.now(dt.timezone.utc) - previous
                        ).total_seconds() >= digest_hours * 3600
                if due:
                    with contextlib.suppress(Exception):
                        send_daily_digest(
                            self.paths,
                            self.config,
                            self.db,
                            self.logger,
                            digest_hours,
                        )
                        self.db.meta_set("last_auto_digest_at", utc_now())
            print(
                f"Run completed: {status} | failures={failures} | {local_now()}"
            )
            return 0 if failures == 0 else 2
        except KeyboardInterrupt:
            self.db.finish_run(
                run_id,
                "interrupted",
                "interrupted by signal",
            )
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

    run._strict_lifecycle_status = True  # type: ignore[attr-defined]
    run._lifecycle_status_version = LIFECYCLE_STATUS_VERSION  # type: ignore[attr-defined]
    orchestrator_cls.run = run

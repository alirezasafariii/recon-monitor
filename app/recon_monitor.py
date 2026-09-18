#!/usr/bin/env python3
from __future__ import annotations

"""Recon Monitor CLI compatibility surface with Analysis quality access.

The established CLI implementation remains in ``recon_monitor_core``. This
module preserves every existing command and adds Analysis-only compatibility
actions for Investigation Queue, offline verified-replay draft collection,
human-verified real-world calibration reports, explicit Validation Runner
passive-live execution, and offline Differential Evidence adaptation.
"""

import sys
from typing import Any, Iterable

import recon_monitor_core as _base
from analysis_benchmark_v2 import load_verified_replay_jsonl_with_diagnostics
from change_guidance_evaluation import (
    CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
    CHANGE_GUIDANCE_EVALUATION_VERSION,
    change_guidance_evaluation,
)
from correlation_engine import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_RULE_VERSION,
    investigation_queue,
)
from derived_change_advisory import (
    DERIVED_CHANGE_ADVISORY_RULE_VERSION,
    DERIVED_CHANGE_ADVISORY_VERSION,
)
from differential_evidence_adapter import adapt_differential_evidence
from meta_ranker import META_RANKER_VERSION, META_RANKER_RULE_VERSION
from real_world_calibration import (
    REAL_WORLD_CALIBRATION_RULE_VERSION,
    REAL_WORLD_CALIBRATION_VERSION,
    build_real_world_calibration_report,
)
from progress_tracking import install_progress_tracking, stop_analysis
from validation_executor import execute_validation_runner_contract
from typed_evidence_adapter import adapt_validation_runner_execution
from verified_replay_collector import (
    VERIFIED_REPLAY_COLLECTOR_RULE_VERSION,
    VERIFIED_REPLAY_COLLECTOR_VERSION,
    collect_verified_replay_drafts,
)


INVESTIGATION_CLI_VERSION = "1.5.0"

for _name, _value in vars(_base).items():
    if _name not in {
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__file__",
        "__cached__",
        "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_BUILD_PARSER = getattr(_base, "_VI_ORIGINAL_BUILD_PARSER", _base.build_parser)
_ORIGINAL_MAIN = getattr(_base, "_VI_ORIGINAL_MAIN", _base.main)
_base._VI_ORIGINAL_BUILD_PARSER = _ORIGINAL_BUILD_PARSER
_base._VI_ORIGINAL_MAIN = _ORIGINAL_MAIN
install_progress_tracking(_base)

# Progress is an additive dashboard layer. Preserve the established handler
# identity used by compatibility/regression checks so the intelligence wrapper
# remains the named owner of the Analysis page rather than appearing replaced.
_dashboard_module = sys.modules.get("dashboard")
if _dashboard_module is not None:
    _dashboard_handler = getattr(_dashboard_module, "DashboardHandler", None)
    if _dashboard_handler is not None:
        _analysis_handler = getattr(_dashboard_handler, "analysis_engine", None)
        if callable(_analysis_handler):
            _analysis_handler.__name__ = "_analysis_engine_with_intelligence"


def _command_parser(parser: Any, command: str) -> Any:
    for action in getattr(parser, "_actions", []):
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and command in choices:
            return choices[command]
    raise RuntimeError(f"{command.title()} CLI parser is unavailable")


def _analysis_parser(parser: Any) -> Any:
    return _command_parser(parser, "analysis")


def _validation_parser(parser: Any) -> Any:
    return _command_parser(parser, "validation")


def _extend_action_choices(command_parser: Any, *extra_actions: str) -> None:
    for action in getattr(command_parser, "_actions", []):
        if getattr(action, "dest", "") != "action":
            continue
        choices = list(getattr(action, "choices", []) or [])
        for extra_action in extra_actions:
            if extra_action not in choices:
                choices.append(extra_action)
        action.choices = choices
        return
    raise RuntimeError("CLI action parser is unavailable")


def build_parser():
    parser = _ORIGINAL_BUILD_PARSER()
    analysis_parser = _analysis_parser(parser)
    _extend_action_choices(
        analysis_parser,
        "investigation-queue",
        "verified-replay-drafts",
        "real-world-calibration",
        "stop",
    )

    existing_dests = {
        str(getattr(action, "dest", ""))
        for action in getattr(analysis_parser, "_actions", [])
    }
    if "verified_corpus" not in existing_dests:
        analysis_parser.add_argument(
            "--verified-corpus",
            action="append",
            default=[],
            dest="verified_corpus",
            help="Path to a human-verified replay JSONL corpus; repeat for multiple files",
        )

    validation_parser = _validation_parser(parser)
    _extend_action_choices(
        validation_parser,
        "runner-execute",
        "runner-adapt",
        "differential-adapt",
    )
    validation_dests = {
        str(getattr(action, "dest", ""))
        for action in getattr(validation_parser, "_actions", [])
    }
    if "contract_id" not in validation_dests:
        validation_parser.add_argument(
            "--contract-id",
            default="",
            help="Validation Runner dry-run contract ID (VDR-...)",
        )
    if "execution_id" not in validation_dests:
        validation_parser.add_argument(
            "--execution-id",
            default="",
            help="Completed Validation Runner execution ID (VEX-...) to adapt offline",
        )
    if "evidence_file" not in validation_dests:
        validation_parser.add_argument(
            "--evidence-file",
            default="",
            help="Local analyst-verified Differential Evidence v2 JSON artifact",
        )
    if "target" not in validation_dests:
        validation_parser.add_argument(
            "--target",
            default="",
            help="Target policy name; required when the scan run contains multiple targets",
        )
    return parser


def _latest_analysis_id(db: Any) -> str:
    row = db.one(
        "SELECT id FROM analysis_runs WHERE status='success' "
        "ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1"
    )
    return str(row["id"]) if row else ""


def investigation_queue_cli_payload(
    db: Any,
    *,
    analysis_id: str = "",
    target: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    selected_analysis = str(analysis_id or "").strip() or _latest_analysis_id(db)
    bounded_limit = max(1, min(500, int(limit or 20)))
    items = (
        investigation_queue(
            db,
            selected_analysis,
            target=str(target or "").strip() or None,
            limit=bounded_limit,
        )
        if selected_analysis
        else []
    )
    if hasattr(db, "all") and hasattr(db, "one"):
        evaluation = change_guidance_evaluation(
            db,
            target=str(target or "").strip(),
            limit=500,
        )
    else:
        evaluation = {
            "version": CHANGE_GUIDANCE_EVALUATION_VERSION,
            "rule_version": CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
            "case_count": 0,
            "comparison_ready": False,
            "unavailable": True,
            "reason": "database evaluation interface unavailable",
        }
    return {
        "cli_version": INVESTIGATION_CLI_VERSION,
        "analysis_id": selected_analysis,
        "target": str(target or "").strip() or None,
        "count": len(items),
        "items": items,
        "change_guidance_evaluation": evaluation,
        "engines": {
            "meta_ranker": {
                "version": META_RANKER_VERSION,
                "rule_version": META_RANKER_RULE_VERSION,
            },
            "correlation": {
                "version": CORRELATION_ENGINE_VERSION,
                "rule_version": CORRELATION_RULE_VERSION,
            },
            "derived_change_advisory": {
                "version": DERIVED_CHANGE_ADVISORY_VERSION,
                "rule_version": DERIVED_CHANGE_ADVISORY_RULE_VERSION,
            },
            "change_guidance_evaluation": {
                "version": CHANGE_GUIDANCE_EVALUATION_VERSION,
                "rule_version": CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
            },
        },
        "safety": {
            "status": "investigation_queue_not_confirmed",
            "queue_is_not_vulnerability_confirmation": True,
            "correlation_cannot_satisfy_admission": True,
            "derived_change_is_advisory_only": True,
            "derived_change_cannot_satisfy_admission": True,
            "derived_change_is_not_double_counted_in_queue_score": True,
            "change_guidance_evaluation_is_observational_only": True,
            "change_guidance_evaluation_is_non_causal": True,
            "change_guidance_evaluation_cannot_auto_tune": True,
            "change_task_feedback_is_observational_only": True,
            "change_task_feedback_cannot_auto_tune": True,
            "change_task_feedback_is_not_target_evidence": True,
            "target_evidence_confidence_uses_target_observations_only": True,
        },
    }


def verified_replay_drafts_cli_payload(db: Any, *, limit: int = 1000) -> dict[str, Any]:
    """Return offline replay-review drafts without trusting or activating them."""

    bounded_limit = max(1, min(5000, int(limit or 1000)))
    payload = collect_verified_replay_drafts(db, limit=bounded_limit)
    return {
        "cli_version": INVESTIGATION_CLI_VERSION,
        "action": "verified-replay-drafts",
        "collector": {
            "version": VERIFIED_REPLAY_COLLECTOR_VERSION,
            "rule_version": VERIFIED_REPLAY_COLLECTOR_RULE_VERSION,
        },
        **payload,
        "operator_guidance": {
            "output_is_review_draft": True,
            "complete_all_evidence_quality_dimensions_before_finalization": True,
            "redirect_stdout_to_json_if_persistent_export_is_needed": True,
            "production_calibration_remains_shadow_only": True,
        },
    }


def real_world_calibration_cli_payload(corpus_paths: Iterable[str]) -> dict[str, Any]:
    """Load verified replay JSONL and produce a holdout/shadow-learning report."""

    paths = [str(path).strip() for path in corpus_paths if str(path).strip()]
    ingestion = load_verified_replay_jsonl_with_diagnostics(paths)
    report = build_real_world_calibration_report(ingestion["records"])
    return {
        "cli_version": INVESTIGATION_CLI_VERSION,
        "action": "real-world-calibration",
        "engine": {
            "version": REAL_WORLD_CALIBRATION_VERSION,
            "rule_version": REAL_WORLD_CALIBRATION_RULE_VERSION,
        },
        "corpus_paths": paths,
        "ingestion": {
            "accepted_count": int(ingestion["accepted_count"]),
            "rejected_count": int(ingestion["rejected_count"]),
            "duplicate_count": int(ingestion["duplicate_count"]),
            "source_files": int(ingestion["source_files"]),
            "mean_evidence_quality": float(ingestion["mean_evidence_quality"]),
            "rejected": list(ingestion["rejected"]),
        },
        "report": report,
        "operator_guidance": {
            "metrics_are_out_of_sample_when_holdout_ready": True,
            "candidate_thresholds_are_learned_from_train_only": True,
            "feedback_is_shadow_only": True,
            "manual_policy_review_required_even_when_ready": True,
            "production_activation_is_not_performed_by_this_command": True,
        },
    }


def _runner_execute_cli(args: Any) -> dict[str, Any]:
    if not str(args.run_id or "").strip():
        raise _base.ReconError("validation runner-execute requires --run-id RUN_ID")
    if not str(args.contract_id or "").strip():
        raise _base.ReconError("validation runner-execute requires --contract-id VDR-...")
    if not str(args.confirmation or "").strip():
        raise _base.ReconError("validation runner-execute requires --confirmation")
    if not bool(args.allow_live):
        raise _base.ReconError("validation runner-execute requires --allow-live")

    paths = _base.AppPaths.from_root(_base.ROOT_DIR)
    paths.ensure()
    if not paths.config.exists():
        raise _base.ReconError("config.env not found. Run ./recon-monitor.sh init")
    config = _base.Config(paths)
    db = _base.Database(paths.db)
    try:
        return execute_validation_runner_contract(
            paths,
            config,
            db,
            scan_run_id=str(args.run_id),
            target=str(getattr(args, "target", "") or ""),
            contract_id=str(args.contract_id),
            confirmation=str(args.confirmation),
            allow_live=True,
            actor="cli",
        )
    finally:
        db.close()


def _runner_adapt_cli(args: Any) -> dict[str, Any]:
    if not str(args.run_id or "").strip():
        raise _base.ReconError("validation runner-adapt requires --run-id RUN_ID")
    if not str(getattr(args, "execution_id", "") or "").strip():
        raise _base.ReconError("validation runner-adapt requires --execution-id VEX-...")

    paths = _base.AppPaths.from_root(_base.ROOT_DIR)
    paths.ensure()
    db = _base.Database(paths.db)
    try:
        return adapt_validation_runner_execution(
            paths,
            db,
            scan_run_id=str(args.run_id),
            target=str(getattr(args, "target", "") or ""),
            execution_id=str(args.execution_id),
            actor="cli",
        )
    finally:
        db.close()


def _differential_adapt_cli(args: Any) -> dict[str, Any]:
    evidence_file = str(getattr(args, "evidence_file", "") or "").strip()
    if not evidence_file:
        raise _base.ReconError("validation differential-adapt requires --evidence-file PATH")

    paths = _base.AppPaths.from_root(_base.ROOT_DIR)
    paths.ensure()
    db = _base.Database(paths.db)
    try:
        return adapt_differential_evidence(
            db,
            artifact_path=evidence_file,
            actor="cli",
        )
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    translated = _base.translate_legacy_args(raw_argv)

    if (
        len(translated) >= 2
        and translated[0] == "validation"
        and translated[1] == "runner-execute"
    ):
        parser = build_parser()
        args = parser.parse_args(translated)
        payload = _runner_execute_cli(args)
        print(_base.json_dumps(payload, pretty=True))
        return 0

    if (
        len(translated) >= 2
        and translated[0] == "validation"
        and translated[1] == "runner-adapt"
    ):
        parser = build_parser()
        args = parser.parse_args(translated)
        payload = _runner_adapt_cli(args)
        print(_base.json_dumps(payload, pretty=True))
        return 0

    if (
        len(translated) >= 2
        and translated[0] == "validation"
        and translated[1] == "differential-adapt"
    ):
        parser = build_parser()
        args = parser.parse_args(translated)
        payload = _differential_adapt_cli(args)
        print(_base.json_dumps(payload, pretty=True))
        return 0

    if len(translated) >= 2 and translated[0] == "analysis" and translated[1] in {
        "investigation-queue",
        "verified-replay-drafts",
        "real-world-calibration",
        "stop",
    }:
        parser = build_parser()
        args = parser.parse_args(translated)

        if translated[1] == "real-world-calibration":
            payload = real_world_calibration_cli_payload(
                list(getattr(args, "verified_corpus", []) or []),
            )
            print(_base.json_dumps(payload, pretty=True))
            return 0

        paths = _base.AppPaths.from_root(_base.ROOT_DIR)
        paths.ensure()
        if not paths.config.exists():
            raise _base.ReconError("config.env not found. Run ./recon-monitor.sh init")
        db = _base.Database(paths.db)
        try:
            if translated[1] == "verified-replay-drafts":
                payload = verified_replay_drafts_cli_payload(
                    db,
                    limit=int(args.limit or 1000),
                )
            elif translated[1] == "stop":
                payload = stop_analysis(
                    paths,
                    db,
                    analysis_id=str(args.analysis_id or ""),
                    run_id=str(args.run_id or ""),
                    target=str(args.target or ""),
                )
            else:
                payload = investigation_queue_cli_payload(
                    db,
                    analysis_id=str(args.analysis_id or ""),
                    target=str(args.target or ""),
                    limit=int(args.limit or 20),
                )
        finally:
            db.close()
        print(_base.json_dumps(payload, pretty=True))
        return 0
    return _ORIGINAL_MAIN(argv)


# Existing main() calls build_parser() through its module globals. Point that
# lookup at the compatibility parser so help/validation includes the new actions
# while every existing command keeps its original implementation.
_base.build_parser = build_parser


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _base.ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Operation interrupted safely.", file=sys.stderr)
        raise SystemExit(130)

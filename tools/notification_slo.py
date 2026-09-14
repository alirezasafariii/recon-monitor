#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Database, ReconError, json_dumps
from finding_notification_operations import finding_notification_diagnostics
from notification_delivery_slo import (
    configure_notification_delivery_slo,
    evaluate_notification_delivery_slo,
    list_notification_delivery_slo_breaches,
    list_notification_delivery_slo_events,
    notification_delivery_slo_status,
)
from notification_supervisor import notification_supervisor_status
from recon_alert_operations import recon_alert_diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect and configure notification delivery SLOs.")
    parser.add_argument("action", nargs="?", default="status", choices=["status", "configure", "breaches", "events"])
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--status-filter", choices=["open", "resolved"], default="")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--pending-warning-seconds", type=int, default=0)
    parser.add_argument("--pending-critical-seconds", type=int, default=0)
    parser.add_argument("--backlog-warning", type=int, default=0)
    parser.add_argument("--backlog-critical", type=int, default=0)
    parser.add_argument("--dead-letter-warning", type=int, default=0)
    parser.add_argument("--dead-letter-critical", type=int, default=0)
    parser.add_argument("--heartbeat-warning-seconds", type=int, default=0)
    parser.add_argument("--heartbeat-critical-seconds", type=int, default=0)
    parser.add_argument("--failure-warning-count", type=int, default=0)
    parser.add_argument("--failure-critical-count", type=int, default=0)
    parser.add_argument("--cooldown-seconds", type=int, default=-1)
    return parser


def _evaluate(db: Database) -> dict[str, object]:
    workers = {
        "finding": finding_notification_diagnostics(db),
        "recon_alert": recon_alert_diagnostics(db),
    }
    supervisor = notification_supervisor_status(db)
    return evaluate_notification_delivery_slo(db, workers=workers, supervisor=supervisor)


def _optional_positive(value: int) -> int | None:
    return int(value) if int(value) > 0 else None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = AppPaths.from_root(ROOT)
    paths.ensure()
    db = Database(paths.db)
    try:
        if args.action == "configure":
            if args.enable and args.disable:
                raise ReconError("Choose only one of --enable or --disable")
            enabled = True if args.enable else False if args.disable else None
            result = configure_notification_delivery_slo(
                db,
                enabled=enabled,
                pending_warning_seconds=_optional_positive(args.pending_warning_seconds),
                pending_critical_seconds=_optional_positive(args.pending_critical_seconds),
                backlog_warning=_optional_positive(args.backlog_warning),
                backlog_critical=_optional_positive(args.backlog_critical),
                dead_letter_warning=_optional_positive(args.dead_letter_warning),
                dead_letter_critical=_optional_positive(args.dead_letter_critical),
                heartbeat_warning_seconds=_optional_positive(args.heartbeat_warning_seconds),
                heartbeat_critical_seconds=_optional_positive(args.heartbeat_critical_seconds),
                failure_warning_count=_optional_positive(args.failure_warning_count),
                failure_critical_count=_optional_positive(args.failure_critical_count),
                cooldown_seconds=int(args.cooldown_seconds) if int(args.cooldown_seconds) >= 0 else None,
            )
        elif args.action == "breaches":
            result = {
                "slo": notification_delivery_slo_status(db),
                "breaches": list_notification_delivery_slo_breaches(
                    db, status=str(args.status_filter or ""), limit=max(1, min(500, int(args.limit)))
                ),
            }
        elif args.action == "events":
            result = {
                "slo": notification_delivery_slo_status(db),
                "events": list_notification_delivery_slo_events(db, limit=max(1, min(500, int(args.limit)))),
            }
        else:
            result = _evaluate(db)
        print(json_dumps(result, pretty=True))
        if isinstance(result, dict) and str(result.get("state") or "") == "critical":
            return 2
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

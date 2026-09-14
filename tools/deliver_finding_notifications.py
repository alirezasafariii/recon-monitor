#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, ReconError, json_dumps
from finding_notification_operations import (
    configure_finding_notification_worker,
    drain_finding_notification_outbox,
    finding_notification_diagnostics,
    list_dead_letters,
    retry_dead_letters,
    run_finding_notification_worker,
    watch_finding_notification_worker,
    worker_policy,
)
from finding_notification_outbox import DELIVERABLE_MODES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate the scheduled Potential Finding notification outbox worker."
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="run",
        choices=["run", "watch", "status", "failed", "retry", "drain", "configure"],
    )
    parser.add_argument("--target", default="", help="Optional target policy filter")
    parser.add_argument(
        "--mode",
        default="",
        choices=["", *sorted(DELIVERABLE_MODES)],
        help="Optional delivery mode filter",
    )
    parser.add_argument("--limit", type=int, default=0, help="Maximum events per worker batch")
    parser.add_argument("--event-id", default="", help="Specific dead-letter event ID")
    parser.add_argument("--force", action="store_true", help="Run even when scheduler interval is not due")
    parser.add_argument("--max-batches", type=int, default=20, help="Maximum drain batches")
    parser.add_argument("--max-cycles", type=int, default=0, help="Optional watch-cycle limit")
    parser.add_argument("--enable", action="store_true", help="Enable scheduled worker policy")
    parser.add_argument("--disable", action="store_true", help="Disable scheduled worker policy")
    parser.add_argument("--interval-seconds", type=int, default=0, help="Worker scheduler interval (60-3600)")
    parser.add_argument("--batch-limit", type=int, default=0, help="Persistent batch limit (1-500)")
    # Backward-compatible alias from the first outbox worker release.
    parser.add_argument("--requeue-failed", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = AppPaths.from_root(ROOT)
    paths.ensure()
    if not paths.config.exists():
        raise ReconError("config.env not found. Run ./recon-monitor.sh init")
    config = Config(paths)
    logger = Logger(paths, verbose=False)
    db = Database(paths.db)
    try:
        action = "retry" if args.requeue_failed else str(args.action)
        if action == "status":
            result = finding_notification_diagnostics(db)
        elif action == "failed":
            result = {
                "policy": worker_policy(db),
                "dead_letters": list_dead_letters(
                    db, target=str(args.target or ""), limit=max(1, min(500, int(args.limit or 100)))
                ),
            }
        elif action == "retry":
            result = {
                "requeued": retry_dead_letters(
                    db,
                    event_id=str(args.event_id or ""),
                    target=str(args.target or ""),
                ),
                "diagnostics": finding_notification_diagnostics(db),
            }
        elif action == "drain":
            result = drain_finding_notification_outbox(
                config=config,
                logger=logger,
                db=db,
                max_batches=max(1, min(100, int(args.max_batches or 20))),
                batch_limit=max(1, min(500, int(args.limit or 100))),
            )
        elif action == "watch":
            result = watch_finding_notification_worker(
                config=config,
                logger=logger,
                db=db,
                max_cycles=max(0, int(args.max_cycles or 0)),
            )
        elif action == "configure":
            if args.enable and args.disable:
                raise ReconError("Choose only one of --enable or --disable")
            enabled = True if args.enable else False if args.disable else None
            result = configure_finding_notification_worker(
                db,
                enabled=enabled,
                interval_seconds=int(args.interval_seconds) if args.interval_seconds else None,
                batch_limit=int(args.batch_limit) if args.batch_limit else None,
            )
        else:
            result = run_finding_notification_worker(
                config=config,
                logger=logger,
                db=db,
                trigger="cli",
                force=bool(args.force),
                target=str(args.target or ""),
                mode=str(args.mode or ""),
                limit=int(args.limit) if args.limit else None,
            )
        print(json_dumps(result, pretty=True))
        failed = int((result.get("delivery") or {}).get("failed", 0) or 0) if isinstance(result, dict) else 0
        return 0 if failed == 0 else 2
    finally:
        db.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Worker stopped safely.", file=sys.stderr)
        raise SystemExit(130)

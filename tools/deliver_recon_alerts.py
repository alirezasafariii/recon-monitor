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
from recon_alert_operations import (
    configure_recon_alert_worker,
    drain_recon_alert_outbox,
    list_recon_alert_dead_letters,
    recon_alert_diagnostics,
    recon_alert_worker_policy,
    retry_recon_alert_dead_letters,
    run_recon_alert_worker,
    watch_recon_alert_worker,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate the scheduled Recon Change Alert outbox worker."
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="run",
        choices=["run", "watch", "status", "failed", "retry", "drain", "configure"],
    )
    parser.add_argument("--target", default="", help="Optional target policy filter")
    parser.add_argument("--run-id", default="", help="Optional Recon run filter")
    parser.add_argument("--limit", type=int, default=0, help="Maximum events per worker batch")
    parser.add_argument("--event-id", default="", help="Specific dead-letter event ID")
    parser.add_argument("--force", action="store_true", help="Run even when scheduler interval is not due")
    parser.add_argument("--max-batches", type=int, default=20, help="Maximum drain batches")
    parser.add_argument("--max-cycles", type=int, default=0, help="Optional watch-cycle limit")
    parser.add_argument("--enable", action="store_true", help="Enable scheduled worker policy")
    parser.add_argument("--disable", action="store_true", help="Disable scheduled worker policy")
    parser.add_argument("--interval-seconds", type=int, default=0, help="Worker scheduler interval (60-3600)")
    parser.add_argument("--batch-limit", type=int, default=0, help="Persistent batch limit (1-500)")
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
        action = str(args.action)
        target = str(args.target or "")
        recon_run_id = str(args.run_id or "")
        if action == "status":
            result = recon_alert_diagnostics(db, target=target)
        elif action == "failed":
            result = {
                "policy": recon_alert_worker_policy(db),
                "dead_letters": list_recon_alert_dead_letters(
                    db,
                    target=target,
                    limit=max(1, min(500, int(args.limit or 100))),
                ),
            }
        elif action == "retry":
            result = {
                "requeued": retry_recon_alert_dead_letters(
                    db,
                    event_id=str(args.event_id or ""),
                    target=target,
                ),
                "diagnostics": recon_alert_diagnostics(db, target=target),
            }
        elif action == "drain":
            result = drain_recon_alert_outbox(
                config=config,
                logger=logger,
                db=db,
                target=target,
                recon_run_id=recon_run_id,
                max_batches=max(1, min(100, int(args.max_batches or 20))),
                batch_limit=max(1, min(500, int(args.limit or 100))),
            )
        elif action == "watch":
            result = watch_recon_alert_worker(
                config=config,
                logger=logger,
                db=db,
                max_cycles=max(0, int(args.max_cycles or 0)),
            )
        elif action == "configure":
            if args.enable and args.disable:
                raise ReconError("Choose only one of --enable or --disable")
            enabled = True if args.enable else False if args.disable else None
            result = configure_recon_alert_worker(
                db,
                enabled=enabled,
                interval_seconds=int(args.interval_seconds) if args.interval_seconds else None,
                batch_limit=int(args.batch_limit) if args.batch_limit else None,
            )
        else:
            result = run_recon_alert_worker(
                config=config,
                logger=logger,
                db=db,
                trigger="cli",
                force=bool(args.force),
                target=target,
                recon_run_id=recon_run_id,
                limit=int(args.limit) if args.limit else None,
            )
        print(json_dumps(result, pretty=True))
        if not isinstance(result, dict):
            return 0
        delivery = result.get("delivery") or {}
        failed = int(delivery.get("failed", 0) or 0) if isinstance(delivery, dict) else 0
        failed += int(result.get("failed", 0) or 0) if action == "drain" else 0
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

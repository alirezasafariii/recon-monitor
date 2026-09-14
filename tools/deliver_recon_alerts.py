#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, ReconError, json_dumps
from recon_alert_outbox import (
    deliver_recon_alert_outbox,
    recon_alert_outbox_summary,
    requeue_failed_recon_alerts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Operate the durable Recon Change Alert outbox worker.")
    parser.add_argument("action", nargs="?", default="run", choices=["run", "watch", "status", "retry"])
    parser.add_argument("--target", default="", help="Optional target policy filter")
    parser.add_argument("--run-id", default="", help="Optional Recon run filter")
    parser.add_argument("--event-id", default="", help="Specific failed outbox event to requeue")
    parser.add_argument("--limit", type=int, default=50, help="Maximum events claimed per worker pass (1-500)")
    parser.add_argument("--interval-seconds", type=int, default=60, help="Watch interval (60-3600 seconds)")
    parser.add_argument("--max-cycles", type=int, default=0, help="Optional watch-cycle limit; 0 means unbounded")
    return parser


def _run_once(args: argparse.Namespace, config: Config, logger: Logger, db: Database) -> dict[str, object]:
    return deliver_recon_alert_outbox(
        config=config,
        logger=logger,
        db=db,
        target=str(args.target or ""),
        run_id=str(args.run_id or ""),
        limit=max(1, min(500, int(args.limit or 50))),
    )


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
        if args.action == "status":
            result: dict[str, object] = {
                "target": str(args.target or ""),
                "outbox": recon_alert_outbox_summary(db, target=str(args.target or "")),
            }
        elif args.action == "retry":
            result = {
                "requeued": requeue_failed_recon_alerts(
                    db,
                    event_id=str(args.event_id or ""),
                    target=str(args.target or ""),
                ),
                "outbox": recon_alert_outbox_summary(db, target=str(args.target or "")),
            }
        elif args.action == "watch":
            interval = max(60, min(3600, int(args.interval_seconds or 60)))
            max_cycles = max(0, int(args.max_cycles or 0))
            cycles = 0
            totals = {"attempted": 0, "delivered": 0, "retry_pending": 0, "failed": 0}
            while True:
                delivery = _run_once(args, config, logger, db)
                cycles += 1
                for key in totals:
                    totals[key] += int(delivery.get(key, 0) or 0)
                if max_cycles and cycles >= max_cycles:
                    break
                time.sleep(interval)
            result = {
                "cycles": cycles,
                "interval_seconds": interval,
                **totals,
                "outbox": recon_alert_outbox_summary(db, target=str(args.target or "")),
            }
        else:
            result = _run_once(args, config, logger, db)
        print(json_dumps(result, pretty=True))
        return 2 if int(result.get("failed", 0) or 0) else 0
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

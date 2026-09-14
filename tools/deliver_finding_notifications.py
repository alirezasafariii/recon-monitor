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
from finding_notification_outbox import (
    DELIVERABLE_MODES,
    deliver_finding_notification_outbox,
    requeue_failed_finding_notifications,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deliver due Potential Finding notifications from the durable outbox."
    )
    parser.add_argument("--target", default="", help="Optional target policy filter")
    parser.add_argument(
        "--mode",
        default="",
        choices=["", *sorted(DELIVERABLE_MODES)],
        help="Optional delivery mode filter",
    )
    parser.add_argument("--limit", type=int, default=50, help="Maximum due events to process")
    parser.add_argument(
        "--requeue-failed",
        action="store_true",
        help="Reset matching terminal failed events before attempting delivery",
    )
    parser.add_argument("--event-id", default="", help="Optional failed event ID to requeue")
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
        requeued = 0
        if args.requeue_failed:
            requeued = requeue_failed_finding_notifications(
                db,
                event_id=str(args.event_id or ""),
                target=str(args.target or ""),
            )
        result = deliver_finding_notification_outbox(
            config=config,
            logger=logger,
            db=db,
            target=str(args.target or ""),
            mode=str(args.mode or ""),
            limit=max(1, min(500, int(args.limit or 50))),
        )
        result["requeued"] = requeued
        print(json_dumps(result, pretty=True))
        return 0 if int(result.get("failed", 0) or 0) == 0 else 2
    finally:
        db.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Operation interrupted safely.", file=sys.stderr)
        raise SystemExit(130)

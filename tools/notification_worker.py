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
from notification_supervisor import (
    configure_notification_supervisor,
    notification_supervisor_status,
    run_notification_supervisor_cycle,
    watch_notification_supervisor,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate the unified supervisor for Finding and Recon Alert delivery workers."
    )
    parser.add_argument("action", nargs="?", default="run", choices=["run", "watch", "status", "configure"])
    parser.add_argument("--owner-id", default="", help="Optional stable supervisor owner ID")
    parser.add_argument("--max-cycles", type=int, default=0, help="Optional watch-cycle limit")
    parser.add_argument("--enable", action="store_true", help="Enable supervisor execution")
    parser.add_argument("--disable", action="store_true", help="Disable supervisor execution")
    parser.add_argument("--poll-seconds", type=int, default=0, help="Supervisor poll interval (5-300)")
    parser.add_argument("--lease-seconds", type=int, default=0, help="Single-instance lease duration (60-3600)")
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
        if action == "status":
            result = notification_supervisor_status(db)
        elif action == "configure":
            if args.enable and args.disable:
                raise ReconError("Choose only one of --enable or --disable")
            enabled = True if args.enable else False if args.disable else None
            result = configure_notification_supervisor(
                db,
                enabled=enabled,
                poll_seconds=int(args.poll_seconds) if args.poll_seconds else None,
                lease_seconds=int(args.lease_seconds) if args.lease_seconds else None,
            )
        elif action == "watch":
            result = watch_notification_supervisor(
                config=config,
                logger=logger,
                db=db,
                owner_id=str(args.owner_id or ""),
                max_cycles=max(0, int(args.max_cycles or 0)),
            )
        else:
            result = run_notification_supervisor_cycle(
                config=config,
                logger=logger,
                db=db,
                owner_id=str(args.owner_id or ""),
                trigger="cli",
            )
        print(json_dumps(result, pretty=True))
        return 2 if isinstance(result, dict) and str(result.get("status") or "") in {"failed", "partial_failure"} else 0
    finally:
        db.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Notification supervisor stopped safely.", file=sys.stderr)
        raise SystemExit(130)

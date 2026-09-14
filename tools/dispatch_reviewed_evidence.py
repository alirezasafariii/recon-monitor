#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, ReconError, json_dumps
from reviewed_evidence_dispatcher import dispatch_reviewed_evidence


SUPPORTED_KINDS = (
    "account_enumeration",
    "authentication_session",
    "graphql_data_exposure",
    "material_classification",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Dispatch one existing offline reviewed-evidence record through its "
            "family Admission bridge and the Potential Finding notification pipeline."
        )
    )
    parser.add_argument("--review-id", required=True, help="Existing CID-/ASL-/GQLD-/MCR- review identifier")
    parser.add_argument(
        "--review-kind",
        choices=SUPPORTED_KINDS,
        default="",
        help="Optional explicit review kind; otherwise inferred from the review ID prefix",
    )
    parser.add_argument("--actor", default="cli", help="Audit actor label")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = AppPaths.from_root(ROOT)
    paths.ensure()
    if not paths.config.exists():
        raise ReconError("config.env not found. Run ./recon-monitor.sh init")

    config = Config(paths)
    db = Database(paths.db)
    logger = Logger(paths, verbose=False)
    try:
        ctx = SimpleNamespace(paths=paths, config=config, db=db, logger=logger)
        result = dispatch_reviewed_evidence(
            ctx,
            review_id=str(args.review_id),
            review_kind=str(args.review_kind or ""),
            actor=str(args.actor or "cli"),
        )
    finally:
        db.close()
    print(json_dumps(result, pretty=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Operation interrupted safely.", file=sys.stderr)
        raise SystemExit(130)

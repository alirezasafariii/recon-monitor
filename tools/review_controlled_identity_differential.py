#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from controlled_identity_differential import review_controlled_identity_artifact
from core import AppPaths, Database, ReconError, json_dumps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review a redacted controlled-identity comparison offline."
    )
    parser.add_argument(
        "--evidence-file",
        required=True,
        help="Path to an analyst-reviewed controlled identity comparison JSON file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = AppPaths.from_root(ROOT)
    paths.ensure()
    db = Database(paths.db)
    try:
        result = review_controlled_identity_artifact(
            db,
            artifact_path=args.evidence_file,
            actor="offline-cli",
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

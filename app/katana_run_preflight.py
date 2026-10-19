"""Policy-aware Katana guard for the normal recon-monitor.sh entry point.

Uses the same PolicySet parser/selector as the Orchestrator. Does no scanning,
network I/O or database writes. Returns nonzero before handing control to CLI
if a selected URL-enabled target lacks verified project Katana.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from core import AppPaths, PolicySet, ReconError
from katana_runtime_contract import check_project, urls_enabled


def main(argv: list[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    if len(tokens) < 2 or tokens[1] != "run":
        print("Katana preflight: expected ROOT run [OPTIONS]", file=sys.stderr)
        return 2
    root = Path(tokens[0]).resolve()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target")
    parser.add_argument("--resume")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--help", "-h", action="store_true", dest="help")
    parser.add_argument("--json-plan", action="store_true")
    parser.add_argument("--allow-active", action="store_true")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--no-progress", action="store_true")
    try:
        flags, _unknown = parser.parse_known_args(tokens[2:])
    except (ValueError, SystemExit):
        return 2
    if flags.dry_run or flags.help:
        return 0
    try:
        policies = PolicySet.load(AppPaths.from_root(root))
        selected = policies.select(flags.target)
    except (ReconError, OSError, ValueError) as exc:
        print(f"[ERROR] Target policy preflight: {exc}", file=sys.stderr)
        return 2
    if urls_enabled(selected):
        error = check_project(root)
        if error:
            print(f"[ERROR] {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

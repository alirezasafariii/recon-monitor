#!/usr/bin/env python3
"""Source-tree entry point for the installed dashboard review implementation."""
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from dashboard_review_support import main, ReconError

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReconError, OSError, sqlite3.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

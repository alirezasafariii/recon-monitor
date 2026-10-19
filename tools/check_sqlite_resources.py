#!/usr/bin/env python3
"""Run regression tests and fail on SQLite connections without explicit close."""
import argparse
import sys
import tracemalloc
import unittest
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pattern', default='test_*.py')
    parser.add_argument('--tracemalloc', action='store_true')
    args = parser.parse_args()
    tests = Path(__file__).resolve().parents[1] / 'tests'
    sys.path.insert(0, str(tests))
    from sqlite_resource_guard import SQLiteResourceGuard
    # Import modules before enabling allocation tracing; the tests themselves
    # and the production connections they exercise remain inside the guard.
    suite = unittest.defaultTestLoader.discover(str(tests), pattern=args.pattern)
    if args.tracemalloc:
        tracemalloc.start(5)
    with SQLiteResourceGuard() as guard:
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        guard.assert_all_closed()
    print(f'SQLite resources: {len(guard.records)} connections explicitly closed')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())

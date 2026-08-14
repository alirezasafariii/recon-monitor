from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATHS = (
    "app/verified_replay_collector.py",
    "tests/test_verified_replay_collector_v942.py",
    "docs/VERIFIED_REPLAY_COLLECTOR.md",
)


class VerifiedReplayHashProbeTmpTests(unittest.TestCase):
    def test_print_final_file_hashes(self):
        for relative in PATHS:
            digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            print(f"REPLAY_SHA256 {digest}  {relative}")
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()

"""Checkpoint cleanup survives Next and cancellation, including an exited leader."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from core import CommandRunner


@unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
class CheckpointShutdownTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.runner = CommandRunner(MagicMock())
        self.runner.next_raise = False
        self.saved = self.root / "checkpoint-saved"
        self.output = self.root / "output.txt"

    def cleanup_code(self):
        return (
            "import os, signal, sys, time\nfrom pathlib import Path\n"
            "signal.alarm(10)\n"
            "def shutdown(*args):\n"
            "    time.sleep(1.5)\n"
            f"    Path({str(self.saved)!r}).write_text('durable')\n"
            "    print('saved', flush=True)\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, shutdown)\n"
            "print('ready', flush=True)\n"
            "while True: time.sleep(0.05)\n"
        )

    def test_next_allows_slow_checkpoint_publication(self):
        requested = threading.Event()
        self.runner.next_check = requested.is_set
        result = self.runner.run(
            [sys.executable, "-u", "-c", self.cleanup_code()], timeout=8,
            termination_grace_seconds=2.2, output_path=self.output,
            line_callback=lambda line, _: requested.set() if line == "ready" else None,
        )
        self.assertTrue(result.operator_next)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(self.saved.read_text(), "durable")
        self.assertIn("saved", self.output.read_text())
        self.assertFalse(any(t.name == "command-watchdog" for t in threading.enumerate()))
        self.runner.next_check = None
        following = self.runner.run([sys.executable, "-c", "print('reusable')"], timeout=5)
        self.assertEqual(following.returncode, 0)

    def test_external_cancellation_preserves_checkpoint_grace(self):
        result = self.runner.run(
            [sys.executable, "-u", "-c", self.cleanup_code()], timeout=8,
            termination_grace_seconds=3.2, output_path=self.output,
            line_callback=lambda line, _: self.runner.terminate_active() if line == "ready" else None,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.saved.read_text(), "durable")
        self.assertIn("saved", self.output.read_text())
        self.assertIsNone(self.runner._active)

    def test_exited_leader_does_not_shorten_descendant_cleanup(self):
        ready = self.root / "descendant-ready"
        descendant = (
            "import os, signal, sys, time\nfrom pathlib import Path\n"
            "signal.alarm(10)\n"
            "def shutdown(*args):\n"
            "    time.sleep(1.5)\n"
            f"    Path({str(self.saved)!r}).write_text('durable')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, shutdown)\n"
            f"Path({str(ready)!r}).touch()\n"
            "while True: time.sleep(0.05)\n"
        )
        parent = (
            "import signal, subprocess, sys, time\nfrom pathlib import Path\n"
            "signal.alarm(10)\n"
            "signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))\n"
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"while not Path({str(ready)!r}).exists(): time.sleep(0.01)\n"
            "print('ready', flush=True)\n"
            "while True: time.sleep(0.05)\n"
        )
        requested = threading.Event()
        self.runner.next_check = requested.is_set
        result = self.runner.run(
            [sys.executable, "-u", "-c", parent], timeout=8,
            termination_grace_seconds=2.2, output_path=self.output,
            line_callback=lambda line, _: requested.set() if line == "ready" else None,
        )
        self.assertTrue(result.operator_next)
        self.assertEqual(self.saved.read_text(), "durable")
        self.assertFalse(any(t.name == "command-watchdog" for t in threading.enumerate()))

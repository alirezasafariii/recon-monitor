from __future__ import annotations

from contextlib import contextmanager

import errno
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, CommandRunner, Logger, NextStageRequested


REAL_POPEN = subprocess.Popen


@unittest.skipUnless(os.name == "posix", "CommandRunner process groups require POSIX")
class CommandRunnerStdinTests(unittest.TestCase):
    LARGE_INPUT = "example.test\n" * 100_000

    def setUp(self):
        for name in ("socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("local process test attempted network I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = AppPaths.from_root(Path(tmp.name))
        self.paths.ensure()
        self.runner = CommandRunner(Logger(self.paths, verbose=False))
        self.output = self.paths.root / "captured.txt"
        self.allowed_commands = set()
        self.processes = []

        def local_python_only(args, **kwargs):
            self.assertIn(tuple(args), self.allowed_commands, "unexpected subprocess command")
            proc = REAL_POPEN(args, **kwargs)
            self.processes.append(proc)
            return proc

        guard = patch("core.subprocess.Popen", side_effect=local_python_only)
        guard.start()
        self.addCleanup(guard.stop)
        self.addCleanup(self._cleanup_processes)

    def _cleanup_processes(self):
        for proc in self.processes:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                if sys.platform != "darwin" or proc.poll() is None:
                    raise
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            for stream in (proc.stdin, proc.stdout):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def _command(self, code):
        args = [sys.executable, "-u", "-c", "import signal; signal.alarm(5)\n" + code]
        self.allowed_commands.add(tuple(args))
        return args

    def _invoke(self, code, *, maximum=3, **kwargs):
        result = []
        failures = []

        def run():
            try:
                result.append(self.runner.run(self._command(code), output_path=self.output, **kwargs))
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(maximum)
        if thread.is_alive():
            # Bound failing regressions independently of CommandRunner itself.
            self._cleanup_processes()
            thread.join(1)
            self.fail("CommandRunner exceeded the local regression time limit")
        if failures:
            raise failures[0]
        return result[0]

    def _assert_clean(self):
        self.assertIsNone(self.runner._active)
        self.assertFalse(self.runner._stop.is_set())
        self.assertFalse(any(thread.name == "command-watchdog" for thread in threading.enumerate()))
        for proc in self.processes:
            self.assertIsNotNone(proc.poll())
            self.assertTrue(proc.stdout.closed)
            if proc.stdin is not None:
                self.assertTrue(proc.stdin.closed)

    @contextmanager
    def _macos_dead_group_signals(self):
        real_killpg = os.killpg
        denied = []

        def deny_exited_group(pid, sig):
            proc = next(proc for proc in self.processes if proc.pid == pid)
            if proc.poll() is not None:
                denied.append(sig)
                raise PermissionError(errno.EPERM, "exited macOS process group")
            return real_killpg(pid, sig)

        with patch("core.sys.platform", "darwin"), patch("core.os.killpg", side_effect=deny_exited_group):
            yield denied

    def test_timeout_applies_while_large_stdin_is_not_read(self):
        result = self._invoke("import time\nprint('prefix', flush=True)\ntime.sleep(2)", timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.operator_next)
        self.assertLess(result.duration, 1.8)
        self.assertEqual(self.output.read_text(), "prefix\n")
        self.assertEqual(result.lines, 1)
        self._assert_clean()

    def test_next_applies_while_large_stdin_is_not_read(self):
        requested = threading.Event()
        self.runner.next_check = requested.is_set
        self.runner.next_raise = False
        result = self._invoke("import time\nprint('prefix', flush=True)\ntime.sleep(2)", timeout=10, input_text=self.LARGE_INPUT,
                              line_callback=lambda _line, _count: requested.set())
        self.assertEqual(result.returncode, 125)
        self.assertTrue(result.operator_next)
        self.assertFalse(result.timed_out)
        self.assertLess(result.duration, 1.8)
        self.assertEqual(self.output.read_text(), "prefix\n")
        self._assert_clean()

    def test_default_next_exception_is_raised_after_output_and_resources_are_saved(self):
        self.runner.next_check = lambda: True
        with self.assertRaises(NextStageRequested):
            self._invoke("import time\nprint('prefix', flush=True)\ntime.sleep(2)", timeout=10, input_text=self.LARGE_INPUT)
        self._assert_clean()

    def test_large_stdout_and_stdin_make_progress_together(self):
        callbacks = []
        code = "import sys, hashlib\nsys.stdout.write('output-line\\n' * 20000)\nsys.stdout.flush()\ndata=sys.stdin.buffer.read()\nprint('receipt=' + hashlib.sha256(data).hexdigest(), flush=True)"
        result = self._invoke(code, timeout=2, input_text=self.LARGE_INPUT, line_callback=lambda line, count: callbacks.append((line, count)))
        expected = hashlib.sha256(self.LARGE_INPUT.encode()).hexdigest()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.lines, 20001)
        self.assertEqual(callbacks[-1], ("receipt=" + expected, 20001))
        self.assertEqual(self.output.read_text(), "output-line\n" * 20000 + "receipt=" + expected + "\n")
        self._assert_clean()

    def test_multibyte_input_and_chunked_newlines_remain_lossless(self):
        text = "دامنه.test\r\n🙂\n" * 30000
        code = "import os, sys, hashlib, time\ndata=sys.stdin.buffer.read()\nos.write(1, b'\\xf0')\ntime.sleep(0.02)\nos.write(1, b'\\x9f\\x99\\x82\\r')\ntime.sleep(0.02)\nos.write(1, b'\\n')\nos.write(1, hashlib.sha256(data).hexdigest().encode())"
        result = self._invoke(code, timeout=None, input_text=text)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(), "🙂\n" + hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(result.lines, 2)
        self._assert_clean()

    def test_early_stdin_close_returns_the_process_result_without_broken_pipe_error(self):
        result = self._invoke("import os, sys\nos.close(0)\nprint('refused', flush=True)\nsys.exit(7)", timeout=2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.timed_out)
        self.assertEqual(self.output.read_text(), "refused\n")
        self._assert_clean()

    def test_empty_or_absent_input_delivers_eof(self):
        for value in (None, ""):
            with self.subTest(input=value):
                result = self._invoke("import sys\nprint(len(sys.stdin.read()), flush=True)", timeout=2, input_text=value)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(self.output.read_text(), "0\n")
                self._assert_clean()

    def test_external_cancellation_interrupts_large_stdin(self):
        prefix = threading.Event()

        def cancel():
            if prefix.wait(2):
                self.runner.terminate_active()

        thread = threading.Thread(target=cancel, daemon=True)
        thread.start()
        result = self._invoke("import time\nprint('prefix', flush=True)\ntime.sleep(2)", timeout=10, input_text=self.LARGE_INPUT,
                              line_callback=lambda _line, _count: prefix.set())
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.operator_next)
        self.assertLess(result.duration, 1.8)
        self.assertEqual(self.output.read_text(), "prefix\n")
        self._assert_clean()

    def test_runner_is_reusable_after_a_blocked_stdin_timeout(self):
        first = self._invoke("import time\ntime.sleep(2)", timeout=0.1, input_text=self.LARGE_INPUT)
        self.assertTrue(first.timed_out)
        second = self._invoke("import sys\nprint(sys.stdin.read(), end='')", timeout=2, input_text="next\n")
        self.assertEqual(second.returncode, 0)
        self.assertFalse(second.timed_out)
        self.assertEqual(self.output.read_text(), "next\n")
        self._assert_clean()

    def test_callback_exception_terminates_the_process_and_closes_pipes(self):
        def broken_callback(_line, _count):
            raise RuntimeError("offline callback failure")

        with self.assertRaisesRegex(RuntimeError, "offline callback failure"):
            self._invoke("import time\nprint('prefix', flush=True)\ntime.sleep(2)", timeout=10, input_text="small", line_callback=broken_callback)
        self.assertEqual(self.output.read_text(), "prefix\n")
        self._assert_clean()

    def test_heartbeat_and_next_poll_errors_do_not_disable_timeout(self):
        def broken_callback():
            raise RuntimeError("offline poll failure")

        self.runner.next_check = broken_callback
        result = self._invoke("import time\ntime.sleep(2)", timeout=0.2, input_text=self.LARGE_INPUT, heartbeat=broken_callback)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self._assert_clean()

    def test_descendant_holding_stdin_cannot_outlive_the_deadline(self):
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\nprint('parent-exited', flush=True)"
        result = self._invoke(code, timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration, 1.8)
        self.assertEqual(self.output.read_text(), "parent-exited\n")
        self._assert_clean()

    def test_descendant_holding_stdout_cannot_outlive_the_deadline(self):
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], stdin=subprocess.DEVNULL)\nprint('parent-exited', flush=True)"
        result = self._invoke(code, timeout=0.7)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration, 1.8)
        self.assertEqual(self.output.read_text(), "parent-exited\n")
        self._assert_clean()

    def test_process_ignoring_sigterm_is_force_killed_and_output_is_kept(self):
        code = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nprint('prefix', flush=True)\ntime.sleep(5)"
        result = self._invoke(code, timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration, 2.5)
        self.assertEqual(self.output.read_text(), "prefix\n")
        self._assert_clean()

    def test_eof_tail_is_delivered_while_inherited_stdin_is_still_pending(self):
        requested = threading.Event()
        self.runner.next_check = requested.is_set
        self.runner.next_raise = False
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\nprint('tail', end='', flush=True)"
        result = self._invoke(code, timeout=2, input_text=self.LARGE_INPUT, line_callback=lambda _line, _count: requested.set())
        self.assertTrue(result.operator_next)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.lines, 1)
        self.assertEqual(self.output.read_text(), "tail")
        self._assert_clean()

    def test_truncated_multibyte_stdout_does_not_hide_timeout(self):
        result = self._invoke("import os, time\nos.write(1, b'prefix\\n\\xf0')\ntime.sleep(2)", timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertEqual(self.output.read_text(), "prefix\n\ufffd")
        self.assertEqual(result.lines, 2)
        self._assert_clean()

    def test_popen_failure_closes_output_and_keeps_runner_reusable(self):
        opened = []
        real_open = Path.open

        def tracked_open(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            if path == self.output:
                opened.append(handle)
                self.addCleanup(handle.close)
            return handle

        with patch.object(Path, "open", tracked_open), patch("core.subprocess.Popen", side_effect=OSError("offline spawn failure")):
            with self.assertRaisesRegex(OSError, "offline spawn failure"):
                self.runner.run(self._command("print('ready')"), output_path=self.output, input_text=self.LARGE_INPUT)
        self.assertTrue(opened[0].closed)
        self._assert_clean()
        result = self._invoke("print('ready')", timeout=2)
        self.assertEqual(result.returncode, 0)
        self._assert_clean()

    def test_watchdog_start_failure_terminates_child_and_closes_all_handles(self):
        with patch("core.threading.Thread.start", side_effect=RuntimeError("offline thread failure")):
            with self.assertRaisesRegex(RuntimeError, "offline thread failure"):
                self.runner.run(self._command("import time; time.sleep(2)"), output_path=self.output, input_text=self.LARGE_INPUT)
        self._assert_clean()

    def test_detached_pipe_holder_cannot_block_timeout_cleanup(self):
        pid_path = self.paths.root / "detached.pid"

        def cleanup_detached():
            if pid_path.exists():
                try:
                    os.kill(int(pid_path.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

        self.addCleanup(cleanup_detached)
        code = "import subprocess, sys\nfrom pathlib import Path\nchild=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], start_new_session=True)\nPath(" + repr(str(pid_path)) + ").write_text(str(child.pid))\nprint('parent-exited', flush=True)"
        result = self._invoke(code, timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration, 2.8)
        self.assertEqual(self.output.read_text(), "parent-exited\n")
        self._assert_clean()

    def test_macos_dead_group_permission_error_keeps_timeout_and_output(self):
        # Retain both pipes after the group leader exits, without creating any
        # live member of its original process group.
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'], start_new_session=True)\nprint('parent-exited', flush=True)"

        with self._macos_dead_group_signals() as denied, patch("threading.excepthook") as thread_error:
            result = self._invoke(code, timeout=0.2, input_text=self.LARGE_INPUT)
        self.assertIn(signal.SIGTERM, denied)
        self.assertIn(signal.SIGKILL, denied)
        thread_error.assert_not_called()
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration, 2.8)
        self.assertEqual(self.output.read_text(), "parent-exited\n")
        self._assert_clean()
        following = self._invoke("print('reusable')", timeout=2)
        self.assertEqual(following.returncode, 0)
        self._assert_clean()

    def test_macos_dead_group_permission_error_keeps_next_checkpoint(self):
        self.runner.next_raise = False
        requested = threading.Event()
        self.runner.next_check = requested.is_set
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'], start_new_session=True)\nprint('checkpoint', flush=True)"

        def request_next(_line, _count):
            self.processes[-1].wait(timeout=1)
            requested.set()

        with self._macos_dead_group_signals(), patch("threading.excepthook") as thread_error:
            result = self._invoke(code, timeout=10, line_callback=request_next)
        thread_error.assert_not_called()
        self.assertTrue(result.operator_next)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 125)
        self.assertLess(result.duration, 2.8)
        self.assertEqual(self.output.read_text(), "checkpoint\n")
        self._assert_clean()

    def test_macos_dead_group_permission_error_does_not_mask_callback_failure(self):
        def broken_callback(_line, _count):
            self.processes[-1].wait(timeout=1)
            raise RuntimeError("original callback failure")

        with self._macos_dead_group_signals():
            with self.assertRaisesRegex(RuntimeError, "original callback failure"):
                self._invoke("print('saved')", timeout=2, line_callback=broken_callback)
        self.assertEqual(self.output.read_text(), "saved\n")
        self._assert_clean()

    def test_macos_dead_group_permission_error_allows_external_cancellation(self):
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'], start_new_session=True)\nprint('cancelled', flush=True)"

        def cancel(_line, _count):
            self.processes[-1].wait(timeout=1)
            self.runner.terminate_active()

        with self._macos_dead_group_signals() as denied, patch("threading.excepthook") as thread_error:
            result = self._invoke(code, timeout=10, line_callback=cancel)
        thread_error.assert_not_called()
        self.assertIn(signal.SIGTERM, denied)
        self.assertIn(signal.SIGKILL, denied)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.operator_next)
        self.assertEqual(self.output.read_text(), "cancelled\n")
        self.assertLess(result.duration, 2.8)
        self._assert_clean()

    def test_live_child_signal_permission_error_reaches_caller_without_thread_failure(self):
        real_killpg = os.killpg

        def deny_sigterm(pid, sig):
            if sig == signal.SIGTERM:
                raise PermissionError(errno.EPERM, "live process group denied")
            return real_killpg(pid, sig)

        with patch("core.sys.platform", "darwin"), patch("core.os.killpg", side_effect=deny_sigterm), patch("threading.excepthook") as thread_error:
            with self.assertRaisesRegex(PermissionError, "live process group denied"):
                self._invoke("import time\nprint('saved', flush=True)\ntime.sleep(2)", timeout=0.2)
        thread_error.assert_not_called()
        self.assertEqual(self.output.read_text(), "saved\n")
        self._assert_clean()

    def test_linux_exited_group_permission_error_is_not_suppressed(self):
        def on_exit(_line, _count):
            self.processes[-1].wait(timeout=1)
            self.runner.terminate_active()

        with patch("core.sys.platform", "linux"), patch("core.os.killpg", side_effect=PermissionError(errno.EPERM, "Linux group denied")):
            with self.assertRaisesRegex(PermissionError, "Linux group denied"):
                self._invoke("print('saved')", timeout=2, line_callback=on_exit)
        self._assert_clean()

    def test_macos_unexpected_signal_error_is_not_suppressed(self):
        def on_exit(_line, _count):
            self.processes[-1].wait(timeout=1)
            self.runner.terminate_active()

        with patch("core.sys.platform", "darwin"), patch("core.os.killpg", side_effect=OSError(errno.EINVAL, "unexpected signal error")):
            with self.assertRaisesRegex(OSError, "unexpected signal error"):
                self._invoke("print('saved')", timeout=2, line_callback=on_exit)
        self._assert_clean()


if __name__ == "__main__":
    unittest.main()

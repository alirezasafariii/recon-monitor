from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server_core as api
from api_process_control import APIProcessControl, ControlledAPIHTTPServer
from core import AppPaths, ReconError

INSTANCE = "a" * 32
OTHER_INSTANCE = "b" * 32
PID = 42424242
REAL_POPEN = subprocess.Popen
REAL_KILL = os.kill


class PortableShutdownTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.pid_path, _ = api.api_paths(self.paths)
        self.record = {"version": 2, "pid": PID, "start_token": "", "control_instance": INSTANCE}
        self.pid_path.write_text(json.dumps(self.record) + "\n")
        self.control = APIProcessControl(self.paths, INSTANCE)
        for name in ("socket.getaddrinfo", "socket.socket.connect", "subprocess.Popen"):
            guard = patch(name, side_effect=AssertionError("Shutdown regression attempted external I/O"))
            guard.start()
            self.addCleanup(guard.stop)

    def _ack(self):
        self.control.path.write_text(json.dumps({"control_instance": INSTANCE, "pid": PID, "status": "stopped"}))

    def test_non_linux_stop_requires_ack_and_never_signals_a_pid(self):
        def respond(_):
            request = json.loads(self.control.path.read_text())
            self.assertEqual(request, {"control_instance": INSTANCE, "pid": PID, "action": "stop"})
            self._ack()

        with patch.object(api.os, "pidfd_open", None, create=True), \
             patch.object(api.signal, "pidfd_send_signal", None, create=True), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")), \
             patch.object(api.subprocess, "run", side_effect=AssertionError("Unneeded ps check")), \
             patch.object(api.time, "sleep", side_effect=respond):
            self.assertTrue(api.stop_api(self.paths))
        self.assertFalse(self.pid_path.exists())
        self.assertFalse(self.control.path.exists())

    def test_reused_pid_without_ack_keeps_record_and_never_signals(self):
        raw = self.pid_path.read_text()
        # The old instance can exit and the PID can be reused after any check.
        # Writing the old instance's request never affects the new instance.
        other = APIProcessControl(self.paths, OTHER_INSTANCE)
        with patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")), \
             patch.object(api.time, "monotonic", side_effect=[0.0, 4.0]):
            with self.assertRaisesRegex(ReconError, "not acknowledged"):
                api.stop_api(self.paths)
        self.assertEqual(self.pid_path.read_text(), raw)
        self.assertFalse(other.path.exists())
        self.assertEqual(json.loads(self.control.path.read_text())["control_instance"], INSTANCE)

    def test_ack_after_exit_is_accepted_without_overwriting_it(self):
        self._ack()
        with patch.object(api.os, "kill", side_effect=AssertionError("PID may already be reused")), \
             patch.object(api.time, "sleep", side_effect=AssertionError("Ack must be accepted immediately")):
            self.assertTrue(api.stop_api(self.paths))

    def test_wrong_instance_pid_or_status_is_not_an_ack(self):
        for response in (
            {"control_instance": OTHER_INSTANCE, "pid": PID, "status": "stopped"},
            {"control_instance": INSTANCE, "pid": PID + 1, "status": "stopped"},
            {"control_instance": INSTANCE, "pid": PID, "status": "running"},
            {"control_instance": INSTANCE, "pid": True, "status": "stopped"},
        ):
            with self.subTest(response=response):
                self.control.path.write_text(json.dumps(response))
                self.assertFalse(self.control.is_stopped(PID))

    def test_shutdown_preserves_a_replacement_api_record(self):
        replacement = {**self.record, "pid": PID + 1, "control_instance": OTHER_INSTANCE}

        def respond(_):
            self.pid_path.write_text(json.dumps(replacement))
            self._ack()

        with patch.object(api.time, "sleep", side_effect=respond), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            self.assertTrue(api.stop_api(self.paths))
        self.assertEqual(json.loads(self.pid_path.read_text()), replacement)

    def test_stop_request_write_failure_keeps_pid_record(self):
        raw = self.pid_path.read_text()
        with patch("api_process_control.atomic_write_text", side_effect=OSError(errno.ENOSPC, "fixture full")), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            with self.assertRaisesRegex(ReconError, "PID record retained"):
                api.stop_api(self.paths)
        self.assertEqual(self.pid_path.read_text(), raw)

    def test_new_instance_is_part_of_status_identity_without_proc(self):
        command = f"/usr/bin/python {self.paths.app / 'recon_monitor.py'} api foreground --control-instance {OTHER_INSTANCE}"
        with patch.object(api, "_process_alive", return_value=True), \
             patch.object(api, "_process_start_token", return_value=""), \
             patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=command)):
            active, _ = api.api_status(self.paths)
        self.assertFalse(active)

    def test_non_linux_status_handles_ps_paths_with_spaces(self):
        script = (self.paths.root / "checkout with spaces" / "app" / "recon_monitor.py").resolve()
        paths = AppPaths.from_root(script.parents[1])
        for prefix in (f"/usr/bin/python {script}", f"'/usr/bin/python' '{script}'"):
            with self.subTest(prefix=prefix):
                command = f"{prefix} api foreground --host 127.0.0.1 --port 9090 --control-instance {INSTANCE}"
                with patch.object(api, "_process_alive", return_value=True), \
                     patch.object(api, "_process_start_token", return_value=""), \
                     patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=command)):
                    info = api._api_process_info(paths, PID, "", INSTANCE)
                self.assertIsNotNone(info)
                self.assertEqual(info["port"], 9090)

    def test_ack_is_preserved_if_pid_record_cannot_be_removed(self):
        self._ack()
        with patch.object(Path, "unlink", side_effect=PermissionError("fixture")):
            self.assertTrue(api.stop_api(self.paths))
        self.assertTrue(self.pid_path.exists())
        self.assertTrue(self.control.is_stopped(PID))
        self.assertTrue(api.stop_api(self.paths))
        self.assertFalse(self.pid_path.exists())

    def test_argument_mentioning_script_is_not_the_api_executable(self):
        command = f"/usr/bin/python unrelated.py {self.paths.app / 'recon_monitor.py'} api foreground"
        with patch.object(api, "_process_alive", return_value=True), \
             patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=command)):
            self.assertIsNone(api._api_process_info(self.paths, PID))

    def test_malformed_or_future_records_never_downgrade_to_legacy_signalling(self):
        for value in (
            True, {"pid": True}, {"pid": PID, "version": 3},
            {"pid": PID, "version": 2},
            {"pid": PID, "control_instance": "../unexpected"},
        ):
            with self.subTest(record=value):
                self.pid_path.write_text(json.dumps(value))
                with patch.object(api.os, "kill", side_effect=AssertionError("Invalid PID record used")):
                    self.assertFalse(api.stop_api(self.paths))

    def test_start_uses_a_unique_private_instance_even_without_start_token(self):
        ids = []
        for _ in range(2):
            self.pid_path.unlink(missing_ok=True)
            with patch.object(api.subprocess, "Popen", return_value=Mock(pid=PID)) as spawn, \
                 patch.object(api, "_process_start_token", return_value=""), \
                 patch.object(api.time, "sleep"):
                self.assertEqual(api.start_api(self.paths, "127.0.0.1", 8790), PID)
            record = json.loads(self.pid_path.read_text())
            ids.append(record["control_instance"])
            cmd = spawn.call_args.args[0]
            self.assertEqual(cmd[cmd.index("--control-instance") + 1], ids[-1])
            self.assertEqual(record["version"], 2)
            self.assertEqual(record["start_token"], "")
            self.assertEqual(self.pid_path.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(*ids)

    def test_control_files_are_private_and_request_checks_pid(self):
        self.control.request_stop(os.getpid())
        self.assertEqual(self.control.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.control.stop_requested())
        self.control.request_stop(os.getpid() + 1)
        self.assertFalse(self.control.stop_requested())

    def test_foreground_cli_passes_the_instance_to_the_production_server(self):
        import recon_monitor_core as cli

        self.paths.config.write_text("I_HAVE_AUTHORIZATION=yes\n")
        with patch.object(cli, "ROOT_DIR", self.paths.root), \
             patch.object(cli, "Logger") as logger, \
             patch.object(cli, "Database") as database, \
             patch.object(cli, "serve_api") as serve:
            self.assertEqual(cli.main(["api", "foreground", "--host", "127.0.0.1", "--port", "8790", "--control-instance", INSTANCE]), 0)
        serve.assert_called_once_with(self.paths, logger.return_value, "127.0.0.1", 8790, False, control_instance=INSTANCE)
        database.return_value.close.assert_called_once()

    def test_control_parser_ignores_malformed_wrong_instance_and_oversized_files(self):
        for raw in ("not json", "[]", "x" * 4097, "\ud800", json.dumps({"control_instance": OTHER_INSTANCE, "action": "stop", "pid": os.getpid()})):
            with self.subTest(raw=repr(raw[:60])):
                self.control.path.write_bytes(raw.encode("utf-8", errors="surrogatepass"))
                self.assertFalse(self.control.stop_requested())
                self.assertFalse(self.control.is_stopped(PID))

    def _legacy(self):
        self.pid_path.write_text(str(PID) + "\n")
        identity = patch.object(api, "_api_process_info", return_value={"pid": PID, "start_token": "linux-start"})
        identity.start()
        self.addCleanup(identity.stop)

    def test_legacy_non_linux_refuses_to_signal_and_retains_pid(self):
        self._legacy()
        with patch.object(api.os, "pidfd_open", None, create=True), \
             patch.object(api.signal, "pidfd_send_signal", None, create=True), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            with self.assertRaisesRegex(ReconError, "Cannot safely stop this legacy API"):
                api.stop_api(self.paths)
        self.assertTrue(self.pid_path.exists())

    def test_legacy_missing_start_token_refuses_even_with_pidfd_functions(self):
        self._legacy()
        with patch.object(api, "_api_process_info", return_value={"pid": PID, "start_token": ""}), \
             patch.object(api.os, "pidfd_open", create=True) as open_fd, \
             patch.object(api.signal, "pidfd_send_signal", create=True) as send:
            with self.assertRaisesRegex(ReconError, "Cannot safely stop"):
                api.stop_api(self.paths)
        open_fd.assert_not_called()
        send.assert_not_called()
        self.assertTrue(self.pid_path.exists())

    def test_pidfd_open_failures_never_fall_back_to_kill(self):
        self._legacy()
        for error in (PermissionError(errno.EPERM, "fixture"), OSError(errno.ENOSYS, "fixture"), OSError(errno.EMFILE, "fixture")):
            with self.subTest(error=error), \
                 patch.object(api.os, "pidfd_open", side_effect=error, create=True), \
                 patch.object(api.signal, "pidfd_send_signal", create=True) as send, \
                 patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
                with self.assertRaisesRegex(ReconError, "No PID signal fallback"):
                    api.stop_api(self.paths)
                send.assert_not_called()
                self.assertTrue(self.pid_path.exists())

    def test_linux_escalation_uses_the_same_pinned_fd_and_confirms_exit(self):
        self._legacy()
        with patch.object(api.os, "pidfd_open", return_value=55, create=True) as open_fd, \
             patch.object(api.signal, "pidfd_send_signal", create=True) as send, \
             patch.object(api.select, "select", side_effect=[([], [], []), ([55], [], [])]) as wait, \
             patch.object(api.os, "close") as close, \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            self.assertTrue(api.stop_api(self.paths))
        open_fd.assert_called_once_with(PID)
        self.assertEqual([call.args for call in send.call_args_list], [(55, signal.SIGTERM), (55, signal.SIGKILL)])
        self.assertTrue(all(call.args[0] == [55] for call in wait.call_args_list))
        close.assert_called_once_with(55)
        self.assertFalse(self.pid_path.exists())

    def test_pid_reuse_after_fd_open_sends_no_signal_and_closes_fd(self):
        self._legacy()
        with patch.object(api, "_api_process_info", side_effect=[{"start_token": "old"}, None]), \
             patch.object(api.os, "pidfd_open", return_value=55, create=True), \
             patch.object(api.signal, "pidfd_send_signal", create=True) as send, \
             patch.object(api.os, "close") as close:
            with self.assertRaisesRegex(ReconError, "identity changed"):
                api.stop_api(self.paths)
        send.assert_not_called()
        close.assert_called_once_with(55)
        self.assertTrue(self.pid_path.exists())

    def test_unconfirmed_pidfd_exit_keeps_record(self):
        self._legacy()
        with patch.object(api.os, "pidfd_open", return_value=55, create=True), \
             patch.object(api.signal, "pidfd_send_signal", create=True), \
             patch.object(api.select, "select", return_value=([], [], [])), \
             patch.object(api.os, "close") as close:
            with self.assertRaisesRegex(ReconError, "exit was not confirmed"):
                api.stop_api(self.paths)
        self.assertTrue(self.pid_path.exists())
        close.assert_called_once_with(55)


class LocalAPIServerShutdownTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="api fixture ")
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        for name in ("socket.getaddrinfo", "socket.socket.connect", "subprocess.Popen"):
            guard = patch(name, side_effect=AssertionError("Only the explicit local API fixture is allowed"))
            guard.start()
            self.addCleanup(guard.stop)

    def _server(self):
        ready = threading.Event()
        polled = threading.Event()
        servers = []
        errors = []
        logger = Mock()
        logger.info.side_effect = lambda message, **kwargs: ready.set() if message == "API started" else None

        def create(address, handler, control):
            server = ControlledAPIHTTPServer(address, handler, control)
            action = server.service_actions

            def actions():
                action()
                polled.set()

            server.service_actions = actions
            servers.append(server)
            return server

        def serve():
            try:
                api.serve_api(self.paths, logger, "127.0.0.1", 0, control_instance=INSTANCE)
            except Exception as exc:
                errors.append(exc)
                ready.set()

        thread = threading.Thread(target=serve, daemon=True)
        with patch.object(api, "ControlledAPIHTTPServer", side_effect=create), patch("socket.getfqdn", return_value="localhost"):
            thread.start()
            self.assertTrue(ready.wait(3), "Fixture failed to start")
        self.assertFalse(errors)

        def cleanup():
            if thread.is_alive():
                servers[0].shutdown()
            thread.join(3)
            servers[0].server_close()

        self.addCleanup(cleanup)
        self.paths.state.joinpath("api.pid").write_text(json.dumps({"version": 2, "pid": os.getpid(), "control_instance": INSTANCE}))
        return servers[0], thread, polled, errors

    def test_real_server_closes_listener_before_ack_without_pidfd_or_proc(self):
        server, thread, _, errors = self._server()
        with patch.object(api.os, "pidfd_open", None, create=True), \
             patch.object(api.signal, "pidfd_send_signal", None, create=True), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            self.assertTrue(api.stop_api(self.paths))
        thread.join(2)
        self.assertFalse(thread.is_alive(), "Shutdown deadlocked")
        self.assertEqual(server.fileno(), -1)
        self.assertFalse(errors)

    def test_real_server_ignores_another_instances_request(self):
        server, thread, polled, errors = self._server()
        APIProcessControl(self.paths, OTHER_INSTANCE).request_stop(os.getpid())
        polled.clear()
        self.assertTrue(polled.wait(2))
        self.assertTrue(thread.is_alive())
        self.assertFalse(server.control_stop_requested)
        self.assertTrue(api.stop_api(self.paths))
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)

    def test_real_child_start_stop_in_path_with_spaces_without_linux_identity(self):
        # A loopback-only fixture imports the production server. It performs no
        # HTTP request, opens no database and runs no reconnaissance stage.
        script = self._fixture_script()
        children = []

        def spawn(command, **kwargs):
            self.assertEqual(command[:4], [sys.executable, str(script), "api", "foreground"])
            child = REAL_POPEN(command, **kwargs)
            children.append(child)
            return child

        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)

        self.addCleanup(cleanup)
        with patch.object(api.subprocess, "Popen", side_effect=spawn), \
             patch.object(api, "_process_start_token", return_value=""), \
             patch.object(api.os, "pidfd_open", None, create=True), \
             patch.object(api.signal, "pidfd_send_signal", None, create=True), \
             patch.object(api.os, "kill", side_effect=AssertionError("Unbound PID signal")):
            pid = api.start_api(self.paths, "127.0.0.1", 0)
            self.assertEqual(pid, children[0].pid)
            self.assertTrue(api.stop_api(self.paths))
            self.assertEqual(children[0].wait(timeout=5), 0)

    def _fixture_script(self):
        self.paths.app.mkdir()
        script = self.paths.app / "recon_monitor.py"
        script.write_text(
            "import argparse, sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(APP)!r})\n"
            "from api_server_core import serve_api\nfrom core import AppPaths\n"
            "class Logger:\n    def info(self, *args, **kwargs):\n        if args[0] == 'API started': print('ready', flush=True)\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_argument('command')\nparser.add_argument('action')\n"
            "parser.add_argument('--host')\nparser.add_argument('--port', type=int)\n"
            "parser.add_argument('--control-instance', default='')\n"
            "args = parser.parse_args()\n"
            "serve_api(AppPaths.from_root(Path(__file__).resolve().parents[1]), Logger(), args.host, args.port, control_instance=args.control_instance)\n"
        )
        return script

    @unittest.skipUnless(sys.platform == "linux" and callable(getattr(os, "pidfd_open", None)) and callable(getattr(signal, "pidfd_send_signal", None)), "Linux pidfds required")
    def test_real_legacy_linux_child_uses_pidfd_with_exact_argv_boundaries(self):
        script = self._fixture_script()
        child = REAL_POPEN([sys.executable, str(script), "api", "foreground", "--host", "127.0.0.1", "--port", "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def cleanup():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()

        self.addCleanup(cleanup)
        self.assertTrue(api.select.select([child.stdout], [], [], 5)[0], "Fixture failed to start")
        self.assertEqual(child.stdout.readline().strip(), "ready")
        if not api._process_start_token(child.pid):
            self.skipTest("Fixture PID is not exposed through /proc in this execution environment")
        self.paths.state.joinpath("api.pid").write_text(str(child.pid) + "\n")

        def probe(pid, sig):
            self.assertEqual(pid, child.pid)
            self.assertEqual(sig, 0, "Only the read-only liveness probe may use a numeric PID")
            return REAL_KILL(pid, sig)

        def spawn_ps(command, **kwargs):
            self.assertEqual(command, ["ps", "-p", str(child.pid), "-o", "command="])
            return REAL_POPEN(command, **kwargs)

        with patch.object(api.subprocess, "Popen", side_effect=spawn_ps), \
             patch.object(api.os, "kill", side_effect=probe), \
             patch.object(api.signal, "pidfd_send_signal", wraps=signal.pidfd_send_signal) as send:
            self.assertTrue(api.stop_api(self.paths))
        self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        self.assertEqual(send.call_count, 1)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core as runtime
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy, query_host_records_fallback
from reporting import _stage_metrics
from stages import StageContext, stage_dns


class DNSCollectionQualityTests(unittest.TestCase):
    TARGET = "example.test"
    RECORDS = {
        ("A", "192.0.2.10"),
        ("AAAA", "2001:db8::10"),
        ("CNAME", "edge.example.test"),
        ("NS", "ns.example.test"),
    }
    FLAGS = {"-a": "A", "-aaaa": "AAAA", "-cname": "CNAME", "-ns": "NS"}

    def setUp(self) -> None:
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = runtime.Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = TargetPolicy.from_dict({
            "name": self.TARGET, "roots": [self.TARGET],
            "analysis": {"asset_graph": False},
            "limits": {"timeout_seconds": 1800},
        })
        self.current = Path(self.temp.name) / "current"
        self.changes = Path(self.temp.name) / "changes"
        self.current.mkdir()
        self.changes.mkdir()
        self.tool_calls = []

    def _seed(self, db=None, run_id="previous-run") -> None:
        db = db or self.db
        db.upsert_asset(self.TARGET, self.TARGET, ["root"], run_id)
        for rrtype, value in self.RECORDS:
            db.upsert_dns(self.TARGET, self.TARGET, rrtype, value, run_id)

    def _current_records(self, db=None) -> set[tuple[str, str]]:
        db = db or self.db
        return {(row["rrtype"], row["value"]) for row in db.all(
            "SELECT rrtype,value FROM dns_records WHERE target=? AND is_current=1",
            (self.TARGET,),
        )}

    def _tool(self, outcomes=None, *, wildcard_exit=0, missing_output=None):
        outcomes = outcomes or {}

        def run(args, **kwargs):
            self.tool_calls.append((args, kwargs))
            rrtype = next((value for flag, value in self.FLAGS.items() if flag in args), None)
            code, timed_out, values = outcomes.get(rrtype, (0, False, []))
            if rrtype is None:
                code, timed_out = wildcard_exit, wildcard_exit == 124
                output = Path(args[args.index("-l") + 1]).read_text()
            else:
                output = "" if not values else json.dumps({
                    "host": self.TARGET, rrtype.lower(): values,
                }) + "\n"
            if rrtype != missing_output or rrtype is None:
                Path(kwargs["output_path"]).write_text(output, encoding="utf-8")
            return SimpleNamespace(
                returncode=code, timed_out=timed_out, operator_next=False,
                duration=0.25, lines=len(output.splitlines()),
            )

        return run

    def _context(self, runner):
        return StageContext(
            paths=self.paths, config=Config(self.paths), policy=self.policy,
            db=self.db, runner=SimpleNamespace(run=runner), run_id="current-run",
            logger=MagicMock(), progress=MagicMock(), run_dir=Path(self.temp.name),
            allow_active=False,
        )

    def _dnsx_stage(self, **kwargs):
        with patch("stages.tool_path", return_value="dnsx"):
            return stage_dns(self._context(self._tool(**kwargs)))

    def test_explicit_empty_rrtypes_preserve_previous_records(self) -> None:
        for rrtypes in ([], set(), iter(())):
            with self.subTest(rrtypes=type(rrtypes).__name__):
                self._seed()
                self.db.finalize_dns_current(self.TARGET, "current-run", rrtypes)
                self.assertEqual(self._current_records(), self.RECORDS)

    def test_only_successful_rrtypes_are_retired(self) -> None:
        self._seed()
        self.db.upsert_dns(self.TARGET, self.TARGET, "A", "192.0.2.20", "current-run")
        self.db.upsert_dns("other.test", "other.test", "A", "192.0.2.30", "previous-run")
        self.db.finalize_dns_current(self.TARGET, "current-run", iter(["a", "A"]))
        self.assertEqual(self._current_records(), (self.RECORDS - {("A", "192.0.2.10")}) | {("A", "192.0.2.20")})
        self.assertEqual(self.db.one("SELECT is_current FROM dns_records WHERE target='other.test'")[0], 1)

    def test_omitted_rrtypes_still_finalize_all_types(self) -> None:
        self._seed()
        self.db.upsert_dns(self.TARGET, self.TARGET, "A", "192.0.2.20", "current-run")
        self.db.finalize_dns_current(self.TARGET, "current-run")
        self.assertEqual(self._current_records(), {("A", "192.0.2.20")})

    def test_all_queries_timeout_preserves_records_and_reports_partial(self) -> None:
        self._seed()
        metrics = self._dnsx_stage(outcomes={rrtype: (124, True, []) for rrtype, _ in self.RECORDS})
        self.assertEqual(self._current_records(), self.RECORDS)
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(metrics["successful_rrtypes"], [])
        self.assertEqual(metrics["failed_rrtypes"], ["A", "AAAA", "CNAME", "NS"])
        self.assertEqual(metrics["removed_records"], 0)
        self.assertEqual((self.changes / "dns-changes.tsv").read_text(), "")
        self.assertEqual(len(metrics["dns_query_outcomes"]), 4)
        for outcome in metrics["dns_query_outcomes"]:
            self.assertEqual(outcome["stop_reason"], "timeout")
            self.assertEqual(outcome["exit_code"], 124)
            self.assertTrue(outcome["timed_out"])
            self.assertEqual(outcome["input_hosts"], 1)
            self.assertEqual(outcome["duration_seconds"], 0.25)
        self.assertTrue(all(kwargs["timeout"] == 1800 for _, kwargs in self.tool_calls))

    def test_mixed_results_retire_only_completed_types(self) -> None:
        self._seed()
        metrics = self._dnsx_stage(outcomes={
            "A": (0, False, ["192.0.2.20"]),
            "AAAA": (124, True, []),
            "CNAME": (1, False, []),
        })
        self.assertEqual(self._current_records(), {
            ("A", "192.0.2.20"), ("AAAA", "2001:db8::10"), ("CNAME", "edge.example.test"),
        })
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(metrics["successful_rrtypes"], ["A", "NS"])
        self.assertEqual(metrics["failed_rrtypes"], ["AAAA", "CNAME"])
        self.assertEqual(metrics["new_records"], 1)
        self.assertEqual(metrics["removed_records"], 2)
        changes = (self.changes / "dns-changes.tsv").read_text()
        self.assertNotIn("AAAA", changes)
        self.assertNotIn("CNAME", changes)

    def test_successful_empty_answers_can_retire_previous_records(self) -> None:
        self._seed()
        metrics = self._dnsx_stage()
        self.assertEqual(self._current_records(), set())
        self.assertEqual(metrics["collection_status"], "completed")
        self.assertEqual(metrics["successful_rrtypes"], ["A", "AAAA", "CNAME", "NS"])
        self.assertEqual(metrics["failed_rrtypes"], [])
        self.assertEqual(metrics["removed_records"], 4)

    def test_timeout_flag_overrides_zero_exit_code(self) -> None:
        self._seed()
        metrics = self._dnsx_stage(outcomes={"A": (0, True, ["192.0.2.20"])})
        self.assertEqual(self._current_records(), {("A", "192.0.2.10")})
        self.assertNotIn("A", metrics["successful_rrtypes"])
        self.assertEqual(metrics["collection_status"], "partial")

    def test_missing_output_is_not_an_empty_successful_answer(self) -> None:
        self._seed()
        metrics = self._dnsx_stage(missing_output="A")
        self.assertEqual(self._current_records(), {("A", "192.0.2.10")})
        self.assertEqual(metrics["dns_query_outcomes"][0]["stop_reason"], "output_missing")
        self.assertEqual(metrics["collection_status"], "partial")

    def test_wildcard_timeout_keeps_classification_and_reports_partial(self) -> None:
        self._seed()
        self.db.execute("UPDATE assets SET wildcard=1 WHERE target=?", (self.TARGET,))
        metrics = self._dnsx_stage(wildcard_exit=124)
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertFalse(metrics["wildcard_classification_complete"])
        self.assertEqual(self.db.one("SELECT wildcard FROM assets WHERE target=?", (self.TARGET,))[0], 1)
        self.assertEqual(metrics["dns_wildcard_outcomes"][0]["stop_reason"], "timeout")

    def test_transient_system_dns_failure_is_not_a_negative_answer(self) -> None:
        with patch("core.socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_AGAIN, "temporary failure")):
            with self.assertRaises(socket.gaierror):
                query_host_records_fallback(self.TARGET)

    def test_system_dns_nonexistent_host_is_a_valid_empty_answer(self) -> None:
        with patch("core.socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_NONAME, "not found")):
            self.assertEqual(query_host_records_fallback(self.TARGET), {"A": set(), "AAAA": set()})

    def test_system_dns_failure_preserves_records_even_when_other_hosts_resolve(self) -> None:
        self._seed()
        (self.current / "subdomains.txt").write_text("example.test\napi.example.test\n")

        def resolve(host):
            if host == self.TARGET:
                raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")
            return {"A": {"192.0.2.20"}, "AAAA": set()}

        with patch("stages.tool_path", return_value=None), patch("stages.query_host_records_fallback", side_effect=resolve):
            metrics = stage_dns(self._context(None))
        self.assertEqual(self._current_records(), self.RECORDS | {("A", "192.0.2.20")})
        self.assertEqual(metrics["collection_status"], "partial")
        self.assertEqual(metrics["successful_rrtypes"], [])
        self.assertEqual(metrics["failed_rrtypes"], ["A", "AAAA"])
        self.assertEqual(metrics["removed_records"], 0)
        self.assertEqual(metrics["dns_fallback_failures"][0]["host"], self.TARGET)

    def test_successful_system_dns_empty_answers_retire_only_address_types(self) -> None:
        self._seed()
        with patch("stages.tool_path", return_value=None), patch("stages.query_host_records_fallback", return_value={"A": set(), "AAAA": set()}):
            metrics = stage_dns(self._context(None))
        self.assertEqual(self._current_records(), {record for record in self.RECORDS if record[0] in {"CNAME", "NS"}})
        self.assertEqual(metrics["collection_status"], "completed")
        self.assertEqual(metrics["successful_rrtypes"], ["A", "AAAA"])

    def test_timeout_is_partial_through_run_report_and_baseline_persistence(self) -> None:
        for with_baseline in (False, True):
            with self.subTest(with_baseline=with_baseline), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                paths = AppPaths.from_root(Path(tmp))
                paths.ensure()
                paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
                db = runtime.Database(paths.db)
                stack.callback(db.close)
                seed_run = None
                if with_baseline:
                    seed_run = db.create_run(None, 1, "offline-seed")
                    db.create_run_target(seed_run, self.policy, paths.output / "seed", True)
                    self._seed(db, seed_run)
                    db.finish_run_target(seed_run, self.TARGET, "success")
                    db.execute("UPDATE runs SET status='success' WHERE id=?", (seed_run,))
                    self.assertTrue(db.successful_snapshot_status(self.TARGET)["exists"])
                orchestrator = runtime.Orchestrator(paths, Config(paths), Logger(paths), db, progress=False, allow_active=False)
                stack.enter_context(patch.object(orchestrator, "_record_versions"))
                stack.enter_context(patch.object(orchestrator, "install_signal_handlers"))
                stack.enter_context(patch("stages.tool_path", return_value="dnsx"))
                captured = {}
                calls = []

                def offline_stage(ctx):
                    calls.append(ctx.db.one("SELECT current_stage FROM run_targets WHERE run_id=?", (ctx.run_id,))[0])
                    return {"collection_status": "completed"}

                def offline_report(ctx, _baseline):
                    captured.update(_stage_metrics(ctx))
                    return {"analysis": {"analysis_id": "offline"}, "finding_notifications": {"status": "success"}}

                real_dns = runtime.STAGE_FUNCTIONS["dns"]
                stages = {name: offline_stage for name in runtime.STAGE_FUNCTIONS}
                stages["dns"] = real_dns
                stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
                stack.enter_context(patch("recon_monitor_core.stage_report", side_effect=offline_report))
                stack.enter_context(patch.object(orchestrator.runner, "run", side_effect=self._tool(outcomes={rrtype: (124, True, []) for rrtype, _ in self.RECORDS})))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                code = orchestrator.run(PolicySet({}, [self.policy], paths.policy))
                run_id = orchestrator.current_run_id
                self.assertEqual(code, 2)
                self.assertIn("urls", calls)
                self.assertEqual(db.stage_status(run_id, self.TARGET, "dns"), "partial")
                self.assertEqual(db.one("SELECT status FROM runs WHERE id=?", (run_id,))[0], "partial")
                self.assertEqual(db.one("SELECT status FROM run_targets WHERE run_id=?", (run_id,))[0], "partial")
                lifecycle = db.one("SELECT * FROM target_run_lifecycle WHERE run_id=?", (run_id,))
                self.assertEqual(lifecycle["collection_status"], "partial")
                self.assertFalse(lifecycle["baseline_eligible"])
                self.assertEqual(captured["dns"]["status"], "partial")
                self.assertEqual(captured["dns"]["metrics"]["failed_rrtypes"], ["A", "AAAA", "CNAME", "NS"])
                snapshot = db.successful_snapshot_status(self.TARGET)
                self.assertEqual(snapshot["exists"], with_baseline)
                if with_baseline:
                    self.assertEqual(snapshot["run_id"], seed_run)
                    self.assertEqual(self._current_records(db), self.RECORDS)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import stages
from core import (
    APP_VERSION,
    AppPaths,
    CommandRunner,
    Config,
    Logger,
    Progress,
    TargetPolicy,
    read_jsonl,
    utc_now,
)
from stable_confirmation import (
    _observe_pending_dns,
    _observe_pending_fingerprints,
)
from successful_snapshot import SuccessfulSnapshotDatabase
from stages import StageContext


class StableChangeConfirmationTests(unittest.TestCase):
    TARGET = "example.test"
    URL = "https://example.test/"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n'
            'ALERT_MIN_SCORE="0"\n'
            'ALERT_COOLDOWN_HOURS="0"\n',
            encoding="utf-8",
        )
        self.config = Config(self.paths)
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.logger = Logger(self.paths, verbose=False)
        self.policy = TargetPolicy.from_dict(
            {
                "name": self.TARGET,
                "roots": [self.TARGET],
                "analysis": {
                    "stable_confirmations": 2,
                    "track_confirmation_state": True,
                    "semantic_change_classification": True,
                    "explainable_risk": True,
                },
                "alert": {
                    "confirmed_only": True,
                    "minimum_score": 0,
                    "cooldown_hours": 0,
                },
            }
        )

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _insert_run(self, run_id: str) -> None:
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,1)",
            (run_id, APP_VERSION, "running", utc_now(), self.TARGET),
        )

    def _start(self, run_id: str, *, baseline: bool = False) -> StageContext:
        self._insert_run(run_id)
        run_dir = self.paths.output / self.TARGET / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        self.db.create_run_target(run_id, self.policy, run_dir, baseline)
        (run_dir / "current").mkdir(parents=True, exist_ok=True)
        (run_dir / "changes").mkdir(parents=True, exist_ok=True)
        return StageContext(
            self.paths,
            self.config,
            self.policy,
            self.db,
            self.logger,
            CommandRunner(self.logger, self.db),
            Progress(False),
            run_id,
            run_dir,
            False,
            None,
            None,
        )

    @staticmethod
    def _fingerprint_record(title: str) -> dict[str, object]:
        return {
            "status_code": 200,
            "title": title,
            "webserver": "test",
            "technologies": [],
            "content_type": "text/html",
            "content_length": 1,
            "body_hash": title.lower(),
            "final_url": StableChangeConfirmationTests.URL,
        }

    def _seed_fingerprint_baseline(self) -> None:
        self._start("RUN-SEED", baseline=True)
        self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("A"),
            "hash-a",
            "RUN-SEED",
        )
        self.db.finish_run_target("RUN-SEED", self.TARGET, "success")

    def test_a_to_b_to_b_confirms_same_fingerprint_state(self) -> None:
        self._seed_fingerprint_baseline()

        first = self._start("RUN-B-1")
        _is_new, changed, old = self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("B"),
            "hash-b",
            "RUN-B-1",
        )
        self.assertTrue(changed)
        stages.emit_event(
            first,
            "fingerprint_change",
            self.URL,
            "HTTP fingerprint changed",
            {"old": old or {}, "new": self._fingerprint_record("B")},
        )
        first_events = list(read_jsonl(first.events_path))
        self.assertEqual(len(first_events), 1)
        self.assertEqual(first_events[0]["confirmation_state"], "observed")
        self.assertEqual(first_events[0]["observation_count"], 1)
        first_key = first_events[0]["dedup_key"]
        self.db.finish_run_target("RUN-B-1", self.TARGET, "success")

        committed = self.db.one(
            "SELECT state_version,occurrences,confirmation_state FROM stable_change_state "
            "WHERE target=? AND subject_key=?",
            (self.TARGET, f"fingerprint:{self.URL}"),
        )
        self.assertIsNotNone(committed)
        self.assertEqual(str(committed["state_version"]), "hash-b")
        self.assertEqual(int(committed["occurrences"]), 1)
        self.assertEqual(str(committed["confirmation_state"]), "observed")

        second = self._start("RUN-B-2")
        _is_new, changed, _old = self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("B"),
            "hash-b",
            "RUN-B-2",
        )
        self.assertFalse(changed)
        _observe_pending_fingerprints(second)
        second_events = list(read_jsonl(second.events_path))
        self.assertEqual(len(second_events), 1)
        self.assertEqual(second_events[0]["dedup_key"], first_key)
        self.assertEqual(second_events[0]["confirmation_state"], "confirmed")
        self.assertEqual(second_events[0]["observation_count"], 2)
        self.assertEqual(
            second_events[0]["details"]["confirmation_transition"],
            "observed_to_confirmed",
        )

    def test_b_to_c_resets_confirmation_and_uses_new_event_identity(self) -> None:
        self._seed_fingerprint_baseline()

        first = self._start("RUN-B")
        _new, _changed, old = self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("B"),
            "hash-b",
            "RUN-B",
        )
        stages.emit_event(
            first,
            "fingerprint_change",
            self.URL,
            "HTTP fingerprint changed",
            {"old": old or {}, "new": self._fingerprint_record("B")},
        )
        key_b = list(read_jsonl(first.events_path))[0]["dedup_key"]
        self.db.finish_run_target("RUN-B", self.TARGET, "success")

        second = self._start("RUN-C")
        _new, changed, old = self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("C"),
            "hash-c",
            "RUN-C",
        )
        self.assertTrue(changed)
        stages.emit_event(
            second,
            "fingerprint_change",
            self.URL,
            "HTTP fingerprint changed",
            {"old": old or {}, "new": self._fingerprint_record("C")},
        )
        event_c = list(read_jsonl(second.events_path))[0]
        self.assertNotEqual(event_c["dedup_key"], key_b)
        self.assertEqual(event_c["confirmation_state"], "observed")
        self.assertEqual(event_c["observation_count"], 1)
        provisional = self.db.one(
            "SELECT state_version,occurrences,confirmation_state FROM stable_change_run_state "
            "WHERE run_id=? AND target=? AND subject_key=?",
            ("RUN-C", self.TARGET, f"fingerprint:{self.URL}"),
        )
        self.assertEqual(str(provisional["state_version"]), "hash-c")
        self.assertEqual(int(provisional["occurrences"]), 1)
        self.assertEqual(str(provisional["confirmation_state"]), "observed")

    def test_failed_second_observation_does_not_advance_committed_count(self) -> None:
        self._seed_fingerprint_baseline()

        first = self._start("RUN-B-1")
        _new, _changed, old = self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("B"),
            "hash-b",
            "RUN-B-1",
        )
        stages.emit_event(
            first,
            "fingerprint_change",
            self.URL,
            "HTTP fingerprint changed",
            {"old": old or {}, "new": self._fingerprint_record("B")},
        )
        self.db.finish_run_target("RUN-B-1", self.TARGET, "success")

        failed = self._start("RUN-B-FAILED")
        self.db.upsert_fingerprint(
            self.TARGET,
            self.URL,
            self._fingerprint_record("B"),
            "hash-b",
            "RUN-B-FAILED",
        )
        _observe_pending_fingerprints(failed)
        provisional = self.db.one(
            "SELECT occurrences,confirmation_state FROM stable_change_run_state "
            "WHERE run_id=? AND target=? AND subject_key=?",
            ("RUN-B-FAILED", self.TARGET, f"fingerprint:{self.URL}"),
        )
        self.assertEqual(int(provisional["occurrences"]), 2)
        self.assertEqual(str(provisional["confirmation_state"]), "confirmed")
        self.db.finish_run_target("RUN-B-FAILED", self.TARGET, "failed")

        committed = self.db.one(
            "SELECT occurrences,confirmation_state FROM stable_change_state "
            "WHERE target=? AND subject_key=?",
            (self.TARGET, f"fingerprint:{self.URL}"),
        )
        self.assertEqual(int(committed["occurrences"]), 1)
        self.assertEqual(str(committed["confirmation_state"]), "observed")
        self.assertIsNone(
            self.db.one(
                "SELECT 1 FROM stable_change_run_state WHERE run_id=? AND target=?",
                ("RUN-B-FAILED", self.TARGET),
            )
        )

    def test_dns_rrset_is_confirmed_by_same_state_not_next_change(self) -> None:
        host = "api.example.test"
        seed = self._start("RUN-DNS-SEED", baseline=True)
        self.db.upsert_dns(self.TARGET, host, "A", "192.0.2.10", seed.run_id)
        self.db.finalize_dns_current(self.TARGET, seed.run_id, ["A"])
        self.db.finish_run_target(seed.run_id, self.TARGET, "success")

        first = self._start("RUN-DNS-B")
        self.db.upsert_dns(self.TARGET, host, "A", "192.0.2.20", first.run_id)
        self.db.finalize_dns_current(self.TARGET, first.run_id, ["A"])
        stages.emit_event(
            first,
            "dns_change",
            f"{host} A 192.0.2.20",
            "New DNS record",
            {
                "action": "added",
                "host": host,
                "rrtype": "A",
                "value": "192.0.2.20",
            },
        )
        first_event = list(read_jsonl(first.events_path))[0]
        self.assertEqual(first_event["confirmation_state"], "observed")
        self.db.finish_run_target(first.run_id, self.TARGET, "success")

        second = self._start("RUN-DNS-B-2")
        self.db.upsert_dns(self.TARGET, host, "A", "192.0.2.20", second.run_id)
        self.db.finalize_dns_current(self.TARGET, second.run_id, ["A"])
        (second.current / "dns-filtered-hosts.txt").write_text(
            host + "\n", encoding="utf-8"
        )
        _observe_pending_dns(second, {"successful_rrtypes": ["A"]})
        second_events = list(read_jsonl(second.events_path))
        self.assertEqual(len(second_events), 1)
        self.assertEqual(second_events[0]["dedup_key"], first_event["dedup_key"])
        self.assertEqual(second_events[0]["confirmation_state"], "confirmed")
        self.assertEqual(second_events[0]["observation_count"], 2)

    def test_runtime_stage_hooks_are_installed(self) -> None:
        self.assertTrue(getattr(stages, "_STABLE_CONFIRMATION_INSTALLED", False))
        self.assertIs(stages.emit_event.__module__, sys.modules["stable_confirmation"])


if __name__ == "__main__":
    unittest.main()

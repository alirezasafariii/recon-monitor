from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import test_baseline_raw_analysis_v960 as baseline_fixture
from analysis_engine import replay_analysis, run_analysis
from analysis_input_snapshot import analysis_inputs
from core import json_dumps, utc_now


class AnalysisEntityTagInputTests(unittest.TestCase):
    TARGET = "example.test"
    RUN = "RUN-BASELINE"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp, self.paths, self.db, _ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.db.close)

    def _tags(self, table="entity_tags"):
        return {
            (str(row["target"]), str(row["entity_type"]), str(row["entity_value"]), str(row["tag"]))
            for row in self.db.all(f"SELECT * FROM {table}")
        }

    def _snapshot(self, scope):
        return dict(self.db.one(
            "SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope=?",
            (self.RUN, scope),
        ))

    def _versions(self, scope):
        return [dict(row) for row in self.db.all(
            "SELECT * FROM analysis_input_snapshot_versions WHERE run_id=? AND scope=? ORDER BY revision",
            (self.RUN, scope),
        )]

    def _legacy_snapshot(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        # Model an existing v2 snapshot captured before output tags were excluded.
        payload = json.loads(self._snapshot(self.TARGET)["payload_json"])
        payload["entity_tags"] = [dict(row) for row in self.db.all("SELECT * FROM main.entity_tags")]
        serialized = json_dumps(payload)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        for table in ("analysis_input_snapshots", "analysis_input_snapshot_versions"):
            self.db.execute(
                f"UPDATE {table} SET payload_json=?,integrity_hash=? WHERE run_id=? AND scope=? AND revision=1",
                (serialized, digest, self.RUN, self.TARGET),
            )
        return self._versions(self.TARGET)[0]

    def _raw_finding(self):
        now = utc_now()
        self.db.execute(
            "INSERT INTO findings(target,dedup_key,template_id,name,severity,matched_at,details_json,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                self.TARGET, "missing-security-header", "missing-security-header",
                "Required browser security header missing", "medium", "https://example.test/",
                json_dumps({
                    "browser_security_header_surface": True,
                    "required_security_header_missing_or_invalid_observed": True,
                    "status_code": 200,
                }),
                now, now, self.RUN,
            ),
        )

    def test_real_automatic_analysis_reuses_inputs_despite_new_classification_tags(self):
        self._raw_finding()
        first = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        first_tags = self._tags("main.entity_tags")
        self.assertEqual({row[1] for row in first_tags}, {"analysis_hypothesis", "candidate"})
        self.assertEqual(first["input_snapshot"]["revision"], 1)

        for _ in range(2):
            result = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
            self.assertEqual(result["input_snapshot"], first["input_snapshot"])
        self.assertGreater(len(self._tags("main.entity_tags")), len(first_tags))
        self.assertEqual(len(self._versions(self.TARGET)), 1)
        self.assertEqual(json.loads(self._snapshot(self.TARGET)["payload_json"])["entity_tags"], [])

    def test_target_and_global_capture_keep_business_tags_and_preserve_live_outputs(self):
        for target in (self.TARGET, "other.test"):
            for entity_type in ("alert", "asset", "endpoint", "analysis_hypothesis", "candidate"):
                self.db.add_tag(target, entity_type, "fixture-entity", "payment")
        live_tags = self._tags("main.entity_tags")
        for target in (self.TARGET, None):
            with self.subTest(target=target):
                expected = {
                    row for row in live_tags
                    if row[1] in {"alert", "asset", "endpoint"}
                    and (target is None or row[0] == target)
                }
                with analysis_inputs(self.paths, self.db, self.RUN, target, refresh=True):
                    self.assertEqual(self._tags(), expected)
                payload = json.loads(self._snapshot(target or "*")["payload_json"])
                self.assertEqual(len(payload["entity_tags"]), len(expected))
                self.assertEqual(self._tags("main.entity_tags"), live_tags)

    def test_changes_to_existing_output_tags_do_not_advance_either_scope(self):
        self.db.add_tag(self.TARGET, "analysis_hypothesis", "hypothesis", "near-family:idor")
        self.db.add_tag(self.TARGET, "candidate", "candidate", "proximity:strong")
        original = {}
        for target in (self.TARGET, None):
            with analysis_inputs(self.paths, self.db, self.RUN, target) as meta:
                original[target] = meta
        self.db.remove_tag(self.TARGET, "analysis_hypothesis", "hypothesis", "near-family:idor")
        self.db.execute("UPDATE main.entity_tags SET tag='proximity:moderate' WHERE entity_type='candidate'")
        self.db.add_tag("other.test", "analysis_hypothesis", "new-hypothesis", "near-family:idor")
        for target in (self.TARGET, None):
            with self.subTest(target=target):
                with analysis_inputs(self.paths, self.db, self.RUN, target, refresh=True) as refreshed:
                    self.assertEqual(refreshed, original[target])
                self.assertEqual(len(self._versions(target or "*")), 1)

    def test_business_tag_change_advances_revision_and_old_replay_retains_context(self):
        alert_id, _is_new, _old = self.db.upsert_alert(
            self.TARGET, "entity-tag-input", "new_url", "MEDIUM", 30,
            "Development endpoint", "https://dev.example.test/status", {}, self.RUN,
        )
        first = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        self.db.add_tag(self.TARGET, "alert", str(alert_id), "payment")
        second = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        old = replay_analysis(self.paths, self.db, self.RUN, self.TARGET, revision=1)
        self.assertEqual(second["input_snapshot"]["revision"], 2)
        self.assertNotEqual(first["input_snapshot"]["integrity_hash"], second["input_snapshot"]["integrity_hash"])
        self.assertEqual(old["input_snapshot"], first["input_snapshot"])
        contexts = []
        for result in (first, second, old):
            row = self.db.one(
                "SELECT adjusted_score,business_context FROM analysis_results WHERE analysis_id=? AND alert_id=?",
                (result["analysis_id"], alert_id),
            )
            contexts.append((int(row["adjusted_score"]), str(row["business_context"])))
        self.assertEqual(contexts[0][1], "development")
        self.assertEqual(contexts[1][1], "payment")
        self.assertGreater(contexts[1][0], contexts[0][0])
        self.assertEqual(contexts[2], contexts[0])
        self.assertEqual(len(self._versions(self.TARGET)), 2)
        self.assertIn((self.TARGET, "alert", str(alert_id), "payment"), self._tags("main.entity_tags"))

    def test_refresh_cleans_legacy_outputs_once_without_rewriting_archived_payload(self):
        self.db.add_tag(self.TARGET, "analysis_hypothesis", "old-hypothesis", "near-family:idor")
        self.db.add_tag(self.TARGET, "candidate", "old-candidate", "proximity:strong")
        legacy = self._legacy_snapshot()
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as cleaned:
            self.assertEqual(cleaned["revision"], 2)
            self.assertEqual(self._tags(), set())
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as unchanged:
            self.assertEqual(unchanged, cleaned)
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True, revision=1) as replayed:
            self.assertEqual(replayed["integrity_hash"], legacy["integrity_hash"])
            self.assertEqual(self._tags(), self._tags("main.entity_tags"))
        self.assertEqual(self._versions(self.TARGET)[0], legacy)
        self.assertEqual(len(self._versions(self.TARGET)), 2)

    def test_new_combined_snapshot_excludes_outputs_from_legacy_target_snapshot(self):
        self.db.add_tag(self.TARGET, "alert", "fixture-alert", "payment")
        self.db.add_tag(self.TARGET, "analysis_hypothesis", "old-hypothesis", "near-family:idor")
        self.db.add_tag(self.TARGET, "candidate", "old-candidate", "proximity:strong")
        legacy = self._legacy_snapshot()
        # Replay must combine preserved target inputs, including their business
        # tags, rather than take changed tags from the live collection tables.
        self.db.remove_tag(self.TARGET, "alert", "fixture-alert", "payment")
        self.db.add_tag(self.TARGET, "alert", "fixture-alert", "development")
        with analysis_inputs(self.paths, self.db, self.RUN, None, replay=True):
            self.assertEqual(self._tags(), {(self.TARGET, "alert", "fixture-alert", "payment")})
        self.assertEqual(self._versions(self.TARGET)[0], legacy)
        self.assertEqual(self._snapshot(self.TARGET), legacy)
        payload = json.loads(self._snapshot("*")["payload_json"])
        self.assertEqual([row["entity_type"] for row in payload["entity_tags"]], ["alert"])


if __name__ == "__main__":
    unittest.main()

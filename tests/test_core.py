from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import (  # noqa: E402
    AppPaths,
    Config,
    Database,
    Logger,
    PolicySet,
    RunLock,
    TargetPolicy,
    explain_risk,
    extract_js_indicators,
    normalize_url,
    risk_score,
    semantic_js_normalize,
    sha256_text,
)


class CoreTests(unittest.TestCase):
    def test_normalize_url(self) -> None:
        self.assertEqual(normalize_url("HTTPS://Example.COM:443//a//#frag"), "https://example.com/a/")
        self.assertEqual(normalize_url("http://example.com:8080/a?x=1#z"), "http://example.com:8080/a?x=1")
        self.assertIsNone(normalize_url("javascript:alert(1)"))

    def test_scope(self) -> None:
        policy = TargetPolicy.from_dict(
            {
                "name": "example",
                "roots": ["example.com"],
                "include": [r"(^|\.)example\.com$"],
                "exclude": [r"(^|\.)blocked\.example\.com$"],
            }
        )
        self.assertTrue(policy.host_in_scope("api.example.com"))
        self.assertFalse(policy.host_in_scope("blocked.example.com"))
        self.assertFalse(policy.host_in_scope("example.com.evil.test"))
        self.assertTrue(policy.url_in_scope("https://api.example.com/v1"))

    def test_active_three_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\n', encoding="utf-8")
            config = Config(paths)
            policy = TargetPolicy.from_dict(
                {
                    "name": "example",
                    "roots": ["example.com"],
                    "modules": {"ports": True},
                    "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"},
                }
            )
            self.assertFalse(policy.active_allowed(config, False))
            self.assertTrue(policy.active_allowed(config, True))

    def test_semantic_js(self) -> None:
        a = "// build\nconst x = 1; //# sourceMappingURL=a.map"
        b = "const   x=1;\n//# sourceMappingURL=b.map"
        self.assertEqual(sha256_text(semantic_js_normalize(a)), sha256_text(semantic_js_normalize(b)))

    def test_js_redaction(self) -> None:
        text = 'const apiKey = "secret"; const u="/api/v1/admin"; query UserList { id }'
        findings = extract_js_indicators(text)
        self.assertIn(("endpoint", "/api/v1/admin", False), findings)
        self.assertTrue(any(kind == "sensitive_marker" and redacted for kind, _, redacted in findings))
        self.assertIn(("graphql_operation", "UserList", False), findings)

    def test_risk(self) -> None:
        score, severity = risk_score("new_subdomain", "admin.example.com")
        self.assertGreaterEqual(score, 45)
        self.assertIn(severity, {"MEDIUM", "HIGH", "CRITICAL"})

    def test_explainable_risk(self) -> None:
        score, severity, reasons, change_class = explain_risk(
            "new_url",
            "https://api.example.com/admin/export",
            {"sources": ["wayback", "katana"], "status_code": 200},
        )
        self.assertGreaterEqual(score, 50)
        self.assertTrue(reasons)
        self.assertIn(change_class, {"api", "authentication", "asset"})
        self.assertIn(severity, {"MEDIUM", "HIGH", "CRITICAL"})

    def test_asset_graph_and_observation_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "state.db")
            try:
                db.upsert_edge("t", "root", "example.com", "contains", "host", "api.example.com", "r1")
                edge = db.one("SELECT relation FROM asset_edges WHERE target='t'")
                self.assertEqual(edge["relation"], "contains")
                count, state = db.observe_event(
                    "t", "key", "fingerprint_change", "https://example.com/", "application", "r1", confirmations=2
                )
                self.assertEqual((count, state), (1, "observed"))
                count, state = db.observe_event(
                    "t", "key", "fingerprint_change", "https://example.com/", "application", "r2", confirmations=2
                )
                self.assertEqual((count, state), (2, "confirmed"))
            finally:
                db.close()

    def test_database_alert_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "state.db")
            try:
                alert_id, is_new, _ = db.upsert_alert("t", "k", "new_url", "LOW", 20, "x", "item", {}, "run")
                self.assertTrue(is_new)
                alert_id2, is_new2, old = db.upsert_alert("t", "k", "new_url", "MEDIUM", 45, "x2", "item", {}, "run2")
                self.assertFalse(is_new2)
                self.assertEqual(alert_id, alert_id2)
                row = db.one("SELECT occurrences,risk_score,title FROM alerts WHERE id=?", (alert_id,))
                self.assertEqual(row["occurrences"], 2)
                self.assertEqual(row["risk_score"], 45)
                self.assertEqual(row["title"], "x2")
            finally:
                db.close()

    def test_policy_load(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            payload = {"schema": 1, "targets": [{"name": "x", "roots": ["example.com"]}]}
            paths.policy.write_text(json.dumps(payload), encoding="utf-8")
            policies = PolicySet.load(paths)
            self.assertEqual(policies.targets[0].name, "x")


    def test_fingerprint_extended_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "state.db")
            try:
                record = {
                    "status_code": 200, "title": "ok", "webserver": "srv", "technologies": ["x"],
                    "content_type": "text/html", "content_length": 10, "body_hash": "b",
                    "favicon_hash": "f", "jarm": "j", "ip": "192.0.2.1", "cname": "c",
                    "cdn": "cdn", "final_url": "https://example.com/", "redirect_chain": [],
                    "http2": True, "tls_issuer": "issuer", "tls_expiry": "expiry",
                    "tls_sans": ["example.com"], "tls_serial": "serial",
                    "screenshot_path": None, "screenshot_hash": "shot",
                }
                is_new, changed, _ = db.upsert_fingerprint("t", "https://example.com/", record, "h", "run")
                self.assertTrue(is_new)
                self.assertFalse(changed)
                row = db.one("SELECT tls_issuer,screenshot_hash FROM fingerprints")
                self.assertEqual(row["tls_issuer"], "issuer")
                self.assertEqual(row["screenshot_hash"], "shot")
            finally:
                db.close()

    def test_database_heartbeat_from_worker_thread(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "state.db")
            errors: list[BaseException] = []
            try:
                policy = TargetPolicy.from_dict({"name": "example", "roots": ["example.com"]})
                db.execute(
                    "INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,?,?,?)",
                    ("run", "test", "running", "2026-01-01T00:00:00Z", 1),
                )
                db.create_run_target("run", policy, Path(temp) / "run", False)
                db.stage_begin("run", "example", "subdomains", 1)

                def worker() -> None:
                    try:
                        db.stage_heartbeat("run", "example", "subdomains")
                    except BaseException as exc:  # pragma: no cover - asserted below
                        errors.append(exc)

                thread = threading.Thread(target=worker)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                row = db.one(
                    "SELECT heartbeat_at FROM stage_runs WHERE run_id=? AND target=? AND stage=?",
                    ("run", "example", "subdomains"),
                )
                self.assertIsNotNone(row)
                self.assertTrue(row["heartbeat_at"])
            finally:
                db.close()

    def test_database_meta(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp) / "state.db")
            try:
                db.meta_set("x", "y")
                self.assertEqual(db.meta_get("x"), "y")
            finally:
                db.close()

    def test_stale_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.from_root(Path(temp))
            paths.ensure()
            logger = Logger(paths, verbose=False)
            paths.lock.write_text(json.dumps({"pid": 99999999}), encoding="utf-8")
            with RunLock(paths.lock, logger):
                self.assertTrue(paths.lock.exists())
            self.assertFalse(paths.lock.exists())


if __name__ == "__main__":
    unittest.main()

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database, utc_now
from dashboard import DashboardHandler, _candidate_card, _diff_html, _layout, _suggested_action


class DashboardV31Tests(unittest.TestCase):
    def test_layout_has_analyst_console_navigation_and_theme(self):
        page = _layout("Test", "<p>body</p>", username="analyst", role="analyst", current_path="/workbench")
        self.assertIn("Decision Console", page)
        self.assertIn("nav-item active", page)
        self.assertIn("Review queue", page)
        self.assertIn("themeToggle", page)
        self.assertIn("globalSearch", page)
        self.assertNotIn("https://", page)

    def test_diff_renderer_marks_semantic_lines(self):
        rendered = _diff_html("@@ block @@\n-old\n+new\n context")
        self.assertIn("diff-hunk", rendered)
        self.assertIn("diff-del", rendered)
        self.assertIn("diff-add", rendered)
        self.assertNotIn("<script", rendered)

    def test_suggested_action_is_status_aware(self):
        title, detail = _suggested_action({"status": "new", "risk_score": 90})
        self.assertEqual(title, "Triage evidence")
        self.assertIn("scope", detail)
        title, _ = _suggested_action({"status": "investigating", "risk_score": 70})
        self.assertEqual(title, "Record reproducible evidence")

    def test_workbench_renders_priority_queue(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td))
            db = Database(paths.db)
            now = utc_now()
            try:
                db.execute("""INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id,priority,assignee,workflow_note)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           ("example.com","a1","endpoint","HIGH",88,"New admin endpoint","/api/admin","{}","new",1,now,now,"r1","urgent","",""))
                db.execute("""INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                           ("example.com","/api/admin","path","admin",93,"[]","[]","[]",now,now,"r1"))
            finally:
                db.close()
            handler = object.__new__(DashboardHandler)
            handler.db_path = paths.db
            handler.path = "/workbench"
            handler.query = lambda: {}
            captured = {}
            handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.workbench()
            self.assertEqual(captured["title"], "Review queue")
            self.assertIn("New admin endpoint", captured["body"])
            self.assertIn("Supporting unresolved alerts", captured["body"])
            self.assertIn("Queue health", captured["body"])

    def test_command_center_renders_decision_inbox(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td))
            db = Database(paths.db)
            now = utc_now()
            try:
                db.execute("""INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id,priority,assignee,workflow_note)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           ("example.com","a2","endpoint","HIGH",91,"Decision inbox signal","/api/export","{}","new",1,now,now,"r1","urgent","",""))
            finally:
                db.close()
            handler = object.__new__(DashboardHandler)
            handler.db_path = paths.db
            handler.path = "/"
            handler.query = lambda: {}
            captured = {}
            handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.overview()
            self.assertEqual(captured["title"], "Command center")
            self.assertIn("Decision inbox", captured["body"])
            self.assertIn("What needs your attention?", captured["body"])
            self.assertIn("Coverage snapshot", captured["body"])

    def test_candidate_card_uses_progressive_disclosure(self):
        card = _candidate_card({
            "candidate_id":"c1", "title":"Possible object authorization issue", "target":"example.com",
            "candidate_state":"plausible", "analyst_decision":"unreviewed", "endpoint":"/api/accounts/{accountId}",
            "likelihood_score":72, "evidence_strength":64, "impact_potential":88, "observation_quality":81,
            "investigation_value":76, "supporting_evidence_json":"[{\"text\":\"Object identifier observed\"}]",
            "contradicting_evidence_json":"[]", "missing_evidence_json":"[\"Ownership boundary\"]",
            "safe_next_action":"Review the expected ownership boundary."
        })
        self.assertIn("Investigation", card)
        self.assertIn("Why it matters", card)
        self.assertIn("What is missing", card)
        self.assertIn("Review the expected ownership boundary", card)


if __name__ == "__main__":
    unittest.main()

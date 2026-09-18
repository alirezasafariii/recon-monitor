from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from dependency_advisory_matcher import (
    match_versioned_technology,
    parse_versioned_technology,
    version_matches_range,
)
from passive_evidence_extractor import extract_passive_family_evidence


class DependencyAdvisoryMatcherTests(unittest.TestCase):
    def test_exact_version_parser_is_fail_closed(self):
        parsed = parse_versioned_technology("jQuery:3.4.1")
        self.assertEqual(parsed["name"], "jquery")
        self.assertEqual(parsed["version"], "3.4.1")
        self.assertIsNone(parse_versioned_technology("jQuery"))
        self.assertIsNone(parse_versioned_technology("jQuery:latest"))
        self.assertIsNone(parse_versioned_technology("jQuery:3.5.0-beta.1"))

    def test_range_matching_is_deterministic(self):
        self.assertTrue(version_matches_range("3.4.1", ">=1.2,<3.5.0"))
        self.assertFalse(version_matches_range("3.5.0", ">=1.2,<3.5.0"))
        self.assertTrue(version_matches_range("4.17.23", ">=4.0.0,<=4.17.23"))
        self.assertFalse(version_matches_range("4.18.0", ">=4.0.0,<=4.17.23"))
        self.assertFalse(version_matches_range("4.17.21-beta.1", "<4.18.0"))

    def test_curated_catalog_positive_matches_only(self):
        jquery = match_versioned_technology("jQuery:3.4.1")
        self.assertTrue(jquery["version_exact"])
        self.assertIn(
            "GHSA-gxr4-xjj5-5px2",
            {row["advisory_id"] for row in jquery["matches"]},
        )

        jquery_patched_for_that_advisory = match_versioned_technology("jQuery:3.5.0")
        self.assertEqual(jquery_patched_for_that_advisory["matches"], [])
        self.assertFalse(jquery_patched_for_that_advisory["catalog_is_exhaustive"])
        self.assertFalse(jquery_patched_for_that_advisory["absence_of_match_means_safe"])

        bootstrap = match_versioned_technology("Bootstrap:4.3.0")
        self.assertIn(
            "GHSA-9v3m-8fp8-mj99",
            {row["advisory_id"] for row in bootstrap["matches"]},
        )

        lodash_current_advisory = match_versioned_technology("Lodash:4.17.23")
        self.assertIn(
            "GHSA-r5fr-rjxr-66jc",
            {row["advisory_id"] for row in lodash_current_advisory["matches"]},
        )
        self.assertEqual(
            match_versioned_technology("Lodash:4.18.0")["matches"],
            [],
        )

    def test_passive_extractor_preserves_advisory_provenance(self):
        vulnerable = extract_passive_family_evidence(
            endpoint="https://example.test/",
            target="example.test",
            details={"technologies": ["jQuery:3.4.1", "React"]},
        )
        self.assertTrue(
            vulnerable["known_vulnerable_component_match_observed"]
        )
        matches = vulnerable["dependency_advisory_matches"]
        self.assertEqual(matches[0]["product"], "jquery")
        self.assertEqual(matches[0]["version"], "3.4.1")
        self.assertTrue(matches[0]["matched_range"])
        self.assertTrue(matches[0]["source_url"].startswith("https://"))
        self.assertEqual(
            vulnerable["_passive_evidence_extractor"][
                "dependency_advisory_match_count"
            ],
            1,
        )

        unknown_version = extract_passive_family_evidence(
            endpoint="https://example.test/",
            target="example.test",
            details={"technologies": ["jQuery"]},
        )
        self.assertNotIn(
            "known_vulnerable_component_match_observed",
            unknown_version,
        )

        no_match = extract_passive_family_evidence(
            endpoint="https://example.test/",
            target="example.test",
            details={"technologies": ["jQuery:3.5.0"]},
        )
        self.assertNotIn(
            "known_vulnerable_component_match_observed",
            no_match,
        )
        self.assertFalse(
            no_match["_passive_evidence_extractor"][
                "absence_of_dependency_match_means_safe"
            ]
        )

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-DEP',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-DEP','example.test','policy','success','report',?,?,?,1)",
            (now, now, str(paths.output / "RUN-DEP")),
        )
        return temp, paths, db, now

    def _insert_surface(self, db, now, *, url: str, technologies: list[str]):
        db.execute(
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                url,
                "absolute_url",
                "general",
                90,
                "[]",
                "[]",
                json_dumps(["fingerprint"]),
                now,
                now,
                "RUN-DEP",
            ),
        )
        db.execute(
            "INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                url,
                "fp-" + str(abs(hash(url))),
                200,
                "App",
                "test",
                json_dumps(technologies),
                "text/html",
                2048,
                now,
                now,
                "RUN-DEP",
            ),
        )

    def test_raw_analysis_promotes_only_exact_affected_component_versions(self):
        temp, paths, db, now = self._project()
        try:
            vulnerable_url = "https://example.test/vulnerable"
            ambiguous_url = "https://example.test/ambiguous"
            unmatched_url = "https://example.test/unmatched"
            self._insert_surface(
                db,
                now,
                url=vulnerable_url,
                technologies=["jQuery:3.4.1"],
            )
            self._insert_surface(
                db,
                now,
                url=ambiguous_url,
                technologies=["jQuery"],
            )
            self._insert_surface(
                db,
                now,
                url=unmatched_url,
                technologies=["jQuery:3.5.0"],
            )

            result = run_analysis(paths, db, "RUN-DEP", "example.test")
            runtime = result["bug_candidates"]["detection_runtime"]
            self.assertIn(
                "dependency_supply_chain",
                set(runtime["potential_finding_families"]),
            )

            rows = db.all(
                "SELECT endpoint,supporting_evidence_json "
                "FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='dependency_supply_chain' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )
            self.assertEqual(
                [str(row["endpoint"]) for row in rows],
                [vulnerable_url],
            )
            evidence = json.loads(str(rows[0]["supporting_evidence_json"]))
            advisory_items = [
                item
                for item in evidence
                if item.get("type")
                == "known_vulnerable_component_match_observed"
            ]
            self.assertEqual(len(advisory_items), 1)
            self.assertIn(
                "GHSA-gxr4-xjj5-5px2",
                {
                    match.get("advisory_id")
                    for match in advisory_items[0].get("advisory_matches", [])
                },
            )
            self.assertEqual(runtime["active_requests_added"], 0)
            self.assertFalse(runtime["collector_behavior_changed"])
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected exactly one seal replacement, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.16.0"\nRULE_VERSION = "2026.08.12.6.16"',
    'ENGINE_VERSION = "6.17.0"\nRULE_VERSION = "2026.08.12.6.17"',
)
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.16.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.16"',
    'CANDIDATE_ENGINE_VERSION = "6.17.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.17"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.16.0"\nREASONING_RULE_VERSION = "2026.08.12.6.16"',
    'REASONING_ENGINE_VERSION = "6.17.0"\nREASONING_RULE_VERSION = "2026.08.12.6.17"',
)

replace_once(
    "tests/test_physical_raw_collector_injection_v6160.py",
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.16.0")\n'
    '        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.16.0")',
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)\n'
    '        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)\n'
    '        self.assertGreaterEqual(\n'
    '            tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")),\n'
    '            (6, 16, 0),\n'
    '        )',
)

seal_test = '''from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from raw_family_collectors import AUTHORIZATION_FAMILIES, AUTHORIZATION_OBSERVATIONS


class Analysis617SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_617(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.17.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.17.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.17.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.17")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.17")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.17")

    def test_run_analysis_routes_both_authorization_families_to_hypothesis_and_candidate(self) -> None:
        families = set(AUTHORIZATION_FAMILIES)
        self.assertEqual(families, {"broken_function_authorization", "mass_assignment"})

        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td))
            paths.ensure()
            db = Database(paths.db)
            try:
                now = utc_now()
                run_id = "run-617-seal"
                target = "fixture.invalid"
                db.execute(
                    "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
                    (run_id, "6.17.0", "success", now, now, target),
                )
                alerts = [
                    (
                        "Lower privilege admin execution",
                        "/api/admin/users/disable",
                        {
                            "method": "POST",
                            "body_fields": ["user_id"],
                            "status_code": 200,
                            "context_observations": [
                                {
                                    "context": "viewer",
                                    "role": "viewer",
                                    "expected_access": False,
                                    "status_code": 200,
                                }
                            ],
                        },
                    ),
                    (
                        "Privileged profile property accepted",
                        "/api/profile",
                        {
                            "method": "PATCH",
                            "body_fields": ["display_name", "role"],
                            "status_code": 200,
                            "privileged_property_accepted": True,
                        },
                    ),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(
                        target,
                        f"617:{title}",
                        "new_endpoint",
                        "HIGH",
                        90,
                        title,
                        endpoint,
                        details,
                        run_id,
                    )

                result = run_analysis(paths, db, run_id, target)
                hypothesis_rows = db.all(
                    "SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                routed = {}
                for row in hypothesis_rows:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in families and "raw-collector-authorization-v1" in rules:
                        routed[family] = row

                self.assertEqual(set(routed), families, hypothesis_rows)
                for family, expected in AUTHORIZATION_OBSERVATIONS.items():
                    row = routed[family]
                    self.assertEqual(str(row["bug_variant"]), expected.variant)
                    self.assertEqual(str(row["state"]), "promoted")

                candidate_rows = db.all(
                    "SELECT bug_family,bug_variant,rule_ids_json FROM bug_candidates WHERE analysis_id=?",
                    (result["analysis_id"],),
                )
                candidates = {}
                for row in candidate_rows:
                    family = str(row["bug_family"])
                    rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in families and "raw-collector-authorization-v1" in rules:
                        candidates[family] = row

                self.assertEqual(set(candidates), families, candidate_rows)
                for family, expected in AUTHORIZATION_OBSERVATIONS.items():
                    self.assertEqual(str(candidates[family]["bug_variant"]), expected.variant)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_617_seal.py").write_text(seal_test, encoding="utf-8")

seal_doc = '''# Analysis Engine 6.17 — Seal

Analysis 6.17 is sealed after the physical raw-collector cutover for Broken Function Level Authorization and Mass Assignment / Broken Object Property Level Authorization.

## Sealed version lineage

- Analysis engine: `6.17.0`
- Candidate engine: `6.17.0`
- Security reasoning engine: `6.17.0`
- Rule lineage: `2026.08.12.6.17`
- Authorization collector rule lineage: `2026.08.12.6.17`

The application release version remains independent from the Analysis Engine version.

## End-to-end seal contract

The seal requires both migrated authorization families to travel through the physical authorization collector into the hidden-hypothesis/admission path and, when decisive stored target evidence is present, into a promoted candidate. The resulting hypothesis and candidate must retain `raw-collector-authorization-v1` in rule lineage.

The seal also requires surface-only cases to remain non-admitted under the existing family-specific admission contract. No admission thresholds, detector conditions, ranking weights, or active-validation behavior are changed by sealing.

## Validation boundary

The seal is a regression and architecture claim, not a new accuracy claim. It is validated by the dedicated 6.17 seal test, the authorization collector contract, the full unit suite, the strict Golden analysis benchmark, and the integration runner. A new fresh raw holdout is intentionally deferred until further physical collector decomposition is complete.

## Next migration boundary

The next physical decomposition batch should target the remaining file/remote-resource raw collectors, beginning with File Upload, Path Traversal, and SSRF while preserving their existing detector-execution and admission contracts.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_17_SEAL.md").write_text(seal_doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)

for relative in (
    "docs/ANALYSIS_ENGINE_6_17_SEAL.md",
    "tests/test_analysis_617_seal.py",
):
    if relative not in paths:
        paths.append(relative)

entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

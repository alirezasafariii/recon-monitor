from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


collector = '''from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

BUSINESS_LOGIC_COLLECTOR_VERSION = "1.0.0"
BUSINESS_LOGIC_COLLECTOR_RULE_VERSION = "2026.08.12.6.21"
BUSINESS_LOGIC_FAMILIES = (
    "business_logic",
    "race_condition",
)

BUSINESS_LOGIC_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "business_logic": RawFamilyObservation(
        family="business_logic",
        variant="workflow_invariant",
        base=12,
        missing=(
            "Intended workflow and state/value invariants",
            "Server-side calculation or transition enforcement",
            "Target evidence of an accepted impossible/forbidden business state",
        ),
        rules=(
            "raw-collector-business-logic-v1",
            "candidate-business-workflow",
            "admission-business-invariant",
        ),
        summary=(
            "Stored business-workflow artifacts expose a state-changing operation; promotion requires "
            "target evidence that the intended workflow, value, calculation, or transition invariant was violated."
        ),
        impact=72,
    ),
    "race_condition": RawFamilyObservation(
        family="race_condition",
        variant="duplicate_operation",
        base=10,
        missing=(
            "Idempotency key or transaction guard",
            "Atomic state-transition behavior",
            "Evidence that concurrency created a duplicate or otherwise impossible state",
        ),
        rules=(
            "raw-collector-business-logic-v1",
            "candidate-single-use-operation",
            "admission-atomicity-failure",
        ),
        summary=(
            "Stored artifacts expose a state-changing single-use or balance operation; promotion requires "
            "observed duplicate effect, atomicity failure, concurrency invariant violation, or double-spend behavior."
        ),
        impact=80,
    ),
}


def validate_business_logic_collectors() -> list[str]:
    errors: list[str] = []
    if set(BUSINESS_LOGIC_OBSERVATIONS) != set(BUSINESS_LOGIC_FAMILIES):
        errors.append("business-logic collector profile coverage drift")
    for family in BUSINESS_LOGIC_FAMILIES:
        observation = BUSINESS_LOGIC_OBSERVATIONS.get(family)
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not spec.wstg_ids:
            errors.append(f"business detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"business detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"business detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"business detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"business detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_business_logic_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_business_logic_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.21 business-logic collector registry: " + "; ".join(errors))
    return [
        BUSINESS_LOGIC_OBSERVATIONS[family]
        for family in BUSINESS_LOGIC_FAMILIES
        if BUSINESS_LOGIC_OBSERVATIONS[family].packet_present(execution_map)
    ]
'''
(ROOT / "app" / "raw_family_collectors" / "business_logic.py").write_text(collector, encoding="utf-8")

init_path = ROOT / "app" / "raw_family_collectors" / "__init__.py"
replace_once(
    init_path,
    "from raw_family_collectors.client_side import (\n",
    '''from raw_family_collectors.business_logic import (
    BUSINESS_LOGIC_COLLECTOR_RULE_VERSION,
    BUSINESS_LOGIC_COLLECTOR_VERSION,
    BUSINESS_LOGIC_FAMILIES,
    BUSINESS_LOGIC_OBSERVATIONS,
    collect_business_logic_observations,
    validate_business_logic_collectors,
)
from raw_family_collectors.client_side import (
''',
)
replace_once(
    init_path,
    '    "CLIENT_SIDE_COLLECTOR_VERSION",\n',
    '''    "BUSINESS_LOGIC_COLLECTOR_VERSION",
    "BUSINESS_LOGIC_COLLECTOR_RULE_VERSION",
    "BUSINESS_LOGIC_FAMILIES",
    "BUSINESS_LOGIC_OBSERVATIONS",
    "collect_business_logic_observations",
    "validate_business_logic_collectors",
    "CLIENT_SIDE_COLLECTOR_VERSION",
''',
)

bug_path = ROOT / "app" / "bug_candidates.py"
replace_once(
    bug_path,
    'from raw_family_collectors import collect_api_configuration_observations, collect_authorization_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
    'from raw_family_collectors import collect_api_configuration_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
)
text = bug_path.read_text(encoding="utf-8")
bola_marker = '    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n'
if text.count(bola_marker) != 1:
    raise RuntimeError("6.21 collector insertion marker drift")
loop = '''    # Analysis 6.21 — physical business-logic/race collector ownership.
    # WSTG/OWASP/CWE/write-ups define detector criteria only; passive target
    # evidence remains owned by execution/reconstruction and family admission.
    for observation in collect_business_logic_observations(execution_map):
        emit(
            observation.family,
            observation.variant,
            observation.base,
            [],
            [],
            list(observation.missing),
            list(observation.rules),
            observation.summary,
            direct=observation.direct,
            impact=observation.impact,
        )

'''
text = text.replace(bola_marker, loop + bola_marker, 1)
start = text.find("    # Business logic and race watchlist: deliberately low-confidence without behavior evidence.\n")
end = text.find("    # Execution-only families still enter the hidden hypothesis ledger even when\n")
if start < 0 or end < 0 or end <= start:
    raise RuntimeError("6.21 business/race legacy cutover boundaries not found")
text = text[:start] + '''    # Analysis 6.21: Business Logic and Race Condition legacy alert emission was physically removed.
    # raw_family_collectors.business_logic owns emission metadata; execution/reconstruction
    # remains the sole source of target evidence, blockers, and condition signals.

''' + text[end:]
bug_path.write_text(text, encoding="utf-8")

# Tighten the write-up lineage to the exact primary advisory used by both detectors.
for relative in ("app/family_detectors/business_logic.py", "app/family_detectors/race_condition.py"):
    path = ROOT / relative
    replace_once(path, '"https://securitylab.github.com/advisories/"', '"https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/"')


test = '''from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from family_detectors import evaluate_family_detector, execute_detector_intelligence, get_detector_spec
from hypothesis_admission import assess_admission
from raw_family_collectors import BUSINESS_LOGIC_FAMILIES, BUSINESS_LOGIC_OBSERVATIONS, collect_business_logic_observations, validate_business_logic_collectors


class PhysicalRawCollectorBusinessLogic6210Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(BUSINESS_LOGIC_FAMILIES), {"business_logic", "race_condition"})
        self.assertEqual(validate_business_logic_collectors(), [])
        for family in BUSINESS_LOGIC_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url == "https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/" for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_both_families(self):
        fixtures = {
            "business_logic": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={"workflow_invariant_violation": True}, category="api", business_context="commerce"),
            "race_condition": dict(target="fixture.invalid", endpoint="/api/transfer", method="POST", endpoint_schema={}, details={"duplicate_effect_observed": True}, category="api", business_context="payment"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_business_logic_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(BUSINESS_LOGIC_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "business_logic": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={}, category="api", business_context="commerce"),
            "race_condition": dict(target="fixture.invalid", endpoint="/api/transfer", method="POST", endpoint_schema={}, details={}, category="api", business_context="payment"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_collector_is_metadata_only(self):
        for family, observation in BUSINESS_LOGIC_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_business_race_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_business_logic_observations(execution_map)", source)
        self.assertIn("Analysis 6.21: Business Logic and Race Condition legacy alert emission was physically removed", source)
        self.assertNotIn("# Business logic and race watchlist: deliberately low-confidence without behavior evidence.", source)
        self.assertNotIn('emit("business_logic", "workflow_invariant"', source)
        self.assertNotIn('emit("race_condition", "duplicate_operation"', source)

    def test_run_analysis_routes_both_through_business_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-621-business"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.20.0", "success", now, now, target))
                alerts = [
                    ("Workflow invariant", "/api/checkout", {"method": "POST", "workflow_invariant_violation": True, "category": "api"}),
                    ("Duplicate transfer", "/api/transfer", {"method": "POST", "duplicate_effect_observed": True, "category": "api"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"621:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(BUSINESS_LOGIC_FAMILIES) and "raw-collector-business-logic-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(BUSINESS_LOGIC_FAMILIES), hypotheses)
                for family, expected in BUSINESS_LOGIC_OBSERVATIONS.items():
                    rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(rows, (family, routed[family]))
                    promoted = [row for row in rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted, (family, [dict(row) for row in rows]))
                    conditions = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(any(
                        {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & conditions
                        for row in promoted
                    ), (family, conditions, [dict(row) for row in promoted]))
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-business-logic-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(BUSINESS_LOGIC_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_physical_raw_collector_business_logic_v6210.py").write_text(test, encoding="utf-8")

doc = '''# Analysis Engine 6.21 — Business Logic / Race Condition raw collectors

Analysis 6.21 physically decomposes `business_logic` and `race_condition` from the alert-orchestrator monolith.

Both families remain grounded in the mandatory four-layer detector contract: OWASP WSTG, OWASP Top 10 taxonomy, MITRE CWE, and a real primary security write-up. The Branch Deploy Action GHSL-2025-038 advisory is used as the primary control-flow/TOCTOU case and its exact advisory URL is pinned in both physical detector specs.

The collector contributes emission metadata only. It does not manufacture workflow violations, duplicate effects, atomicity failures, or any other target evidence. Those signals remain owned by stored passive execution/reconstruction artifacts and are filtered through family-scoped evidence extraction and admission.

A workflow name, checkout route, transfer route, or single-use semantic is therefore only a hypothesis surface. Business Logic promotion requires an observed invariant violation. Race Condition promotion requires an observed duplicate/atomicity/concurrency effect that sequential behavior should not permit.

This phase is an architecture/regression claim and consumes no new fresh holdout.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_21_BUSINESS_LOGIC_RAW_COLLECTORS.md").write_text(doc, encoding="utf-8")

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
    "app/raw_family_collectors/business_logic.py",
    "tests/test_physical_raw_collector_business_logic_v6210.py",
    "docs/ANALYSIS_ENGINE_6_21_BUSINESS_LOGIC_RAW_COLLECTORS.md",
):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    entries.append(f"{hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

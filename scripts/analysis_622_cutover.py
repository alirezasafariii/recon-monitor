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

AUTHENTICATION_COLLECTOR_VERSION = "1.0.0"
AUTHENTICATION_COLLECTOR_RULE_VERSION = "2026.08.12.6.22"
AUTHENTICATION_FAMILIES = (
    "authentication_session",
    "account_enumeration",
)

AUTHENTICATION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "authentication_session": RawFamilyObservation(
        family="authentication_session",
        variant="auth_lifecycle",
        base=20,
        missing=(
            "Expected authentication/session lifecycle and trust boundary",
            "Token/session rotation, expiry, state, and validation controls",
            "Stored target evidence of an authentication boundary or lifecycle failure",
        ),
        rules=(
            "raw-collector-authentication-v1",
            "candidate-auth-surface",
            "admission-auth-lifecycle-failure",
        ),
        summary=(
            "Stored artifacts expose an authentication or session lifecycle surface; promotion requires "
            "target evidence of a boundary regression, session-validation failure, token lifecycle failure, missing state, or token exposure."
        ),
        impact=82,
    ),
    "account_enumeration": RawFamilyObservation(
        family="account_enumeration",
        variant="identity_response_difference",
        base=15,
        missing=(
            "Controlled present-versus-absent identity observations",
            "Repeatable response/body/length/timing comparison",
            "Evidence that the observable difference reveals account existence",
        ),
        rules=(
            "raw-collector-authentication-v1",
            "candidate-recovery-identity",
            "admission-identity-differential",
        ),
        summary=(
            "Stored artifacts expose an identity lookup surface; promotion requires a controlled, material "
            "existing-versus-nonexistent account response, error, body-length, or timing differential."
        ),
        impact=48,
    ),
}


def validate_authentication_collectors() -> list[str]:
    errors: list[str] = []
    if set(AUTHENTICATION_OBSERVATIONS) != set(AUTHENTICATION_FAMILIES):
        errors.append("authentication collector profile coverage drift")
    for family in AUTHENTICATION_FAMILIES:
        observation = AUTHENTICATION_OBSERVATIONS.get(family)
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
            errors.append(f"authentication detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"authentication detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"authentication detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"authentication detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"authentication detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_authentication_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_authentication_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.22 authentication collector registry: " + "; ".join(errors))
    return [
        AUTHENTICATION_OBSERVATIONS[family]
        for family in AUTHENTICATION_FAMILIES
        if AUTHENTICATION_OBSERVATIONS[family].packet_present(execution_map)
    ]
'''
(ROOT / "app" / "raw_family_collectors" / "authentication.py").write_text(collector, encoding="utf-8")

init_path = ROOT / "app" / "raw_family_collectors" / "__init__.py"
replace_once(
    init_path,
    "from raw_family_collectors.business_logic import (\n",
    '''from raw_family_collectors.authentication import (
    AUTHENTICATION_COLLECTOR_RULE_VERSION,
    AUTHENTICATION_COLLECTOR_VERSION,
    AUTHENTICATION_FAMILIES,
    AUTHENTICATION_OBSERVATIONS,
    collect_authentication_observations,
    validate_authentication_collectors,
)
from raw_family_collectors.business_logic import (
''',
)
replace_once(
    init_path,
    '    "BUSINESS_LOGIC_COLLECTOR_VERSION",\n',
    '''    "AUTHENTICATION_COLLECTOR_VERSION",
    "AUTHENTICATION_COLLECTOR_RULE_VERSION",
    "AUTHENTICATION_FAMILIES",
    "AUTHENTICATION_OBSERVATIONS",
    "collect_authentication_observations",
    "validate_authentication_collectors",
    "BUSINESS_LOGIC_COLLECTOR_VERSION",
''',
)

bug_path = ROOT / "app" / "bug_candidates.py"
replace_once(
    bug_path,
    'from raw_family_collectors import collect_api_configuration_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
    'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
)
text = bug_path.read_text(encoding="utf-8")
bola_marker = '    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n'
if text.count(bola_marker) != 1:
    raise RuntimeError("6.22 collector insertion marker drift")
loop = '''    # Analysis 6.22 — physical authentication/account-enumeration collector ownership.
    # WSTG/OWASP/CWE/write-ups define detector criteria only; passive stored target
    # evidence remains owned by execution/reconstruction and family admission.
    for observation in collect_authentication_observations(execution_map):
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
start = text.find("    # Authentication / recovery / enumeration\n")
end = text.find("    # Analysis 6.19: legacy Open Redirect alert emission was physically removed.\n")
if start < 0 or end < 0 or end <= start:
    raise RuntimeError("6.22 authentication legacy cutover boundaries not found")
text = text[:start] + '''    # Analysis 6.22: Authentication/Session and Account Enumeration legacy alert emission was physically removed.
    # raw_family_collectors.authentication owns emission metadata; execution/reconstruction
    # remains the sole source of target evidence, blockers, and condition signals.

''' + text[end:]
bug_path.write_text(text, encoding="utf-8")

base_path = ROOT / "app" / "family_detectors" / "base.py"
replace_once(
    base_path,
    'def writeup(ref: str, url: str, relation: str, lesson: str) -> WriteupReference:\n    return WriteupReference(ref=ref, url=url, relation=relation, lesson=lesson)\n',
    'def writeup(ref: str, url: str, relation: str, lesson: str, *, source: str = "GitHub Security Lab") -> WriteupReference:\n    return WriteupReference(ref=ref, url=url, relation=relation, lesson=lesson, source=source)\n',
)

account_detector = '''from .base import make_spec, writeup
SPEC = make_spec(
    family="account_enumeration",
    strategy="identity_differential",
    surface_terms=("username","email","forgot password","reset password","account exists","user not found"),
    surface_fields=("username","email","login","user"),
    confounders=("authentication_session","information_disclosure"),
    expected_wstg=("WSTG-IDNT-04",),
    expected_cwe=("CWE-204",),
    writeups=(
        writeup(
            "CVE-2022-40482 / Laravel user-enumeration timing differential",
            "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j",
            "exact",
            "Identity input is only a lookup surface; promotion requires a controlled existing/non-existing account discrepancy, and timing is decisive only when repeatable and materially separated.",
            source="GitHub Advisory Database",
        ),
    ),
)
'''
(ROOT / "app" / "family_detectors" / "account_enumeration.py").write_text(account_detector, encoding="utf-8")


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
from raw_family_collectors import AUTHENTICATION_FAMILIES, AUTHENTICATION_OBSERVATIONS, collect_authentication_observations, validate_authentication_collectors


class PhysicalRawCollectorAuthentication6220Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(AUTHENTICATION_FAMILIES), {"authentication_session", "account_enumeration"})
        self.assertEqual(validate_authentication_collectors(), [])
        auth = get_detector_spec("authentication_session")
        self.assertEqual(set(auth.wstg_ids), {"WSTG-ATHN-04", "WSTG-SESS-01"})
        self.assertEqual(set(auth.owasp_ids), {"A07:2025", "API2:2023"})
        self.assertEqual(set(auth.cwe_ids), {"CWE-287"})
        self.assertTrue(auth.writeups)
        self.assertTrue(all(ref.url == "https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/" for ref in auth.writeups))
        enum = get_detector_spec("account_enumeration")
        self.assertEqual(set(enum.wstg_ids), {"WSTG-IDNT-04"})
        self.assertEqual(set(enum.owasp_ids), {"A07:2025", "API2:2023"})
        self.assertEqual(set(enum.cwe_ids), {"CWE-204"})
        self.assertEqual(len(enum.writeups), 1)
        self.assertEqual(enum.writeups[0].url, "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j")
        self.assertEqual(enum.writeups[0].source, "GitHub Advisory Database")
        self.assertEqual(enum.writeups[0].relation, "exact")
        for family in AUTHENTICATION_FAMILIES:
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in get_detector_spec(family).writeups), family)

    def test_positive_execution_contracts_admit_both_families(self):
        auth_raw = dict(
            target="fixture.invalid", endpoint="/api/session/refresh", method="POST",
            endpoint_schema={"authentication_hints": ["session"]},
            details={"context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}]},
            category="authentication", business_context="identity",
        )
        enum_raw = dict(
            target="fixture.invalid", endpoint="/forgot-password", method="POST",
            endpoint_schema={"body_fields": ["email"]},
            details={"context_observations": [
                {"context": "existing_identity", "status_code": 200, "response_text": "reset sent"},
                {"context": "absent_identity", "status_code": 404, "response_text": "unknown user"},
            ]},
            category="authentication", business_context="identity",
        )
        execution_map = {}
        for family, raw in (("authentication_session", auth_raw), ("account_enumeration", enum_raw)):
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_authentication_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(AUTHENTICATION_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "authentication_session": dict(
                target="fixture.invalid", endpoint="/login", method="POST",
                endpoint_schema={"authentication_hints": ["session"]}, details={}, category="authentication", business_context="identity",
            ),
            "account_enumeration": dict(
                target="fixture.invalid", endpoint="/forgot-password", method="POST",
                endpoint_schema={"body_fields": ["email"]}, details={}, category="authentication", business_context="identity",
            ),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_uniform_existing_absent_observations_do_not_promote_enumeration(self):
        raw = dict(
            target="fixture.invalid", endpoint="/forgot-password", method="POST",
            endpoint_schema={"body_fields": ["email"]},
            details={"context_observations": [
                {"context": "existing_identity", "status_code": 200, "response_text": "If the account exists, mail will be sent"},
                {"context": "absent_identity", "status_code": 200, "response_text": "If the account exists, mail will be sent"},
            ]},
            category="authentication", business_context="identity",
        )
        execution, assessment = self._assessment("account_enumeration", raw)
        signals = {str(row.get("type") or "") for row in execution.get("account_enumeration", {}).get("support", [])}
        self.assertNotIn("response_difference", signals)
        self.assertFalse(assessment["admitted"], (assessment, execution.get("account_enumeration")))

    def test_collector_is_metadata_only(self):
        for family, observation in AUTHENTICATION_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_authentication_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_authentication_observations(execution_map)", source)
        self.assertIn("Analysis 6.22: Authentication/Session and Account Enumeration legacy alert emission was physically removed", source)
        self.assertNotIn("# Authentication / recovery / enumeration", source)
        self.assertNotIn('emit("authentication_session", "auth_lifecycle"', source)
        self.assertNotIn('emit("account_enumeration", "identity_response_difference"', source)

    def test_run_analysis_routes_both_through_authentication_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-622-auth"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.21.0", "success", now, now, target))
                alerts = [
                    ("Authentication boundary regression", "/api/session/refresh", {
                        "method": "POST",
                        "context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}],
                    }),
                    ("Account existence differential", "/forgot-password", {
                        "method": "POST", "body_fields": ["email"],
                        "context_observations": [
                            {"context": "existing_identity", "status_code": 200, "response_text": "reset sent"},
                            {"context": "absent_identity", "status_code": 404, "response_text": "unknown user"},
                        ],
                    }),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"622:{title}", "authentication", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(AUTHENTICATION_FAMILIES) and "raw-collector-authentication-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(AUTHENTICATION_FAMILIES), hypotheses)
                for family, expected in AUTHENTICATION_OBSERVATIONS.items():
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
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-authentication-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(AUTHENTICATION_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_physical_raw_collector_authentication_v6220.py").write_text(test, encoding="utf-8")

doc = '''# Analysis Engine 6.22 — Authentication / Account Enumeration raw collectors

Analysis 6.22 physically decomposes `authentication_session` and `account_enumeration` from the alert-orchestrator monolith.

Both families retain the mandatory four-layer grounding contract:

- OWASP WSTG defines the testing semantics.
- OWASP Top 10:2025 / API Security Top 10:2023 provides risk taxonomy.
- MITRE CWE provides weakness taxonomy.
- Real security write-ups provide concrete lessons and confounders.

`authentication_session` is grounded in WSTG-ATHN-04 and WSTG-SESS-01, OWASP A07:2025 plus API2:2023, CWE-287, and the exact GHSL ruby-saml authentication-bypass advisory. Authentication route names, tokens, or session terminology are only surfaces. Promotion requires stored target evidence of an authentication/session lifecycle failure such as a boundary regression, session validation failure, token rotation failure, missing state, or token exposure.

`account_enumeration` is grounded in WSTG-IDNT-04, OWASP A07:2025 plus API2:2023, CWE-204, and the Laravel timing-enumeration advisory CVE-2022-40482. The detector lesson is deliberately narrow: identity inputs are only lookup surfaces. Promotion requires controlled present-versus-absent identity observations with a material response, error, body-length, or repeatable timing discrepancy. Uniform responses remain hidden hypotheses and do not promote.

The collector is metadata-only. It never turns WSTG, OWASP, CWE, a write-up, a route name, or the absence of a visible control into target evidence. Target evidence continues to come only from stored passive execution/reconstruction artifacts and must satisfy family admission.

No active password guessing, credential stuffing, account probing, token forgery, session hijacking, or external requests are introduced by this change.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_22_AUTHENTICATION_RAW_COLLECTORS.md").write_text(doc, encoding="utf-8")

manifest_path = ROOT / "MANIFEST.sha256"
entries: set[str] = set()
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.add(rel.strip())
entries.update({
    "app/raw_family_collectors/authentication.py",
    "docs/ANALYSIS_ENGINE_6_22_AUTHENTICATION_RAW_COLLECTORS.md",
    "tests/test_physical_raw_collector_authentication_v6220.py",
})
lines = []
for rel in sorted(entries):
    path = ROOT / rel
    if not path.is_file():
        raise RuntimeError(f"manifest path missing after 6.22 cutover: {rel}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {rel}")
manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

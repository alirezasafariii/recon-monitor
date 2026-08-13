from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing marker {label} in {rel}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# Top-level release identity for the orchestration cutover. Detector/admission/
# reconstruction component versions remain unchanged because their semantics are
# not modified in 6.28.
for rel, old, new in (
    ("app/analysis_engine.py", 'ENGINE_VERSION = "6.27.0"\nRULE_VERSION = "2026.08.13.6.27"', 'ENGINE_VERSION = "6.28.0"\nRULE_VERSION = "2026.08.13.6.28"'),
    ("app/bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "6.27.0"\nCANDIDATE_RULE_VERSION = "2026.08.13.6.27"', 'CANDIDATE_ENGINE_VERSION = "6.28.0"\nCANDIDATE_RULE_VERSION = "2026.08.13.6.28"'),
    ("app/security_reasoning.py", 'REASONING_ENGINE_VERSION = "6.27.0"\nREASONING_RULE_VERSION = "2026.08.13.6.27"', 'REASONING_ENGINE_VERSION = "6.28.0"\nREASONING_RULE_VERSION = "2026.08.13.6.28"'),
):
    replace_once(rel, old, new, f"6.28 version bump {rel}")


ownership_module = '''from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import (
    API_CONFIGURATION_FAMILIES,
    AUTHENTICATION_FAMILIES,
    AUTHORIZATION_FAMILIES,
    BUSINESS_LOGIC_FAMILIES,
    CLIENT_SIDE_FAMILIES,
    EXPOSURE_HEADERS_FAMILIES,
    FILE_REMOTE_FAMILIES,
    INJECTION_FAMILIES,
    OWASP_TOP10_2025_FAMILIES,
    RawFamilyObservation,
    collect_api_configuration_observations,
    collect_authentication_observations,
    collect_authorization_observations,
    collect_business_logic_observations,
    collect_client_side_observations,
    collect_exposure_headers_observations,
    collect_file_remote_resource_observations,
    collect_injection_observations,
    collect_owasp_top10_2025_observations,
)
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES

ORCHESTRATION_ENGINE_VERSION = "1.0.0"
ORCHESTRATION_RULE_VERSION = "2026.08.13.6.28"


@dataclass(frozen=True)
class RawCollectorBinding:
    name: str
    families: tuple[str, ...]
    collector: Callable[[Mapping[str, Mapping[str, Any]]], list[RawFamilyObservation]]


RAW_COLLECTOR_BINDINGS: tuple[RawCollectorBinding, ...] = (
    RawCollectorBinding("injection", tuple(INJECTION_FAMILIES), collect_injection_observations),
    RawCollectorBinding("authorization", tuple(AUTHORIZATION_FAMILIES), collect_authorization_observations),
    RawCollectorBinding("file_remote_resource", tuple(FILE_REMOTE_FAMILIES), collect_file_remote_resource_observations),
    RawCollectorBinding("client_side", tuple(CLIENT_SIDE_FAMILIES), collect_client_side_observations),
    RawCollectorBinding("api_configuration", tuple(API_CONFIGURATION_FAMILIES), collect_api_configuration_observations),
    RawCollectorBinding("business_logic", tuple(BUSINESS_LOGIC_FAMILIES), collect_business_logic_observations),
    RawCollectorBinding("authentication", tuple(AUTHENTICATION_FAMILIES), collect_authentication_observations),
    RawCollectorBinding("exposure_headers", tuple(EXPOSURE_HEADERS_FAMILIES), collect_exposure_headers_observations),
    RawCollectorBinding("owasp_top10_2025", tuple(OWASP_TOP10_2025_FAMILIES), collect_owasp_top10_2025_observations),
)

RAW_OWNED_FAMILIES = tuple(sorted(family for binding in RAW_COLLECTOR_BINDINGS for family in binding.families))
BOLA_OWNED_FAMILIES = ("broken_object_authorization",)
STATIC_OWNED_FAMILIES = tuple(sorted(STATIC_SPECIALIZED_FAMILIES))

PRIMARY_FAMILY_OWNERSHIP: dict[str, str] = {
    **{family: "raw" for family in RAW_OWNED_FAMILIES},
    **{family: "bola" for family in BOLA_OWNED_FAMILIES},
    **{family: "static" for family in STATIC_OWNED_FAMILIES},
}


def validate_family_ownership() -> list[str]:
    errors: list[str] = []
    expected = set(FAMILY_ADMISSION_POLICIES)
    raw_seen: set[str] = set()
    duplicates: set[str] = set()
    for binding in RAW_COLLECTOR_BINDINGS:
        if not binding.name or not binding.families:
            errors.append(f"invalid raw collector binding: {binding.name!r}")
        for family in binding.families:
            if family in raw_seen:
                duplicates.add(family)
            raw_seen.add(family)
    if duplicates:
        errors.append(f"raw primary ownership overlap: {sorted(duplicates)}")
    if len(RAW_OWNED_FAMILIES) != 30 or len(set(RAW_OWNED_FAMILIES)) != 30:
        errors.append(f"raw ownership must be exactly 30 unique families, got {len(set(RAW_OWNED_FAMILIES))}")
    if set(BOLA_OWNED_FAMILIES) != {"broken_object_authorization"}:
        errors.append(f"BOLA ownership drift: {sorted(BOLA_OWNED_FAMILIES)}")
    if len(STATIC_OWNED_FAMILIES) != 5 or len(set(STATIC_OWNED_FAMILIES)) != 5:
        errors.append(f"static specialized ownership must be exactly 5 unique families, got {len(set(STATIC_OWNED_FAMILIES))}")
    raw = set(RAW_OWNED_FAMILIES)
    bola = set(BOLA_OWNED_FAMILIES)
    static = set(STATIC_OWNED_FAMILIES)
    if raw & bola or raw & static or bola & static:
        errors.append("primary ownership sets overlap")
    owned = raw | bola | static
    if owned != expected:
        errors.append(f"primary ownership drift: missing={sorted(expected-owned)} extra={sorted(owned-expected)}")
    if len(PRIMARY_FAMILY_OWNERSHIP) != 36:
        errors.append(f"primary ownership registry must contain 36 families, got {len(PRIMARY_FAMILY_OWNERSHIP)}")
    return errors


def collect_raw_owned_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_family_ownership()
    if errors:
        raise RuntimeError("Invalid Analysis 6.28 family ownership registry: " + "; ".join(errors))
    observations: list[RawFamilyObservation] = []
    for binding in RAW_COLLECTOR_BINDINGS:
        batch = binding.collector(execution_map)
        allowed = set(binding.families)
        for observation in batch:
            if observation.family not in allowed:
                raise RuntimeError(
                    f"Analysis 6.28 raw collector {binding.name} emitted unowned family {observation.family}"
                )
            observations.append(observation)
    return observations
'''
(ROOT / "app" / "family_orchestration.py").write_text(ownership_module, encoding="utf-8")


# Move DOM/postMessage/open-redirect static supplement logic out of the candidate
# orchestrator. These remain supplements to raw primary ownership, not owners.
static_path = ROOT / "app" / "static_family_collectors.py"
static_text = static_path.read_text(encoding="utf-8")
if "STATIC_SUPPLEMENTAL_FAMILIES" in static_text:
    raise SystemExit("static supplemental adapter already exists")
static_text += '''\n\nSTATIC_SUPPLEMENTAL_FAMILIES = (\n    "dom_xss",\n    "postmessage_trust",\n    "open_redirect",\n)\n\n\ndef collect_client_static_supplemental_observations(\n    db: Database, analysis_id: str, target: str | None = None\n) -> list[StaticFamilyObservation]:\n    observations: list[StaticFamilyObservation] = []\n    params: list[Any] = [analysis_id]\n    target_clause = ""\n    if target:\n        target_clause = " AND target=?"\n        params.append(target)\n    rows = db.all(f"SELECT * FROM js_dataflows WHERE analysis_id=?{target_clause}", tuple(params))\n    for row in rows:\n        source = str(row["source_kind"])\n        sink = str(row["sink_kind"])\n        current_target = str(row["target"])\n        js_url = str(row["js_url"])\n        confidence = parse_int(row["confidence"], 0)\n        support = [\n            {"type": "source_sink", "source": "javascript_dataflow", "source_group": "static_flow", "weight": 18, "text": f"Static source/sink proximity observed: {source} -> {sink}"},\n        ]\n        if sink in {"innerHTML", "eval"}:\n            support.append({"type": "dangerous_sink", "source": "javascript_sink", "source_group": "static_sink", "weight": 20, "text": f"Dangerous DOM/JS sink observed: {sink}"})\n        if sink == "navigation":\n            support.append({"type": "navigation_sink", "source": "javascript_sink", "source_group": "static_sink", "weight": 18, "text": "Navigation sink observed in static flow"})\n        if source == "postMessage":\n            support.append({"type": "postmessage_handler", "source": "javascript_dataflow", "source_group": "message_source", "weight": 16, "text": "postMessage-controlled source observed"})\n        contradict = [\n            {"type": "static_only", "source": "analysis_limit", "weight": -8, "text": "Static proximity does not prove runtime reachability or missing sanitization"}\n        ]\n        missing = ("Runtime reachability", "Sanitization or encoding behavior", "Whether the value is transformed before the sink")\n        family = ""\n        variant = ""\n        summary = ""\n        if source == "postMessage":\n            family, variant = "postmessage_trust", "message_to_sensitive_sink"\n            summary = "A postMessage-controlled value appears near a sensitive client sink; origin validation and message schema checks are unknown."\n        elif sink in {"innerHTML", "eval"}:\n            family, variant = "dom_xss", "source_to_dom_sink"\n            summary = "A user-influenced browser source appears near an executable or HTML-rendering sink; runtime reachability and sanitization are unknown."\n        elif sink == "navigation":\n            family, variant = "open_redirect", "source_to_navigation_sink"\n            summary = "A user-influenced browser source appears near a navigation sink; destination validation is unknown."\n        if not family:\n            continue\n        observations.append(StaticFamilyObservation(\n            target=current_target, endpoint="", source_ref=f"js-dataflow:{js_url}:{source}:{sink}",\n            family=family, variant=variant,\n            likelihood=_clamp(28 + confidence * 0.45 + sum(parse_int(x.get("weight"), 0) for x in support + contradict)),\n            evidence_strength=_strength(confidence, support, contradict, direct=True), impact=DETECTOR_SPECS[family].impact,\n            support=tuple(support), contradict=tuple(contradict), missing=missing,\n            rules=("static-supplement-client-v1", f"candidate-{variant}"), summary=summary,\n        ))\n    return observations\n\n\ndef collect_static_candidate_observations(\n    db: Database, analysis_id: str, target: str | None = None\n) -> list[StaticFamilyObservation]:\n    return [\n        *collect_client_static_supplemental_observations(db, analysis_id, target),\n        *collect_specialized_static_observations(db, analysis_id, target),\n    ]\n'''
static_path.write_text(static_text, encoding="utf-8")


# Collapse bug_candidates orchestration to generic adapters.
bug_path = ROOT / "app" / "bug_candidates.py"
bug = bug_path.read_text(encoding="utf-8")
old_import = 'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations, collect_owasp_top10_2025_observations\nfrom static_family_collectors import collect_specialized_static_observations\n'
new_import = 'from family_orchestration import collect_raw_owned_observations, validate_family_ownership\nfrom static_family_collectors import collect_static_candidate_observations\n'
if old_import not in bug:
    raise SystemExit("bug_candidates collector import marker missing")
bug = bug.replace(old_import, new_import, 1)
bug = bug.replace('    auth_hints = [str(x) for x in _list(endpoint_schema.get("authentication_hints"))]\n', '', 1)
bug = bug.replace('    haystack = " ".join([endpoint, item, category, context, json_dumps(details), " ".join(body_fields + query_fields + path_fields)]).lower()\n', '', 1)
start = bug.index('    # Analysis 6.16 — physical raw collector ownership for server-side injection families.')
end = bug.index('    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.', start)
generic_raw = '''    ownership_errors = validate_family_ownership()\n    if ownership_errors:\n        raise RuntimeError("Invalid Analysis 6.28 family ownership registry: " + "; ".join(ownership_errors))\n\n    # Analysis 6.28 — generic raw primary-owner orchestration. Collector metadata\n    # never manufactures target evidence; execution/reconstruction owns evidence and\n    # family admission remains the only promotion gate.\n    for observation in collect_raw_owned_observations(execution_map):\n        emit(\n            observation.family,\n            observation.variant,\n            observation.base,\n            [],\n            [],\n            list(observation.missing),\n            list(observation.rules),\n            observation.summary,\n            direct=observation.direct,\n            impact=observation.impact,\n        )\n\n'''
bug = bug[:start] + generic_raw + bug[end:]
legacy_start = bug.index('    # Analysis 6.17: Function Authorization and Mass Assignment legacy collection was physically')
legacy_end = bug.index('    return count\n\n\ndef _static_candidates', legacy_start)
bug = bug[:legacy_start] + '    return count\n\n\ndef _static_candidates' + bug[legacy_end + len('    return count\n\n\ndef _static_candidates'):]
static_start = bug.index('    # JavaScript data-flow candidates.', bug.index('def _static_candidates'))
static_end = bug.index('    return count\n\n\ndef generate_bug_candidates', static_start)
generic_static = '''    # Analysis 6.28 — static adapters own all persisted static candidate emission.\n    # Primary ownership remains machine-verifiable in family_orchestration; the\n    # DOM/postMessage/open-redirect adapter is supplemental only.\n    for observation in collect_static_candidate_observations(db, analysis_id, target):\n        candidate_id = _insert_candidate(\n            db, analysis_id=analysis_id, source_run_id=run_id, target=observation.target,\n            alert_id=None, asset="", endpoint=observation.endpoint, source_ref=observation.source_ref,\n            family=observation.family, variant=observation.variant,\n            likelihood=observation.likelihood, evidence_strength=observation.evidence_strength,\n            impact_potential=observation.impact, support=[dict(item) for item in observation.support],\n            contradict=[dict(item) for item in observation.contradict], missing=list(observation.missing),\n            rule_ids=list(observation.rules), summary=observation.summary,\n        )\n        if candidate_id:\n            count += 1\n\n'''
bug = bug[:static_start] + generic_static + bug[static_end:]
for forbidden in (
    'collect_injection_observations(execution_map)',
    'collect_authorization_observations(execution_map)',
    'collect_file_remote_resource_observations(execution_map)',
    'collect_client_side_observations(execution_map)',
    'collect_api_configuration_observations(execution_map)',
    'collect_business_logic_observations(execution_map)',
    'collect_authentication_observations(execution_map)',
    'collect_exposure_headers_observations(execution_map)',
    'collect_owasp_top10_2025_observations(execution_map)',
    'detector-execution-fallback',
    'if source == "postMessage"',
):
    if forbidden in bug:
        raise SystemExit(f"legacy orchestrator marker remains: {forbidden}")
bug_path.write_text(bug, encoding="utf-8")


# Historical 6.27 seal owns the 6.27 floor, not the current top-level release.
seal627 = ROOT / "tests" / "test_analysis_627_seal.py"
text = seal627.read_text(encoding="utf-8")
text = text.replace('    def test_analysis_layer_versions_are_exactly_627(self) -> None:\n', '    def test_analysis_layer_versions_preserve_627_floor(self) -> None:\n', 1)
for old, new in (
    ('        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.27.0")', '        self.assertGreaterEqual(tuple(int(x) for x in analysis_engine.ENGINE_VERSION.split(".")), (6, 27, 0))'),
    ('        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.27.0")', '        self.assertGreaterEqual(tuple(int(x) for x in bug_candidates.CANDIDATE_ENGINE_VERSION.split(".")), (6, 27, 0))'),
    ('        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.27.0")', '        self.assertGreaterEqual(tuple(int(x) for x in security_reasoning.REASONING_ENGINE_VERSION.split(".")), (6, 27, 0))'),
    ('        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.13.6.27")', '        self.assertGreaterEqual(tuple(int(x) for x in analysis_engine.RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))'),
    ('        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.13.6.27")', '        self.assertGreaterEqual(tuple(int(x) for x in bug_candidates.CANDIDATE_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))'),
    ('        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.13.6.27")', '        self.assertGreaterEqual(tuple(int(x) for x in security_reasoning.REASONING_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))'),
):
    if old not in text:
        raise SystemExit(f"missing historical 6.27 assertion: {old}")
    text = text.replace(old, new, 1)
seal627.write_text(text, encoding="utf-8")


test_module = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import analysis_engine
import bug_candidates
import security_reasoning
from family_evidence_extractors import FAMILY_EVIDENCE_EXTRACTOR_PROFILES
from family_orchestration import (
    BOLA_OWNED_FAMILIES,
    ORCHESTRATION_ENGINE_VERSION,
    ORCHESTRATION_RULE_VERSION,
    PRIMARY_FAMILY_OWNERSHIP,
    RAW_COLLECTOR_BINDINGS,
    RAW_OWNED_FAMILIES,
    STATIC_OWNED_FAMILIES,
    collect_raw_owned_observations,
    validate_family_ownership,
)
from family_reasoners import FAMILY_REASONER_PROFILES
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, STATIC_SUPPLEMENTAL_FAMILIES


class Analysis628OrchestratorCleanupTests(unittest.TestCase):
    def test_exact_release_and_orchestration_versions(self) -> None:
        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.28.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.13.6.28")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.28.0")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.13.6.28")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.28.0")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.13.6.28")
        self.assertEqual(ORCHESTRATION_ENGINE_VERSION, "1.0.0")
        self.assertEqual(ORCHESTRATION_RULE_VERSION, "2026.08.13.6.28")

    def test_primary_ownership_is_exact_30_plus_1_plus_5_partition(self) -> None:
        self.assertEqual(validate_family_ownership(), [])
        self.assertEqual(len(RAW_OWNED_FAMILIES), 30)
        self.assertEqual(len(set(RAW_OWNED_FAMILIES)), 30)
        self.assertEqual(BOLA_OWNED_FAMILIES, ("broken_object_authorization",))
        self.assertEqual(len(STATIC_OWNED_FAMILIES), 5)
        self.assertEqual(set(STATIC_OWNED_FAMILIES), set(STATIC_SPECIALIZED_FAMILIES))
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(len(families), 36)
        self.assertEqual(set(PRIMARY_FAMILY_OWNERSHIP), families)
        self.assertEqual(set(bug_candidates.BUG_FAMILIES), families)
        self.assertEqual(set(FAMILY_REASONER_PROFILES), families)
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), families)
        self.assertEqual(set(RAW_OWNED_FAMILIES) | set(BOLA_OWNED_FAMILIES) | set(STATIC_OWNED_FAMILIES), families)
        self.assertFalse(set(RAW_OWNED_FAMILIES) & set(BOLA_OWNED_FAMILIES))
        self.assertFalse(set(RAW_OWNED_FAMILIES) & set(STATIC_OWNED_FAMILIES))
        self.assertFalse(set(BOLA_OWNED_FAMILIES) & set(STATIC_OWNED_FAMILIES))

    def test_raw_binding_registry_has_no_family_overlap_and_collects_all_30_generically(self) -> None:
        seen: set[str] = set()
        for binding in RAW_COLLECTOR_BINDINGS:
            self.assertTrue(binding.name)
            self.assertTrue(binding.families)
            self.assertFalse(seen & set(binding.families), binding.name)
            seen.update(binding.families)
        self.assertEqual(seen, set(RAW_OWNED_FAMILIES))
        execution_map = {family: {"support": [{"type": "surface", "source": "fixture"}], "contradict": []} for family in RAW_OWNED_FAMILIES}
        observations = collect_raw_owned_observations(execution_map)
        self.assertEqual(len(observations), 30)
        self.assertEqual({item.family for item in observations}, set(RAW_OWNED_FAMILIES))

    def test_static_supplements_are_not_primary_owners(self) -> None:
        self.assertEqual(set(STATIC_SUPPLEMENTAL_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        self.assertTrue(set(STATIC_SUPPLEMENTAL_FAMILIES) <= set(RAW_OWNED_FAMILIES))
        self.assertFalse(set(STATIC_SUPPLEMENTAL_FAMILIES) & set(STATIC_OWNED_FAMILIES))
        for family in STATIC_SUPPLEMENTAL_FAMILIES:
            self.assertEqual(PRIMARY_FAMILY_OWNERSHIP[family], "raw")

    def test_bug_candidate_orchestrator_has_no_per_family_raw_or_static_branching(self) -> None:
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("analyze_bola_signal(", source)
        self.assertIn("collect_static_candidate_observations(db, analysis_id, target)", source)
        self.assertNotIn("detector-execution-fallback", source)
        for marker in (
            "collect_injection_observations(execution_map)",
            "collect_authorization_observations(execution_map)",
            "collect_file_remote_resource_observations(execution_map)",
            "collect_client_side_observations(execution_map)",
            "collect_api_configuration_observations(execution_map)",
            "collect_business_logic_observations(execution_map)",
            "collect_authentication_observations(execution_map)",
            "collect_exposure_headers_observations(execution_map)",
            "collect_owasp_top10_2025_observations(execution_map)",
            'if source == "postMessage"',
            'elif sink in {"innerHTML", "eval"}',
            'elif sink == "navigation"',
        ):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_628_orchestrator_cleanup.py").write_text(test_module, encoding="utf-8")


doc = '''# Analysis Engine 6.28 — Final Orchestrator Cleanup

Analysis 6.28 removes family-specific orchestration from `bug_candidates.py` while preserving all detector, admission, standards, and evidence semantics sealed in 6.27.

## Primary ownership partition

The primary family ownership registry is now machine-verifiable:
- 30 raw physical families through nine metadata-only raw collector bindings;
- 1 dedicated BOLA family through `bola_intelligence.py`;
- 5 specialized static families through `static_family_collectors.py`.

The three JavaScript families DOM XSS, postMessage trust, and open redirect may receive persisted static supplemental observations, but their primary ownership remains raw. Supplemental adapters never alter the 30 + 1 + 5 partition.

## Orchestrator shape

`bug_candidates._alert_candidates()` now follows one generic path:
1. execute passive detector intelligence;
2. collect raw-owned metadata through the central registry;
3. run the dedicated BOLA analyzer;
4. apply generic detector extraction, hypothesis admission, quality guard, and candidate insertion.

There is no execution-family fallback and no per-family raw collector loop in the orchestrator. All 36 primary owners are explicit, so an unowned execution family is treated as registry drift instead of being silently emitted.

`bug_candidates._static_candidates()` now consumes one static adapter stream. DOM/postMessage/open-redirect branching lives in a static supplemental adapter; specialized static family ownership remains unchanged.

## Security invariant

WSTG, OWASP, CWE, and related write-ups remain detector-design knowledge only. They never count as target evidence. Promotion continues to require stored target evidence satisfying the existing family detector and admission contracts.

## Validation

The 6.28 cutover must preserve the immutable 6.26 v4 corpus and the sealed 6.27 regression metrics, then pass the full unit, strict Golden, and integration suites on Python 3.11 and Python 3.13.

No first-scan/second-scan alert lifecycle behavior is changed in 6.28.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_28_ORCHESTRATOR_CLEANUP.md").write_text(doc, encoding="utf-8")

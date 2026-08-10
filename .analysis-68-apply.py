from __future__ import annotations

from pathlib import Path


def replace(path: str, old: str, new: str, *, count: int = 1) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    actual = text.count(old)
    if actual < count:
        raise SystemExit(f"{path}: expected at least {count} occurrences, found {actual}: {old[:120]!r}")
    text = text.replace(old, new, count)
    p.write_text(text, encoding="utf-8")


# Break the extractor/reasoner import cycle by giving extraction its own frozen
# identity-gate registry. A dedicated test below asserts it never drifts from
# the reasoner identity gates.
replace(
    "app/family_evidence_extractors.py",
    "from hypothesis_admission import FAMILY_ADMISSION_POLICIES\nfrom family_reasoners import FAMILY_IDENTITY_GATES\n",
    "from hypothesis_admission import FAMILY_ADMISSION_POLICIES\n",
)
replace(
    "app/family_evidence_extractors.py",
    'FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.08.10.6.8"\n\n\n@dataclass',
    '''FAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.08.10.6.8"\n\n\n# Extraction has an explicit copy of the identity gates so this module stays\n# below the reasoning layer and cannot create an import cycle. Tests require\n# exact equality with family_reasoners.FAMILY_IDENTITY_GATES.\nFAMILY_EXTRACTION_IDENTITY_GATES: dict[str, tuple[int, ...]] = {\n    "broken_object_authorization": (0, 1),\n    "broken_function_authorization": (0, 1),\n    "mass_assignment": (1,),\n    "authentication_session": (0,),\n    "account_enumeration": (0,),\n    "dom_xss": (0, 1),\n    "postmessage_trust": (0,),\n    "open_redirect": (0, 1),\n    "ssrf": (0,),\n    "file_upload": (0, 1),\n    "path_traversal": (0, 1),\n    "information_disclosure": (0,),\n    "graphql_authorization": (0, 1),\n    "graphql_data_exposure": (0, 1),\n    "websocket_authorization": (0, 1),\n    "cors_misconfiguration": (0,),\n    "sensitive_caching": (0, 1),\n    "business_logic": (0,),\n    "race_condition": (0, 1),\n    "sql_injection": (1,),\n    "nosql_injection": (1,),\n    "command_injection": (1,),\n    "server_side_template_injection": (1,),\n    "ldap_injection": (1,),\n    "unrestricted_resource_consumption": (0,),\n    "sensitive_business_flow_abuse": (0,),\n    "security_misconfiguration": (0,),\n    "improper_inventory_management": (0,),\n    "unsafe_api_consumption": (0,),\n    "source_map_exposure": (0,),\n    "secret_exposure": (0, 1),\n}\n\n\n@dataclass''',
)
replace(
    "app/family_evidence_extractors.py",
    "gates = FAMILY_IDENTITY_GATES.get(family, ())",
    "gates = FAMILY_EXTRACTION_IDENTITY_GATES.get(family, ())",
)
replace(
    "app/family_evidence_extractors.py",
    "gate_indices = FAMILY_IDENTITY_GATES[family]",
    "gate_indices = FAMILY_EXTRACTION_IDENTITY_GATES[family]",
)
replace(
    "app/family_evidence_extractors.py",
    '        item["extractor_channel"] = channel\n',
    '        item.setdefault("extractor_channel", channel)\n',
)

# Candidate and hypothesis production: every packet is scoped before admission,
# persistence, merging, and production reasoning.
replace(
    "app/bug_candidates.py",
    "from bola_intelligence import analyze_bola_signal\n",
    "from bola_intelligence import analyze_bola_signal\nfrom family_evidence_extractors import scope_family_evidence\n",
)
replace(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.5.0"\nCANDIDATE_RULE_VERSION = "2026.08.10.6.5"',
    'CANDIDATE_ENGINE_VERSION = "6.8.0"\nCANDIDATE_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/bug_candidates.py",
    '''    if family not in BUG_FAMILIES:\n        raise ReconError(f"Unknown bug family: {family}")\n    admission = assess_admission(family, support, contradict)\n''',
    '''    if family not in BUG_FAMILIES:\n        raise ReconError(f"Unknown bug family: {family}")\n    extraction = scope_family_evidence(family, support, contradict, channel="candidate")\n    support = extraction["support"]\n    contradict = extraction["contradict"]\n    admission = assess_admission(family, support, contradict)\n''',
)
replace(
    "app/bug_candidates.py",
    '''        nonlocal count\n        hypothesis = record_hypothesis(\n''',
    '''        nonlocal count\n        extraction = scope_family_evidence(family, support, contradict, channel="alert")\n        support = extraction["support"]\n        contradict = extraction["contradict"]\n        hypothesis = record_hypothesis(\n''',
)

# Admission is an independent enforcement boundary. New scoped evidence from a
# different family is ignored even if its type matches this policy. Historical
# unscoped fixtures remain valid for regression and benchmark compatibility.
replace(
    "app/hypothesis_admission.py",
    'ADMISSION_ENGINE_VERSION = "2.3.0"\nADMISSION_RULE_VERSION = "2026.08.10.6.4"',
    'ADMISSION_ENGINE_VERSION = "2.4.0"\nADMISSION_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/hypothesis_admission.py",
    '''    support_items = [dict(item) for item in support]\n    contradict_items = [dict(item) for item in (contradict or [])]\n''',
    '''    support_items = [\n        dict(item) for item in support\n        if not str(item.get("family_scope") or "").strip()\n        or str(item.get("family_scope") or "").strip() == family\n    ]\n    contradict_items = [\n        dict(item) for item in (contradict or [])\n        if not str(item.get("family_scope") or "").strip()\n        or str(item.get("family_scope") or "").strip() == family\n    ]\n''',
)

# Reasoning is the second independent boundary: each family sees only its own
# namespaced evidence, while unscoped historical benchmark evidence remains
# readable. This makes combined multi-family dossiers safe by construction.
replace(
    "app/family_reasoners.py",
    "from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission\n",
    "from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission\nfrom family_evidence_extractors import filter_evidence_for_family\n",
)
replace(
    "app/family_reasoners.py",
    'FAMILY_REASONER_VERSION = "1.0.0"\nFAMILY_REASONER_RULE_VERSION = "2026.08.10.6.7"',
    'FAMILY_REASONER_VERSION = "1.1.0"\nFAMILY_REASONER_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/family_reasoners.py",
    '''    support_items = [dict(item) for item in support]\n    contradict_items = [dict(item) for item in (contradict or [])]\n    support_types = _signal_types(support_items)\n''',
    '''    support_items = filter_evidence_for_family(family, support)\n    contradict_items = filter_evidence_for_family(family, contradict or [])\n    support_types = _signal_types(support_items)\n''',
)

replace(
    "app/analysis_ranking.py",
    'RANKING_ENGINE_VERSION = "2.0.0"\nRANKING_RULE_VERSION = "2026.08.10.6.7"',
    'RANKING_ENGINE_VERSION = "2.1.0"\nRANKING_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/security_family_ranker.py",
    'SECURITY_FAMILY_RANKER_VERSION = "1.0.0"\nSECURITY_FAMILY_RANKER_RULE_VERSION = "2026.08.10.6.7"',
    'SECURITY_FAMILY_RANKER_VERSION = "1.1.0"\nSECURITY_FAMILY_RANKER_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.7.0"\nREASONING_RULE_VERSION = "2026.08.10.6.7"',
    'REASONING_ENGINE_VERSION = "6.8.0"\nREASONING_RULE_VERSION = "2026.08.10.6.8"',
)
replace(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.5.0"\nRULE_VERSION = "2026.08.10.6.5"',
    'ENGINE_VERSION = "6.8.0"\nRULE_VERSION = "2026.08.10.6.8"',
)

# Historical version assertions should reflect the current integrated engine;
# their behavioral fixtures remain unchanged.
replace(
    "tests/test_analysis_coverage_v610.py",
    '''        self.assertEqual(ENGINE_VERSION, "6.5.0")\n        self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.5.0")\n        self.assertEqual(REASONING_ENGINE_VERSION, "6.7.0")\n        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.3.0")\n''',
    '''        self.assertEqual(ENGINE_VERSION, "6.8.0")\n        self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.8.0")\n        self.assertEqual(REASONING_ENGINE_VERSION, "6.8.0")\n        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.4.0")\n''',
)
replace(
    "tests/test_family_reasoners_v670.py",
    '''        self.assertEqual(FAMILY_REASONER_VERSION, "1.0.0")\n        self.assertEqual(RANKING_ENGINE_VERSION, "2.0.0")\n''',
    '''        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")\n        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")\n''',
)
replace(
    "tests/test_analysis_ranking_v650.py",
    '''        self.assertEqual(RANKING_ENGINE_VERSION, "2.0.0")\n        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")\n        self.assertEqual(REASONING_ENGINE_VERSION, "6.7.0")\n''',
    '''        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")\n        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")\n        self.assertEqual(REASONING_ENGINE_VERSION, "6.8.0")\n''',
)

Path("tests/test_family_evidence_extractors_v680.py").write_text(r'''from __future__ import annotations

import unittest

from analysis_ranking import RANKING_ENGINE_VERSION, rank_families
from family_evidence_extractors import (
    FAMILY_EVIDENCE_EXTRACTOR_PROFILES,
    FAMILY_EVIDENCE_EXTRACTOR_VERSION,
    FAMILY_EXTRACTION_IDENTITY_GATES,
    evidence_role,
    filter_evidence_for_family,
    scope_family_evidence,
)
from family_reasoners import FAMILY_IDENTITY_GATES, FAMILY_REASONER_VERSION, reason_family
from hypothesis_admission import ADMISSION_ENGINE_VERSION, FAMILY_ADMISSION_POLICIES, assess_admission


def ev(kind: str, source: str, family_scope: str = "") -> dict[str, str]:
    item = {"type": kind, "source": source, "source_group": source, "text": kind}
    if family_scope:
        item["family_scope"] = family_scope
    return item


class FamilyEvidenceExtractors680Tests(unittest.TestCase):
    def test_registry_exactly_covers_every_family_with_unique_strategy(self) -> None:
        self.assertEqual(FAMILY_EVIDENCE_EXTRACTOR_VERSION, "1.0.0")
        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")
        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.4.0")
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), set(FAMILY_ADMISSION_POLICIES))
        self.assertEqual(len(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), 31)
        strategies = [profile.strategy for profile in FAMILY_EVIDENCE_EXTRACTOR_PROFILES.values()]
        self.assertEqual(len(strategies), len(set(strategies)))
        self.assertTrue(all(profile.channels for profile in FAMILY_EVIDENCE_EXTRACTOR_PROFILES.values()))

    def test_extractor_identity_gates_cannot_drift_from_reasoners(self) -> None:
        self.assertEqual(FAMILY_EXTRACTION_IDENTITY_GATES, FAMILY_IDENTITY_GATES)

    def test_shared_signal_is_namespaced_per_family(self) -> None:
        raw = [ev("input_parameter", "endpoint_schema")]
        sql = scope_family_evidence("sql_injection", raw, channel="alert")
        nosql = scope_family_evidence("nosql_injection", raw, channel="alert")
        self.assertEqual(sql["support"][0]["family_scope"], "sql_injection")
        self.assertEqual(nosql["support"][0]["family_scope"], "nosql_injection")
        self.assertNotEqual(sql["support"][0]["evidence_namespace"], nosql["support"][0]["evidence_namespace"])
        self.assertEqual(sql["extraction_state"], "surface_only")
        self.assertEqual(nosql["extraction_state"], "surface_only")

    def test_pre_scoped_evidence_cannot_be_reassigned(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [ev("input_parameter", "input"), ev("sql_query_surface", "sql")],
            channel="alert",
        )
        reassigned = scope_family_evidence("nosql_injection", packet["support"], channel="alert")
        self.assertEqual(reassigned["support"], [])
        self.assertEqual(reassigned["rejected_cross_family_count"], 2)

    def test_admission_ignores_complete_evidence_scoped_to_other_family(self) -> None:
        wrong_scope = [
            ev("input_parameter", "input", "nosql_injection"),
            ev("sql_query_surface", "sql", "nosql_injection"),
            ev("query_structure_influence", "behavior", "nosql_injection"),
        ]
        self.assertFalse(assess_admission("sql_injection", wrong_scope)["admitted"])
        legacy_unscoped = [
            ev("input_parameter", "input"),
            ev("sql_query_surface", "sql"),
            ev("query_structure_influence", "behavior"),
        ]
        self.assertTrue(assess_admission("sql_injection", legacy_unscoped)["admitted"])

    def test_reasoner_ignores_other_family_scope_even_for_shared_signal_names(self) -> None:
        sql = scope_family_evidence(
            "sql_injection",
            [
                ev("input_parameter", "input"),
                ev("sql_query_surface", "sql"),
                ev("query_structure_influence", "behavior"),
            ],
            channel="candidate",
        )["support"]
        nosql = scope_family_evidence(
            "nosql_injection",
            [
                ev("input_parameter", "input2"),
                ev("nosql_query_surface", "nosql"),
                ev("nosql_operator_accepted", "behavior2"),
            ],
            channel="candidate",
        )["support"]
        combined = [*sql, *nosql]
        sql_row = reason_family("sql_injection", combined, [])
        nosql_row = reason_family("nosql_injection", combined, [])
        self.assertTrue(sql_row["assessment"]["admitted"])
        self.assertTrue(nosql_row["assessment"]["admitted"])
        self.assertEqual(sql_row["condition_hits"], ["query_structure_influence"])
        self.assertEqual(nosql_row["condition_hits"], ["nosql_operator_accepted"])
        self.assertEqual(len(filter_evidence_for_family("sql_injection", combined)), 3)
        self.assertEqual(len(filter_evidence_for_family("nosql_injection", combined)), 3)

    def test_combined_scoped_dossier_keeps_family_rankings_independent(self) -> None:
        sql = scope_family_evidence(
            "sql_injection",
            [ev("input_parameter", "i1"), ev("sql_query_surface", "i2"), ev("query_structure_influence", "i3")],
        )["support"]
        bola = scope_family_evidence(
            "broken_object_authorization",
            [ev("object_identifier", "b1"), ev("object_operation", "b2"), ev("cross_identity_object_access", "b3")],
        )["support"]
        rows = {row["family"]: row for row in rank_families([*sql, *bola], [])}
        self.assertTrue(rows["sql_injection"]["assessment"]["admitted"])
        self.assertTrue(rows["broken_object_authorization"]["assessment"]["admitted"])
        self.assertEqual(rows["nosql_injection"]["family_fit_score"], 0.0)
        self.assertEqual(rows["broken_function_authorization"]["family_fit_score"], 0.0)

    def test_signal_roles_are_derived_from_each_family_policy(self) -> None:
        for family, policy in FAMILY_ADMISSION_POLICIES.items():
            required = list(policy.get("required", []))
            condition_signal = sorted(required[-1])[0]
            with self.subTest(family=family, condition_signal=condition_signal):
                self.assertEqual(evidence_role(family, condition_signal), "condition")
            for index in FAMILY_EXTRACTION_IDENTITY_GATES[family]:
                identity_signal = sorted(required[index])[0]
                if index != len(required) - 1:
                    with self.subTest(family=family, identity_signal=identity_signal):
                        self.assertEqual(evidence_role(family, identity_signal), "identity")

    def test_blocking_controls_are_scoped_and_tagged_as_controls(self) -> None:
        packet = scope_family_evidence(
            "broken_function_authorization",
            [ev("privileged_function", "surface"), ev("state_change", "operation")],
            [ev("lower_privilege_denied", "control")],
        )
        self.assertEqual(packet["contradict"][0]["signal_role"], "control")
        self.assertTrue(packet["contradict"][0]["counts_for_family"])
        self.assertEqual(packet["contradict"][0]["family_scope"], "broken_function_authorization")
        self.assertFalse(assess_admission("broken_function_authorization", packet["support"], packet["contradict"])["admitted"])

    def test_contextual_surface_is_preserved_without_counting_for_family(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [ev("semantic_marker", "semantic")],
        )
        self.assertEqual(packet["support"][0]["signal_role"], "surface")
        self.assertFalse(packet["support"][0]["counts_for_family"])
        self.assertEqual(packet["extraction_state"], "surface_only")


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")

Path("docs/ANALYSIS_ENGINE_6_8_FAMILY_EVIDENCE_EXTRACTION.md").write_text(r'''# Analysis Engine 6.8 — Family-Specific Evidence Extraction

## Purpose

Analysis 6.7 separated family reasoning. Analysis 6.8 moves the same separation one layer earlier: evidence is now namespaced at extraction time so one vulnerability family cannot silently borrow another family's evidence merely because a signal type is shared.

The core invariant is:

`raw recon clue -> family extractor namespace -> hidden hypothesis -> family admission -> family reasoner -> candidate`

## 31 extractor profiles

`app/family_evidence_extractors.py` contains exactly one `FamilyEvidenceExtractorProfile` for every family in `FAMILY_ADMISSION_POLICIES`.

Every profile owns a unique extraction strategy and declares the evidence channels relevant to that family. Examples include object/identity boundaries for BOLA, role/function boundaries for BFLA, SQL query semantics for SQL injection, process-execution semantics for command injection, server-template evaluation for SSTI, filesystem confinement for path traversal, cross-origin credential boundaries for CORS, and atomicity invariants for race conditions.

Import-time validation fails if extractor coverage differs from admission coverage or if a profile is malformed.

## Evidence namespace

Every new candidate/hypothesis evidence item is annotated with:

- `family_scope`
- `evidence_namespace`
- `extractor_id`
- `extractor_version`
- `extractor_rule_version`
- `extractor_channel`
- `signal_role`
- `counts_for_family`
- `extraction_state`

Signal roles are derived from that family's own admission policy:

- `surface`: useful hypothesis context but not policy evidence
- `identity`: identifies the family-specific security boundary
- `condition`: directly supports the vulnerability condition
- `control`: a family-specific blocking/security control
- `contextual_control`: contradictory context that is not a formal blocker

Surface clues remain preserved. They are not deleted merely because they cannot establish a finding.

## Cross-family evidence firewall

Pre-scoped evidence may never be relabeled into a different family. `scope_family_evidence()` quarantines it and reports `rejected_cross_family_count`.

Admission independently ignores evidence whose non-empty `family_scope` belongs to another family.

Family reasoners independently apply the same rule before calculating group coverage, source counts, confounders, admission state, or family fit.

This is defense in depth: an upstream extraction mistake cannot become a downstream family promotion simply through a shared signal name.

## Shared signal names are safe

Some families legitimately use the same abstract signal name. For example `input_parameter` appears in multiple injection policies and `state_change` appears in multiple authorization/business-logic policies.

In 6.8 the same raw clue becomes separate namespaced evidence packets such as:

- `family:sql_injection / input_parameter`
- `family:nosql_injection / input_parameter`

A SQL-scoped input cannot satisfy NoSQL admission or ranking, and vice versa.

## Multi-label behavior

Family isolation does not force a single label. If one raw observation independently establishes two vulnerability conditions, the extraction pipeline creates two separately scoped evidence packets. Each family must satisfy its own admission and reasoner independently.

## Historical benchmark compatibility

Existing Golden v1-v3 fixtures are intentionally unscoped. Unscoped evidence remains readable as legacy evidence so historical regression benchmarks do not change meaning solely because provenance metadata was added.

New production extraction is always scoped. Golden v4 remains a consumed post-freeze evaluation and is not reused as a fresh 6.8 holdout.

## Versions

- Analysis Engine: `6.8.0`
- Candidate Engine: `6.8.0`
- Admission Engine: `2.4.0`
- Family Reasoner: `1.1.0`
- Ranking Engine: `2.1.0`
- Security Family Ranker: `1.1.0`
- Security Reasoning Engine: `6.8.0`
- Family Evidence Extractor: `1.0.0`
- Rule: `2026.08.10.6.8`

## Regression contract

6.8 must preserve:

- weak clues in hidden hypotheses;
- family-specific admission gates;
- target evidence vs external-knowledge separation;
- positive/negative/unknown evidence separation;
- multi-label findings when independently established;
- existing Golden regression behavior for unscoped historical fixtures.

New tests additionally require exact 31-family extractor coverage, unique extraction strategies, extractor/reasoner identity-gate equality, cross-family reassignment rejection, admission isolation, reasoner isolation, control scoping, and shared-signal namespacing.
''', encoding="utf-8")

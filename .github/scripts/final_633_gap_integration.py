from __future__ import annotations

from hashlib import sha256
from pathlib import Path

ROOT = Path('.')


def replace_once(path: str, old: str, new: str) -> None:
    file = ROOT / path
    text = file.read_text(encoding='utf-8')
    if old not in text:
        raise RuntimeError(f'{path}: expected migration anchor not found')
    file.write_text(text.replace(old, new, 1), encoding='utf-8')


EVIDENCE_SCOPE = '''from __future__ import annotations

"""Family evidence namespace and cross-family quarantine.

This module is derived from the strongest isolation property of Analysis 6.33:
evidence explicitly scoped to one vulnerability family must never silently
satisfy another family. Legacy unscoped evidence remains accepted for backward
compatibility, while newly persisted hypothesis evidence is annotated with the
canonical family namespace.
"""

from typing import Any, Iterable, Mapping

FAMILY_EVIDENCE_SCOPE_VERSION = "1.0.0"
FAMILY_EVIDENCE_SCOPE_RULE_VERSION = "2026.08.16.1"


def scope_family_evidence(
    family: str,
    items: Iterable[Mapping[str, Any]],
    *,
    annotate_unscoped: bool,
    channel: str,
) -> dict[str, Any]:
    """Partition evidence into accepted and cross-family quarantined records.

    Explicit cross-family scope fails closed. Unscoped legacy records remain
    readable; callers at persistence boundaries should set ``annotate_unscoped``
    so all newly stored evidence receives a stable family namespace.
    """

    canonical_family = str(family or "").strip()
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for raw in items:
        item = dict(raw)
        existing_scope = str(item.get("family_scope") or "").strip()
        if existing_scope and existing_scope != canonical_family:
            quarantined = dict(item)
            quarantined["scope_rejection_reason"] = "cross_family_evidence"
            quarantined["expected_family_scope"] = canonical_family
            rejected.append(quarantined)
            continue
        if annotate_unscoped and canonical_family:
            item["family_scope"] = canonical_family
            item["evidence_namespace"] = f"family:{canonical_family}"
            item["evidence_scope_version"] = FAMILY_EVIDENCE_SCOPE_VERSION
            item["evidence_scope_rule_version"] = FAMILY_EVIDENCE_SCOPE_RULE_VERSION
            item.setdefault("evidence_scope_channel", str(channel or "unknown"))
        accepted.append(item)
    return {
        "family": canonical_family,
        "accepted": accepted,
        "rejected": rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "version": FAMILY_EVIDENCE_SCOPE_VERSION,
        "rule_version": FAMILY_EVIDENCE_SCOPE_RULE_VERSION,
        "channel": str(channel or "unknown"),
    }
'''
(ROOT / 'app/family_evidence_scope.py').write_text(EVIDENCE_SCOPE, encoding='utf-8')


RESEARCHER_LOGIC = '''from __future__ import annotations

"""Source-free researcher playbooks for canonical final-analyzer families.

Standards and write-up research define methodology only. This projection strips
source/ref/url provenance and exposes reasoning guidance that cannot create or
satisfy target evidence. Admission is computed independently before this logic
is attached to an assessment.
"""

import re
from typing import Any, Mapping

from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec

RESEARCHER_LOGIC_VERSION = "1.0.0"
RESEARCHER_LOGIC_RULE_VERSION = "2026.08.16.1"


def _humanize(value: Any) -> str:
    text = re.sub(r"[_\\-]+", " ", str(value or "").strip())
    return re.sub(r"\\s+", " ", text).strip()


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def researcher_logic_for_family(family: str) -> dict[str, Any]:
    """Return an explanatory playbook with zero target-evidence authority."""

    if family not in MIGRATED_FAMILIES:
        raise KeyError(f"family has no canonical final-analyzer spec: {family}")
    spec = get_detection_spec(family)
    promotion_groups = [set(group) for group in spec.promotion_required]
    decisive = set(promotion_groups[-1]) if promotion_groups else set()
    identity_groups: list[list[str]] = []
    for group in promotion_groups[:-1]:
        values = sorted(_humanize(value) for value in (group - decisive) if _humanize(value))
        if values:
            identity_groups.append(values)

    methodology = _unique([str(step.principle).strip() for step in spec.standard.methodology])
    writeup_logic = _unique([str(item.lesson).strip() for item in spec.standard.writeups])
    controls = sorted(_humanize(value) for value in spec.blocking_contradictions)
    overrides = sorted(_humanize(value) for value in spec.override_signals)

    return {
        "version": RESEARCHER_LOGIC_VERSION,
        "rule_version": RESEARCHER_LOGIC_RULE_VERSION,
        "role": "reasoning_guidance_only_not_target_evidence",
        "family": spec.family,
        "family_spec_version": spec.version,
        "security_principle": str(spec.principle).strip(),
        "research_strategy": str(spec.strategy).strip(),
        "attack_surface_terms": _unique([_humanize(value) for value in spec.standard.surface_terms]),
        "attack_surface_fields": _unique([_humanize(value) for value in spec.standard.surface_fields]),
        "identity_preconditions": identity_groups,
        "decisive_condition_signals": sorted(_humanize(value) for value in decisive),
        "expected_controls": controls,
        "override_conditions": overrides,
        "confounders": list(spec.standard.confounders),
        "false_positive_checks": list(spec.standard.false_positive_checks),
        "methodology_logic": methodology,
        "writeup_logic": writeup_logic,
        "reasoning_sequence": [
            "Establish the family identity from target-specific surface and precondition observations.",
            "Require a direct stored observation of the decisive security condition instead of inferring it from names, keywords, standards, or missing telemetry.",
            "Search for implemented controls and contradictory observations that falsify the vulnerable interpretation.",
            "Keep support, contradiction, and unknown evidence separate; absence of evidence is not evidence of vulnerability or safety.",
            "Treat standards and real-world research as methodology provenance only; they never count as an independent target-evidence source.",
        ],
        "evidence_policy": "advisory_only_non_evidentiary",
    }


def _forbidden_key_present(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower() in {"source", "ref", "url", "counts_as_target_evidence"}:
                return True
            if _forbidden_key_present(child):
                return True
    elif isinstance(value, list):
        return any(_forbidden_key_present(child) for child in value)
    return False


def validate_researcher_logic() -> list[str]:
    errors: list[str] = []
    for family in MIGRATED_FAMILIES:
        logic = researcher_logic_for_family(family)
        if not logic.get("security_principle"):
            errors.append(f"{family}:missing_security_principle")
        if not logic.get("decisive_condition_signals"):
            errors.append(f"{family}:missing_decisive_conditions")
        if not logic.get("writeup_logic"):
            errors.append(f"{family}:missing_writeup_logic")
        if _forbidden_key_present(logic):
            errors.append(f"{family}:provenance_leaked_into_source_free_logic")
    return errors


_ERRORS = validate_researcher_logic()
if _ERRORS:
    raise RuntimeError("Final analyzer researcher logic invalid: " + "; ".join(_ERRORS))
'''
(ROOT / 'app/researcher_logic.py').write_text(RESEARCHER_LOGIC, encoding='utf-8')


# Admission: reject explicitly cross-family evidence before it can satisfy any
# group, attach source-free researcher guidance only after the decision, and
# namespace newly persisted hypothesis evidence.
replace_once(
    'app/hypothesis_admission.py',
    'from family_reasoning import (\n    FAMILY_REASONING_RULE_VERSION,\n    FAMILY_REASONING_VERSION,\n    admission_policy_map,\n)\n',
    'from family_reasoning import (\n    FAMILY_REASONING_RULE_VERSION,\n    FAMILY_REASONING_VERSION,\n    admission_policy_map,\n)\nfrom family_evidence_scope import scope_family_evidence\nfrom researcher_logic import researcher_logic_for_family\n',
)
replace_once(
    'app/hypothesis_admission.py',
    '    support_items = [dict(item) for item in support]\n    contradict_items = [dict(item) for item in (contradict or [])]\n',
    '    raw_support_items = [dict(item) for item in support]\n    raw_contradict_items = [dict(item) for item in (contradict or [])]\n    support_scope = scope_family_evidence(\n        family, raw_support_items, annotate_unscoped=False, channel="admission"\n    )\n    contradict_scope = scope_family_evidence(\n        family, raw_contradict_items, annotate_unscoped=False, channel="admission"\n    )\n    support_items = list(support_scope["accepted"])\n    contradict_items = list(contradict_scope["accepted"])\n',
)
# Add diagnostics to both the missing-policy and normal-policy result paths.
text_path = ROOT / 'app/hypothesis_admission.py'
text = text_path.read_text(encoding='utf-8')
needle = '        result["knowledge_references"] = knowledge_for_family(family)\n'
insert = '''        result["evidence_scope"] = {
            "version": support_scope["version"],
            "rule_version": support_scope["rule_version"],
            "rejected_cross_family_support": int(support_scope["rejected_count"]),
            "rejected_cross_family_contradictions": int(contradict_scope["rejected_count"]),
        }
        result["knowledge_references"] = knowledge_for_family(family)
'''
if needle not in text:
    raise RuntimeError('hypothesis_admission.py: unknown-policy knowledge anchor missing')
text = text.replace(needle, insert, 1)
needle2 = '    result["knowledge_references"] = knowledge_for_family(family)\n'
insert2 = '''    result["evidence_scope"] = {
        "version": support_scope["version"],
        "rule_version": support_scope["rule_version"],
        "rejected_cross_family_support": int(support_scope["rejected_count"]),
        "rejected_cross_family_contradictions": int(contradict_scope["rejected_count"]),
    }
    try:
        result["researcher_logic"] = researcher_logic_for_family(family)
    except KeyError:
        pass
    result["knowledge_references"] = knowledge_for_family(family)
'''
if needle2 not in text:
    raise RuntimeError('hypothesis_admission.py: normal-policy knowledge anchor missing')
text = text.replace(needle2, insert2, 1)
text_path.write_text(text, encoding='utf-8')

replace_once(
    'app/hypothesis_admission.py',
    '    # Admission is fixed first from target evidence only.\n    assessment = assess_admission(family, support, contradict)\n',
    '''    # Persist only evidence that is unscoped legacy data or explicitly belongs
    # to this family. Newly stored evidence is namespaced so later correlation or
    # replay cannot silently rebind it to another vulnerability family.
    persisted_support_scope = scope_family_evidence(
        family, support, annotate_unscoped=True, channel="hypothesis_persistence"
    )
    persisted_contradict_scope = scope_family_evidence(
        family, contradict, annotate_unscoped=True, channel="hypothesis_persistence"
    )
    support = list(persisted_support_scope["accepted"])
    contradict = list(persisted_contradict_scope["accepted"])

    # Admission is fixed first from target evidence only.
    assessment = assess_admission(family, support, contradict)
    assessment.setdefault("evidence_scope", {})["quarantined_at_persistence"] = (
        int(persisted_support_scope["rejected_count"])
        + int(persisted_contradict_scope["rejected_count"])
    )
''',
)


AUDIT_DOC = '''# Final Analyzers — Analysis 6.33 Gap Audit

Audit source: `agent/analysis-engine-6.33-fresh-blind-v8-validation`  
Integration target: `final-analyzers`

## Goal

Use the strongest methodology from Analysis 6.33 without replacing the 8.6
product/evidence runtime or creating a second vulnerability-decision engine.

## Disposition

### Integrated

1. **Source-free researcher playbooks**
   - Derived from canonical `FamilyDetectionSpec` only.
   - Exposes strategy, decisive conditions, controls, confounders, false-positive
     checks, methodology principles, and write-up lessons.
   - Strips source/ref/url provenance from the playbook.
   - Attached only after admission is calculated; it cannot change admission.

2. **Family-scoped evidence isolation**
   - Explicit evidence scoped to another family is quarantined fail-closed.
   - Legacy unscoped evidence remains readable for compatibility.
   - Newly persisted hypothesis evidence receives `family_scope` and
     `evidence_namespace=family:<family>`.
   - Cross-family evidence cannot satisfy required groups or independent-source
     requirements.

### Already covered by final-analyzers

- Standards/methodology/write-up grounding via `family_specs`.
- Knowledge is non-evidentiary.
- Raw Recon context is demoted unless analyzer-owned target evidence is promotion-ready.
- Raw analyzer fan-out is bounded.
- Controls/contradictions and confirmation contracts are canonical Family Reasoning data.
- Temporal/workflow intelligence is context-only.

### Intentionally not ported

1. **Weighted family reasoner admission/scoring**
   - 6.33 family weights, admission bonuses, and confounder penalties remain
     ranking/research ideas only.
   - Final admission remains deterministic evidence-contract evaluation.

2. **Parallel detector execution / raw-condition reconstruction runtime**
   - Wholesale port would create two physical detector runtimes.
   - Useful safety properties already exist in the final analyzer bridge and
     dedicated analyzers: passive-only reconstruction, no knowledge-as-evidence,
     and decisive-condition gating.

### Deferred before main merge

**Structured taxonomy attribution policy** from 6.33 (`direct` vs `contextual`,
`auto_assign`, `when_any`). The current final spec stores taxonomy IDs but does
not yet encode per-reference attribution policy. This should be added as a
metadata/schema migration, not mixed into target-evidence admission.

## Merge principle

`8.6 runtime/product backbone + final-analyzers evidence contracts + selected
6.33 methodology/isolation properties`, with exactly one admission authority.
'''
(ROOT / 'docs/FINAL_ANALYZERS_633_GAP_AUDIT.md').write_text(AUDIT_DOC, encoding='utf-8')


TESTS = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_evidence_scope import scope_family_evidence
from family_specs.registry import MIGRATED_FAMILIES
from hypothesis_admission import assess_admission
from researcher_logic import researcher_logic_for_family, validate_researcher_logic


class Final633GapIntegrationTests(unittest.TestCase):
    def test_researcher_logic_covers_migrated_specs_without_provenance_keys(self):
        self.assertEqual(validate_researcher_logic(), [])
        for family in MIGRATED_FAMILIES:
            logic = researcher_logic_for_family(family)
            self.assertEqual(logic["role"], "reasoning_guidance_only_not_target_evidence")
            self.assertTrue(logic["security_principle"])
            self.assertTrue(logic["decisive_condition_signals"])
            serialized = repr(logic).lower()
            self.assertNotIn("'source':", serialized)
            self.assertNotIn("'ref':", serialized)
            self.assertNotIn("'url':", serialized)
            self.assertNotIn("counts_as_target_evidence", serialized)

    def test_cross_family_scoped_evidence_cannot_admit(self):
        decision = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request", "family_scope": "ssrf"},
            {"type": "sql_query_sink", "source_group": "sink", "family_scope": "ssrf"},
            {"type": "sql_query_influence_observed", "source_group": "behavior", "family_scope": "ssrf"},
        ])
        self.assertFalse(decision["admitted"])
        self.assertEqual(decision["independent_sources"], 0)
        self.assertEqual(decision["evidence_scope"]["rejected_cross_family_support"], 3)

    def test_matching_scope_and_legacy_unscoped_evidence_remain_compatible(self):
        matching = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request", "family_scope": "sql_injection"},
            {"type": "sql_query_sink", "source_group": "sink", "family_scope": "sql_injection"},
            {"type": "sql_query_influence_observed", "source_group": "behavior", "family_scope": "sql_injection"},
        ])
        legacy = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
            {"type": "sql_query_influence_observed", "source_group": "behavior"},
        ])
        self.assertTrue(matching["admitted"])
        self.assertTrue(legacy["admitted"])
        self.assertIn("researcher_logic", matching)
        self.assertEqual(matching["researcher_logic"]["evidence_policy"], "advisory_only_non_evidentiary")

    def test_persistence_scope_annotation_is_deterministic(self):
        packet = scope_family_evidence(
            "ssrf",
            [{"type": "server_fetch_observed", "source_group": "controlled"}],
            annotate_unscoped=True,
            channel="hypothesis_persistence",
        )
        self.assertEqual(packet["rejected_count"], 0)
        item = packet["accepted"][0]
        self.assertEqual(item["family_scope"], "ssrf")
        self.assertEqual(item["evidence_namespace"], "family:ssrf")
        self.assertEqual(item["evidence_scope_channel"], "hypothesis_persistence")

    def test_explicit_cross_family_scope_is_quarantined_not_rebound(self):
        packet = scope_family_evidence(
            "broken_object_authorization",
            [{"type": "unauthorized_object_success", "family_scope": "broken_function_authorization"}],
            annotate_unscoped=True,
            channel="hypothesis_persistence",
        )
        self.assertEqual(packet["accepted_count"], 0)
        self.assertEqual(packet["rejected_count"], 1)
        self.assertEqual(packet["rejected"][0]["scope_rejection_reason"], "cross_family_evidence")


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / 'tests/test_final_633_gap_integration.py').write_text(TESTS, encoding='utf-8')


# Refresh the strict manifest without ever adding this temporary migration script
# or its workflow. Existing listed paths are retained and permanent new files are
# appended deterministically.
manifest = ROOT / 'MANIFEST.sha256'
paths: list[str] = []
for line in manifest.read_text(encoding='utf-8').splitlines():
    if '  ' not in line:
        continue
    _, file_path = line.split('  ', 1)
    if file_path and (ROOT / file_path).exists():
        paths.append(file_path)
paths.extend([
    'app/family_evidence_scope.py',
    'app/researcher_logic.py',
    'docs/FINAL_ANALYZERS_633_GAP_AUDIT.md',
    'tests/test_final_633_gap_integration.py',
])
rows = [
    f"{sha256((ROOT / file_path).read_bytes()).hexdigest()}  {file_path}"
    for file_path in sorted(set(paths))
]
manifest.write_text('\n'.join(rows) + '\n', encoding='utf-8')

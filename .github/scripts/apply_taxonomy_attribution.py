from __future__ import annotations

from pathlib import Path

ROOT = Path('.')


def replace_once(path: str, old: str, new: str) -> None:
    file = ROOT / path
    text = file.read_text(encoding='utf-8')
    if old not in text:
        raise RuntimeError(f'{path}: expected anchor not found: {old[:80]!r}')
    file.write_text(text.replace(old, new, 1), encoding='utf-8')


# Public family-spec API.
replace_once(
    'app/family_specs/__init__.py',
    'from .ssrf import SSRF_STANDARD_SPEC\nfrom .registry import (\n',
    '''from .ssrf import SSRF_STANDARD_SPEC
from .taxonomy_attribution import (
    FAMILY_CWE_ATTRIBUTION,
    TAXONOMY_ATTRIBUTION_RULE_VERSION,
    TAXONOMY_ATTRIBUTION_VERSION,
    TaxonomyAttributionRule,
    resolve_taxonomy_attribution,
    rules_for_family,
    validate_taxonomy_attribution,
)
from .registry import (
''',
)

# Knowledge projection carries attribution policy as non-evidentiary metadata.
replace_once(
    'app/family_specs/knowledge_projection.py',
    'from .base import FamilyDetectionSpec\n\n\nKNOWLEDGE_PROJECTION_VERSION = "1.1.1"\n',
    'from .base import FamilyDetectionSpec\nfrom .taxonomy_attribution import rules_for_family\n\n\nKNOWLEDGE_PROJECTION_VERSION = "1.2.0"\n',
)
replace_once(
    'app/family_specs/knowledge_projection.py',
    'def standard_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:\n    docs: list[dict[str, Any]] = []\n    signals = _classification_signals(spec)\n',
    '''def standard_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    signals = _classification_signals(spec)
    cwe_rules = {rule.ref: rule for rule in rules_for_family(spec.family)}
''',
)
replace_once(
    'app/family_specs/knowledge_projection.py',
    '                    "knowledge_projection_version": KNOWLEDGE_PROJECTION_VERSION,\n                }\n            )\n',
    '''                    "knowledge_projection_version": KNOWLEDGE_PROJECTION_VERSION,
                    "mapping": (
                        cwe_rules[str(ref)].mapping
                        if kind == "cwe" and str(ref) in cwe_rules
                        else "direct"
                    ),
                    "auto_assign": (
                        bool(cwe_rules[str(ref)].auto_assign)
                        if kind == "cwe" and str(ref) in cwe_rules
                        else False
                    ),
                    "when_any": (
                        list(cwe_rules[str(ref)].when_any)
                        if kind == "cwe" and str(ref) in cwe_rules
                        else []
                    ),
                }
            )
''',
)

# Admission remains the sole decision authority; attribution is computed only
# after the admitted boolean and decisive target signals are fixed.
replace_once(
    'app/hypothesis_admission.py',
    'from family_evidence_scope import scope_family_evidence\nfrom researcher_logic import researcher_logic_for_family\n',
    'from family_evidence_scope import scope_family_evidence\nfrom family_specs.taxonomy_attribution import resolve_taxonomy_attribution\nfrom researcher_logic import researcher_logic_for_family\n',
)
replace_once(
    'app/hypothesis_admission.py',
    '    try:\n        result["researcher_logic"] = researcher_logic_for_family(family)\n',
    '''    result["taxonomy_attribution"] = resolve_taxonomy_attribution(
        family,
        admitted=complete,
        decisive_signals=decisive,
    )
    try:
        result["researcher_logic"] = researcher_logic_for_family(family)
''',
)

# Extend the permanent audit disposition.
audit = ROOT / 'docs/FINAL_ANALYZERS_633_GAP_AUDIT.md'
text = audit.read_text(encoding='utf-8')
text = text.replace(
    '### Deferred before main merge\n\n**Structured taxonomy attribution policy** from 6.33 (`direct` vs `contextual`,\n`auto_assign`, `when_any`). The current final spec stores taxonomy IDs but does\nnot yet encode per-reference attribution policy. This should be added as a\nmetadata/schema migration, not mixed into target-evidence admission.\n',
    '''### Integrated after audit

**Structured taxonomy attribution policy** from 6.33 (`direct` vs `contextual`,
`auto_assign`, `when_any`) is now a canonical family-spec-side classification
layer. It resolves only after admission and cannot satisfy target-evidence groups.
Broad/contextual CWE references either require decisive target signals or remain
manual root-cause review only.
''',
)
audit.write_text(text, encoding='utf-8')


TEST = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_specs.knowledge_projection import standard_knowledge_projection
from family_specs.registry import get_detection_spec
from family_specs.taxonomy_attribution import (
    resolve_taxonomy_attribution,
    validate_taxonomy_attribution,
)
from hypothesis_admission import assess_admission


class TaxonomyAttributionTests(unittest.TestCase):
    def test_policy_coverage_matches_all_migrated_specs(self):
        self.assertEqual(validate_taxonomy_attribution(), [])

    def test_bola_assigns_direct_cwe_but_not_broad_contextual_cwe(self):
        result = resolve_taxonomy_attribution(
            "broken_object_authorization",
            admitted=True,
            decisive_signals=("cross_identity_object_access",),
        )
        self.assertEqual(result["assigned_cwe"], ["CWE-639"])
        self.assertEqual(result["manual_review_cwe"], ["CWE-863"])
        self.assertFalse(result["counts_as_target_evidence"])

    def test_bfla_requires_manual_root_cause_cwe_review(self):
        result = resolve_taxonomy_attribution(
            "broken_function_authorization",
            admitted=True,
            decisive_signals=("unauthorized_function_success",),
        )
        self.assertEqual(result["assigned_cwe"], [])
        self.assertEqual(set(result["manual_review_cwe"]), {"CWE-862", "CWE-863"})
        self.assertEqual(result["assignment_state"], "manual_root_cause_review")

    def test_contextual_cwe_requires_decisive_signal(self):
        missing = resolve_taxonomy_attribution(
            "information_disclosure",
            admitted=True,
            decisive_signals=("public_endpoint",),
        )
        self.assertEqual(missing["assigned_cwe"], [])
        self.assertEqual(missing["condition_not_met_cwe"], ["CWE-200"])

        matched = resolve_taxonomy_attribution(
            "information_disclosure",
            admitted=True,
            decisive_signals=("sensitive_marker",),
        )
        self.assertEqual(matched["assigned_cwe"], ["CWE-200"])

    def test_not_admitted_never_assigns_cwe(self):
        result = resolve_taxonomy_attribution(
            "sql_injection",
            admitted=False,
            decisive_signals=("sql_query_influence_observed",),
        )
        self.assertEqual(result["assigned_cwe"], [])
        self.assertEqual(result["assignment_state"], "not_admitted")

    def test_admission_exposes_classification_after_decision(self):
        decision = assess_admission(
            "sql_injection",
            [
                {"type": "input_parameter", "source_group": "surface"},
                {"type": "sql_sink", "source_group": "sink"},
                {"type": "sql_query_influence_observed", "source_group": "runtime"},
            ],
            [],
        )
        attribution = decision["taxonomy_attribution"]
        self.assertEqual(attribution["role"], "classification_only_not_target_evidence")
        if decision["admitted"]:
            self.assertEqual(attribution["assigned_cwe"], ["CWE-89"])
        else:
            self.assertEqual(attribution["assigned_cwe"], [])

    def test_knowledge_docs_carry_mapping_metadata_but_no_evidence_type(self):
        spec = get_detection_spec("broken_object_authorization")
        docs = standard_knowledge_projection(spec)
        cwe = {doc["ref"]: doc for doc in docs if doc["source"] == "MITRE CWE"}
        self.assertEqual(cwe["CWE-639"]["mapping"], "direct")
        self.assertTrue(cwe["CWE-639"]["auto_assign"])
        self.assertEqual(cwe["CWE-863"]["mapping"], "contextual")
        self.assertFalse(cwe["CWE-863"]["auto_assign"])
        self.assertTrue(all(doc["counts_as_target_evidence"] is False for doc in cwe.values()))
        self.assertTrue(all("type" not in doc for doc in cwe.values()))


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / 'tests/test_taxonomy_attribution_final.py').write_text(TEST, encoding='utf-8')

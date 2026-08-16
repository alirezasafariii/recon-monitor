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


# 1) Extend the canonical family-spec schema with per-reference attribution policy.
replace_once(
    'app/family_specs/base.py',
    'FAMILY_SPEC_FRAMEWORK_VERSION = "1.0.0"',
    'FAMILY_SPEC_FRAMEWORK_VERSION = "1.1.0"',
)
replace_once(
    'app/family_specs/base.py',
    '@dataclass(frozen=True)\nclass FamilyStandardSpec:',
    '''@dataclass(frozen=True)\nclass TaxonomyAttributionRule:\n    """Non-evidentiary policy for attributing one standards reference.\n\n    ``mapping`` describes the relationship to the family. ``auto_assign`` only\n    controls post-admission metadata; it can never satisfy an evidence group.\n    ``when_any`` is evaluated against already-decided target evidence signals.\n    """\n\n    namespace: str\n    ref: str\n    mapping: str\n    auto_assign: bool = False\n    when_any: tuple[str, ...] = ()\n\n    def __post_init__(self) -> None:\n        namespace = str(self.namespace or "").strip().lower()\n        if namespace not in {"owasp", "wstg", "cwe", "capec"}:\n            raise ValueError(f"unsupported taxonomy namespace: {self.namespace}")\n        if not str(self.ref or "").strip():\n            raise ValueError("taxonomy attribution ref is required")\n        if self.mapping not in {"direct", "contextual", "methodology"}:\n            raise ValueError(f"invalid taxonomy mapping mode: {self.mapping}")\n        if self.mapping == "methodology" and self.auto_assign:\n            raise ValueError("methodology references cannot be auto-assigned")\n\n    def as_dict(self) -> dict[str, Any]:\n        return {\n            "namespace": str(self.namespace).lower(),\n            "ref": self.ref,\n            "mapping": self.mapping,\n            "auto_assign": bool(self.auto_assign),\n            "when_any": list(self.when_any),\n            "counts_as_target_evidence": False,\n        }\n\n\n@dataclass(frozen=True)\nclass FamilyStandardSpec:''',
)
replace_once(
    'app/family_specs/base.py',
    '    writeups: tuple[WriteupLesson, ...]\n\n    def __post_init__(self) -> None:',
    '    writeups: tuple[WriteupLesson, ...]\n    taxonomy_attribution: tuple[TaxonomyAttributionRule, ...] = ()\n\n    def __post_init__(self) -> None:',
)
replace_once(
    'app/family_specs/base.py',
    '        if any(item.counts_as_target_evidence for item in self.writeups):\n            raise ValueError(f"{self.family}: external knowledge cannot count as target evidence")\n\n    def taxonomy(self) -> dict[str, list[str]]:',
    '''        if any(item.counts_as_target_evidence for item in self.writeups):\n            raise ValueError(f"{self.family}: external knowledge cannot count as target evidence")\n        if self.taxonomy_attribution:\n            expected = {\n                (namespace, ref)\n                for namespace, refs in self.taxonomy().items()\n                for ref in refs\n            }\n            actual = {\n                (str(item.namespace).lower(), item.ref)\n                for item in self.taxonomy_attribution\n            }\n            if len(actual) != len(self.taxonomy_attribution):\n                raise ValueError(f"{self.family}: duplicate taxonomy attribution rule")\n            if actual != expected:\n                missing = sorted(expected - actual)\n                extra = sorted(actual - expected)\n                raise ValueError(\n                    f"{self.family}: taxonomy attribution coverage drift missing={missing} extra={extra}"\n                )\n\n    def taxonomy(self) -> dict[str, list[str]]:''',
)
replace_once(
    'app/family_specs/base.py',
    '    def taxonomy(self) -> dict[str, list[str]]:\n        return {\n            "owasp": list(self.owasp),\n            "wstg": list(self.wstg),\n            "cwe": list(self.cwe),\n            "capec": list(self.capec),\n        }\n\n\n@dataclass(frozen=True)\nclass FamilyDetectionSpec:',
    '''    def taxonomy(self) -> dict[str, list[str]]:\n        return {\n            "owasp": list(self.owasp),\n            "wstg": list(self.wstg),\n            "cwe": list(self.cwe),\n            "capec": list(self.capec),\n        }\n\n    def taxonomy_attribution_policy(self) -> list[dict[str, Any]]:\n        return [item.as_dict() for item in self.taxonomy_attribution]\n\n\n@dataclass(frozen=True)\nclass FamilyDetectionSpec:''',
)
replace_once(
    'app/family_specs/base.py',
    '    def taxonomy(self) -> dict[str, list[str]]:\n        return self.standard.taxonomy()\n\n\ndef _groups',
    '    def taxonomy(self) -> dict[str, list[str]]:\n        return self.standard.taxonomy()\n\n    def taxonomy_attribution_policy(self) -> list[dict[str, Any]]:\n        return self.standard.taxonomy_attribution_policy()\n\n\ndef _groups',
)


TAXONOMY_MODULE = r'''from __future__ import annotations

"""Structured, non-evidentiary taxonomy attribution for final analyzers.

Taxonomy never participates in admission. The evaluator runs only after the
family evidence contract has decided whether a hypothesis is admitted. WSTG is
testing methodology, CAPEC is attack-pattern context, OWASP is risk/methodology
grounding, and CWE is assigned only where a reviewed root-cause policy permits
it.
"""

from dataclasses import replace
from typing import Any, Iterable

from .base import FamilyDetectionSpec, FamilyStandardSpec, TaxonomyAttributionRule

TAXONOMY_ATTRIBUTION_VERSION = "1.0.0"
TAXONOMY_ATTRIBUTION_RULE_VERSION = "2026.08.16.1"

# Conservative defaults: standards are grounding first. CWE auto-assignment is
# opt-in per reviewed family/reference below.
_CWE_OVERRIDES: dict[tuple[str, str], tuple[str, bool, tuple[str, ...]]] = {
    ("broken_object_authorization", "CWE-639"): ("direct", True, ()),
    ("mass_assignment", "CWE-915"): ("direct", True, ()),
    ("ssrf", "CWE-918"): ("direct", True, ()),
    ("file_upload", "CWE-434"): ("direct", True, ()),
    ("path_traversal", "CWE-22"): ("direct", True, ()),
    ("sql_injection", "CWE-89"): ("direct", True, ()),
    ("dom_xss", "CWE-79"): ("direct", True, ()),
    ("cors_misconfiguration", "CWE-942"): ("direct", True, ()),
    ("open_redirect", "CWE-601"): ("direct", True, ()),
    ("account_enumeration", "CWE-204"): ("direct", True, ()),
    ("postmessage_trust", "CWE-346"): (
        "direct", True, ("untrusted_message_accepted",)
    ),
    ("graphql_authorization", "CWE-639"): (
        "direct", True,
        ("graphql_unauthorized_object_response", "graphql_authorization_differential"),
    ),
    ("authentication_session", "CWE-287"): (
        "contextual", True, ("authentication_state_violation",)
    ),
    ("authentication_session", "CWE-613"): (
        "contextual", True, ("session_reuse_after_logout",)
    ),
    ("authentication_session", "CWE-640"): (
        "contextual", True, ("recovery_bypass",)
    ),
    # CWE-384 remains manual: token non-rotation alone does not establish session
    # fixation without evidence that an attacker can predetermine the session.
    ("information_disclosure", "CWE-200"): (
        "contextual", True, ("sensitive_response_observed", "private_field_publicly_observed")
    ),
    ("source_map_exposure", "CWE-200"): (
        "contextual", True, ("source_map_publicly_reachable", "sensitive_source_content_observed")
    ),
    # CWE-798/CWE-321 remain manual because exposed credential material need not
    # be hard-coded. CWE-200 is safe only after actual exposure admission.
    ("secret_exposure", "CWE-200"): (
        "contextual", True, ("credential_material_confirmed", "live_secret_context")
    ),
}

_OWASP_CONTEXTUAL: set[tuple[str, str]] = {
    ("account_enumeration", "A07:2025 Authentication Failures"),
    ("information_disclosure", "A02:2025 Security Misconfiguration"),
    ("secret_exposure", "A07:2025 Authentication Failures"),
}


def _default_rule(family: str, namespace: str, ref: str) -> TaxonomyAttributionRule:
    namespace = str(namespace).lower()
    if namespace == "wstg":
        return TaxonomyAttributionRule(namespace, ref, "methodology", False, ())
    if namespace == "capec":
        return TaxonomyAttributionRule(namespace, ref, "contextual", False, ())
    if namespace == "owasp":
        lower = ref.lower()
        mapping = "methodology" if "cheat sheet" in lower else (
            "contextual" if (family, ref) in _OWASP_CONTEXTUAL else "direct"
        )
        return TaxonomyAttributionRule(namespace, ref, mapping, False, ())
    override = _CWE_OVERRIDES.get((family, ref))
    if override:
        mapping, auto_assign, when_any = override
        return TaxonomyAttributionRule(namespace, ref, mapping, auto_assign, when_any)
    return TaxonomyAttributionRule(namespace, ref, "contextual", False, ())


def apply_taxonomy_attribution(standard: FamilyStandardSpec) -> FamilyStandardSpec:
    """Return the canonical spec with complete per-reference policy attached."""
    rules = tuple(
        _default_rule(standard.family, namespace, ref)
        for namespace, refs in standard.taxonomy().items()
        for ref in refs
    )
    return replace(standard, taxonomy_attribution=rules)


def evaluate_taxonomy_attribution(
    spec: FamilyDetectionSpec,
    *,
    admitted: bool,
    decisive_signals: Iterable[str],
) -> dict[str, Any]:
    """Evaluate post-admission taxonomy metadata without changing the decision."""
    signals = {str(item) for item in decisive_signals if str(item).strip()}
    assigned: dict[str, list[str]] = {"owasp": [], "wstg": [], "cwe": [], "capec": []}
    manual_review: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for rule in spec.standard.taxonomy_attribution:
        conditions = set(rule.when_any)
        conditions_met = not conditions or bool(conditions & signals)
        auto_eligible = bool(admitted and rule.auto_assign and conditions_met)
        state = "assigned" if auto_eligible else (
            "not_admitted" if not admitted else (
                "conditions_not_met" if rule.auto_assign and not conditions_met else "manual_or_grounding_only"
            )
        )
        row = rule.as_dict()
        row.update({
            "conditions_met": conditions_met,
            "state": state,
        })
        decisions.append(row)
        if auto_eligible:
            assigned[str(rule.namespace).lower()].append(rule.ref)
        elif admitted and rule.mapping != "methodology":
            manual_review.append(row)

    return {
        "version": TAXONOMY_ATTRIBUTION_VERSION,
        "rule_version": TAXONOMY_ATTRIBUTION_RULE_VERSION,
        "role": "post_admission_metadata_only",
        "counts_as_target_evidence": False,
        "grounding_taxonomy": spec.taxonomy(),
        "assigned_taxonomy": assigned,
        "manual_review": manual_review,
        "decisions": decisions,
        "assignment_state": (
            "assigned" if any(assigned.values()) else (
                "manual_root_cause_review" if admitted else "not_admitted"
            )
        ),
    }


def validate_taxonomy_attribution_spec(
    spec: FamilyDetectionSpec,
) -> list[str]:
    errors: list[str] = []
    standard = spec.standard
    expected = {
        (namespace, ref)
        for namespace, refs in standard.taxonomy().items()
        for ref in refs
    }
    actual = {
        (str(rule.namespace).lower(), rule.ref)
        for rule in standard.taxonomy_attribution
    }
    if expected != actual:
        errors.append("taxonomy_policy_coverage_drift")
    if len(actual) != len(standard.taxonomy_attribution):
        errors.append("duplicate_taxonomy_policy")

    allowed_signals = set(spec.override_signals)
    for group in spec.promotion_required:
        allowed_signals.update(group)
    for group in spec.confirmation_required:
        allowed_signals.update(group)

    for rule in standard.taxonomy_attribution:
        if rule.mapping == "methodology" and rule.auto_assign:
            errors.append(f"methodology_auto_assignment:{rule.namespace}:{rule.ref}")
        if rule.when_any and not set(rule.when_any).issubset(allowed_signals):
            unknown = sorted(set(rule.when_any) - allowed_signals)
            errors.append(f"unknown_assignment_signal:{rule.ref}:{','.join(unknown)}")
        if str(rule.namespace).lower() in {"wstg", "capec"} and rule.auto_assign:
            errors.append(f"non_root_taxonomy_auto_assignment:{rule.namespace}:{rule.ref}")
    return errors
'''
(ROOT / 'app/family_specs/taxonomy_attribution.py').write_text(TAXONOMY_MODULE, encoding='utf-8')


# 2) Make the registry's canonical specs policy-complete without duplicating the
# family standard files. The imported raw constants remain source definitions;
# get_standard_spec/get_detection_spec return the reviewed decorated specs.
replace_once(
    'app/family_specs/registry.py',
    'from .base import FamilyDetectionSpec, FamilyStandardSpec, compose_detection_spec\n',
    'from .base import FamilyDetectionSpec, FamilyStandardSpec, compose_detection_spec\nfrom .taxonomy_attribution import apply_taxonomy_attribution, validate_taxonomy_attribution_spec\n',
)
replace_once(
    'app/family_specs/registry.py',
    'FAMILY_SPEC_REGISTRY_VERSION = "1.6.0"',
    'FAMILY_SPEC_REGISTRY_VERSION = "1.7.0"',
)
replace_once(
    'app/family_specs/registry.py',
    'FAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {',
    '_RAW_FAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {',
)
replace_once(
    'app/family_specs/registry.py',
    '    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,\n}\n\n\ndef _build_detection_specs()',
    '''    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,\n}\n\nFAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {\n    family: apply_taxonomy_attribution(spec)\n    for family, spec in _RAW_FAMILY_STANDARD_SPECS.items()\n}\n\n\ndef _build_detection_specs()''',
)
replace_once(
    'app/family_specs/registry.py',
    '        if any(item.counts_as_target_evidence for item in spec.standard.writeups):\n            errors.append(f"{family}:external_knowledge_counted_as_evidence")\n\n        expected_groups',
    '''        if any(item.counts_as_target_evidence for item in spec.standard.writeups):\n            errors.append(f"{family}:external_knowledge_counted_as_evidence")\n        for taxonomy_error in validate_taxonomy_attribution_spec(spec):\n            errors.append(f"{family}:{taxonomy_error}")\n\n        expected_groups''',
)
replace_once(
    'app/family_specs/registry.py',
    '        "knowledge_is_non_evidentiary": True,\n        "errors": validate_family_spec_registry(),',
    '        "knowledge_is_non_evidentiary": True,\n        "taxonomy_attribution_is_post_admission_only": True,\n        "errors": validate_family_spec_registry(),',
)


# 3) Export the schema/engine through the family_specs package.
replace_once(
    'app/family_specs/__init__.py',
    '    MethodologyStep,\n    WriteupLesson,\n    compose_detection_spec,\n)',
    '    MethodologyStep,\n    TaxonomyAttributionRule,\n    WriteupLesson,\n    compose_detection_spec,\n)',
)
replace_once(
    'app/family_specs/__init__.py',
    'from .ssrf import SSRF_STANDARD_SPEC\nfrom .registry import (',
    '''from .ssrf import SSRF_STANDARD_SPEC\nfrom .taxonomy_attribution import (\n    TAXONOMY_ATTRIBUTION_RULE_VERSION,\n    TAXONOMY_ATTRIBUTION_VERSION,\n    apply_taxonomy_attribution,\n    evaluate_taxonomy_attribution,\n    validate_taxonomy_attribution_spec,\n)\nfrom .registry import (''',
)


# 4) Attach attribution only after admission has been fixed from target evidence.
replace_once(
    'app/hypothesis_admission.py',
    'from family_evidence_scope import scope_family_evidence\nfrom researcher_logic import researcher_logic_for_family\n',
    '''from family_evidence_scope import scope_family_evidence\nfrom family_specs.registry import get_detection_spec\nfrom family_specs.taxonomy_attribution import evaluate_taxonomy_attribution\nfrom researcher_logic import researcher_logic_for_family\n''',
)
replace_once(
    'app/hypothesis_admission.py',
    'ADMISSION_ENGINE_VERSION = "2.0.0"\nADMISSION_RULE_VERSION = "2026.08.15.4"',
    'ADMISSION_ENGINE_VERSION = "2.1.0"\nADMISSION_RULE_VERSION = "2026.08.16.1"',
)
replace_once(
    'app/hypothesis_admission.py',
    'FAMILY_ADMISSION_POLICIES: dict[str, dict[str, Any]] = admission_policy_map()\n\n\ndef _loads',
    '''FAMILY_ADMISSION_POLICIES: dict[str, dict[str, Any]] = admission_policy_map()\n\n\ndef _taxonomy_attribution(\n    family: str,\n    *,\n    admitted: bool,\n    decisive_signals: Iterable[str],\n) -> dict[str, Any] | None:\n    try:\n        spec = get_detection_spec(family)\n    except KeyError:\n        return None\n    return evaluate_taxonomy_attribution(\n        spec, admitted=admitted, decisive_signals=decisive_signals\n    )\n\n\ndef _loads''',
)
# Unknown-family path: no reviewed spec usually exists, but keep helper fail-closed.
replace_once(
    'app/hypothesis_admission.py',
    '        result["knowledge_references"] = knowledge_for_family(family)\n        result["knowledge_context"] = _classification_context(',
    '''        taxonomy = _taxonomy_attribution(\n            family, admitted=False, decisive_signals=result["decisive_signals"]\n        )\n        if taxonomy is not None:\n            result["taxonomy_attribution"] = taxonomy\n        result["knowledge_references"] = knowledge_for_family(family)\n        result["knowledge_context"] = _classification_context(''',
)
# Normal path: assignment is derived after `complete` and `decisive` are final.
text_path = ROOT / 'app/hypothesis_admission.py'
text = text_path.read_text(encoding='utf-8')
needle = '    result["knowledge_references"] = knowledge_for_family(family)\n    result["knowledge_context"] = _classification_context(\n'
insert = '''    taxonomy = _taxonomy_attribution(\n        family, admitted=complete, decisive_signals=decisive\n    )\n    if taxonomy is not None:\n        result["taxonomy_attribution"] = taxonomy\n    result["knowledge_references"] = knowledge_for_family(family)\n    result["knowledge_context"] = _classification_context(\n'''
if needle not in text:
    raise RuntimeError('hypothesis_admission.py: normal taxonomy anchor missing')
text = text.replace(needle, insert, 1)
text_path.write_text(text, encoding='utf-8')


# 5) Close the previously documented 6.33 taxonomy gap.
audit = ROOT / 'docs/FINAL_ANALYZERS_633_GAP_AUDIT.md'
audit_text = audit.read_text(encoding='utf-8')
old = '''### Deferred before main merge\n\n**Structured taxonomy attribution policy** from 6.33 (`direct` vs `contextual`,\n`auto_assign`, `when_any`). The current final spec stores taxonomy IDs but does\nnot yet encode per-reference attribution policy. This should be added as a\nmetadata/schema migration, not mixed into target-evidence admission.\n'''
new = '''### Integrated after the initial audit\n\n**Structured taxonomy attribution policy** is now part of the canonical final\nspec projection. Every migrated OWASP/WSTG/CWE/CAPEC reference receives a\nreviewed `direct`, `contextual`, or `methodology` relationship plus explicit\n`auto_assign` / `when_any` behavior. Assignment runs only after target-evidence\nadmission is fixed. WSTG/CAPEC never auto-assign, ambiguous CWE root causes stay\nmanual, and standards still contribute zero target evidence.\n\n### Remaining before main merge\n\nNo Analysis 6.33 detector/reasoner runtime is intentionally pending. Remaining\nwork is merge hardening: feature freeze, final diff review, full CI, and branch\nprotection/PR review rather than adding a parallel reasoning engine.\n'''
if old not in audit_text:
    raise RuntimeError('audit deferred taxonomy section missing')
audit.write_text(audit_text.replace(old, new, 1), encoding='utf-8')


TESTS = r'''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec, validate_family_spec_registry
from family_specs.taxonomy_attribution import evaluate_taxonomy_attribution
from hypothesis_admission import assess_admission


class FinalTaxonomyAttributionTests(unittest.TestCase):
    def test_every_migrated_reference_has_exactly_one_policy(self):
        self.assertEqual(validate_family_spec_registry(), [])
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            expected = {
                (namespace, ref)
                for namespace, refs in spec.taxonomy().items()
                for ref in refs
            }
            actual = {
                (item["namespace"], item["ref"])
                for item in spec.taxonomy_attribution_policy()
            }
            self.assertEqual(actual, expected, family)
            self.assertEqual(len(actual), len(spec.taxonomy_attribution_policy()), family)

    def test_sql_injection_cwe_is_assigned_only_after_admission(self):
        hidden = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
        ])
        self.assertFalse(hidden["admitted"])
        self.assertEqual(hidden["taxonomy_attribution"]["assigned_taxonomy"]["cwe"], [])

        admitted = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
            {"type": "sql_query_influence_observed", "source_group": "behavior"},
        ])
        self.assertTrue(admitted["admitted"])
        self.assertIn("CWE-89", admitted["taxonomy_attribution"]["assigned_taxonomy"]["cwe"])
        self.assertFalse(admitted["taxonomy_attribution"]["counts_as_target_evidence"])

    def test_bfla_generic_authorization_cwes_remain_manual(self):
        spec = get_detection_spec("broken_function_authorization")
        packet = evaluate_taxonomy_attribution(
            spec,
            admitted=True,
            decisive_signals={"privileged_function", "state_change", "unauthorized_function_success"},
        )
        self.assertEqual(packet["assigned_taxonomy"]["cwe"], [])
        manual_refs = {item["ref"] for item in packet["manual_review"]}
        self.assertIn("CWE-862", manual_refs)
        self.assertIn("CWE-863", manual_refs)

    def test_authentication_cwe_assignment_is_condition_specific(self):
        spec = get_detection_spec("authentication_session")
        recovery = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"recovery_bypass"}
        )
        self.assertIn("CWE-640", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-287", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-613", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-384", recovery["assigned_taxonomy"]["cwe"])

        logout = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"session_reuse_after_logout"}
        )
        self.assertIn("CWE-613", logout["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-640", logout["assigned_taxonomy"]["cwe"])

        non_rotation = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"token_not_rotated"}
        )
        self.assertNotIn("CWE-384", non_rotation["assigned_taxonomy"]["cwe"])

    def test_wstg_and_capec_never_auto_assign(self):
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            packet = evaluate_taxonomy_attribution(
                spec,
                admitted=True,
                decisive_signals={
                    signal
                    for group in spec.promotion_required
                    for signal in group
                },
            )
            self.assertEqual(packet["assigned_taxonomy"]["wstg"], [], family)
            self.assertEqual(packet["assigned_taxonomy"]["capec"], [], family)

    def test_graphql_object_boundary_can_assign_specific_key_bypass_cwe(self):
        spec = get_detection_spec("graphql_authorization")
        packet = evaluate_taxonomy_attribution(
            spec,
            admitted=True,
            decisive_signals={"graphql_authorization_differential"},
        )
        self.assertIn("CWE-639", packet["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-862", packet["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-863", packet["assigned_taxonomy"]["cwe"])

    def test_taxonomy_assignment_does_not_create_admission(self):
        spec = get_detection_spec("ssrf")
        taxonomy = evaluate_taxonomy_attribution(
            spec, admitted=False, decisive_signals={"server_fetch_observed"}
        )
        self.assertEqual(taxonomy["assigned_taxonomy"]["cwe"], [])
        self.assertEqual(taxonomy["assignment_state"], "not_admitted")


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / 'tests/test_final_taxonomy_attribution.py').write_text(TESTS, encoding='utf-8')


# Refresh strict manifest, preserving existing listed files and adding only
# permanent new files. Temporary migration assets are deliberately excluded.
manifest = ROOT / 'MANIFEST.sha256'
paths: list[str] = []
for line in manifest.read_text(encoding='utf-8').splitlines():
    if '  ' not in line:
        continue
    _, file_path = line.split('  ', 1)
    if file_path and (ROOT / file_path).exists():
        paths.append(file_path)
paths.extend([
    'app/family_specs/taxonomy_attribution.py',
    'tests/test_final_taxonomy_attribution.py',
])
rows = [
    f"{sha256((ROOT / file_path).read_bytes()).hexdigest()}  {file_path}"
    for file_path in sorted(set(paths))
]
manifest.write_text('\n'.join(rows) + '\n', encoding='utf-8')

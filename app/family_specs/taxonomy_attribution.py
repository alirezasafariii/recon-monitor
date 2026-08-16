from __future__ import annotations

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

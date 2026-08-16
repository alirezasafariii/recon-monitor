from __future__ import annotations

"""Structured taxonomy attribution for canonical final-analyzer families.

Taxonomy describes and classifies an already-decided target condition. It never
creates target evidence and never participates in admission. Attribution is
resolved only after admission from the admitted state plus decisive target
signals.
"""

from dataclasses import dataclass
from typing import Any, Iterable

TAXONOMY_ATTRIBUTION_VERSION = "1.0.2"
TAXONOMY_ATTRIBUTION_RULE_VERSION = "2026.08.16.3"


@dataclass(frozen=True)
class TaxonomyAttributionRule:
    kind: str
    ref: str
    mapping: str = "direct"
    auto_assign: bool = True
    when_any: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"cwe", "owasp", "wstg", "capec"}:
            raise ValueError(f"unsupported taxonomy kind: {self.kind}")
        if self.mapping not in {"direct", "contextual"}:
            raise ValueError(f"unsupported mapping mode: {self.mapping}")
        if not self.ref:
            raise ValueError("taxonomy reference is required")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "mapping": self.mapping,
            "auto_assign": bool(self.auto_assign),
            "when_any": list(self.when_any),
            "counts_as_target_evidence": False,
        }


def _cwe(
    ref: str,
    *,
    mapping: str = "direct",
    auto_assign: bool = True,
    when_any: Iterable[str] = (),
) -> TaxonomyAttributionRule:
    return TaxonomyAttributionRule(
        kind="cwe",
        ref=ref,
        mapping=mapping,
        auto_assign=auto_assign,
        when_any=tuple(str(value) for value in when_any),
    )


# Ported selectively from Analysis 6.33. The canonical final-analyzer spec is
# authoritative for which references exist; these rules only describe how a
# matching reference may be attributed after admission.
FAMILY_CWE_ATTRIBUTION: dict[str, tuple[TaxonomyAttributionRule, ...]] = {
    "broken_object_authorization": (
        _cwe("CWE-639"),
        _cwe("CWE-863", mapping="contextual", auto_assign=False),
    ),
    "broken_function_authorization": (
        _cwe("CWE-862", mapping="contextual", auto_assign=False),
        _cwe("CWE-863", mapping="contextual", auto_assign=False),
    ),
    "mass_assignment": (_cwe("CWE-915"),),
    "ssrf": (_cwe("CWE-918"),),
    "file_upload": (_cwe("CWE-434"),),
    "path_traversal": (_cwe("CWE-22"),),
    "sql_injection": (_cwe("CWE-89"),),
    "dom_xss": (_cwe("CWE-79"),),
    "cors_misconfiguration": (_cwe("CWE-942"),),
    "authentication_session": (
        _cwe(
            "CWE-287",
            mapping="contextual",
            auto_assign=True,
            when_any=(
                "authentication_boundary_regression",
                "boundary_regression",
                "protected_to_public",
                "session_validation_failure",
            ),
        ),
    ),
    "open_redirect": (_cwe("CWE-601"),),
    "postmessage_trust": (
        _cwe(
            "CWE-940",
            auto_assign=True,
            when_any=(
                "missing_origin_check",
                "missing_source_window_check",
                "message_schema_unvalidated",
            ),
        ),
        _cwe(
            "CWE-346",
            mapping="contextual",
            auto_assign=False,
            when_any=(
                "missing_origin_check",
                "wildcard_origin",
                "missing_source_window_check",
            ),
        ),
    ),
    "graphql_authorization": (
        _cwe("CWE-862", mapping="contextual", auto_assign=False),
        _cwe("CWE-863", mapping="contextual", auto_assign=False),
    ),
    "account_enumeration": (_cwe("CWE-204"),),
    "information_disclosure": (
        _cwe(
            "CWE-200",
            mapping="contextual",
            auto_assign=True,
            when_any=(
                "sensitive_fields",
                "secret_pattern",
                "debug_information",
                "sensitive_marker",
                "sensitive_expansion",
            ),
        ),
    ),
    "source_map_exposure": (
        _cwe(
            "CWE-200",
            mapping="contextual",
            auto_assign=True,
            when_any=("internal_sources", "source_contents"),
        ),
    ),
    "secret_exposure": (
        _cwe(
            "CWE-798",
            mapping="contextual",
            auto_assign=True,
            when_any=("credential_context", "token_exposure", "non_placeholder_secret"),
        ),
        _cwe("CWE-200", mapping="contextual", auto_assign=False),
    ),
}


def rules_for_family(family: str) -> tuple[TaxonomyAttributionRule, ...]:
    """Resolve explicit 6.33 rules against the authoritative final spec.

    Rules for references absent from the final spec are ignored. References in
    the final spec without a reviewed explicit rule fail closed to
    contextual/manual-only attribution rather than being guessed as direct.
    """

    family_name = str(family)
    explicit_all = list(FAMILY_CWE_ATTRIBUTION.get(family_name, ()))
    try:
        from .registry import FAMILY_STANDARD_SPECS

        standard = FAMILY_STANDARD_SPECS.get(family_name)
    except (ImportError, AttributeError):
        standard = None
    if standard is None:
        return tuple(explicit_all)

    spec_refs = set(standard.cwe)
    explicit = [rule for rule in explicit_all if rule.ref in spec_refs]
    explicit_refs = {rule.ref for rule in explicit}
    for ref in standard.cwe:
        if ref in explicit_refs:
            continue
        explicit.append(_cwe(ref, mapping="contextual", auto_assign=False))
    return tuple(explicit)


def resolve_taxonomy_attribution(
    family: str,
    *,
    admitted: bool,
    decisive_signals: Iterable[str] = (),
) -> dict[str, Any]:
    """Resolve CWE attribution without changing the vulnerability decision."""

    rules = rules_for_family(family)
    signals = {str(value) for value in decisive_signals if str(value)}
    assigned: list[str] = []
    manual: list[str] = []
    blocked_by_conditions: list[str] = []

    for rule in rules:
        if not admitted:
            continue
        if not rule.auto_assign:
            manual.append(rule.ref)
            continue
        conditions = set(rule.when_any)
        if conditions and not (conditions & signals):
            blocked_by_conditions.append(rule.ref)
            continue
        assigned.append(rule.ref)

    if not admitted:
        state = "not_admitted"
    elif assigned:
        state = "assigned"
    else:
        state = "manual_root_cause_review"

    return {
        "family": str(family),
        "version": TAXONOMY_ATTRIBUTION_VERSION,
        "rule_version": TAXONOMY_ATTRIBUTION_RULE_VERSION,
        "role": "classification_only_not_target_evidence",
        "assigned_cwe": assigned,
        "manual_review_cwe": manual,
        "condition_not_met_cwe": blocked_by_conditions,
        "assignment_state": state,
        "rules": [rule.as_dict() for rule in rules],
        "counts_as_target_evidence": False,
    }


def validate_taxonomy_attribution() -> list[str]:
    """Validate effective policy coverage and reference drift against specs."""

    from .registry import FAMILY_STANDARD_SPECS, MIGRATED_FAMILIES

    errors: list[str] = []
    if set(FAMILY_CWE_ATTRIBUTION) != set(MIGRATED_FAMILIES):
        missing = sorted(set(MIGRATED_FAMILIES) - set(FAMILY_CWE_ATTRIBUTION))
        extra = sorted(set(FAMILY_CWE_ATTRIBUTION) - set(MIGRATED_FAMILIES))
        if missing:
            errors.append(f"missing_family_policy:{','.join(missing)}")
        if extra:
            errors.append(f"extra_family_policy:{','.join(extra)}")

    for family in MIGRATED_FAMILIES:
        spec_refs = set(FAMILY_STANDARD_SPECS[family].cwe)
        policy_refs = {rule.ref for rule in rules_for_family(family)}
        if spec_refs != policy_refs:
            errors.append(
                f"{family}:cwe_policy_drift:spec={sorted(spec_refs)}:policy={sorted(policy_refs)}"
            )
        for rule in rules_for_family(family):
            if rule.kind != "cwe":
                errors.append(f"{family}:{rule.ref}:non_cwe_rule_in_cwe_policy")
            if rule.mapping == "contextual" and rule.auto_assign and not rule.when_any:
                errors.append(f"{family}:{rule.ref}:contextual_auto_assign_without_condition")
    return errors

from __future__ import annotations

"""Incremental registry for canonical Analysis Brain family specifications.

Only migrated families are registered here. The registry composes standards and
write-up methodology with the existing canonical Family Reasoning contract, so
there is no second admission policy to drift.
"""

from typing import Any

import family_reasoning as _reasoning

from .base import FamilyDetectionSpec, FamilyStandardSpec, compose_detection_spec
from .broken_function_authorization import BFLA_STANDARD_SPEC
from .broken_object_authorization import BOLA_STANDARD_SPEC
from .dom_xss import DOM_XSS_STANDARD_SPEC
from .sql_injection import SQL_INJECTION_STANDARD_SPEC
from .ssrf import SSRF_STANDARD_SPEC


FAMILY_SPEC_REGISTRY_VERSION = "1.3.0"
MIGRATED_FAMILIES = (
    "broken_object_authorization",
    "broken_function_authorization",
    "ssrf",
    "sql_injection",
    "dom_xss",
)

FAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {
    BOLA_STANDARD_SPEC.family: BOLA_STANDARD_SPEC,
    BFLA_STANDARD_SPEC.family: BFLA_STANDARD_SPEC,
    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,
    SQL_INJECTION_STANDARD_SPEC.family: SQL_INJECTION_STANDARD_SPEC,
    DOM_XSS_STANDARD_SPEC.family: DOM_XSS_STANDARD_SPEC,
}


def _build_detection_specs() -> dict[str, FamilyDetectionSpec]:
    result: dict[str, FamilyDetectionSpec] = {}
    for family, standard in FAMILY_STANDARD_SPECS.items():
        contract = _reasoning.FAMILY_REASONING.get(family)
        if not contract:
            raise RuntimeError(f"{family}: canonical Family Reasoning contract is missing")
        result[family] = compose_detection_spec(
            standard,
            contract,
            reasoning_version=_reasoning.FAMILY_REASONING_VERSION,
            reasoning_rule_version=_reasoning.FAMILY_REASONING_RULE_VERSION,
        )
    return result


FAMILY_DETECTION_SPECS = _build_detection_specs()


def validate_family_spec_registry() -> list[str]:
    errors: list[str] = []
    if set(MIGRATED_FAMILIES) != set(FAMILY_STANDARD_SPECS):
        errors.append("migrated family coverage does not match the standard-spec registry")

    strategies = [spec.strategy for spec in FAMILY_DETECTION_SPECS.values()]
    if len(strategies) != len(set(strategies)):
        errors.append("migrated family strategies must be unique")

    for family, spec in FAMILY_DETECTION_SPECS.items():
        live = _reasoning.FAMILY_REASONING.get(family, {})
        if not spec.standard.owasp:
            errors.append(f"{family}:missing_owasp")
        if not spec.standard.wstg:
            errors.append(f"{family}:missing_wstg")
        if not spec.standard.cwe:
            errors.append(f"{family}:missing_cwe")
        if not spec.standard.writeups:
            errors.append(f"{family}:missing_writeup")
        if any(item.counts_as_target_evidence for item in spec.standard.writeups):
            errors.append(f"{family}:external_knowledge_counted_as_evidence")

        expected_groups = tuple(
            frozenset(str(item) for item in group)
            for group in live.get("promotion_required", ())
        )
        if spec.promotion_required != expected_groups:
            errors.append(f"{family}:promotion_contract_drift")
        expected_confirmation = tuple(
            frozenset(str(item) for item in group)
            for group in live.get("confirmation_required", ())
        )
        if spec.confirmation_required != expected_confirmation:
            errors.append(f"{family}:confirmation_contract_drift")
        if spec.blocking_contradictions != frozenset(live.get("blocking_contradictions", ())):
            errors.append(f"{family}:blocking_contradiction_drift")
        if spec.override_signals != frozenset(live.get("override_signals", ())):
            errors.append(f"{family}:override_signal_drift")
        if spec.min_independent_sources != int(live.get("min_independent_sources", 1)):
            errors.append(f"{family}:independent_source_drift")
    return errors


_ERRORS = validate_family_spec_registry()
if _ERRORS:
    raise RuntimeError("Family specification registry invalid: " + "; ".join(_ERRORS))


def get_standard_spec(family: str) -> FamilyStandardSpec:
    return FAMILY_STANDARD_SPECS[str(family)]


def get_detection_spec(family: str) -> FamilyDetectionSpec:
    return FAMILY_DETECTION_SPECS[str(family)]


def registry_status() -> dict[str, Any]:
    return {
        "version": FAMILY_SPEC_REGISTRY_VERSION,
        "coverage_mode": "incremental_reference_implementation",
        "migrated_families": list(MIGRATED_FAMILIES),
        "knowledge_is_non_evidentiary": True,
        "errors": validate_family_spec_registry(),
    }

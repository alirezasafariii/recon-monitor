from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

INJECTION_COLLECTOR_VERSION = "1.0.0"
INJECTION_COLLECTOR_RULE_VERSION = "2026.08.12.6.16"
INJECTION_FAMILIES = (
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "server_side_template_injection",
    "ldap_injection",
)

INJECTION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "sql_injection": RawFamilyObservation(
        family="sql_injection",
        variant="query_semantic_influence",
        base=18,
        missing=("Whether input reaches dynamic SQL construction", "Controlled error/boolean/timing differential", "Parameter binding behavior"),
        rules=("raw-collector-injection-v1", "candidate-sql-query-surface", "admission-sql-query-influence"),
        summary="A client-controlled input reaches a database/query-shaped surface; promotion requires stored evidence that SQL semantics are influenced.",
    ),
    "nosql_injection": RawFamilyObservation(
        family="nosql_injection",
        variant="operator_influence",
        base=18,
        missing=("Whether structured input is interpreted as query operators", "Typed schema/operator allowlist", "Controlled result differential"),
        rules=("raw-collector-injection-v1", "candidate-nosql-query-surface", "admission-nosql-operator-influence"),
        summary="Structured client input appears in a NoSQL/document-query surface; promotion requires observed operator or query-result influence.",
    ),
    "command_injection": RawFamilyObservation(
        family="command_injection",
        variant="process_execution_influence",
        base=20,
        missing=("Whether input reaches a shell/process API", "Argument-array vs shell-string construction", "Harmless output/timing execution evidence"),
        rules=("raw-collector-injection-v1", "candidate-command-surface", "admission-command-execution-effect"),
        summary="Client-controlled input appears in process/diagnostic functionality; promotion requires an observed command-execution effect.",
    ),
    "server_side_template_injection": RawFamilyObservation(
        family="server_side_template_injection",
        variant="server_expression_evaluation",
        base=20,
        missing=("Whether rendering occurs server-side", "Expression evaluation behavior", "Template sandbox/escaping controls"),
        rules=("raw-collector-injection-v1", "candidate-template-render-surface", "admission-template-evaluation"),
        summary="Client-controlled content appears in a template/rendering surface; promotion requires observed server-side expression evaluation.",
    ),
    "ldap_injection": RawFamilyObservation(
        family="ldap_injection",
        variant="filter_influence",
        base=18,
        missing=("Whether input changes an LDAP filter", "Filter escaping/binding", "Controlled search/authentication differential"),
        rules=("raw-collector-injection-v1", "candidate-ldap-surface", "admission-ldap-filter-influence"),
        summary="Client-controlled input appears in a directory/LDAP surface; promotion requires observed filter or result influence.",
    ),
}


def validate_injection_collectors() -> list[str]:
    errors: list[str] = []
    if set(INJECTION_OBSERVATIONS) != set(INJECTION_FAMILIES):
        errors.append("injection collector profile coverage drift")
    for family in INJECTION_FAMILIES:
        observation = INJECTION_OBSERVATIONS.get(family)
        if family not in DETECTOR_SPECS:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not DETECTOR_SPECS[family].condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_injection_observations(execution_map: Mapping[str, Mapping[str, Any]]) -> list[RawFamilyObservation]:
    errors = validate_injection_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.16 injection collector registry: " + "; ".join(errors))
    return [
        INJECTION_OBSERVATIONS[family]
        for family in INJECTION_FAMILIES
        if INJECTION_OBSERVATIONS[family].packet_present(execution_map)
    ]

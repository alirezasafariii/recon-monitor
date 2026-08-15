from __future__ import annotations

"""Dedicated SQL Injection analyzer backed by the canonical family spec.

Standards and real-world research define the SQLi detection methodology. The
analyzer still promotes only from stored target evidence; taxonomy and write-up
knowledge never become evidence or independent sources.
"""

from typing import Any, Iterable, Mapping

from core import Database
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family


SQL_INJECTION_FAMILY_ANALYZER_VERSION = "1.1.0"
SQL_INJECTION_SPEC = get_detection_spec("sql_injection")

# Compatibility exports; canonical definitions live in family_specs.
TAXONOMY = SQL_INJECTION_SPEC.taxonomy()
METHOD = tuple(step.as_dict() for step in SQL_INJECTION_SPEC.standard.methodology)
FALSE_POSITIVES = tuple(SQL_INJECTION_SPEC.standard.false_positive_checks)
WRITEUPS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in SQL_INJECTION_SPEC.standard.writeups
)


def analyze_sql_injection_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "",
    method: str = "UNKNOWN",
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    path_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    return analyze_injection_family(
        analyzer=SqlInjectionFamilyAnalyzer(),
        family="sql_injection",
        variant="sql_query_construction",
        endpoint=endpoint,
        method=method,
        body_fields=body_fields,
        query_fields=query_fields,
        path_fields=path_fields,
        details=details,
        semantic_text=semantic_text,
        input_type="sql_input",
        sink_type="sql_query_sink",
        input_keywords=SQL_INJECTION_SPEC.standard.surface_fields,
        sink_keywords=(
            "select ",
            "insert ",
            "update ",
            "delete ",
            "execute ",
            "sql",
            "database",
            "cursor",
            "query(",
        ),
        unsafe_types=("unsafe_sql_concatenation_observed", "sql_error_signature_observed"),
        direct_types=("sql_query_influence_observed", "sql_behavior_differential"),
        contradiction_types=(
            "parameterized_query_observed",
            "query_parameter_binding_observed",
            "input_not_reaching_query",
        ),
        observation_keys=(
            "sql_injection_observations",
            "database_query_observations",
            "sql_runtime_observations",
        ),
        taxonomy=TAXONOMY,
        methodology=METHOD,
        false_positive_checks=FALSE_POSITIVES,
        writeup_patterns=WRITEUPS,
        rule_ids=(
            "family-sql_injection-input",
            "family-sql_injection-sink",
            "family-sql_injection-controlled-behavior",
        ),
        summary="SQL Injection hypothesis from stored target evidence; no payload was generated or sent.",
        base=24,
    )


class SqlInjectionFamilyAnalyzer(FamilyAnalyzer):
    family = "sql_injection"
    analyzer_version = SQL_INJECTION_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_sql_injection_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

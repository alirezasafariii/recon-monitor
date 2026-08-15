from __future__ import annotations

"""Canonical standards and real-world research grounding for SQL Injection.

The specification defines detection methodology only. OWASP, WSTG, CWE,
CAPEC and write-up material can classify or explain target observations but can
never satisfy admission or confirmation by themselves.
"""

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


SQL_INJECTION_STANDARD_SPEC = FamilyStandardSpec(
    family="sql_injection",
    version="1.0.0",
    strategy="sql_query_semantics",
    principle=(
        "SQL-looking parameters are only attack-surface clues; promotion requires "
        "stored target evidence that user-controlled data reaches SQL construction "
        "and can alter query semantics or that unsafe SQL construction is actually observed."
    ),
    owasp=(
        "A05:2025 Injection",
        "Injection",
    ),
    wstg=("WSTG-INPV-05",),
    cwe=("CWE-89",),
    capec=("CAPEC-66",),
    methodology=(
        MethodologyStep(
            id="SQLI-01-input-surface",
            basis=("WSTG-INPV-05", "CWE-89"),
            principle=(
                "Identify the exact externally influenced parameter, header, path, "
                "body or stored value that may enter database query construction."
            ),
        ),
        MethodologyStep(
            id="SQLI-02-query-sink",
            basis=("WSTG-INPV-05", "CWE-89"),
            principle=(
                "Require a concrete server-side SQL/query construction boundary; "
                "parameter names or SQL keywords without a sink are discovery context only."
            ),
        ),
        MethodologyStep(
            id="SQLI-03-semantic-boundary",
            basis=("OWASP A05:2025", "CWE-89"),
            principle=(
                "Look for target evidence of unsafe query construction, a database-specific "
                "error tied to the input, or a controlled boolean/behavioral/query-semantic differential."
            ),
        ),
        MethodologyStep(
            id="SQLI-04-safe-controls",
            basis=("OWASP A05:2025", "CWE-89"),
            principle=(
                "Treat prepared statements, parameter binding, enforced typing and evidence "
                "that the input never reaches SQL construction as contradiction evidence."
            ),
        ),
        MethodologyStep(
            id="SQLI-05-decision",
            basis=("WSTG-INPV-05", "GHSL-2026-059"),
            principle=(
                "Only stored target observations may satisfy the evidence contract; "
                "standards and real-world write-ups define what to look for but add zero target evidence."
            ),
        ),
    ),
    surface_terms=(
        "sql",
        "select",
        "where",
        "order by",
        "database",
        "query builder",
        "postgres",
        "mysql",
        "sqlite",
    ),
    surface_fields=(
        "q",
        "query",
        "filter",
        "sort",
        "order",
        "search",
        "where",
        "id",
    ),
    confounders=(
        "nosql_injection",
        "command_injection",
        "ssti",
    ),
    false_positive_checks=(
        "A parameter named query, filter, sort, order or id does not establish SQL construction or SQL injection.",
        "A SQL/query-builder keyword in static text does not prove that target-controlled data reaches the query sink.",
        "A generic server error without database-specific context tied to the controlled input is not decisive SQL injection evidence.",
        "Prepared statements, bound parameters, enforced typing or proof that the input does not reach query construction contradict the hypothesis.",
        "OWASP, WSTG, CWE, CAPEC and write-up similarity never count as target evidence or an independent evidence source.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-2026-059-chatwoot",
            source="GitHub Security Lab",
            ref="GHSL-2026-059 / Chatwoot SQL Injection",
            url="https://securitylab.github.com/advisories/GHSL-2026-059_Chatwoot/",
            relation="direct",
            lesson=(
                "The useful detection pattern is a concrete path from user-controlled filter "
                "data into dynamically constructed SQL without parameter binding; the lesson "
                "defines detector criteria but is never evidence about another target."
            ),
            signal_hints=(
                "sql_input",
                "sql_query_sink",
                "unsafe_sql_concatenation_observed",
                "sql_query_influence_observed",
                "query_parameter_binding_observed",
            ),
        ),
    ),
)

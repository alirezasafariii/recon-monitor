from __future__ import annotations

"""Dedicated GraphQL Excessive Data Exposure analyzer.

Sensitive-looking field names in a client query are structural surface only.
Promotion needs an independent stored field-policy or response observation.
Confirmation requires controlled evidence that a role receives fields outside
its intended field-level authorization boundary. Raw field values are never
copied into analyzer output.
"""

from typing import Any, Iterable, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth


GRAPHQL_DATA_EXPOSURE_FAMILY_ANALYZER_VERSION = "1.0.0"
GRAPHQL_DATA_EXPOSURE_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

GRAPHQL_DATA_EXPOSURE_TAXONOMY = {
    "owasp": ["API3:2023 Broken Object Property Level Authorization", "GraphQL Access Control"],
    "wstg": ["WSTG-APIT-03"],
    "cwe": ["CWE-200"],
    "related_cwe": ["CWE-862", "CWE-863", "CWE-359"],
}

GRAPHQL_DATA_EXPOSURE_METHOD = (
    {
        "id": "GQL-DATA-01-field-surface",
        "basis": ["WSTG-APIT-03", "OWASP GraphQL Cheat Sheet"],
        "principle": "Identify sensitive field names referenced by GraphQL operations without treating schema/query visibility as returned data.",
    },
    {
        "id": "GQL-DATA-02-field-policy",
        "basis": ["API3:2023", "OWASP GraphQL Cheat Sheet"],
        "principle": "Model which fields the current role is intended to receive; field names and client rendering needs are not substitutes for server-side field authorization policy.",
    },
    {
        "id": "GQL-DATA-03-controlled-response",
        "basis": ["WSTG-APIT-03", "CWE-200"],
        "principle": "Direct evidence requires a stored controlled response observation that records field names/types and authorization context, not unnecessary sensitive values.",
    },
    {
        "id": "GQL-DATA-04-contradictions",
        "basis": ["CWE-862"],
        "principle": "Observed field-level authorization or absence of restricted fields is contradiction evidence on the relevant role/operation.",
    },
)

GRAPHQL_DATA_EXPOSURE_FALSE_POSITIVE_CHECKS = (
    "A sensitive-looking field in a GraphQL query or schema does not prove the server returned that field to an unauthorized role.",
    "Introspection visibility is not excessive data exposure by itself.",
    "A field may be intentionally available to the current role; expected field policy must be explicit before direct classification.",
    "GraphQL errors, aliases, fragments and nullable fields can change response shape without indicating exposure.",
    "Direct evidence stores only field names/types, role context and booleans; raw PII, tokens and financial values are outside analyzer output.",
    "General Information Disclosure remains a neighboring family; GraphQL Data Exposure is specific to field/property authorization and excessive API response shape.",
)

GRAPHQL_DATA_EXPOSURE_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-apit-03-excessive-data",
        "source": "OWASP WSTG",
        "ref": "WSTG-APIT-03 / Testing for Excessive Data Exposure",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_for_Excessive_Data_Exposure",
        "principle": "API responses should not return sensitive fields beyond what the client and caller are authorized to receive.",
        "signals": ["sensitive_fields", "sensitive_graphql_response_observed"],
    },
    {
        "id": "owasp-graphql-field-access-control",
        "source": "OWASP Cheat Sheet Series",
        "ref": "GraphQL Cheat Sheet / Query Access",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "principle": "GraphQL field access may require requester-specific checks so consumers receive only authorized object properties.",
        "signals": ["client_operation", "field_authorization_differential"],
    },
)


def _safe_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text[:120])
    return result


def analyze_graphql_data_exposure_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "/graphql",
    js_url: str = "",
    operation_name: str = "",
    operation_type: str = "query",
    sensitive_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    fields = _safe_names(sensitive_fields)
    operation_name = str(operation_name or details.get("operation_name") or "").strip()[:160]
    operation_type = str(operation_type or details.get("operation_type") or "query").strip().lower()[:40]
    if not fields:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    structural_group = f"graphql_static_data:{js_url or endpoint}:{operation_name or operation_type}"
    add_unique(support, {
        "type": "sensitive_fields", "source": "graphql_intelligence", "source_group": structural_group, "weight": 20,
        "text": f"Client GraphQL operation references potentially sensitive field names: {', '.join(fields[:8])}.",
    })
    add_unique(support, {
        "type": "client_operation", "source": "graphql_intelligence", "source_group": structural_group, "weight": 14,
        "text": f"The fields are referenced by a client-visible GraphQL {operation_type or 'operation'} named {operation_name or 'unnamed'}.",
    })

    policy = details.get("graphql_field_policy") or details.get("field_authorization_policy") or details.get("minimum_response_policy")
    if isinstance(policy, Mapping) and truth(policy.get("documented")) is True:
        add_unique(support, {
            "type": "field_policy_context", "source": "stored_security_policy", "source_group": "graphql_field_policy", "weight": 15,
            "text": "Stored target policy documents a role-specific GraphQL field/response boundary for this operation.",
        })

    runtime = observations(
        details,
        "graphql_data_exposure_observations",
        "graphql_field_observations",
        "graphql_runtime_observations",
    )
    for index, obs in enumerate(runtime[:50]):
        controlled = truth(scalar(obs, ("controlled_test_context", "authorized_test_context", "controlled_role_context"))) is True
        policy_known = truth(scalar(obs, ("field_policy_expected_restricted", "expected_field_policy_documented", "restricted_field_expected"))) is True
        group = f"graphql_data_observation:{index}"
        if truth(scalar(obs, ("field_authorization_observed", "field_policy_enforced"))) is True:
            add_unique(contradict, {
                "type": "field_authorization_observed", "source": "stored_graphql_observation", "source_group": group, "weight": -36,
                "text": "Stored controlled response evidence shows field-level authorization enforcement on the relevant operation.",
            })
        if truth(scalar(obs, ("sensitive_fields_not_returned", "restricted_fields_absent"))) is True:
            add_unique(contradict, {
                "type": "sensitive_fields_not_returned", "source": "stored_graphql_observation", "source_group": group, "weight": -40,
                "text": "Stored controlled response shape omits the restricted GraphQL fields for the tested role.",
            })
        if not (controlled and policy_known):
            continue
        if truth(scalar(obs, ("sensitive_graphql_response_observed", "restricted_fields_returned", "sensitive_response_observed"))) is True:
            add_unique(support, {
                "type": "sensitive_graphql_response_observed", "source": "stored_controlled_graphql_response", "source_group": group, "weight": 56,
                "text": "Stored controlled response shape includes restricted GraphQL field names for a role that policy marks as unauthorized for those fields.",
            })
        if truth(scalar(obs, ("field_authorization_differential", "role_field_differential"))) is True:
            add_unique(support, {
                "type": "field_authorization_differential", "source": "stored_controlled_graphql_comparison", "source_group": group, "weight": 54,
                "text": "A controlled role comparison shows a field-level authorization differential inconsistent with the documented response policy.",
            })

    observed_types = {item["type"] for item in support}
    if "sensitive_graphql_response_observed" in observed_types:
        variant = "restricted_fields_returned"
    elif "field_authorization_differential" in observed_types:
        variant = "field_authorization_differential"
    elif "field_policy_context" in observed_types:
        variant = "sensitive_fields_with_policy_context"
    else:
        variant = "sensitive_field_surface"

    return finalize_result(
        analyzer=GraphqlDataExposureFamilyAnalyzer(),
        family="graphql_data_exposure",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=GRAPHQL_DATA_EXPOSURE_TAXONOMY,
        methodology=GRAPHQL_DATA_EXPOSURE_METHOD,
        false_positive_checks=GRAPHQL_DATA_EXPOSURE_FALSE_POSITIVE_CHECKS,
        writeup_patterns=GRAPHQL_DATA_EXPOSURE_WRITEUP_PATTERNS,
        direct_types={"sensitive_graphql_response_observed", "field_authorization_differential"},
        rule_ids=("family-graphql-sensitive-fields", "family-graphql-field-policy", "family-graphql-controlled-response"),
        summary="GraphQL excessive-data hypothesis based on client field structure plus stored field-policy/controlled response evidence.",
        base=22,
        extra_meta={
            "family_rule_version": GRAPHQL_DATA_EXPOSURE_FAMILY_ANALYZER_RULE_VERSION,
            "sensitive_field_names": fields[:16],
            "operation_name": operation_name,
            "operation_type": operation_type,
            "runtime_observation_count": len(runtime),
            "raw_sensitive_values_copied": False,
            "active_graphql_request_performed": False,
        },
    )


class GraphqlDataExposureFamilyAnalyzer(FamilyAnalyzer):
    family = "graphql_data_exposure"
    analyzer_version = GRAPHQL_DATA_EXPOSURE_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_graphql_data_exposure_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

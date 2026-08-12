from __future__ import annotations

"""Dedicated GraphQL Authorization analyzer.

Client-visible object identifiers and GraphQL operations are discovery surface.
Promotion requires an independent target evidence root such as an explicitly
stored resolver/ownership policy observation or controlled authorization
comparison. Confirmation requires stored behavior showing an unauthorized
object response or a role/ownership authorization differential using only
explicitly authorized test identities and test-owned objects.
"""

from typing import Any, Iterable, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth


GRAPHQL_AUTHORIZATION_FAMILY_ANALYZER_VERSION = "1.0.0"
GRAPHQL_AUTHORIZATION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

GRAPHQL_AUTHORIZATION_TAXONOMY = {
    "owasp": ["API1:2023 Broken Object Level Authorization", "GraphQL Access Control"],
    "wstg": ["WSTG-APIT-02", "WSTG-ATHZ-02"],
    "cwe": ["CWE-862"],
    "related_cwe": ["CWE-639", "CWE-863", "CWE-285"],
}

GRAPHQL_AUTHORIZATION_METHOD = (
    {
        "id": "GQL-AUTHZ-01-operation-surface",
        "basis": ["OWASP GraphQL Cheat Sheet", "WSTG-APIT-02"],
        "principle": "Identify object-bearing GraphQL queries or mutations, but never infer missing resolver authorization from an identifier alone.",
    },
    {
        "id": "GQL-AUTHZ-02-resolver-boundary",
        "basis": ["OWASP GraphQL Cheat Sheet", "WSTG-ATHZ-02"],
        "principle": "Model authorization at resolver, node and edge boundaries and keep expected ownership/role policy separate from observed response behavior.",
    },
    {
        "id": "GQL-AUTHZ-03-controlled-comparison",
        "basis": ["WSTG-APIT-02", "CWE-639"],
        "principle": "Direct evidence is accepted only from controlled comparisons involving authorized test identities and test-owned objects; no identifier enumeration is performed.",
    },
    {
        "id": "GQL-AUTHZ-04-contradictions",
        "basis": ["CWE-862"],
        "principle": "Observed resolver authorization or denial across the expected boundary is contradiction evidence unless a stronger controlled differential is already stored.",
    },
)

GRAPHQL_AUTHORIZATION_FALSE_POSITIVE_CHECKS = (
    "An argument named id, userId, nodeId, objectId, accountId or similar does not prove broken authorization.",
    "Client-side knowledge of an object identifier is not evidence that another identity can access that object.",
    "Introspection or schema visibility is not GraphQL authorization failure by itself.",
    "A 200 GraphQL HTTP status is not direct evidence; GraphQL errors and field-level nullability must be interpreted in stored response context.",
    "Direct evidence requires explicitly authorized test identities and test-owned objects; unrelated real-user identifiers are outside this analyzer contract.",
    "BOLA/IDOR is a neighboring root-cause family and may correlate with this GraphQL-specific resolver boundary, but neither family confirms the other automatically.",
)

GRAPHQL_AUTHORIZATION_WRITEUP_PATTERNS = (
    {
        "id": "owasp-graphql-access-control",
        "source": "OWASP Cheat Sheet Series",
        "ref": "GraphQL Cheat Sheet / Access Control",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "principle": "GraphQL APIs should validate authorization for requested objects and enforce controls at nodes, edges and resolvers.",
        "signals": ["graphql_identifier", "graphql_operation", "graphql_authorization_differential"],
    },
    {
        "id": "owasp-wstg-apit-02-graphql-bola",
        "source": "OWASP WSTG",
        "ref": "WSTG-APIT-02 / API Broken Object Level Authorization",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization",
        "principle": "GraphQL object identifiers must remain bound to the caller's authorized object scope.",
        "signals": ["graphql_identifier", "graphql_unauthorized_object_response"],
    },
)


def _safe_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text[:120])
    return result


def analyze_graphql_authorization_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "/graphql",
    js_url: str = "",
    operation_name: str = "",
    operation_type: str = "query",
    identifiers: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    identifiers = _safe_names(identifiers)
    operation_name = str(operation_name or details.get("operation_name") or "").strip()[:160]
    operation_type = str(operation_type or details.get("operation_type") or "query").strip().lower()[:40]
    if not identifiers and not operation_name:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    structural_group = f"graphql_static_operation:{js_url or endpoint}:{operation_name or operation_type}"
    if identifiers:
        add_unique(support, {
            "type": "graphql_identifier", "source": "graphql_intelligence", "source_group": structural_group, "weight": 20,
            "text": f"Client-visible GraphQL object-identifier fields are present: {', '.join(identifiers[:6])}.",
        })
    if operation_name or operation_type:
        label = operation_name or "unnamed operation"
        add_unique(support, {
            "type": "graphql_operation", "source": "graphql_intelligence", "source_group": structural_group, "weight": 16,
            "text": f"Client-visible GraphQL {operation_type or 'operation'} contract observed for {label}.",
        })

    policy = details.get("graphql_authorization_policy") or details.get("resolver_authorization_policy") or details.get("ownership_policy")
    if isinstance(policy, Mapping) and truth(policy.get("documented")) is True:
        add_unique(support, {
            "type": "resolver_policy_context", "source": "stored_security_policy", "source_group": "graphql_resolver_policy", "weight": 14,
            "text": "Stored target policy documents an ownership or role boundary for this GraphQL resolver/operation.",
        })

    runtime = observations(
        details,
        "graphql_authorization_observations",
        "graphql_authz_observations",
        "graphql_runtime_observations",
    )
    for index, obs in enumerate(runtime[:50]):
        controlled = truth(scalar(obs, ("controlled_test_context", "authorized_test_context", "test_context_controlled"))) is True
        test_owned = truth(scalar(obs, ("test_owned_object", "controlled_object", "object_is_test_owned"))) is True
        group = f"graphql_authz_observation:{index}"
        if truth(scalar(obs, ("resolver_authorization_observed", "authorization_enforced"))) is True:
            add_unique(contradict, {
                "type": "resolver_authorization_observed", "source": "stored_graphql_observation", "source_group": group, "weight": -34,
                "text": "Stored controlled evidence shows resolver-level authorization enforcement on the relevant boundary.",
            })
        if truth(scalar(obs, ("cross_context_denied", "unauthorized_context_denied"))) is True:
            add_unique(contradict, {
                "type": "cross_context_denied", "source": "stored_graphql_observation", "source_group": group, "weight": -40,
                "text": "Stored controlled comparison shows the out-of-scope GraphQL object request is denied.",
            })
        if not (controlled and test_owned):
            continue
        if truth(scalar(obs, ("graphql_unauthorized_object_response", "unauthorized_object_response", "out_of_scope_object_returned"))) is True:
            add_unique(support, {
                "type": "graphql_unauthorized_object_response", "source": "stored_controlled_graphql_response", "source_group": group, "weight": 58,
                "text": "A controlled test identity received an out-of-scope test-owned GraphQL object despite the documented ownership/role boundary.",
            })
        if truth(scalar(obs, ("graphql_authorization_differential", "authorization_differential", "role_or_owner_differential"))) is True:
            add_unique(support, {
                "type": "graphql_authorization_differential", "source": "stored_controlled_graphql_comparison", "source_group": group, "weight": 54,
                "text": "Stored like-for-like GraphQL comparison shows an authorization differential inconsistent with the documented test ownership/role boundary.",
            })

    observed_types = {item["type"] for item in support}
    if "graphql_unauthorized_object_response" in observed_types:
        variant = "unauthorized_test_object_response"
    elif "graphql_authorization_differential" in observed_types:
        variant = "resolver_authorization_differential"
    elif "resolver_policy_context" in observed_types:
        variant = "object_boundary_with_policy_context"
    else:
        variant = "graphql_object_boundary_surface"

    return finalize_result(
        analyzer=GraphqlAuthorizationFamilyAnalyzer(),
        family="graphql_authorization",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=GRAPHQL_AUTHORIZATION_TAXONOMY,
        methodology=GRAPHQL_AUTHORIZATION_METHOD,
        false_positive_checks=GRAPHQL_AUTHORIZATION_FALSE_POSITIVE_CHECKS,
        writeup_patterns=GRAPHQL_AUTHORIZATION_WRITEUP_PATTERNS,
        direct_types={"graphql_unauthorized_object_response", "graphql_authorization_differential"},
        rule_ids=("family-graphql-object-surface", "family-graphql-resolver-boundary", "family-graphql-controlled-comparison"),
        summary="GraphQL object-level authorization hypothesis derived from client operation structure plus stored resolver/policy/controlled comparison evidence.",
        base=24,
        extra_meta={
            "family_rule_version": GRAPHQL_AUTHORIZATION_FAMILY_ANALYZER_RULE_VERSION,
            "identifier_fields": identifiers[:12],
            "operation_name": operation_name,
            "operation_type": operation_type,
            "runtime_observation_count": len(runtime),
            "identifier_enumeration_performed": False,
            "cross_user_request_performed": False,
            "raw_response_values_copied": False,
        },
    )


class GraphqlAuthorizationFamilyAnalyzer(FamilyAnalyzer):
    family = "graphql_authorization"
    analyzer_version = GRAPHQL_AUTHORIZATION_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_graphql_authorization_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )

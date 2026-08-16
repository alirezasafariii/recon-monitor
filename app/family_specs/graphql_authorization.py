from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


GRAPHQL_AUTHORIZATION_STANDARD_SPEC = FamilyStandardSpec(
    family="graphql_authorization",
    version="1.0.0",
    strategy="graphql_resolver_object_authorization_boundary",
    principle=(
        "GraphQL identifiers, operations, introspection and documented resolver policy are discovery/context only; "
        "promotion requires stored controlled behavior showing that a test identity received a test-owned object outside "
        "its authorized scope or an equivalent resolver authorization differential."
    ),
    owasp=("API1:2023 Broken Object Level Authorization", "OWASP GraphQL Cheat Sheet / Access Control"),
    wstg=("WSTG-APIT-02", "WSTG-ATHZ-02"),
    cwe=("CWE-862", "CWE-639", "CWE-863", "CWE-285"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="GQL-AUTHZ-01-operation-surface",
            basis=("API1:2023", "OWASP GraphQL Cheat Sheet", "WSTG-APIT-02"),
            principle="Identify object-bearing GraphQL queries or mutations, but never infer missing resolver authorization from an identifier, schema field or operation name alone.",
        ),
        MethodologyStep(
            id="GQL-AUTHZ-02-resolver-boundary",
            basis=("OWASP GraphQL Cheat Sheet", "WSTG-ATHZ-02", "CWE-862"),
            principle="Model authorization at resolver, node and edge boundaries and keep the expected ownership/role policy separate from observed response behavior.",
        ),
        MethodologyStep(
            id="GQL-AUTHZ-03-controlled-comparison",
            basis=("WSTG-APIT-02", "CWE-639", "CWE-863"),
            principle="Potential-Finding admission requires controlled comparisons involving explicitly authorized test identities and test-owned objects; identifier visibility or enumeration is not evidence.",
        ),
        MethodologyStep(
            id="GQL-AUTHZ-04-response-decision",
            basis=("API1:2023", "CWE-862", "CWE-639"),
            principle="Decisive evidence is an unauthorized test-object response or a like-for-like authorization differential inconsistent with the documented ownership/role boundary.",
        ),
        MethodologyStep(
            id="GQL-AUTHZ-05-falsification",
            basis=("CWE-862", "CWE-863"),
            principle="Observed resolver authorization and denial across the expected controlled boundary are contradiction evidence unless a stronger controlled failure on the same operation is stored.",
        ),
    ),
    surface_terms=("graphql", "query", "mutation", "node", "resolver", "edge", "object authorization"),
    surface_fields=("id", "node_id", "user_id", "account_id", "order_id", "object_id", "tenant_id"),
    confounders=("broken_object_authorization", "broken_function_authorization", "graphql_data_exposure"),
    false_positive_checks=(
        "An argument named id, userId, nodeId, objectId, accountId or similar is only an object surface.",
        "Client-side knowledge of a GraphQL object identifier is not evidence that another identity can access that object.",
        "Introspection or schema visibility is not a GraphQL authorization failure by itself.",
        "A documented resolver ownership/role policy is expected behavior context, not evidence that the policy fails.",
        "A GraphQL HTTP 200 status is not authorization evidence; field errors, nullability and response shape must be interpreted in the controlled context.",
        "Direct evidence is limited to explicitly authorized test identities and test-owned objects; unrelated real-user identifiers are outside this analyzer contract.",
        "BOLA may correlate with GraphQL object authorization but neither family confirms the other automatically.",
        "OWASP, WSTG, CWE and write-up similarity add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-graphql-access-control-global",
            source="OWASP Cheat Sheet Series",
            ref="GraphQL Cheat Sheet / Access Control",
            url="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            relation="canonical_graphql_authorization_method",
            lesson=(
                "GraphQL authorization must be enforced for requested objects at nodes, edges and resolvers. The reusable detector lesson is to compare the caller's authorized object scope with the actual resolver response."
            ),
            signal_hints=("graphql_identifier", "graphql_operation", "graphql_authorization_differential", "resolver_authorization_observed"),
        ),
        WriteupLesson(
            id="owasp-wstg-apit-02-graphql-bola",
            source="OWASP WSTG",
            ref="WSTG-APIT-02 / API Broken Object Level Authorization",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization",
            relation="object_authorization_test_method",
            lesson=(
                "The reusable GraphQL lesson is that object identifiers remain bound to the caller's authorized object scope; only a controlled out-of-scope response or differential establishes the failure."
            ),
            signal_hints=("graphql_identifier", "graphql_unauthorized_object_response", "graphql_authorization_differential", "cross_context_denied"),
        ),
    ),
)

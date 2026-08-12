from .base import make_spec, writeup
SPEC = make_spec(
    family="graphql_authorization", strategy="graphql_resolver_authorization",
    surface_terms=("graphql","query","mutation","resolver","node id","relay"),
    surface_fields=("id","nodeId","userId","tenantId","operationName"),
    confounders=("broken_object_authorization","broken_function_authorization","graphql_data_exposure"),
    expected_wstg=("WSTG-APIT-02","WSTG-ATHZ-02"), expected_cwe=("CWE-862","CWE-863"),
    writeups=(
        writeup(
            "GHSL-2025-130 / Sentry cross-organization object authorization failure",
            "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/",
            "adjacent_primary_case",
            "GraphQL transport does not change the authorization condition: an object identifier is only a surface until the resolver/object lookup is shown to escape the caller's organization, tenant, or ownership boundary.",
        ),
    ),
)

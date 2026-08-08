# Semantic Candidate Intelligence 4.3

Semantic Candidate Intelligence converts stored endpoint, JavaScript, HTTP, GraphQL, and analysis evidence into higher-quality inputs for Bug Candidate Engine. It is static and offline during analysis replay.

## Endpoint contracts

The engine builds an approximate contract from available evidence:

- HTTP method;
- normalized endpoint;
- path, query, and body fields;
- object identifiers;
- authentication hints;
- inferred authentication boundary;
- output-field and response-shape metadata when available;
- confidence.

An approximate contract is not a server specification. Missing fields remain unknown.

## Authentication boundaries

Possible boundary labels include:

- `public`
- `session_required`
- `bearer_required`
- `api_key_required`
- `authentication_required`
- `role_gated_hint`
- `mixed`
- `unknown`

The labels come from stored HTTP status, headers or client-visible authentication hints. A `401` or `403` does not prove that object- or function-level authorization is correct.

## Response-shape fingerprints

When a stored response is available, the engine records only structural information:

- JSON key paths;
- value types;
- sensitive-key markers;
- status and content-type context when present;
- a structural confidence score.

Sensitive values are not intentionally copied into the semantic record. Response shape can strengthen or weaken candidates such as excessive data exposure or authorization-boundary regression.

## Semantic JavaScript units

The static parser records units such as:

- API calls and routes;
- storage keys;
- authorization checks;
- WebSocket channels;
- postMessage handlers;
- feature flags.

These are static observations. Minification, bundling, dead code, or parser limitations can create incomplete results.

## Feature flags

Boolean-like feature markers with strong flag semantics are recorded with name, observed value, source JavaScript, and confidence. A flag change can be linked to related endpoints and candidates, but the presence of a flag does not prove that a server-side function is enabled.

## Parameter relationships

The engine maps co-occurring identifiers such as:

- `tenantId`
- `orgId`
- `accountId`
- `customerId`
- `userId`
- `orderId`
- `invoiceId`

These relationships help specialize a generic authorization candidate into a possible cross-tenant, account-object, or nested-resource boundary. They do not prove unauthorized access.

## Candidate bundles

Related candidates can be grouped around a shared endpoint, object boundary, JavaScript change, or semantic contract. A bundle summarizes possible variants rather than presenting every related candidate as an unrelated issue.

```bash
./recon-monitor.sh analysis bundles --limit 100
./recon-monitor.sh analysis semantic --limit 200
```

Dashboard:

- `/candidate-bundles`
- `/semantic-intelligence`

API:

- `GET /api/v1/analysis/candidate-bundles`
- `GET /api/v1/analysis/semantic`

## Safety boundary

Semantic intelligence does not execute payloads, alter requests, bypass authentication, enumerate unrelated user objects, or automatically confirm a vulnerability. It improves prioritization and evidence explanation for authorized manual review.

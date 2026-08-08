# Behavioral Intelligence Engine — Recon Monitor 4.5.0

Recon Monitor 4.5 compares **stored observations** across completed analysis runs. It does not send additional requests, execute payloads, bypass authentication, or confirm vulnerabilities automatically.

## Core capabilities

### Authentication boundary diffs

For each endpoint, the engine compares the stored boundary classification from the latest previous analysis with the current analysis:

- `public`
- `authentication_required`
- `session_required`
- `bearer_required`
- `api_key_required`
- `role_gated_hint`
- `mixed`
- `unknown`

Transitions are classified as:

- `boundary_regression`
- `boundary_hardening`
- `visibility_lost`
- `new_public_boundary`
- `new_protected_boundary`
- `boundary_changed`
- `stable`

A protected-to-public transition can create an unverified authentication/session candidate. It remains unreviewed until an analyst records a decision.

### Structural response diffs

The engine compares redacted response structure rather than sensitive values:

- added and removed JSON key paths
- changed value types
- sensitive-looking key additions
- HTTP status transitions
- error-to-data transitions

Stored values are not required for structural comparison. A shape change is evidence, not proof of exposure.

### Protocol-specific engines

The engine creates normalized findings for:

- REST contracts and versioned API paths
- GraphQL queries and mutations
- WebSocket URLs and subscription channels
- OAuth/OIDC markers such as `redirect_uri`, `state`, `nonce`, PKCE, and code-verifier fields
- cache-related response directives and `Vary` context

These engines operate on stored endpoint contracts, JavaScript semantic units, GraphQL intelligence, and response headers already present in alert evidence.

### Identity and authorization graph

The engine creates entities and relations such as:

```text
Endpoint --reads--> Account
Endpoint --updates--> User
Tenant --parent_of--> User
GraphQL operation --references--> accountId
```

This graph helps specialize generic authorization candidates into account, tenant, role, or object-boundary investigations.

### Stored context observations

When alert evidence already contains explicit contexts such as anonymous, authenticated, or role-specific observations, they are normalized into `behavioral_observations`. Recon Monitor does not create those contexts through automatic active testing.

## Candidate integration

Behavioral evidence can strengthen or weaken existing candidates. New direct candidates may be created for:

- authentication boundary regression
- protected/error response changing to data
- sensitive structural expansion
- high-confidence protocol-specific findings

Safety and quality rules:

- automatic candidates remain `unreviewed`
- automatic likelihood is capped at 96%
- no behavioral candidate is automatically confirmed
- missing evidence and contradicting evidence are retained
- no active network validation is performed

## CLI

```bash
./recon-monitor.sh analysis behavioral
./recon-monitor.sh analysis boundary-diffs
./recon-monitor.sh analysis response-diffs
./recon-monitor.sh analysis protocols
./recon-monitor.sh analysis identity-graph
```

Use `--id ANALYSIS_ID` to inspect a specific analysis and `--limit` to limit list output.

## API

```text
GET /api/v1/analysis/behavioral
GET /api/v1/analysis/boundary-diffs
GET /api/v1/analysis/response-diffs
GET /api/v1/analysis/protocols
GET /api/v1/analysis/identity-graph
```

The API remains local and uses the existing token/RBAC controls.

## Dashboard

Open:

```text
/behavioral-intelligence
```

The page shows:

- authentication boundary changes
- structural response changes
- protocol-specific findings
- identity and authorization relations

Candidate detail pages include a Behavioral context section linking the candidate to relevant boundary, shape, protocol, and identity evidence.

## Database schema 11

New additive tables:

```text
behavioral_observations
authentication_boundary_diffs
response_shape_diffs
protocol_findings
identity_entities
identity_relations
```

All existing schema 10 records remain unchanged.

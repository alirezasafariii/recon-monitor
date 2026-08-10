# Correlation Engine V2

Correlation Engine V2 upgrades Recon Monitor from same-endpoint bundling to an
offline cross-surface graph built from data already collected during analysis.

It never sends requests to a target and its scores are **not target evidence**.

## Inputs reused from the existing schema

V2 deliberately reuses the existing tables instead of introducing a parallel
graph store:

- `endpoint_contracts`
- `parameter_relationships`
- `authentication_boundaries`
- `response_shape_fingerprints`
- `bug_candidates`
- `analysis_hypotheses`

## Graph model

A surface node is an endpoint contract enriched with:

- normalized endpoint
- HTTP method
- object/identity tokens
- parameter relationship signatures
- authentication boundary
- sensitive response tokens
- related promoted candidates

Edges are created when two surfaces share enough context, including:

- same normalized endpoint or alert
- shared object model (`account`, `user`, `order`, etc.)
- shared resource vocabulary
- shared parameter relationships
- same authentication boundary
- authentication-boundary differentials on otherwise related resources
- same semantic/source reference

The resulting cluster is deterministic and exposes an explainable
`cluster_strength`.

## Correlation family priors

Family scores are generated from two sources:

1. already-promoted candidates on related surfaces, weighted by surface
   similarity and investigation value;
2. conservative cluster heuristics such as identity/object models spanning
   multiple endpoints.

These scores are capped and marked as `non_evidentiary_cross_surface_prior`.

Correlation cannot:

- satisfy hypothesis admission
- add an independent evidence root
- increase target evidence confidence directly
- confirm a vulnerability

## Meta Ranker integration

`hypothesis_admission.py` calls Correlation Engine V2 after admission has already
been decided. Only `family_scores` are passed to Meta Ranker as its 5% correlation
component.

The full correlation context is persisted in `admission_json` for auditability.

## Investigation Queue

`investigation_queue(db, analysis_id)` returns one investigation item per
correlation cluster instead of one row per raw finding.

Each queue item includes:

- queue score
- primary bug family
- bug proximity score
- target evidence confidence
- hunt priority
- cluster strength
- related endpoints
- object tokens
- authentication boundaries
- Top-3 bug families
- member hypothesis IDs

Queue status remains:

`investigation_queue_not_confirmed`

## Example

```text
/api/accounts/{accountId}/users/{userId}
                         \
                          > account object cluster
                         /
/api/accounts/{accountId}/orders/{orderId}

Objects: account, user, order
Auth boundaries: bearer_required, mixed

BOLA / IDOR              correlation prior 72
Information Disclosure   correlation prior 46
```

This means the surfaces should be investigated together. It does not mean either
vulnerability exists.

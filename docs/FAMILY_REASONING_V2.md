# Family Reasoning Framework V2

## Purpose

Family Reasoning V2 gives every vulnerability family in Recon Monitor a reviewed, explicit evidence contract. It removes the previous behavior where only a few families had strict admission policy while other families silently fell back to a generic gate.

The framework is intentionally epistemic rather than exploit-oriented. It defines what may become a **Potential Finding**, what remains a hidden hypothesis, what evidence should be sought before analyst confirmation, and what validation class is appropriate. It never creates target evidence.

## Coverage

The catalog covers all 21 Candidate Engine families:

1. BOLA / IDOR (`broken_object_authorization`)
2. Broken Function Level Authorization (`broken_function_authorization`)
3. Mass Assignment / Property Authorization (`mass_assignment`)
4. Authentication or Session Weakness (`authentication_session`)
5. Account Enumeration (`account_enumeration`)
6. DOM-based XSS (`dom_xss`)
7. Unsafe postMessage Trust (`postmessage_trust`)
8. Open Redirect / Navigation Injection (`open_redirect`)
9. SSRF Candidate (`ssrf`)
10. Unsafe File Upload or Import (`file_upload`)
11. Path Traversal Candidate (`path_traversal`)
12. Sensitive Information Disclosure (`information_disclosure`)
13. Source-map Exposure (`source_map_exposure`)
14. Credential or Token Exposure (`secret_exposure`)
15. GraphQL Authorization Weakness (`graphql_authorization`)
16. GraphQL Excessive Data Exposure (`graphql_data_exposure`)
17. Business Logic Weakness (`business_logic`)
18. Race Condition / Duplicate Operation (`race_condition`)
19. WebSocket Authorization Weakness (`websocket_authorization`)
20. CORS Misconfiguration (`cors_misconfiguration`)
21. Sensitive Response Caching (`sensitive_caching`)

`catalog_audit()` fails completeness checks if the catalog and Candidate Engine family sets diverge.

## Contract layers

Each family defines the following independent layers.

### Promotion evidence

`promotion_required` is the minimum set of family-specific target observations needed before a hypothesis can be exposed as a Potential Finding. Each entry is an OR-group; every group must have at least one matching evidence type.

This is **not** vulnerability confirmation. A structural candidate may legitimately be promoted while still lacking runtime or cross-context proof.

### Independent sources

`min_independent_sources` prevents duplicated or single-root observations from masquerading as corroboration. The Admission Engine counts `source_group`, then `source`, then evidence type.

### Blocking contradictions

`blocking_contradictions` contains stored evidence that supports an enforcing or non-vulnerable interpretation. A complete-looking hypothesis remains hidden when a blocking contradiction is present, unless a decisive `override_signal` is also present.

### Confirmation evidence

`confirmation_required` is deliberately stronger than promotion evidence. It describes the direct behavior that should exist before the technical claim is considered demonstrated, for example:

- BOLA: unauthorized/cross-context object behavior
- BFLA: unauthorized function success or role differential
- DOM XSS: runtime sink reachability or unsanitized flow
- SSRF: observed server-side fetch behavior
- Business Logic: invariant/state-transition violation
- Race: duplicate/non-atomic behavior

Analyst confirmation remains an explicit human decision. The catalog makes the missing proof visible; knowledge/correlation/history cannot satisfy these requirements.

### Investigation requirements

`case_requirements` supplies the evidence-readiness vocabulary used by investigation workflows. Authorization families prefer identity, ownership/role and comparable-response evidence; other families retain concrete endpoint/evidence/expected-behavior requirements until richer family-specific collectors are available.

### Validation class

Every family has one of four validation classes:

- `offline`
- `passive_live`
- `controlled`
- `manual_only`

The class is guidance for the existing Safe Validation boundary, not permission to run a request. Scope, authorization, request budgets and approval gates remain authoritative.

## Admission behavior

`hypothesis_admission.py` now builds `FAMILY_ADMISSION_POLICIES` exclusively from the Family Reasoning catalog.

For all known families:

```text
Detector evidence
    ↓
Family Reasoning promotion contract
    ↓
Independent-source check
    ↓
Blocking-contradiction check
    ↓
Admitted Potential Finding OR hidden hypothesis
```

For an unknown family, admission fails closed:

```text
unknown family
    ↓
missing-family-reasoning-policy
    ↓
shadow_signal
    ↓
NOT promoted
```

There is no longer an `existing-family-gate` path that silently admits a family without a reviewed policy.

## Epistemic boundary

The order remains fixed:

```text
target evidence
    ↓
Family Reasoning / admission decision is fixed
    ↓
knowledge + writeups + history + correlation + LLM advisory
    ↓
proximity and investigation context only
```

The following can never satisfy Family Reasoning admission requirements:

- curated vulnerability knowledge
- historical analyst outcomes
- cross-surface correlation
- writeup similarity
- LLM advisory scores

They remain non-evidentiary ranking context.

## Detector/schema drift

`candidate_evidence_schema_map()` is generated from the same catalog and intentionally includes the evidence names actually produced by current detectors. This resolves the canonical contract for known drift such as:

- Mass Assignment: `privileged_property` as well as legacy `privileged_fields`
- SSRF: `remote_destination` / `server_feature` as well as canonical URL/server-fetch semantics
- DOM XSS: `dataflow_source` + `dataflow_sink`, not an invented single `source_sink` signal

Candidate Engine migration to consume this generated map is a separate compatibility step; the Admission Engine already uses the canonical catalog in V2.

## Safety

Family Reasoning V2 does not add exploit payloads, credential guessing, identifier enumeration, concurrent race execution, internal SSRF targets, dangerous file paths, or automatic active validation.

It is a reasoning and evidence-governance layer only.

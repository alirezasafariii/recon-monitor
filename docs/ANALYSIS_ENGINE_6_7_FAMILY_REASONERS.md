# Analysis Engine 6.7 — Family-Specific Reasoning Boundaries

Analysis 6.7 changes family classification from a shared generic ranking formula to a dedicated analytical reasoner per vulnerability family.

The goal is simple:

**a clue that is relevant to one bug family must not accidentally increase confidence in a neighboring family merely because both share generic input, route, state-change, or response evidence.**

## Core model

Each of the 31 modeled `FAMILY_ADMISSION_POLICIES` has exactly one `FamilyReasonerProfile` in `app/family_reasoners.py`.

A family reasoner owns:

1. a primary security question;
2. family-specific required-group weights;
3. a strict identity gate;
4. family-scoped evidence/source counting;
5. family-specific blocking controls inherited from admission policy;
6. explicit neighboring/confounder families;
7. a confounder penalty that applies only when a competing family has decisive condition evidence and the target family does not;
8. family fit separate from vulnerability-condition confidence.

Import-time validation fails if any admission family lacks a reasoner or identity gate, if group weights do not match the family admission groups, if weights do not sum to 1.0 with the shared source/admission terms, or if a confounder/gate is invalid.

## Family fit is not vulnerability confidence

The same principle from Analysis 6.5 remains:

- **Family fit:** which vulnerability family best describes the observed evidence?
- **Condition confidence:** is the actual vulnerability condition established?

A directly observed security control can reduce condition confidence to a contradicted state while increasing certainty about which family was tested. Therefore blocking contradictions are not subtracted from family identity fit.

## Family-scoped source counting

Analysis 6.5 counted independent evidence sources from the whole case while computing family compatibility.

Analysis 6.7 counts a source only if the evidence type is part of that family's own required/override/control vocabulary.

Example:

- object authorization observations do not increase SQL injection source confidence;
- a generic `input_parameter` does not give SQL/NoSQL/Command/SSTI/LDAP an independent-source bonus unless family-specific semantic evidence is also present;
- unrelated response or workflow observations remain visible in the evidence dossier but are not counted as family support.

The reasoner exposes:

- `scoped_independent_sources`;
- `unscoped_evidence_count`;
- `source_ratio`.

## Identity gates

A family may not participate meaningfully in ranking from weak generic evidence alone.

Examples:

- SQL Injection requires SQL query semantics before generic input evidence can identify the family;
- NoSQL Injection requires NoSQL/document-query semantics;
- Command Injection requires a process/shell execution surface;
- SSTI requires server-template semantics;
- LDAP Injection requires LDAP/directory-query semantics;
- BOLA requires object identity plus object operation;
- BFLA requires privileged-function plus role/state context;
- File Upload requires actual file input plus upload/import operation;
- Path Traversal requires path/filename input plus a file operation;
- Open Redirect requires destination control plus a navigation sink;
- Race Condition requires a state-changing operation plus single-use/balance/duplicate semantics.

If a decisive family-specific vulnerability condition is already directly observed, it can identify the family even when some earlier surface groups are sparse. Otherwise all identity-gate groups must be present before the family gets a non-zero fit score.

## Confounder boundaries

Every family declares the neighboring families most likely to be confused with it.

Important boundaries include:

- BOLA vs BFLA vs Mass Assignment;
- Authentication/Session vs Account Enumeration vs Secret Exposure;
- DOM XSS vs postMessage Trust vs Open Redirect;
- Open Redirect vs SSRF;
- SSRF vs Unsafe API Consumption;
- File Upload vs Path Traversal;
- Information Disclosure vs Secret Exposure vs Source Map Exposure vs Security Misconfiguration;
- GraphQL Authorization vs GraphQL Data Exposure vs BOLA/BFLA;
- CORS vs Information Disclosure vs Security Misconfiguration;
- Sensitive Caching vs Information Disclosure;
- Business Logic vs Race Condition vs Sensitive Business Flow Abuse;
- SQL vs NoSQL vs LDAP vs Command Injection vs SSTI;
- Resource Consumption vs Sensitive Business Flow Abuse vs Race Condition;
- Security Misconfiguration vs Inventory Management;
- Unsafe API Consumption vs SSRF/Resource Consumption.

A confounder does **not** blindly subtract score.

Penalty is applied only when:

1. the competing family has decisive condition evidence in the current support set; and
2. the target family's own decisive condition is absent.

This preserves legitimate multi-label cases where two independently established vulnerabilities coexist.

## Production path

`app/security_family_ranker.py` adapts family reasoners to the existing production ranking table.

`app/security_reasoning.py` no longer uses the legacy generic `_family_score()` loop for live candidate ranking. The old helper remains only for backward compatibility/tests.

Production family ranking now records:

- family-specific primary question;
- weighted group results;
- identity-group hits;
- condition hits;
- condition confidence;
- blocking controls;
- confounder evidence and penalty;
- scoped source count;
- unscoped evidence count;
- reasoner/rule versions.

## Test strategy

Analysis 6.7 adds two dedicated test layers.

### Family separation tests

Focused pairs verify common confusion boundaries such as:

- SQL vs NoSQL;
- SSRF vs Open Redirect;
- File Upload vs Path Traversal;
- Secret Exposure vs generic Information Disclosure;
- Race Condition vs generic Business Logic;
- BFLA with a correctly enforced lower-privilege denial.

### 31-family canonical matrix

Every one of the 31 families has a canonical evidence signature. Each signature must:

- rank its own family Top-1;
- satisfy its own admission condition;
- produce `family_fit_score = 1.0` under the canonical complete case.

The matrix also asserts that a generic `input_parameter` alone cannot select an injection family.

## Golden v4 discipline

Golden v4 is a completed, consumed fresh post-freeze evaluation of Analysis 6.5.

Analysis 6.7 intentionally changes a protected 6.5 ranking file. Therefore `validate_freeze(v4)` must now detect `POST-FREEZE MODEL MUTATION DETECTED` and refuse to replay v4 as a fresh evaluation.

The historical v4 corpus/report remain sealed and unchanged. Builder/seal invariants continue to pass, while the protocol test becomes version-aware:

- on the frozen 6.5 ranking engine, the v4 model freeze matches;
- on 6.7, model drift is expected and must be detected;
- v4 may not be re-scored and described as fresh for 6.7.

A future unbiased evaluation for this architecture requires a new independent holdout.

## Evidence contract

Analysis 6.7 preserves the overall epistemic contract:

`surface clue -> family-specific hypothesis -> family-scoped evidence -> contradiction/confounder check -> family admission -> precise taxonomy when justified`

The important change is that the middle of the chain is no longer shared across families. Each vulnerability category now owns its own analytical boundary.

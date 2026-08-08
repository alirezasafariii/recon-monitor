# Security Reasoning Core 4.6

Recon Monitor 4.6 upgrades the stored-data analysis pipeline from rule matching to explainable, evidence-based security reasoning. It does not exploit targets, generate attack payloads, bypass authorization, or automatically confirm vulnerabilities.

## Goals

The engine is designed to answer six separate questions for every candidate:

1. Which vulnerability families are compatible with the observations?
2. Which preconditions are actually present?
3. What supports the hypothesis?
4. What contradicts it, and what is simply unknown?
5. How trustworthy, reachable, and complete is the evidence?
6. Is the candidate valuable enough to enter the analyst review queue?

## Processing pipeline

```text
Stored observations
  -> normalized semantic facts
  -> unified evidence records
  -> independent evidence roots
  -> family-specific preconditions
  -> falsification and formal unknowns
  -> Top-3 family ranking
  -> calibrated likelihood / exploitability / coverage
  -> lifecycle and analyst review
```

## Separate scores

- **Calibrated likelihood**: compatibility between the observed facts and the vulnerability family, adjusted using family feedback where enough labels exist.
- **Evidence strength**: quality and independence of supporting observations.
- **Exploitability confidence**: confidence that the stored observations demonstrate conditions that could make the behavior exploitable. This is deliberately lower than likelihood when runtime or authorization evidence is missing.
- **Impact potential**: possible severity if the candidate is later confirmed.
- **Evidence coverage**: percentage of required/supporting/contradicting questions for which the system has an observation.
- **Investigation value**: queue priority, combining security relevance, evidence, novelty, observation quality, and historical noise.

No automatic score confirms a vulnerability. Analyst confirmation remains mandatory.

## Unified Evidence Model

Every reasoning signal is materialized in `evidence_records` with:

```text
evidence_id
analysis_id
target
source_type
source_tool
source_artifact
source_run_id
parser_name
parser_version
polarity
fact_type
fact_value
source_trust
observation_quality
integrity_hash
root_fingerprint
derived_from
first_seen
last_seen
```

`root_fingerprint` prevents multiple derived descriptions of the same observation from receiving full independent weight. Candidate-to-evidence relationships are stored in `candidate_evidence_links`.

## Family-specific reasoning

The engine uses distinct precondition, supporting, contradictory, and missing-evidence schemas instead of one generic keyword score. Current schemas cover authorization, authentication, data exposure, client-side injection, redirect, server-side fetch, file handling, GraphQL, WebSocket, OAuth/OIDC, caching, business logic, and race-condition candidates.

A family can be ranked highly only when its required conditions are sufficiently represented. Keyword-only matches remain weak or `insufficient_evidence`.

## Formal unknown model

The engine keeps three states separate:

```text
positive evidence
negative/contradictory evidence
unknown
```

For example, an observed anonymous `401` is evidence for an authentication boundary in that context. It does not prove object-level authorization, tenant isolation, or role enforcement. Missing observations remain unknown and are listed explicitly.

## Falsification

Every reasoning trace contains:

```text
why it may exist
why it may be wrong
what would strengthen it
what would weaken it
what would reject it
```

Contradictory evidence changes the score but does not silently erase the candidate. Rejection is an analyst decision or a clearly defined rule outcome.

## Top-3 family ranking

Candidate classification is multi-label. `family_rankings` stores the three most compatible vulnerability families, their score, the matched and missing preconditions, and the evidence roots used. The original candidate family remains the primary label unless the reasoning layer has enough evidence to specialize it.

## Reachability and context

The engine distinguishes:

```text
static_reference
referenced
observed
reachable
executed
unknown
```

It also records available contexts such as anonymous/authenticated observations, protocol findings, authentication-boundary changes, structural response changes, feature activation, and identity/object relationships. Static-only candidates receive lower exploitability confidence.

## Calibration and Golden Dataset

Analyst labels in `candidate_gold_labels` are evaluated per family. Positive labels include `confirmed`, `useful`, `useful_candidate`, `correct_family`, and `useful_weak_signal`. The engine calculates:

```text
Top-1 family accuracy
Top-3 family accuracy
Brier score
strong-candidate precision proxy
average evidence coverage
average exploitability confidence
candidates per 1,000 evidence records
```

`family_calibration` stores predicted-vs-observed gaps. With insufficient samples, the engine reports that limitation instead of presenting a statistically strong claim.

## Shadow rules

Experimental rules write only to `shadow_rule_results`. They do not change candidate state, analyst decision, or the main review queue. Shadow results can be evaluated before promotion to production rules.

## Regression gate

`reasoning_regression_gate` compares a reasoning run with a prior successful baseline and checks:

- Top-3 family accuracy;
- strong-candidate precision proxy;
- evidence coverage;
- candidate noise rate;
- retention of confirmed fingerprints when replaying the same source run.

Confirmed-fingerprint retention is not enforced between different source runs because the underlying evidence may legitimately differ.

## CLI

```bash
./recon-monitor.sh analysis reasoning
./recon-monitor.sh analysis evidence-trace --candidate-id CANDIDATE_ID
./recon-monitor.sh analysis reasoning-evaluate --id ANALYSIS_ID
./recon-monitor.sh analysis family-calibration --id ANALYSIS_ID
./recon-monitor.sh analysis shadow-rules --id ANALYSIS_ID
./recon-monitor.sh analysis regression-gate --id ANALYSIS_ID
```

Use `analysis replay --run RUN_ID` to apply the new reasoning engine to stored data without starting a new recon run or sending new network requests.

## Dashboard and API

Dashboard route:

```text
/security-reasoning
```

Candidate Detail contains calibrated likelihood, exploitability confidence, evidence coverage, precondition/reachability state, Top-3 families, provenance, formal unknowns, falsification, and shadow-rule results.

Read-only local API routes:

```text
GET /api/v1/analysis/security-reasoning
GET /api/v1/analysis/evidence-trace?candidate_id=...
GET /api/v1/analysis/family-calibration
GET /api/v1/analysis/shadow-rules
GET /api/v1/analysis/regression-gate
```

## Safety boundary

The reasoning core operates on data already collected under the configured scope and policy. It does not:

- generate exploit payloads;
- conduct authorization bypass attempts;
- access unrelated users' objects;
- run concurrency attacks;
- automatically confirm or report a vulnerability.

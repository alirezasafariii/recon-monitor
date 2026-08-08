# Safe Validation Engine — Recon Monitor 5.1

## Purpose

The Safe Validation Engine turns a Security Case into a bounded validation plan. It can strengthen, weaken, or leave a candidate inconclusive, but it never confirms a vulnerability automatically.

## Validation levels

### Offline

Uses stored observations, response shapes, boundaries, evidence lineage, and previous analyses. It sends no network requests and is the default level.

### Passive live

May execute only explicitly approved, in-scope `GET`, `HEAD`, or `OPTIONS` requests. It is intended for low-risk observations such as current reachability, authentication boundaries, redacted response structure, selected headers, redirect locations without following them, and source-map presence.

### Controlled

Creates a plan for authorization-sensitive families but the automatic executor refuses to run it. Controlled validation belongs in a separately approved workflow using registered test identities and test objects.

### Manual only

Used for SSRF, executable XSS, uploads, path traversal, race conditions, payment/refund, account recovery, role changes, webhooks, destructive operations, or other cases where an automated production check would be unsafe.

## Live execution gates

All live conditions must be satisfied:

1. The plan itself is eligible for passive live execution.
2. The case-specific approval phrase is stored.
3. The CLI or API caller explicitly enables live execution.
4. `I_HAVE_AUTHORIZATION=yes`.
5. `ENABLE_ACTIVE_MODULES=yes`.
6. The target policy contains `I_AM_AUTHORIZED_FOR_ACTIVE_TESTING`.
7. The URL is currently inside the target scope.

A general target authorization does not replace candidate-specific approval.

## Hard limits

Default live limits:

```text
Methods: GET, HEAD, OPTIONS
Maximum requests: 3
Maximum runtime: 15 seconds
Maximum response bytes: 256 KiB
Concurrency: 1
Minimum delay: 1 second
Retries: 0
Redirect following: disabled
Cookies/credential replay: disabled
Query replay: disabled
```

The executor rejects unsafe methods, dangerous paths, sensitive query keys, private/reserved address resolution, and out-of-scope redirects.

## Stop conditions

Validation stops when it encounters:

- HTTP 429;
- repeated server errors;
- an out-of-scope or unsafe destination;
- an oversized response;
- an unsafe state-changing path;
- likely third-party personal data;
- an expired or invalid approval;
- a failed authorization gate.

Raw response bodies are not persisted. Validation observations retain bounded metadata, redacted shapes, selected headers, hashes, and safety decisions.

## Candidate families

### Common passive-live candidates

- authentication/session boundary observations;
- information disclosure and excessive data exposure;
- low-risk CORS header observations;
- non-followed redirect observations;
- cache directives;
- source-map presence;
- selected GraphQL data-shape and enumeration signals.

### Plan-only controlled candidates

- BOLA/IDOR;
- BFLA;
- cross-tenant authorization;
- mass assignment;
- GraphQL authorization;
- WebSocket authorization.

The engine never guesses identifiers, enumerates objects, or requests third-party records.

### Manual-only candidates

- SSRF;
- executable reflected/stored/DOM XSS;
- uploads and traversal;
- races and concurrency attacks;
- payment, refund, redemption, or balance operations;
- account recovery;
- role or permission changes;
- webhook/event triggering;
- destructive operations.

## HAR and Burp import

HAR and Burp XML imports are treated as analyst-supplied evidence:

- maximum input size is bounded;
- only in-scope records are retained;
- authorization, cookie, and related secrets are redacted;
- raw request and response bodies are not stored;
- only bounded metadata and redacted response structures are retained;
- XML DTD and entity declarations are rejected.

Imported evidence does not confirm a candidate.

## Result states

```text
not_eligible
plan_ready
awaiting_approval
running
strengthened
weakened
inconclusive
blocked_by_scope
stopped_for_safety
requires_manual_review
```

The candidate's analyst decision remains `unreviewed` until a human records a decision.

## Analyst feedback

Validation feedback uses structured outcomes and reason codes. It is added to audit and calibration inputs but does not silently rewrite earlier decisions.

Examples include:

```text
ownership_boundary_failure
authorization_enforced
identifier_ignored
unexpected_sensitive_data
expected_behavior
wrong_bug_family
insufficient_evidence
manual_review_required
```

## CLI

```bash
./recon-monitor.sh validation eligibility --case-id CASE_ID
./recon-monitor.sh validation plan --case-id CASE_ID --level offline
./recon-monitor.sh validation approve --plan-id PLAN_ID \
  --confirmation I_CONFIRM_SAFE_VALIDATION_FOR_PLAN_ID
./recon-monitor.sh validation run --plan-id PLAN_ID
./recon-monitor.sh validation run --plan-id PLAN_ID --allow-live
./recon-monitor.sh validation show --case-id CASE_ID
./recon-monitor.sh validation import-har --case-id CASE_ID --file session.har
./recon-monitor.sh validation import-burp --case-id CASE_ID --file burp.xml
./recon-monitor.sh validation feedback --run-id RUN_ID \
  --decision strengthened --reason unexpected_sensitive_data
```

## Dashboard and API

Dashboard route:

```text
/safe-validation
```

Local API routes:

```text
GET  /api/v1/validation/eligibility
GET  /api/v1/validation/plans
POST /api/v1/validation/plan
POST /api/v1/validation/approve
POST /api/v1/validation/run
POST /api/v1/validation/feedback
```

API authentication and role checks remain active.

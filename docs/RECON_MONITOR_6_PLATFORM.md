# Recon Monitor 6.0 — Intelligence, Automation and Hardening Platform

Recon Monitor 6.0 closes the loop between collection, analysis, bounded validation, analyst decisions and operations. It remains local-first and authorization-gated. It does not add exploit automation, destructive testing, credential replay, object enumeration or automatic vulnerability confirmation.

## 1. Validation Intelligence

Every completed validation run receives separate scores for:

- test reliability;
- context coverage;
- response comparability;
- identity confidence;
- scope confidence;
- freshness;
- overall confidence.

The result is compared with the previous validation, stored authentication-boundary observations and response-shape history. Limitations are persisted instead of being hidden inside one confidence number.

## 2. Revalidation policies

A case can be revalidated after:

- a configured interval;
- a deployment signature change;
- a response-shape change;
- an authentication-boundary change;
- an evidence change;
- a manual decision.

Automatic processing creates and executes **offline plans only**. It performs zero network requests. Passive-live validation still requires a case-specific plan, exact approval phrase, authorization gates and `--allow-live`.

## 3. Data Quality and Coverage

Each completed run gets a persisted quality snapshot covering stage/tool success, DNS, HTTP, JavaScript, endpoint contracts, response shapes, authentication contexts, behavioral comparisons and parser diversity.

The engine reports explicit blind spots such as:

- no authenticated context;
- only one identity or role context;
- JavaScript stage succeeded but produced no files;
- endpoints exist without response shapes;
- no behavioral comparison is possible;
- failed or missing pipeline stages.

A low candidate count is therefore not presented as evidence that the target is secure.

## 4. Cost-aware review priority

Open cases receive separate estimates for:

- security value;
- expected information gain;
- analyst effort;
- required contexts and identities;
- historical family precision.

`review_value` prioritizes cases that can produce meaningful security information without consuming disproportionate analyst time. It does not replace likelihood, impact or evidence-strength scores.

## 5. Burp round-trip

A case can export a redacted JSON package containing endpoint context, method, known parameters, ownership model, reasoning, missing evidence and safe stop conditions.

Structured results can be imported back with a decision and reason code. Raw request and response bodies, cookies, authorization values and sensitive query values are not retained.

## 6. Security Story Correlation v2

Candidates are correlated using endpoint prefixes, deployment signatures, object context and authentication-boundary context. Each story stores explicit links to its candidate members and a transparent correlation explanation.

## 7. Automation

Schedule policies can generate a macOS LaunchAgent. The scheduled workflow:

1. checks Quiet Hours;
2. runs the authorized target workflow;
3. refreshes platform intelligence;
4. processes due offline revalidations;
5. delivers immediate notifications.

Applying a LaunchAgent is supported only on macOS and requires an explicit `--apply` operation.

## 8. Smart notifications

Events are classified as immediate, digest, system warning or silent. A 24-hour fingerprint suppresses duplicate delivery while preserving occurrence counts. Per-target policies and minimum scores can override the default classification.

## 9. Platform hardening

Version 6 adds:

- scoped and expiring API tokens;
- account failure counters and temporary lockout;
- `lead_analyst` RBAC role;
- CSRF and same-origin form enforcement;
- localhost binding protection;
- security-posture checks;
- safe file-permission repair;
- tamper-evident audit hash chaining.

Existing installations keep their current authentication setting during upgrade. The example configuration enables dashboard authentication for new installations.

## 10. Retention

Retention is preview-first. Confirmed evidence and case evidence are protected. Deletion requires the exact preview-specific confirmation phrase and refuses paths outside the project root.

Default policies:

- raw HTTP artifacts: 90 days;
- JavaScript snapshots: 180 days;
- temporary exports: 30 days;
- logs: 45 days;
- backups: latest 10;
- confirmed and case evidence: protected.

## 11. Performance diagnostics

Dashboard route durations and platform operations are sampled. The diagnostics page shows slow operations, cache-hit rate, database and WAL sizes, and largest tables. Normal dashboard pages still use bounded queries and persisted snapshots.

## 12. Target templates

Templates exist for passive-only, standard web, JavaScript SPA, API-heavy, GraphQL, large-enterprise and low-noise monitoring. Templates update modules, limits and analysis preferences only. They never infer or expand scope and never grant active-testing authorization.

## 13. Report Quality Assistant

Report drafts are checked for affected asset, observed behavior, expected behavior, impact, evidence, reproduction, scope confirmation and redaction. Missing sections remain visible and unverified candidates are not represented as confirmed vulnerabilities.

## Safety boundary

Automated live validation remains limited to approved, in-scope `GET`, `HEAD` and `OPTIONS` plans with strict budgets, no redirect following, no credential or cookie replay, no raw body storage and immediate stop conditions. BOLA/BFLA cross-context tests, SSRF, executable XSS, file upload, traversal, race, payment, recovery, role modification and destructive actions remain controlled-plan-only or manual-only.

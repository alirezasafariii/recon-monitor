# BOLA / IDOR Intelligence 2.0

## Purpose

Recon Monitor treats object references as investigation surfaces, not vulnerabilities. A BOLA / IDOR Potential Finding is admitted only when stored target evidence connects a client-controlled object reference and object operation to an object-level authorization-boundary failure or conflict.

The engine is offline-first. It analyzes evidence already collected by Recon Monitor and does not perform cross-user enumeration, object substitution, exploitation, or automatic active validation.

## Scientific evidence model

A basic object endpoint such as `GET /orders/{id}` produces a hidden hypothesis. It does **not** become a Potential Finding merely because an identifier and HTTP method are present.

Promotion requires all three evidence classes:

1. **Object reference** — a structural path/query/body/GraphQL object identifier.
2. **Object operation** — a known read/create/update/delete operation.
3. **Authorization-boundary evidence** — stored target evidence supporting at least one of:
   - cross-identity object access;
   - cross-tenant / cross-organization object access;
   - explicit identity/object ownership mismatch;
   - parent-child scope mismatch;
   - authorization expectation vs observed response differential;
   - object access without a secondary guard known by the stored target evidence to be required;
   - identity/object relation conflict;
   - successful object response in a context explicitly recorded as unauthorized.

Weak or incomplete signals remain in `analysis_hypotheses` as `shadow_signal`, `shadow_partial`, or `shadow_contradicted`. They are not discarded.

## Contradicting evidence

The following stored observations push a hypothesis away from promotion unless stronger target-specific positive evidence exists:

- unauthorized comparison context denied with 401/403/404;
- explicit ownership enforcement observation;
- explicit tenant/parent scope-binding observation;
- a required secondary guard being enforced;
- evidence that the object is intentionally public/shared/global.

A denial in the currently observed anonymous context is not proof that BOLA is absent; it only means cross-object authorization remains untested.

## Real-world patterns used to design the model

External material defines **what evidence relationships to look for**. It never counts as target evidence and never increases target confidence by itself.

### OWASP API1:2023 — Broken Object Level Authorization

The central authorization question is whether the logged-in identity may perform the requested action on the requested object. Object IDs can appear in path, query, headers, or request payloads. Identifier unpredictability is defense-in-depth, not authorization.

Reference: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

### OWASP WSTG — BOLA / IDOR testing

The testing model maps object references and compares access across objects/identities with distinct authorization scopes. Recon Monitor records that comparison as a missing-evidence requirement unless equivalent evidence already exists in stored observations; it does not perform the live comparison automatically.

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization

### CWE-639 — Authorization Bypass Through User-Controlled Key

The relevant weakness is not merely a controllable key. The authorization process must fail to ensure that the authenticated user has entitlement to the referenced record.

Reference: https://cwe.mitre.org/data/definitions/639.html

### GitHub Security Lab — Spree GHSL-2026-029

Pattern modeled: object key accepted while a secondary access guard (order token / ownership binding) is not enforced. Recon Monitor only emits `object_access_without_secondary_guard` when stored target evidence explicitly records that a guard is required, absent, and the operation succeeded.

Reference: https://securitylab.github.com/advisories/GHSL-2026-029_Spree/

### GitHub Security Lab — Zammad GHSL-2026-049

Pattern modeled: object fetched by ID and returned without enforcing the group/role boundary that should protect it. Recon Monitor models this as an authorization expectation/response conflict or identity/object relation mismatch when the target evidence contains that relationship.

Reference: https://securitylab.github.com/advisories/GHSL-2026-049_Zammad/

### GitHub Security Lab — Wekan GHSL-2026-044

Pattern modeled: authorization succeeds for a parent scope, but a separately supplied child ID is acted upon without binding the child to that parent. Recon Monitor models an explicit stored mismatch as `parent_child_scope_mismatch`; the mere presence of two IDs is only structural context.

Reference: https://securitylab.github.com/advisories/GHSL-2026-044_Wekan/

### GitHub Security Lab — Sentry GHSL-2025-130

Pattern modeled: a valid organization context is combined with an object from another organization and the response succeeds. Recon Monitor models explicit stored request-tenant vs object-tenant mismatch as `cross_tenant_object_access`.

Reference: https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/

## Knowledge/evidence separation

Knowledge references are persisted only in the hypothesis knowledge context. They are forbidden from `supporting_evidence_json` and do not contribute weights, source counts, likelihood, evidence strength, or admission.

```text
External knowledge
      ↓
Defines evidence relationships to seek
      ↓
Target observations / stored context
      ↓
Deterministic evidence extraction
      ↓
Hypothesis admission
      ↓
Potential Finding only if sufficient
```

## Safety

No automatic live object substitution is performed. Any analyst validation must use only explicitly authorized test identities and objects and remains gated by target policy. Potential Findings remain unverified until analyst validation.

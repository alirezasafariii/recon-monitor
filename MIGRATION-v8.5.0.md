# Recon Monitor v8.5.0 Migration

## Scope

v8.5.0 introduces BOLA / IDOR Intelligence 2.0. Schema remains 18; the migration is code/rule-only and does not remove or rewrite historical evidence.

## Behavior change

Previously, BOLA candidate generation could mature from a structured object identifier plus a known object operation once generic quality conditions were met. In v8.5.0 those signals are retained as hidden hypotheses but are not analyst-facing candidates until stored target evidence supports an object-level authorization-boundary mismatch.

New decisive BOLA evidence classes include cross-owner/cross-tenant access, parent-child scope mismatch, authorization-response differential, identity/object relation conflict, and a required secondary object guard being absent while the stored operation succeeds.

Strong stored enforcement evidence can keep a hypothesis hidden. This does not delete the signal; it remains auditable in the hypothesis ledger.

## Knowledge sources

OWASP API1:2023, OWASP WSTG, CWE-639, and public GitHub Security Lab advisories for Spree, Zammad, Wekan, and Sentry inform the evidence model. These references are knowledge context only and never count as target evidence.

## Safety

The new engine is offline-only. It does not perform automatic cross-user object substitution or active authorization validation.

## Compatibility

- Application: 8.5.0
- Database schema: 18
- Analysis engine: 5.2.0
- Candidate engine: 5.2.0
- Admission engine: 1.1.0
- BOLA engine: 2.0.0

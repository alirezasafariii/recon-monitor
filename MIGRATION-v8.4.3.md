# Recon Monitor v8.4.3 Migration

## Scope

v8.4.3 introduces a recall-preserving analysis admission layer. The migration is additive and does not delete or rewrite prior runs, alerts, candidates, analyst decisions, evidence snapshots, or audit history.

## Schema

Schema version increases from 17 to 18.

A new `analysis_hypotheses` table stores weak and incomplete security hypotheses before they are eligible for analyst-facing candidate promotion. The table records:

- semantic hypothesis fingerprint
- source run / analysis / target / endpoint lineage
- merged supporting and contradicting signals
- missing family-specific evidence
- decisive signal types
- admission assessment and state
- external knowledge references used only as detection guidance
- promotion link when a hypothesis becomes a candidate
- first/last seen timestamps and seen count

## Recall-preserving behavior

A hypothesis that does not meet a family-specific admission gate is not discarded. It remains in `analysis_hypotheses` and can accumulate complementary evidence from later observations in the same analysis. Only admitted hypotheses are materialized into `bug_candidates`.

This separates hidden analysis state from analyst-facing Potential Findings without treating absence of evidence as evidence of safety.

## Compatibility

Existing databases migrate automatically through `Database.migrate()`. Schema 18 is additive. No `init` is required and existing configuration, policies, runs, evidence, decisions, and backups remain valid.

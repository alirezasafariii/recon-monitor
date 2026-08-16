# Final Analyzers — Analysis 6.33 Gap Audit

Audit source: `agent/analysis-engine-6.33-fresh-blind-v8-validation`  
Integration target: `final-analyzers`

## Goal

Use the strongest methodology from Analysis 6.33 without replacing the 8.6
product/evidence runtime or creating a second vulnerability-decision engine.

## Disposition

### Integrated

1. **Source-free researcher playbooks**
   - Derived from canonical `FamilyDetectionSpec` only.
   - Exposes strategy, decisive conditions, controls, confounders, false-positive
     checks, methodology principles, and write-up lessons.
   - Strips source/ref/url provenance from the playbook.
   - Attached only after admission is calculated; it cannot change admission.

2. **Family-scoped evidence isolation**
   - Explicit evidence scoped to another family is quarantined fail-closed.
   - Legacy unscoped evidence remains readable for compatibility.
   - Newly persisted hypothesis evidence receives `family_scope` and
     `evidence_namespace=family:<family>`.
   - Cross-family evidence cannot satisfy required groups or independent-source
     requirements.

### Already covered by final-analyzers

- Standards/methodology/write-up grounding via `family_specs`.
- Knowledge is non-evidentiary.
- Raw Recon context is demoted unless analyzer-owned target evidence is promotion-ready.
- Raw analyzer fan-out is bounded.
- Controls/contradictions and confirmation contracts are canonical Family Reasoning data.
- Temporal/workflow intelligence is context-only.

### Intentionally not ported

1. **Weighted family reasoner admission/scoring**
   - 6.33 family weights, admission bonuses, and confounder penalties remain
     ranking/research ideas only.
   - Final admission remains deterministic evidence-contract evaluation.

2. **Parallel detector execution / raw-condition reconstruction runtime**
   - Wholesale port would create two physical detector runtimes.
   - Useful safety properties already exist in the final analyzer bridge and
     dedicated analyzers: passive-only reconstruction, no knowledge-as-evidence,
     and decisive-condition gating.

### Deferred before main merge

**Structured taxonomy attribution policy** from 6.33 (`direct` vs `contextual`,
`auto_assign`, `when_any`). The current final spec stores taxonomy IDs but does
not yet encode per-reference attribution policy. This should be added as a
metadata/schema migration, not mixed into target-evidence admission.

## Merge principle

`8.6 runtime/product backbone + final-analyzers evidence contracts + selected
6.33 methodology/isolation properties`, with exactly one admission authority.

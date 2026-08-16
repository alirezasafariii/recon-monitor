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

### Integrated after the initial audit

**Structured taxonomy attribution policy** is now part of the canonical final
spec projection. Every migrated OWASP/WSTG/CWE/CAPEC reference receives a
reviewed `direct`, `contextual`, or `methodology` relationship plus explicit
`auto_assign` / `when_any` behavior. Assignment runs only after target-evidence
admission is fixed. WSTG/CAPEC never auto-assign, ambiguous CWE root causes stay
manual, and standards still contribute zero target evidence.

### Remaining before main merge

No Analysis 6.33 detector/reasoner runtime is intentionally pending. Remaining
work is merge hardening: feature freeze, final diff review, full CI, and branch
protection/PR review rather than adding a parallel reasoning engine.

## Merge principle

`8.6 runtime/product backbone + final-analyzers evidence contracts + selected
6.33 methodology/isolation properties`, with exactly one admission authority.

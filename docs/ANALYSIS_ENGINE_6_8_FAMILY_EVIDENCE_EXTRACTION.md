# Analysis Engine 6.8 — Family-Specific Evidence Extraction

## Purpose

Analysis 6.7 separated family reasoning. Analysis 6.8 moves the same separation one layer earlier: evidence is now namespaced at extraction time so one vulnerability family cannot silently borrow another family's evidence merely because a signal type is shared.

The core invariant is:

`raw recon clue -> family extractor namespace -> hidden hypothesis -> family admission -> family reasoner -> candidate`

## 31 extractor profiles

`app/family_evidence_extractors.py` contains exactly one `FamilyEvidenceExtractorProfile` for every family in `FAMILY_ADMISSION_POLICIES`.

Every profile owns a unique extraction strategy and declares the evidence channels relevant to that family. Examples include object/identity boundaries for BOLA, role/function boundaries for BFLA, SQL query semantics for SQL injection, process-execution semantics for command injection, server-template evaluation for SSTI, filesystem confinement for path traversal, cross-origin credential boundaries for CORS, and atomicity invariants for race conditions.

Import-time validation fails if extractor coverage differs from admission coverage or if a profile is malformed.

## Evidence namespace

Every new candidate/hypothesis evidence item is annotated with:

- `family_scope`
- `evidence_namespace`
- `extractor_id`
- `extractor_version`
- `extractor_rule_version`
- `extractor_channel`
- `signal_role`
- `counts_for_family`
- `extraction_state`

Signal roles are derived from that family's own admission policy:

- `surface`: useful hypothesis context but not policy evidence
- `identity`: identifies the family-specific security boundary
- `condition`: directly supports the vulnerability condition
- `control`: a family-specific blocking/security control
- `contextual_control`: contradictory context that is not a formal blocker

Surface clues remain preserved. They are not deleted merely because they cannot establish a finding.

## Cross-family evidence firewall

Pre-scoped evidence may never be relabeled into a different family. `scope_family_evidence()` quarantines it and reports `rejected_cross_family_count`.

Admission independently ignores evidence whose non-empty `family_scope` belongs to another family.

Family reasoners independently apply the same rule before calculating group coverage, source counts, confounders, admission state, or family fit.

This is defense in depth: an upstream extraction mistake cannot become a downstream family promotion simply through a shared signal name.

## Shared signal names are safe

Some families legitimately use the same abstract signal name. For example `input_parameter` appears in multiple injection policies and `state_change` appears in multiple authorization/business-logic policies.

In 6.8 the same raw clue becomes separate namespaced evidence packets such as:

- `family:sql_injection / input_parameter`
- `family:nosql_injection / input_parameter`

A SQL-scoped input cannot satisfy NoSQL admission or ranking, and vice versa.

## Multi-label behavior

Family isolation does not force a single label. If one raw observation independently establishes two vulnerability conditions, the extraction pipeline creates two separately scoped evidence packets. Each family must satisfy its own admission and reasoner independently.

## Historical benchmark compatibility

Existing Golden v1-v3 fixtures are intentionally unscoped. Unscoped evidence remains readable as legacy evidence so historical regression benchmarks do not change meaning solely because provenance metadata was added.

New production extraction is always scoped. Golden v4 remains a consumed post-freeze evaluation and is not reused as a fresh 6.8 holdout.

## Versions

- Analysis Engine: `6.8.0`
- Candidate Engine: `6.8.0`
- Admission Engine: `2.4.0`
- Family Reasoner: `1.1.0`
- Ranking Engine: `2.1.0`
- Security Family Ranker: `1.1.0`
- Security Reasoning Engine: `6.8.0`
- Family Evidence Extractor: `1.0.0`
- Rule: `2026.08.10.6.8`

## Regression contract

6.8 must preserve:

- weak clues in hidden hypotheses;
- family-specific admission gates;
- target evidence vs external-knowledge separation;
- positive/negative/unknown evidence separation;
- multi-label findings when independently established;
- existing Golden regression behavior for unscoped historical fixtures.

New tests additionally require exact 31-family extractor coverage, unique extraction strategies, extractor/reasoner identity-gate equality, cross-family reassignment rejection, admission isolation, reasoner isolation, control scoping, and shared-signal namespacing.

# Analysis Engine 6.12 — Raw Condition Reconstruction and Observability

## Purpose

Analysis 6.12 addresses the failure exposed by the Analysis 6.11 blind raw-recon holdout: the engine was precise and conservative, but many raw/minimally-normalized artifacts did not reconstruct the decisive family condition required for admission.

The 6.12 contract is:

> reconstruct only what the stored target artifact can actually establish; improve family routing from family-specific raw semantics; never manufacture a vulnerability condition from a schema name, category label, absent blocker, standard, or write-up.

Analysis 6.11 raw v1 is **consumed**. Every 6.12 measurement against v1 is a development regression result only. It is not fresh, blind, or evidence of generalization.

## Epistemic rules preserved

1. Surface/schema/category evidence may establish family identity, but not the final vulnerability condition.
2. External WSTG/CWE/write-up provenance never counts as target evidence.
3. A missing blocker is not proof of vulnerability.
4. Positive and negative evidence remain separate.
5. Admission thresholds were not reduced.
6. Cross-family evidence still passes through the Analysis 6.8 family evidence firewall.
7. The Analysis 6.7 distinction between Family Fit and Vulnerability Condition Confidence remains intact.
8. Redacted or placeholder credential material may identify a secret-shaped surface, but cannot establish a usable/high-entropy secret.

## New reconstruction layer

`app/family_detectors/reconstruction.py`

The reconstruction layer runs after the existing passive 6.10 raw heuristics and before the physical family detector / family evidence firewall boundary.

It reconstructs decisive evidence only from stored facts such as:

- explicit expected-deny authentication contexts that return success,
- controlled account-identity contexts with observable response differences,
- privilege-sensitive request properties reflected/applied in a successful resulting resource state,
- stored outbound backend request URLs on client-influenced destination surfaces,
- dangerous uploaded types with a successful storage/processing artifact,
- traversal input plus a stored resolved path outside an explicit base path,
- directly observed generic stack traces / exception frames,
- successful public responses containing concrete diagnostic/internal material.

It also adds routing-only identity evidence for process/CLI execution and template-rendering surfaces. Those routing clues cannot satisfy a final admission condition by themselves.

## Raw routing boundary corrections

Analysis 6.12 also removes several generic semantic collisions that the raw benchmark exposed:

- an ordinary `/api/v1/...` route is no longer treated as API inventory drift by itself;
- `{provider}` in an OAuth route is no longer treated as proof of third-party API consumption;
- `report` alone is no longer treated as an SQL/query surface;
- `/upload` and `/import` alone no longer create a Path Traversal identity when no path input exists;
- stored CLI invocation syntax may identify Command Injection as the relevant family without being treated as process-execution proof.

These changes improve family routing while leaving admission conservative.

## Observability accounting

`app/raw_recon_observability.py` explicitly measures exact raw collisions between a positive case and negative variants from the same source root.

On consumed Analysis 6.11 raw v1:

- source roots: **24**
- roots whose positive raw input is exactly identical to at least one negative variant: **15**
- roots distinguishable by exact raw input: **9**

Therefore the historical 6.11 positive recall target cannot be interpreted as if all 24 positives were identifiable from the supplied raw artifact. For an exact positive/negative raw collision, a deterministic detector that consumes only that artifact cannot both recover the positive and preserve negative precision. The correct behavior is to abstain until additional target evidence is collected.

This observability result is diagnostic and does not change labels, admission, or benchmark scoring.

## Consumed-v1 regression runner

`app/raw_recon_regression.py` evaluates current production logic against the already-consumed raw v1 dataset without invoking the Analysis 6.11 fresh-freeze verifier.

Every result is explicitly labeled:

`consumed_diagnostic_regression`

and:

`fresh_or_blind_claim_allowed = false`

Its safety regression requires that the current engine does not degrade the historical v1 safety metrics:

- condition extraction precision,
- admission precision,
- abstention accuracy,
- false-promotion rate,
- wrong-family promotion rate.

## Consumed-v1 development result

Historical Analysis 6.11 fresh result versus current Analysis 6.12 development regression:

| Metric | 6.11 fresh historical | 6.12 consumed regression |
|---|---:|---:|
| Condition extraction precision | 1.000000 | 1.000000 |
| Condition extraction recall | 0.250000 | 0.333333 |
| Routing Top-1 | 0.652778 | 0.930556 |
| Routing Top-3 | 0.777778 | 0.930556 |
| Admission precision | 1.000000 | 1.000000 |
| Admission recall | 0.250000 | 0.333333 |
| Abstention accuracy | 1.000000 | 1.000000 |
| False-promotion rate | 0.000000 | 0.000000 |
| Wrong-family promotion rate | 0.000000 | 0.000000 |
| End-to-end accuracy | 0.812500 | 0.833333 |

This is **not a fresh benchmark improvement claim**. It is evidence that the 6.12 development changes move the consumed diagnostic set in the intended direction without sacrificing its historical safety metrics.

The remaining routing errors are primarily cases where the negative replay contains no family-specific raw surface at all, including information-disclosure and secret-exposure negatives, plus a safe CORS response whose stored headers demonstrate a non-reflected trusted origin but do not satisfy the family identity gate. Fabricating identity evidence for those cases merely to raise Top-3 would violate the raw-evidence contract.

## Version lineage

- Analysis Engine: `6.12.0`
- Candidate Engine: `6.12.0`
- Security Reasoning: `6.12.0`
- Detector Execution Engine: `1.1.0`
- Raw Reconstruction Engine: `1.0.0`
- Raw Observability Engine: `1.0.0`
- Consumed Raw Regression Engine: `1.0.0`
- Rule version: `2026.08.11.6.12`

Admission, evidence-firewall, physical-detector, standards, and family-reasoner semantics remain independently versioned unless explicitly changed.

## What 6.12 does not claim

Analysis 6.12 does not establish fresh real-world recall or generalization. Raw v1 was consumed by Analysis 6.11 and is now only a diagnostic development set.

A new unbiased claim requires:

1. freeze the final 6.12 production logic,
2. pre-register the next raw benchmark protocol and gates,
3. collect a brand-new independent source-root set,
4. ensure the new fixtures contain sufficient raw target observations to make the labeled condition testable without engine-native labels,
5. seal that corpus before scoring,
6. evaluate it exactly once as a fresh holdout.

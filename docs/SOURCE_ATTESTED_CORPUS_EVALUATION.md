# Source-Attested Corpus Evaluation

## Purpose

Source-attested evaluation is the low-operator-skill path for Real-World Corpus
V1. It removes manual security adjudication from the normal evaluation workflow
without pretending that machine-generated labels are human verified.

The evaluator accepts a case only when all conservative source gates pass:

- GitHub reviewed advisory;
- advisory is published and not withdrawn;
- first patched version exists;
- exact fix commit is directly referenced by the advisory;
- exact vulnerable parent and fix revisions are captured;
- revision trees and changed-file pairs are complete;
- patch hashes are present;
- the case is a fresh candidate;
- canonical CWE mapping produces exactly one family hint;
- targeted-family metadata, when present, does not conflict with the unique CWE
  family hint.

Ambiguous cases are excluded rather than guessed.

## Current checked-in corpus coverage

With the current Corpus V1 artifacts, the strict source-attested gate accepts:

- 19 independent source origins;
- 38 paired records;
- 19 source-attested positives;
- 19 source-attested secure negatives;
- 11 canonical vulnerability families.

The remaining exact revision-pair origins are excluded by the conservative
gates. The largest exclusion class is ambiguous CWE-to-family mapping.

These numbers are regression properties of the current frozen corpus, not a
claim about general production accuracy.

## One-command workflow

Run:

```bash
./recon-monitor.sh analysis corpus-v1-auto-evaluate
```

No security expertise is required for source-label construction. The command
loads the checked-in feasibility, public-source evidence and exact revision-pair
artifacts and builds source-attested cases automatically.

Before current-engine replay scores exist, the expected status is:

```text
awaiting_current_engine_replay
```

This is intentional. The evaluator never creates Analysis scores from the
expected label or family.

## Label-blind replay manifest

To prepare a scorer-facing manifest:

```bash
./recon-monitor.sh analysis corpus-v1-auto-evaluate \
  --blind-replay-output ./corpus-v1-blind-replay.json
```

The blind replay manifest contains only:

- opaque case ID;
- source project;
- revision SHA;
- instruction to score all canonical families.

It excludes:

- positive/negative label;
- variant;
- expected family;
- GHSA/source root;
- CWE/advisory metadata;
- attestation outcome.

Opaque case IDs do not contain words such as `positive` or `negative`.

This prevents the scoring stage from learning the expected answer through the
input metadata.

## Joining current-engine scores

A label-blind score artifact may later be supplied with:

```bash
./recon-monitor.sh analysis corpus-v1-auto-evaluate \
  --corpus-scores ./current-engine-scores.json \
  --attested-output ./source-attested-results.json
```

Each score row is keyed by opaque case ID and must provide:

```json
{
  "id": "SA-...",
  "decision_readiness_score": 73,
  "bug_proximity_score": 81,
  "target_evidence_confidence": 69,
  "engine_version": "8.8.0"
}
```

A score row containing a ground-truth `label` is rejected.

When scores are present, the evaluator creates a deterministic label-blind
train/holdout split by case origin and reports holdout metrics at the fixed
threshold. It does not learn or activate a new production threshold.

## Scientific boundary

Source-attested means:

> public advisory + exact fix boundary strongly supports the source label.

It does **not** mean:

> an independent human analyst reproduced and confirmed the vulnerability.

Therefore source-attested metrics are appropriate for:

- automatic regression tracking;
- comparing engine versions;
- finding obvious weak families;
- detecting large precision/recall regressions;
- guiding engineering work.

They are not sufficient by themselves for:

- claiming a statistically proven real-world vulnerability detection rate;
- automatic production threshold changes;
- vulnerability confirmation against a live target.

## Current remaining engineering boundary

The source-label side is now automatic. The remaining requirement for complete
end-to-end metrics is a label-blind **current-engine replay scorer** capable of
turning each source revision into the same kind of evidence that Recon Monitor
would observe against a real target.

Until that scorer exists, the evaluator correctly reports
`awaiting_current_engine_replay` instead of fabricating scores from advisory
metadata.

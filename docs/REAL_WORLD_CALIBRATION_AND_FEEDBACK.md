# Real-World Calibration and Shadow Feedback

Recon Monitor 8.6 keeps production vulnerability decisions separate from calibration and learning.

## Goal

The real-world calibration pipeline measures how Analysis decision-readiness behaves on human-verified target history without allowing the measurement layer to become vulnerability evidence or silently tune production decisions.

The pipeline is:

1. collect analyst-reviewed replay drafts from Investigation,
2. explicitly review all evidence-quality dimensions,
3. finalize records against the Verified Replay Contract,
4. export accepted records as JSONL,
5. run a deterministic label-blind train/holdout evaluation,
6. learn candidate thresholds from train only,
7. measure precision, recall, specificity, false-positive rate, false-negative rate, F1 and balanced accuracy on holdout,
8. inspect per-family results and shadow feedback suggestions,
9. make any production policy change separately and manually.

## Verified replay requirements

A record must use a canonical vulnerability family and trusted real-world provenance. It must be human verified and contain:

- `label_source`
- `reviewer_id`
- `reviewed_at`
- `case_origin_id`
- `evidence_snapshot_id`
- a complete evidence-quality review covering reliability, specificity, directness, freshness, independence, reproducibility and uncertainty

Synthetic challenge cases and golden fixtures are intentionally rejected by the real-world replay contract.

## Evidence-quality gate

Contract-valid records may still be excluded from production-quality evaluation if evidence quality is too weak. The default evaluation threshold is 60/100. Exclusion affects calibration metrics only; it does not rewrite the analyst label or target evidence.

## Leakage protection

Train and holdout assignment is deterministic and label blind.

The partition key is derived from `case_origin_id` only. Labels, scores, family names and reviewer identities are not used. All snapshots sharing one case origin stay in the same partition, preventing the same reviewed case from appearing in both train and holdout.

The default holdout target is 20 percent.

## Threshold evaluation

The current decision-readiness threshold is evaluated on holdout data. A candidate threshold may be learned from train data only when the train set has sufficient positive and negative support.

The holdout set never selects the threshold. It only measures whether the candidate generalizes without a material regression in F1, precision, recall or false-positive rate.

Per-family threshold diagnostics use the same rule with stricter fail-closed support checks.

## Shadow feedback learning

Holdout errors are mined for repeated patterns:

- repeated signals in false positives -> precision/noise review candidate
- repeated signals in false negatives -> recall-gap review candidate
- repeated contradictions in false positives -> contradiction-suppression review candidate

These are review suggestions only. The learning layer does not edit signal weights, Family Reasoning rules, admission requirements, confirmation requirements or Candidate state.

## Deployment review gate

Even a healthy corpus never activates production calibration automatically.

The default manual-review gate requires at least:

- 400 trusted evaluation records
- 40 represented canonical families
- 3 human reviewers
- no reviewer contributing more than 70 percent of accepted evaluation records
- 80 holdout records
- holdout precision >= 0.80
- holdout recall >= 0.70
- holdout false-positive rate <= 0.10
- zero case-origin leakage
- a candidate threshold that does not materially regress holdout performance

Passing this gate changes status only to `ready_for_manual_policy_review`. Effective activation remains `shadow_only` until a separate explicit policy change is made.

## CLI

Generate review drafts from existing Investigation decisions:

```bash
./recon-monitor.sh analysis verified-replay-drafts --limit 1000
```

After evidence-quality review and JSONL finalization, evaluate one or more verified corpora:

```bash
./recon-monitor.sh analysis real-world-calibration \
  --verified-corpus ./verified-replay-a.jsonl \
  --verified-corpus ./verified-replay-b.jsonl
```

The real-world calibration command is offline. It does not require target access, credentials, payload generation, live validation or a Recon run.

## Safety boundary

Real-world calibration and feedback:

- perform no network requests,
- do not create target evidence,
- do not satisfy admission,
- do not confirm vulnerabilities,
- do not create Potential Findings,
- do not change Family Reasoning,
- do not apply threshold or weight changes automatically,
- do not allow synthetic/golden records to unlock production policy.

The trusted real-world corpus size must always be reported separately from deterministic golden/synthetic regression coverage.

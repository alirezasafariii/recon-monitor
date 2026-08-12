# Analysis Engine 6.26 — Fresh Raw Holdout v4

Analysis 6.26 is a one-time fresh raw holdout for the sealed Analysis 6.25 detector stack.

## Pre-registration goals

- Evaluate all 36 sealed vulnerability families.
- Select source roots before any detector, ranking, admission, reconstruction benchmark, or quality scoring is executed.
- Require new source roots, new provenance URLs, and new source projects relative to prior Golden/raw corpora.
- Exclude source roots/URLs/projects already exposed in prior v2/v3 discovery pools and shortlists.
- Exclude candidates that reference any real-world write-up already used to ground the current detector intelligence.
- Preserve the raw-label firewall: engine-native evidence labels are never placed inside raw target artifacts.
- Materialize four variants per source root: positive, near-miss, secure-negative, and sparse-noisy.
- Require a target-observable raw delta between the positive and its controls.
- Freeze the corpus and engine inputs before first scoring.
- Allow one first evaluation only. After evaluation, the corpus is consumed and may only be rerun as a labeled regression.

## Source discovery

`app/raw_recon_v4_source_discovery.py` queries reviewed GitHub advisories using only the external CWE taxonomy already mapped to each sealed family. Candidate selection does not execute the Analysis Engine, family ranking, admission assessment, detector execution, or benchmark scoring.

The discovery exclusion set contains all previous raw/golden source roots, URLs and projects, all prior v2/v3 candidate pools/shortlists, and all current detector-grounding write-up URLs.

## Planned collection floor

The v4 freeze will require exactly complete family coverage at collection time:

- at least 36 source roots,
- at least 36 distinct source projects,
- all 36 positive vulnerability families,
- exactly four variants per root,
- zero prior-root overlap,
- zero prior-URL overlap,
- zero prior-project overlap,
- zero grounding-write-up overlap,
- zero positive/control raw collisions,
- 100% positive target-observable delta rate.

These are corpus-integrity requirements, not post-hoc detector-score targets.

## Benchmark gates

The existing raw benchmark quality gates remain pre-registered and unchanged for condition extraction, routing, admission, abstention, false promotion, wrong-family promotion, end-to-end accuracy, source overlap, and label leakage. Analysis 6.26 will report family-level results for all 36 positive families rather than tuning the sealed 6.25 engine on the holdout.

If the first v4 evaluation exposes misses, the holdout is consumed. Any remediation must be trained/calibrated on different source roots and then validated on a future fresh holdout.

# Real-World Corpus V1

## Goal

Build a new, independent, human-reviewable real-world corpus for Recon Monitor without reusing consumed benchmark roots and without consuming the Analysis 6.31 V6 blind corpus.

The target is:

- 100 independent source roots;
- 100 independent source projects where feasible;
- 4 independently supported variants per root: `positive`, `near_miss`, `secure_negative`, `sparse_noisy`;
- 400 reviewed records total;
- at least 50 canonical families before the first score;
- at least 3 human reviewers;
- default 20% holdout after the corpus is frozen.

## Hard independence boundary

Source discovery must firewall all source identities previously exposed to:

- Golden v3;
- Golden v4;
- Raw v1;
- Raw v2;
- Raw v3;
- V6 shortlist/captures.

The firewall compares source root, source project, advisory/CVE identifiers and primary URLs. Golden v3/v4 and Raw v1/v2/v3 are `consumed_benchmark`. V6 is `reserved_blind` and must remain excluded from this corpus until its own one-time blind lifecycle is complete.

A record marked `consumed_benchmark` or `development_only` is train-only. A record marked `reserved_blind` is excluded entirely. Only `fresh_candidate` records may later participate in a new label-blind holdout.

## Source discovery

`app/real_world_corpus_v1.py` can query GitHub's reviewed advisory API and emits metadata-only candidates. Discovery:

- contacts GitHub public metadata only;
- does not contact vulnerability targets;
- does not execute payloads;
- does not run Analysis scoring;
- does not create human labels;
- treats CWE-to-family mappings only as discovery hints.

Final family assignment requires source or human adjudication.

## Git storage policy

The 8.6 source-hygiene policy rejects runtime `*.jsonl` and database files. Therefore Git stores only:

- protocol metadata;
- source candidate registry;
- source discovery report;
- hashes and freeze metadata;
- review/capture schemas.

Human-reviewed replay exports, raw captures, credentials and runtime databases remain outside the repository and are ingested through the existing verified replay/calibration tooling.

## Collection lifecycle

1. Discover fresh primary-source candidates.
2. Apply historical exposure firewall.
3. Review source feasibility and family coverage.
4. Select 100 roots.
5. Collect four controlled observations per root.
6. Bind each observation to source revision and evidence hash.
7. Human-review the label and all seven evidence-quality dimensions.
8. Freeze the accepted corpus.
9. Freeze train/holdout by case origin with all historical/development records forced to train.
10. Run the first score exactly once.

No production threshold or Analysis rule is changed by corpus collection.

## Current phase

`source_discovery` — no scoring has been executed and the V6 reserved blind set remains untouched.

# Analysis Engine 6.4 — Large Real-World Corpus & Held-Out Calibration

Analysis 6.4 expands the standards-grounded benchmark from a compact regression seed into a larger source-rooted evaluation set.

## What changed

- Golden Dataset v3 contains **179 cases**.
- It preserves all 69 v2 cases and adds **33 independent GitHub Security Lab vulnerability roots**.
- Each new real vulnerability root contributes a positive, a decisive-signal-removed near-miss, and a blocking-control secure negative.
- **11 independent source roots** are held out from development and also contribute sparse/noisy recon cases.
- Every case carries WSTG and CWE grounding from `analysis_standards.py`.
- External standards/write-up metadata never counts as target evidence.

## Split discipline

`source_root` is the split unit. A root and every derived variant must stay wholly in `development` or `held_out`. The corpus validator fails on any root leakage. Held-out data is evaluation-only; thresholds are static constants and are never derived from held-out performance.

## Corpus lint

`app/analysis_corpus.py` enforces family/split validity, source root/project/date/provenance, HTTPS provenance, WSTG/CWE consistency, no external-knowledge evidence leakage, expected admission semantics, unique real-positive roots, zero development/held-out root leakage, and minimum corpus diversity.

## Benchmark 3.0

Benchmark 3.0 adds held-out precision/recall, Top-1/Top-3, abstention, false-promotion rate, Brier/ECE, reliability buckets, held-out confusion matrix, source-root leakage rate, and source/root/project statistics.

## Held-out quality floors

- precision >= 0.93
- recall >= 0.85
- Top-1 >= 0.80
- Top-3 >= 0.95
- abstention >= 0.90
- false promotion <= 0.05
- Brier <= 0.15
- ECE <= 0.15
- source-root leakage = 0

A perfect score on this structured corpus is a regression result, not a claim of perfect production-world detection.

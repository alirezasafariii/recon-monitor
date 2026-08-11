# Analysis Engine 6.11 — Blind Raw Recon Benchmark

## Purpose

Analysis 6.11 evaluates the Analysis Engine one layer earlier than the structured-evidence Golden benchmark. The evaluated path is:

`raw/minimally-normalized stored artifact -> detector execution -> physical family detector -> evidence firewall -> admission -> family ranking/reasoning`

The benchmark is intentionally passive/offline. It does not send requests to source projects, execute exploit payloads, brute-force credentials, follow redirects, mutate application state, or validate secrets online.

This phase is an evaluation layer only. Production logic remains Analysis Engine 6.10.0 and Detector Execution Engine 1.0.0. The raw benchmark engine is version 1.0.0 with rule version `2026.08.11.6.11`.

## Epistemic boundary

External advisories are provenance and source material for constructing independent replay fixtures. CWE/WSTG/write-up material never counts as target evidence. The raw corpus is rejected if it contains engine-native evidence labels, `family_scope`, typed `evidence_for/evidence_against`, admission state, CWE/WSTG labels, or other fields that would tell the detector which condition to emit.

The replay fixtures are sanitized raw/minimally-normalized representations derived from primary advisory facts: endpoint/method shape, request field names, response/header behavior, source snippets, and context observations where those facts are available. They are not live target captures, and they are not proof of absolute real-world vulnerability-detection accuracy.

## Pre-registration and freeze

Production and benchmark logic were frozen before post-freeze source collection at commit:

`9f7875ae317635e9042c1ea7bd71cc273219e9b6`

Fourteen protected files are pinned by Git blob SHA in `benchmarks/raw/splits/v1.json`, including Analysis Engine, candidate generation, admission, standards, ranking, family reasoners, evidence firewall, physical detector base/registry, 6.10 execution logic, and the 6.11 benchmark/validator.

Pre-freeze validation run `31444597481` passed syntax, focused 6.11 tests, detector-stack regressions, the full unit suite, Golden v3 regression, and the canonical integration runner.

The acceptance gates were registered before source collection:

| Metric | Gate |
|---|---:|
| Condition extraction precision | >= 0.90 |
| Condition extraction recall | >= 0.75 |
| Routing Top-1 | >= 0.80 |
| Routing Top-3 | >= 0.95 |
| Admission precision | >= 0.93 |
| Admission recall | >= 0.75 |
| Abstention accuracy | >= 0.90 |
| False-promotion rate | <= 0.07 |
| Wrong-family promotion rate | <= 0.05 |
| End-to-end accuracy | >= 0.80 |
| Prior source-root overlap rate | 0 |
| Raw-label leakage rate | 0 |

Five advisory roots observed while verifying the public advisory API before freeze were explicitly excluded and were not eligible for the holdout.

## Post-freeze source selection

Source selection used predeclared family/CWE buckets and reviewed primary GitHub Security Advisories. Eligibility required a reviewed, non-withdrawn advisory, repository advisory URL, source repository, and a minimum technical-description length. Exact prior Golden v3/v4 root/URL overlap was rejected.

The selected holdout contains:

- 24 independent advisory source roots
- 24 distinct source projects
- 20 positive vulnerability families
- 4 variants per root
- 96 total cases
- 24 positive cases
- 24 near-miss cases
- 24 secure-negative cases
- 24 sparse/noisy cases

The source collection and corpus-construction stages did not execute benchmark scoring.

Persistent source inventory: `benchmarks/raw/sources/v1.json`

Corpus: `benchmarks/raw/analysis_raw_v1.jsonl`

Sealed corpus SHA-256:

`af80324f7669c191bcdf9b084108d7018175be993c5868c71dc388d6a2a3413e`

The corpus was sealed unscored after freeze, independence, source-floor, schema, and raw-label-leakage validation. Seal run `31445172722` passed and removed its own temporary workflow.

## First and only fresh evaluation

The first and only fresh evaluation was run exactly once:

- Run: `31445225324`
- Evaluation head: `a11c4c7953fbc67e63a8dc119c5199e98a229495`
- Report: `benchmarks/raw/reports/analysis_raw_v1_postfreeze_report.json`
- Status before scoring: `sealed_unscored`
- Status after scoring: `evaluated_once_consumed`

The one-shot evaluator immediately marked the holdout consumed and deleted itself. Future runs, if ever needed, must be explicitly labeled regression-only and cannot be described as fresh or blind.

## Fresh raw-holdout results

| Metric | Result | Gate | Status |
|---|---:|---:|---|
| Condition extraction precision | **1.000000** | >= 0.90 | PASS |
| Condition extraction recall | **0.250000** | >= 0.75 | **FAIL** |
| Routing Top-1 | **0.652778** | >= 0.80 | **FAIL** |
| Routing Top-3 | **0.777778** | >= 0.95 | **FAIL** |
| Admission precision | **1.000000** | >= 0.93 | PASS |
| Admission recall | **0.250000** | >= 0.75 | **FAIL** |
| Abstention accuracy | **1.000000** | >= 0.90 | PASS |
| False-promotion rate | **0.000000** | <= 0.07 | PASS |
| Wrong-family promotion rate | **0.000000** | <= 0.05 | PASS |
| End-to-end accuracy | **0.812500** | >= 0.80 | PASS |
| Prior source-root overlap | **0.000000** | 0 | PASS |
| Raw-label leakage | **0.000000** | 0 | PASS |

**Overall pre-registered quality gate: FAIL.**

No production detector, admission gate, ranking function, or benchmark threshold was changed after observing this result.

## What the failure means

The strongest result is not a false-positive problem. On this holdout, every admitted finding was correct at the family level: admission precision was 1.0, false-promotion rate was 0, wrong-family promotion was 0, and all 72 non-positive cases abstained correctly.

The dominant failure is **raw condition extraction coverage**. The engine often identified the correct family surface or ranked the correct family near the top but did not derive a decisive condition signal from the raw/minimally-normalized replay artifact. This directly constrained admission recall to 0.25.

Examples visible in the consumed report include:

- Mass Assignment: family identity often ranked correctly, but `privileged_property_accepted` was not established from raw property-write facts.
- Authentication/session: authentication surfaces were recognized, but boundary-regression behavior was not reconstructed.
- Account enumeration: identity lookup was recognized, but differential response evidence was not derived.
- SSRF: URL/fetch surfaces could rank correctly, but some advisory raw representations did not yield a decisive stored server-request condition.
- File Upload vs Path Traversal: upload surfaces could be confused with file/path behavior, while the dangerous-type acceptance condition was missing.
- Path Traversal: path identity was often correct, but escape/unsafe-resolution conditions were not reconstructed.
- Information disclosure and Security Misconfiguration: generic raw response material was insufficient for several decisive public-observation/debug conditions.
- Command Injection and SSTI: the selected source representations frequently lacked a raw signature currently recognized by execution heuristics, so routing fell back to unrelated low-information families.
- Resource Consumption: resource-control surfaces were found, but absence/failure of limiting controls was not established from ordinary raw behavior.
- Secret Exposure: the benchmark intentionally did not inject a synthetic secret after redaction, exposing the limitation of relying on stored credential material rather than richer secret-source lineage.

By contrast, BOLA/BFLA-style stored context comparisons and some CORS/Open Redirect cases performed well because 6.10 already has direct passive transformations from response/context facts into decisive family evidence.

## Interpretation

This benchmark provides stronger end-to-end evidence than the structured Golden v4 evaluation because it starts from raw/minimally-normalized artifacts and requires 6.10 to construct family evidence. It still does not represent live exploitation or a statistically representative sample of all production recon data.

The result supports two simultaneous conclusions:

1. The current admission/evidence firewall is conservative: it strongly resists unsupported promotions and cross-family leakage.
2. Raw detector execution coverage is not yet sufficient: many real vulnerability conditions represented in primary advisories are not reconstructed from stored artifacts without prior typed evidence.

The first property should be preserved while improving the second.

## Next phase

Analysis 6.12 should use this now-consumed v1 report only as a **diagnostic development set** to improve raw detector execution and artifact normalization. High-priority work includes differential/context reconstruction, accepted-write/state evidence, filesystem/upload outcomes, interpreter/process execution traces, resource-control absence evidence, sensitive-response/public-reachability evidence, and better fallback ranking when no family condition is emitted.

After 6.12 is frozen, a **brand-new independent raw holdout v2** must be collected from new source roots/projects. v1 must never be reused to make a fresh generalization claim.

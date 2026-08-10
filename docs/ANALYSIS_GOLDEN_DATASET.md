# Analysis Golden Dataset

Analysis 6.2 adds a reproducible golden benchmark for the vulnerability-condition admission model introduced in Analysis 6.0 and expanded in Analysis 6.1.

## Purpose

The benchmark answers four separate questions instead of collapsing them into one score:

1. **Admission precision/recall** — does decisive target evidence promote the expected family without promoting unrelated families?
2. **Abstention quality** — do attack-surface-only and explicitly secure/control-enforced cases remain hidden?
3. **Family ranking** — is the expected family Top-1 / Top-3 even when admission deliberately abstains?
4. **Calibration** — does the family compatibility score numerically separate positive from near-miss / secure-negative evidence?

The benchmark does not execute attacks, generate exploit payloads, contact target systems, or validate credentials. It operates only on structured stored-fact fixtures.

## Epistemic boundary

External knowledge is provenance, not target evidence.

A case may be derived from an OWASP scenario or a public vulnerability write-up, but the benchmark passes only `support` and `contradict` facts to `assess_admission()`. The `provenance` object is never used to satisfy a required group, increase independent-source count, override a contradiction, or promote a finding.

This preserves the core Analysis contract:

`surface clue -> hidden hypothesis -> decisive target evidence -> Potential Finding`

## Corpus v1

`benchmarks/golden/analysis_golden_v1.jsonl` contains 45 cases across 15 families. Every seeded family has exactly three fixtures:

- `positive`: decisive vulnerability-condition evidence is present.
- `near_miss`: the attack surface exists but decisive evidence is missing.
- `secure_negative`: the surface exists and an explicit enforcement/control signal is present.

The 15 positive seeds are backed by 10 GitHub Security Lab vulnerability advisories and 5 OWASP API Security Top 10 scenarios.

### Real-write-up seeds

- BOLA / IDOR — GHSL-2026-029, Spree.
- SQL Injection — GHSL-2023-141, NocoDB.
- NoSQL Injection — GHSL-2026-005, Rocket.Chat.
- OS Command Injection — GHSL-2020-111, standard-version.
- Server-Side Template Injection — GHSL-2020-204, Corona Warn App Server.
- LDAP Injection — GHSL-2024-009, Redash.
- SSRF — GHSL-2026-045, Wekan.
- Open Redirect — GHSL-2020-085, Sourcegraph.
- Path Traversal — GHSL-2020-133, Adobe git-server.
- Unsafe File Upload / MIME handling — GHSL-2026-052, Docmost.

### OWASP API scenario seeds

- API4:2023 Unrestricted Resource Consumption.
- API6:2023 Unrestricted Access to Sensitive Business Flows.
- API8:2023 Security Misconfiguration.
- API9:2023 Improper Inventory Management.
- API10:2023 Unsafe Consumption of APIs.

## Metrics

`app/analysis_benchmark.py` reports:

- `precision`
- `recall`
- `top1_accuracy`
- `top3_accuracy`
- `abstention_accuracy`
- `false_promotion_rate`
- `macro_family_recall`
- `brier_score`
- expected calibration error (`ece`)

Precision counts every admitted case/family pair, so an unrelated family promoted on an otherwise-correct positive fixture is still a false positive.

Ranking is deliberately separate from admission. A near-miss should normally rank near its expected family while remaining unadmitted.

## Running

```bash
PYTHONPATH=app python3 app/analysis_benchmark.py
PYTHONPATH=app python3 app/analysis_benchmark.py --json
PYTHONPATH=app python3 app/analysis_benchmark.py --strict
```

`--strict` exits non-zero when a quality gate fails.

## Expansion rules

A new family is not considered benchmark-covered until it has at least:

1. one real or authoritative positive source,
2. one surface-only near-miss derived from the same security condition,
3. one secure negative with an explicit enforcement/control fact,
4. a provenance URL and concise evidence-basis description,
5. no external-knowledge fields in `support` or `contradict`.

Future corpus versions should add multiple independent write-ups per family, cross-family confounders, noisy recon evidence, partial behavioral observations, and historical regression fixtures. The long-term target is a balanced corpus large enough to report per-family precision/recall confidence intervals rather than a single seed example per family.

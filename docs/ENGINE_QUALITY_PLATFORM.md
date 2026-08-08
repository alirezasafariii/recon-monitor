# Engine Quality Platform

The Engine Quality Platform measures whether analysis is becoming more useful, rather than merely producing more candidates.

## Core metrics

- Reviewed and strong-candidate precision proxies
- Negative-decision and duplicate rates
- Candidate rate per 1,000 evidence records
- Evidence coverage and observation quality
- Per-family and per-rule performance
- Parser quality and trust summaries
- Unreviewed backlog

These are operational quality metrics, not claims of statistical truth when the reviewed sample is small. The dashboard displays a warning until enough labelled examples exist.

## Rule governance

Rules move through:

```text
draft → shadow → candidate → active → deprecated / disabled
```

Shadow results are recorded separately and cannot change primary candidate state.

## Noise budgets

Default budgets:

| Profile | Maximum candidates | Maximum reviewed noise rate |
|---|---:|---:|
| quiet | 10 | 0.35 |
| balanced | 50 | 0.50 |
| research | 200 | 0.75 |

Overflow is never deleted. It remains stored and is routed outside the primary Review Now queue.

## Target learning

Each target receives an explainable profile containing common candidate families, endpoint prefixes, observed authentication boundaries, decision distribution, and repeatedly rejected path prefixes. Target history affects prioritization context only; it does not suppress raw evidence or confirm security.

## CLI

```bash
./recon-monitor.sh platform quality --target example.com
./recon-monitor.sh platform learning --target example.com
./recon-monitor.sh platform noise-budget --target example.com --profile balanced
./recon-monitor.sh platform rules
```

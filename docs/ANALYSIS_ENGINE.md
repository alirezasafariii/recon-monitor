# Analysis Engine 4.0

Analysis Engine 4.0 is an offline, evidence-based layer for authorized attack-surface monitoring. It does not perform AI inference and does not send new network requests during analysis or replay.

## Pipeline

1. Load alerts and observations produced by a completed recon run.
2. Normalize evidence and create evidence-for / evidence-against records.
3. Compare category volume with the target's rolling median and MAD baseline.
4. Apply analyst-feedback statistics from workflow outcomes.
5. Add business context and temporal context.
6. Produce an adjusted score and calibrated confidence.
7. Create a falsifiable hypothesis, safe next action and review playbook.
8. Cluster similar alerts.
9. Extract endpoint schemas and object identifiers.
10. Analyze stored JavaScript for static source-to-sink candidates, source-map context, GraphQL operations and secret candidates.
11. Build API-family relationships and deployment signatures.
12. Store a versioned analysis run that can be replayed without scanning the target again.

## Safety model

- Analysis and replay are offline.
- Static data-flow results are candidates, not confirmed vulnerabilities.
- Hypotheses never assert exploitation or impact.
- Playbooks require scope confirmation and minimum-safe verification.
- AI and external model providers are not included.
- Active testing remains governed by the existing three authorization gates.

## Commands

```bash
./recon-monitor.sh analyze --run RUN_ID
./recon-monitor.sh analyze --run RUN_ID --target example.com
./recon-monitor.sh analysis replay --run RUN_ID
./recon-monitor.sh analysis list
./recon-monitor.sh analysis show --id ANALYSIS_ID
./recon-monitor.sh analysis quality
./recon-monitor.sh analysis calibration
./recon-monitor.sh analysis feedback
```

## Dashboard

- `/analysis` — analysis history and prioritized results
- `/hypotheses` — evidence-linked hypotheses
- `/clusters` — duplicate and similarity clusters
- `/dataflows` — JavaScript data-flow, source-map and secret candidates
- `/analysis-quality` — feedback outcomes and confidence calibration

## API

- `GET /api/v1/analysis/runs`
- `GET /api/v1/analysis/results`
- `GET /api/v1/analysis/clusters`
- `GET /api/v1/analysis/dataflows`

## Database schema 8

Schema 8 adds versioned analysis tables while preserving every schema-7 table. Existing recon data, alerts, notes, tags, evidence and user configuration remain unchanged.

## Version 4.1 candidate layer

After the evidence, endpoint, JavaScript, GraphQL, secret, and source-map stages complete, Bug Candidate Engine maps combinations of independent signals to probable vulnerability families. It keeps likelihood, evidence strength, and impact potential separate, and never automatically confirms a vulnerability. See `BUG_CANDIDATE_ENGINE.md`.

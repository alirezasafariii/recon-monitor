# Migration to Recon Monitor 8.4.0

Recon Monitor 8.4.0 upgrades the internal Analysis audit model while keeping the visible Dashboard intentionally minimal.

## Database

Schema advances from **16** to **17**. Migration is additive. Existing runs, alerts, analysis results, candidates, cases, analyst decisions and evidence remain in place.

New tables:

- `candidate_evidence_snapshots` — immutable-at-capture structured source snapshots for evidence used by a candidate.
- `candidate_evidence_exclusions` — correlated or lower-value signals intentionally omitted from the independent evidence set, with explicit reasons.
- `candidate_analysis_versions` — versioned audit snapshots of a candidate reasoning outcome.

The normal startup migration creates these tables automatically; no manual SQL is required.

## Dashboard

Analysis exposes only one primary navigation entry. Internal pages remain routable for compatibility, but are hidden from normal navigation. Potential Finding detail now contains the Evidence Dossier and is the primary analyst-facing surface for reasoning review.

## Safety

No active validation is enabled by this migration. Potential Findings remain unverified until analyst review. Evidence snapshots are structured stored observations; internal chain-of-thought is not persisted or exposed.

## Upgrade

```bash
./recon-monitor.sh update check
./recon-monitor.sh dashboard stop
./recon-monitor.sh update install
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh dashboard start --open
```

# Migration to Recon Monitor 4.6.0

## Supported source version

The upgrade patch accepts Recon Monitor `4.5.1` and is idempotent on `4.6.0`.

## Database migration

Schema is upgraded additively from **11 to 12**. Existing runs, alerts, candidates, analyst decisions, notes, tags, evidence exports, policies, tokens, and configuration are preserved.

New reasoning tables:

```text
evidence_records
candidate_evidence_links
family_rankings
candidate_reasoning_traces
shadow_rule_results
family_calibration
reasoning_evaluations
reasoning_regression_gates
```

New `bug_candidates` fields:

```text
calibrated_likelihood
exploitability_confidence
evidence_coverage
precondition_state
reachability_state
unknowns_json
alternative_families_json
reasoning_trace_json
```

## Upgrade

```bash
PATCH=$(find "$HOME/Downloads" -maxdepth 1 \
  -name 'apply-recon-monitor-v4.6.0-security-reasoning-core*.sh' \
  -print -quit)

bash "$PATCH" "$HOME/Downloads/recon-monitor"
```

The patch checks for active runs, stops local services, creates code and online SQLite backups, installs the update, migrates the schema, compiles Python, checks SQLite integrity and foreign keys, runs the full unit and integration suites, and restores the previous installation on failure.

## Verification

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
python3 - <<'PY'
import sqlite3
con=sqlite3.connect('state/recon-v2.db')
print(con.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0])
print(con.execute('PRAGMA integrity_check').fetchone()[0])
con.close()
PY
```

Expected version/schema:

```text
4.6.0
12
ok
```

## Reanalyze an existing run

```bash
./recon-monitor.sh analysis replay \
  --run 20260805-060256-916ece5f \
  --profile balanced

./recon-monitor.sh analysis reasoning
```

Replay uses stored observations and does not perform a new recon run.

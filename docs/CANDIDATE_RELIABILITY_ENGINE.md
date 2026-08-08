# Candidate Reliability Engine 4.2

Candidate Reliability Engine improves the quality of Bug Candidate output without sending new requests to a target. It operates on evidence already stored by Recon Monitor.

## Goals

- reduce candidate noise;
- avoid double-counting correlated signals;
- separate probable vulnerability relevance from data quality;
- rank candidates by investigation value rather than likelihood alone;
- make analyst feedback measurable and reusable;
- evaluate candidate rules against labeled historical data.

## Reliability fields

Each candidate can store:

- `likelihood_score`: how plausible the bug family is;
- `evidence_strength`: how much supporting evidence exists;
- `observation_quality`: freshness, completeness, reproducibility, and source diversity of the underlying observations;
- `impact_potential`: potential effect if the candidate is later confirmed;
- `investigation_value`: review priority after quality, impact, novelty, and historical noise are considered;
- `novelty_score`: whether this is new or recurring for the target;
- `historical_noise`: how often similar candidates were rejected or treated as noise;
- `lifecycle_state`: current cross-replay state;
- `analysis_profile`: `quiet`, `balanced`, or `research`.

None of these fields confirms a vulnerability.

## Independent evidence groups

Signals derived from the same root observation are placed in one source group. Only the strongest signal in a group contributes its full weight.

Example: a path containing `admin`, an `admin` classifier derived from that path, and an administration business-context tag derived from the same path are correlated. They must not be counted as three independent observations.

Independent groups may include:

- endpoint structure;
- HTTP observation;
- JavaScript semantic unit;
- authentication boundary;
- response shape;
- GraphQL operation;
- source-map evidence;
- analyst history.

The candidate stores a quality explanation with raw-signal count, independent-group count, and suppressed correlated-signal count.

## Analysis profiles

### `quiet`

Requires stronger and more diverse evidence. Intended for a low-noise operational queue.

### `balanced`

Default profile. Balances coverage with false-positive reduction.

### `research`

Retains weaker signals for deeper manual research. This changes analysis thresholds, not scan intensity.

Examples:

```bash
./recon-monitor.sh analyze --run RUN_ID --profile balanced
./recon-monitor.sh analysis replay --run RUN_ID --profile quiet
./recon-monitor.sh analysis replay --run RUN_ID --profile research
```

Replay is offline and does not contact the target.

## Structured feedback

Candidate decisions can include a reason code:

- `keyword_only`
- `expected_behavior`
- `duplicate`
- `protected_boundary`
- `non_reachable`
- `test_data_only`
- `parsing_error`
- `out_of_scope`
- `authorization_difference`
- `unexpected_response_shape`
- `role_boundary_failure`
- `sensitive_data_exposure`
- `needs_contract_context`

Example:

```bash
./recon-monitor.sh analysis candidate-set \
  --candidate-id CANDIDATE_ID \
  --decision rejected \
  --reason keyword_only \
  --note "No independent runtime or response evidence exists."
```

## Calibration and evaluation

Per-family calibration compares predicted likelihood with analyst outcomes. Evaluation can use gold labels attached to historical candidates.

```bash
./recon-monitor.sh analysis candidate-calibration
./recon-monitor.sh analysis candidate-evaluate
./recon-monitor.sh analysis candidate-label \
  --candidate-id CANDIDATE_ID \
  --label useful \
  --expected-family broken_object_authorization
```

Gold labels are evaluation data. They do not automatically confirm a vulnerability or change target scope.

## Dashboard and API

Dashboard:

- `/candidate-quality`

API:

- `GET /api/v1/analysis/candidate-quality`

The page exposes family calibration, lifecycle, profile, observation quality, investigation value, and structured feedback context.

# Bug Candidate Engine 6.0

Bug Candidate Engine converts normalized recon and analysis observations into evidence-linked probable vulnerability families. It does not confirm vulnerabilities and does not perform exploitation or active validation.

Version 6.0 preserves the original candidate mapping, reliability and semantic layers, then adds alert-independent raw-surface routing into the canonical 74-family analyzer catalog. The route is bounded and offline-only; it records hidden hypotheses first and cannot bypass Family Reasoning admission.

## Inputs

- analysis results and family-specific evidence schemas;
- endpoint contracts and parameter relationships;
- authentication-boundary observations;
- redacted response-shape fingerprints;
- HTTP/TLS and alert metadata;
- stored raw endpoints, validations, findings and DNS CNAME context, including baseline runs with no Alerts;
- semantic JavaScript units and source-to-sink candidates;
- feature flags;
- source-map and redacted secret intelligence;
- GraphQL operations and identifiers;
- business context and structured analyst feedback.

## Candidate output

Each candidate can store:

- bug family and variant;
- likelihood score;
- evidence-strength score;
- observation-quality score;
- impact-potential score;
- investigation-value score;
- novelty and historical-noise scores;
- lifecycle and analysis profile;
- supporting, contradicting, and missing evidence;
- independent evidence groups and quality explanation;
- safe next action;
- rule IDs and rule version;
- related semantic bundle;
- analyst decision, reason, and note.

Only an analyst can assign `confirmed_by_analyst`. Automatic analysis never confirms a vulnerability.

## Supported probable vulnerability families

The runtime catalog contains **74 canonical families**: the historical 21-family core, the 10-family OWASP phase-one expansion, and the 43-family phase-two expansion. The complete canonical mapping is documented in `OWASP_EXPANSION_PHASE2.md` and `ARCHITECTURE_SINGLE_SOURCE.md`. Representative groups include:

- BOLA / IDOR and cross-object authorization boundaries;
- broken function-level authorization;
- mass assignment and property-level authorization;
- authentication and session weaknesses;
- account enumeration;
- DOM XSS and unsafe postMessage trust;
- open redirect;
- SSRF candidate;
- unsafe file upload/import and path traversal;
- information, source-map, and redacted secret exposure;
- GraphQL authorization and excessive data exposure;
- business-logic and race-condition watchlists;
- WebSocket authorization;
- CORS and sensitive caching candidates when stored header evidence exists.

## Quality controls

- a single keyword cannot produce a strong candidate;
- family-specific required evidence gates are applied;
- correlated signals are grouped and double counting is suppressed;
- observation quality is separated from bug likelihood;
- authentication hints and `401`/`403` responses do not prove authorization safety;
- static JavaScript matches remain labeled as static observations;
- missing and contradicting evidence are always retained;
- candidate lifecycle and historical noise affect investigation priority;
- replay preserves compatible analyst decisions by stable fingerprint;
- calibration is calculated per family when enough analyst labels exist.

## Profiles

```bash
./recon-monitor.sh analyze --run RUN_ID --profile balanced
./recon-monitor.sh analysis replay --run RUN_ID --profile quiet
./recon-monitor.sh analysis replay --run RUN_ID --profile research
```

Profiles change offline analysis thresholds only. They do not alter scan intensity.

## Candidate commands

```bash
./recon-monitor.sh analysis candidates --limit 100
./recon-monitor.sh analysis candidates --family broken_object_authorization
./recon-monitor.sh analysis candidate-show --candidate-id CANDIDATE_ID
./recon-monitor.sh analysis candidate-set \
  --candidate-id CANDIDATE_ID \
  --decision needs_more_evidence \
  --reason needs_contract_context \
  --note "Expected ownership boundary is not documented."
```

Quality and semantic commands:

```bash
./recon-monitor.sh analysis candidate-calibration
./recon-monitor.sh analysis candidate-evaluate
./recon-monitor.sh analysis bundles --limit 100
./recon-monitor.sh analysis semantic --limit 200
```

## Dashboard

- `/bug-candidates`: candidate queue and filters;
- `/bug-candidate?id=...`: evidence, quality, semantic context, next action, and analyst decision;
- `/candidate-quality`: family calibration and reliability metrics;
- `/candidate-bundles`: related candidate groups;
- `/semantic-intelligence`: feature flags, contracts, boundaries, response shapes, and semantic JavaScript units;
- each Alert page includes related candidates.

## API

- `GET /api/v1/analysis/candidates`
- `GET /api/v1/analysis/candidate?id=...`
- `POST /api/v1/analysis/candidates/decision`
- `GET /api/v1/analysis/candidate-quality`
- `GET /api/v1/analysis/candidate-bundles`
- `GET /api/v1/analysis/semantic`

## Safety boundary

The engine suggests review categories and minimum safe next steps. It does not generate exploit payloads, brute-force credentials, access unrelated user records, probe internal infrastructure, or automatically mark a candidate as confirmed.

See also:

- `docs/CANDIDATE_RELIABILITY_ENGINE.md`
- `docs/SEMANTIC_CANDIDATE_INTELLIGENCE.md`

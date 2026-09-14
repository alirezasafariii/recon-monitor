# Differential Evidence v2

Differential Evidence v2 is an offline trust boundary for expected-vs-observed validation evidence that cannot be inferred safely from a single passive metadata observation.

The first supported family is `open_redirect`. The adapter does **not** generate requests, inject parameters, follow redirects, connect to an external destination, load credentials, or mutate the target. Collection remains an explicitly authorized analyst activity outside this adapter.

## Open Redirect artifact

A v2 artifact must identify the existing Recon Monitor run, analysis and hypothesis, use family `open_redirect`, carry a stable `DEV-*` differential ID, and record both a baseline and a probe observation. The probe is accepted only when a 3xx response explicitly returns the reserved controlled destination:

`https://recon-monitor-validation.invalid/open-redirect`

The artifact must also state that no raw response body was stored, the redirect was not followed, no connection to the external destination was made, and an analyst explicitly verified the expected-vs-observed observation. Artifacts older than 24 hours are rejected by default.

## Admission semantics

Differential evidence is not a confirmed vulnerability. The offline adapter first verifies the artifact and then requires an existing `open_redirect` hypothesis with structural redirect-source and navigation-sink evidence. The new direct evidence is added as a separate provenance root and is passed through the existing Canonical Admission path. Only Admission may produce or update a Potential Finding.

Reapplying the same artifact is idempotent. Changing an already-applied `DEV-*` artifact fails closed. A valid differential artifact without prior structural context is rejected rather than treated as a standalone vulnerability claim.

## CLI

```bash
./recon-monitor.sh validation differential-adapt \
  --evidence-file /path/to/verified-differential.json
```

This command is offline. It performs zero network requests and returns `vulnerability_confirmed: false` even when Canonical Admission creates a Potential Finding.

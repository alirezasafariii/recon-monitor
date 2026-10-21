# Execution completion and collection visibility

A normally finished tool or an exhausted crawl queue does not prove that the
application's content was accessible. Recon records execution and visibility
separately. Scores describe configured stages, not the percentage of a site's
pages tested or the probability that it is secure.

## Origin and HTTP observations

Origin probes retain HTTP 401/403 responses as evidence of a live service, while
recording `http_access_restricted` as incomplete content visibility. An initial
HEAD 401/403 receives at most one existing bounded, one-byte GET fallback so a
HEAD-specific restriction does not misclassify an accessible GET endpoint.
Scope, DNS pinning, headers, request budgets and the HTTP 429 stop remain intact.
No login, challenge solving, credential discovery or new authentication context
is performed.

Connection/TLS timeouts remain unobserved origins. A successful sibling origin
cannot erase them from URL-stage completeness. `origin-probe-pending.txt` and
`origin_coverage_pending_origins` retain their identities. Evidence from healthy
origins is preserved. HTTP fingerprint collection independently records restricted
responses and inputs without a response; its attempted count comes from its input
list, not the number of JSON output lines.

Known origin/HTTP gaps make collection partial and block establishing or refreshing
the canonical comparison baseline. An existing trusted baseline remains intact.
An empty JavaScript or endpoint input is reported as `no_input`, not 100% coverage;
it does not by itself fail a scan of an otherwise accessible static site.

## Resume

Explicit resume rechecks incomplete origin probes and refreshes downstream inputs.
When a previously restricted origin becomes accessible, its old completed crawl
receipt cannot suppress a new crawl. A new checkpoint namespace is selected for
that access generation, preserving the previous checkpoint. Further resumes of
the new unfinished crawl continue the same new checkpoint.

Old successful URL receipts with retained origin failures are rechecked on an
explicit resume. Healthy completed origins and verified JavaScript receipts keep
their usual reuse rules. Budgets remain cumulative; no ceiling is reset.

## Final reports

While Report is running, its state is provisional, not failed or already successful.
After target lifecycle/baseline decisions and terminal run states are durable, a
local finalization pass refreshes completeness, data quality, workspace coverage,
analysis diagnostic summaries, report-stage metadata, JSON, HTML and manifest
projections. It never reruns analysis, emits notifications, changes candidates or
performs network requests. Report metrics exclude nested previous analysis/report
snapshots to prevent growth on repeated resumes.

Completeness snapshots are keyed by their stage revision, including all targets
recorded in the run. Missing stages on a sibling target cannot disappear from the
denominator. Running stages never reuse previous-attempt metrics. Disabled modules
are excluded; `no_input` remains distinct from complete visibility. Finalization
failure is surfaced as a report failure without invalidating complete Recon
collection or an already committed baseline.

To refresh diagnostic projections of a finished historical run without scanning:

```bash
./recon-monitor.sh platform finalize --run RUN_ID
```

The command refuses a running scan. For old origin metrics, bounded retained
`origin-probe.jsonl` evidence may add a diagnostic `coverage_audit`. Historical
collector outcomes and baseline decisions are not rewritten. A historical baseline
with newly exposed visibility gaps receives `baseline_review_required`; the command
does not silently revoke it or promote a replacement. A subsequent explicitly
authorized resume collects current evidence under the new rules.

Offline regressions cover restricted roots, mixed healthy/timeout services,
HEAD/GET differences, fingerprint omissions, multi-target gaps, access-generation
checkpoints, historical audits, finalization failures, cache invalidation and a
full orchestrator/report/analysis pipeline with no target traffic.

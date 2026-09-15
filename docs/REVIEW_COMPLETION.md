# Review completion

## Notification policy

Only observed Recon change categories can generate outbound alerts. Baseline
scans remain silent. Potential Findings, Nuclei findings, and high-value cases
remain available for analysis and investigation, but do not generate outbound
notifications. This invariant overrides legacy notification policies. Pending
legacy finding events and outbox rows are marked `suppressed`; their audit
history and the underlying candidates remain intact. Revalidation of an
unchanged endpoint no longer emits a change event.

## Complete delivery

Recon outbox workers send one complete change per transport call. No list or
character truncation occurs before transport delivery. Telegram and Notify
handle their own message chunking. Only the successfully sent event is marked
delivered. Failed events retain their own retry state.

A separate SQLite connection renews owned Recon delivery leases every 30 seconds
while transport I/O is running. Workers verify ownership and expiry before each
send and acknowledgement. A lost owner cannot acknowledge another worker's event
or continue sending the remaining claimed rows. The supervisor also stops on
lost ownership and uses actual completion times in production.

Delivery remains at-least-once: a process crash after the remote service accepts
a message but before the local acknowledgement may produce a retry. Remote
exactly-once delivery cannot be promised without provider idempotency support.

## Immutable analysis inputs

The first analysis captures raw collection tables in `analysis_input_snapshots`,
keyed by source run and target scope, with a SHA-256 integrity hash. JavaScript
artifacts are copied into content-addressed files under
`state/analysis-input-blobs`. Subsequent analysis of the same scope uses these
inputs even after a later scan replaces the current inventory. All-target replay
can combine the existing snapshots when every target has been captured.

Temporary tables isolate frozen input reads to the analysis connection; they are
removed on completion or failure. Current inventory is never rolled back.
Analysis outputs, analyst feedback and current rules remain live, so replay can
evaluate new rules against the same raw observations. This is an input replay,
not a promise that scores never change after feedback or rule updates.

Old runs without a preserved snapshot cannot be reconstructed reliably. Replay
fails explicitly and asks for a fresh scan instead of pretending current data
belongs to an old run. Preserve the database and `state/analysis-input-blobs`
together when backing up or moving an installation. Snapshot storage grows with
the number of scans; collection data and artifacts are not silently pruned.

## Raw inventory coverage

The fixed 5,000-surface truncation is removed. SQLite input is fetched in pages
of 500 rows and the complete selected inventory reaches raw family routing,
including DNS records after the endpoint inventory. The default analyzer budget
is unlimited (`0`); explicit positive budgets still expose incomplete coverage
through the existing quality diagnostics. Large inventories take longer and use
more memory, since joining and routing the inventory still materializes rows.

## Verification

Regression coverage includes replay after inventory mutation, snapshot integrity,
artifact preservation, cleanup after failure, more than 5,000 raw surfaces,
large notification queues, messages longer than 15,000 characters, independent
delivery failures, lease renewal/reclaim, lost ownership, and silent first/later
scan findings. Existing reviewed-evidence tests continue to require Candidate
promotion across all four reviewed families without outbound notifications.

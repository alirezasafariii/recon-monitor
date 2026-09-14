# Unified Reviewed-Evidence Dispatcher

The reviewed-evidence dispatcher is the single operational entrypoint for moving an already-reviewed offline evidence record through the existing family Admission bridge and then through the Potential Finding notification pipeline.

## Supported review kinds

| Review kind | ID prefix | Admission bridge |
| --- | --- | --- |
| `account_enumeration` | `CID-` | controlled identity differential |
| `authentication_session` | `ASL-` | controlled authentication/session lifecycle |
| `graphql_data_exposure` | `GQLD-` | controlled GraphQL field-policy differential |
| `material_classification` | `MCR-` | redacted material classification |

The kind is inferred from the review ID by default. If an explicit kind is supplied, a prefix mismatch fails closed.

## Pipeline

```text
Immutable Reviewed Evidence
        ↓
Reviewed-Evidence Dispatcher
        ↓
Existing Family Admission Bridge
        ↓
Canonical Admission
        ↓
Potential Finding
        ↓
Existing Finding Notification Pipeline
```

The dispatcher does not collect evidence, probe the target, run GraphQL operations, perform login/logout flows, enumerate accounts, validate credential material, or execute provider checks.

Configured notification transports may perform outbound delivery after a Potential Finding transition is queued. That outbound notification traffic is separate from target-side validation and is reported explicitly in dispatcher output.

## Critical ordering invariant

`finding_notification_state` is initialized **before** the family bridge is allowed to create a Candidate. This preserves the conservative historical bootstrap behavior for pre-existing findings while ensuring the Candidate created by the current reviewed-evidence dispatch is still seen as a new Potential Finding.

If notification state were initialized after Candidate promotion, bootstrap could classify that newly-created Candidate as historical state and suppress its initial `new` transition.

## Exactly-once and retry semantics

Family Admission bridges remain exactly-once and own their existing bridge ledgers. The dispatcher adds `reviewed_evidence_dispatch_runs` as an additive orchestration ledger keyed by review kind and review ID.

Notification transition/event creation remains idempotent in `finding_notifications`. Re-running the dispatcher intentionally re-runs notification processing: if delivery previously failed, the existing queued event can be retried without creating a second Candidate or transition. Previously-created event IDs remain attached to the dispatch ledger across retries.

A successful re-apply therefore has these properties:

- no duplicate Potential Finding;
- no duplicate notification transition/event;
- no duplicate successful delivery after the event is already delivered;
- dispatcher `attempts` increments for auditability;
- the original notification event ID remains in dispatcher history.

## CLI

From the repository root:

```bash
python3 tools/dispatch_reviewed_evidence.py --review-id MCR-...
```

The review kind may be supplied explicitly:

```bash
python3 tools/dispatch_reviewed_evidence.py \
  --review-kind graphql_data_exposure \
  --review-id GQLD-...
```

The command requires the normal repository `config.env` because it uses the configured Potential Finding notification transports. It does not require or imply active target validation.

## Semantics

A dispatcher success means an existing analyst-reviewed evidence record was processed through the repository's normal Admission and notification semantics. Its strongest security result is still a **Potential Finding**. The dispatcher never marks a vulnerability as confirmed.

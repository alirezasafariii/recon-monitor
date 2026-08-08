# Investigation Workspace

Version 5.0 makes the security case the primary unit of analyst work.

## Case contents

- Primary and alternative bug-family candidates
- Related alerts
- Evidence and provenance
- Current owner and lifecycle state
- Decision timeline
- Safe validation package
- Report draft and readiness score

## Lifecycle

```text
new
triaged
reviewing
needs_evidence
ready_for_validation
confirmed
rejected
ready_for_report
reported
closed
```

Analyst-selected states are preserved during later synchronization.

## Security stories

Candidates belonging to the same bundle or security boundary are presented as one narrative. Stories reduce duplicated work across endpoint, JavaScript, feature-flag, behavioral, and candidate alerts.

## Safe validation package

A validation package includes affected endpoints, known context, expected boundary, why the case is suspicious, evidence requirements, and stop conditions. It contains no payloads and performs no testing.

## Report draft

The report builder creates a structured draft with visible placeholders. Unverified candidates are never written as confirmed vulnerabilities. Readiness is based on evidence, scope status, case state, and analyst review.

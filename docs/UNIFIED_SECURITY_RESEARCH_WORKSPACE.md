# Unified Security Research Workspace — Recon Monitor 7.0

Recon Monitor 7.0 is a local-first analyst workspace for authorized security research. It builds on the existing recon, candidate, reasoning, case and bounded-validation systems while making the analyst's next safe action explicit.

## Core workflow

`Recon → Analysis → Candidate → Case → Evidence Gap → Analyst Task → Bounded/Manual Validation → Decision → Evidence-linked Report`

No stage automatically converts a candidate into a confirmed vulnerability.

## Evidence Gap Engine

Each case is evaluated against family-specific evidence requirements. The engine records what is present, missing and unknown, a coverage score, the permitted validation class, and recommended next actions. Authorization families require additional authorized identities/roles/ownership relationships rather than automated object enumeration.

## Case Autopilot

Autopilot is investigation orchestration, not exploitation. It creates evidence, decision and report-readiness tasks. It may recommend importing a redacted comparison or collecting another authorized context, but does not replay credentials, enumerate other users' objects or execute destructive actions.

## Context and differential intelligence

Authentication contexts are derived from labeled behavioral observations, identity graph data, redacted imported HTTP evidence and browser-capture metadata. Differential Intelligence separates status, shape, sensitive-field and authorization-boundary changes.

## Coverage and attack surface

Recon Coverage reports explicit blind spots rather than treating a quiet run as evidence of safety. Attack Surface Graph connects target/host/endpoint/JavaScript/candidate/context relationships and overlays coverage.

## Change, memory and planning

Target Memory persists architecture/security-relevant history. Change Intelligence summarizes what changed between runs. Smart Recon Planner proposes a bounded plan and budget based on coverage/change/history, but never starts a run or activates active modules automatically.

## Learning

False Positive Learning uses analyst decisions to estimate family precision and recommend `keep`, `tune` or `shadow_review`. Recommendations do not silently mutate rule governance.

## Reporting

Report Builder links claims to persisted evidence records and redacted observations. Raw references, raw credentials and sensitive body content are excluded. Unconfirmed cases are explicitly blocked from confirmed-vulnerability wording.

## Browser Capture

Browser Capture accepts metadata only: URL, method, status, content type, navigation type, response-shape metadata and an analyst-supplied context label. Sensitive query keys are redacted and secret headers are ignored.

Context names such as `browser-observed` or `Account A`, HTTP 200 responses and
identity/role names do not establish a logged-in session. Authentication profiles
preserve explicit behavioral/imported `auth_state` observations; missing or
conflicting state is `unknown`. An explicitly public/anonymous label declares an
anonymous context. Only profiles with an observed `authenticated` state count
towards authenticated-context and role-comparison coverage.

After updating an installation with previously imported captures, recompute its
profiles and coverage without reimporting the capture or changing scan status:

```bash
./recon-monitor.sh workspace contexts --target example.com
./recon-monitor.sh workspace coverage --target example.com
```

### Offline JavaScript evidence from HAR

The metadata importer does not include source bodies. To prepare JavaScript
already observed in an authorized browser for offline analysis, export a HAR
with response content and run:

```bash
python3 tools/export_har_javascript.py --har ~/Downloads/capture.har --target example.com --output state/browser-captures/javascript.zip
```

The exporter uses the selected project policy and its JavaScript size/file
limits. It selects in-scope `GET` responses with status 200 and a JavaScript
MIME type, including scripts whose URL has no `.js` suffix. The private ZIP
contains hash-named JavaScript bodies and an `index.json` with redacted query
values and exported-body SHA-256 hashes. Request headers, cookies and other
response types are excluded. Missing bodies and limits are reported explicitly.
Export is local: it does not replay HAR requests, import source bodies into the
metadata tables, or promote a partial scan to a completed baseline.

## Operator UX

The v7 dashboard provides a Cockpit, Universal Search, Command Palette (`⌘K`), structured Error IDs, Diagnostics & Repair and Safety Center. Safe repair is preview-first and limited to stale execution state and expired local sessions; it does not delete evidence/cases/targets/output.

Safety Center checks the audit verifier's canonical `ok` result and requires a
persisted scope snapshot. After initial setup, `./recon-monitor.sh platform sync`
refreshes those snapshots from the current policy and refreshes the workspace.
`./recon-monitor.sh workspace safety` then displays the resulting readiness.
Missing scope snapshots, failed audit verification and verifier errors remain
action-required states; refreshing metadata does not change scan completeness.

## CLI

```bash
./recon-monitor.sh workspace --help
./recon-monitor.sh workspace sync --target example.com
./recon-monitor.sh workspace evidence-gap --case-id CASE_ID
./recon-monitor.sh workspace autopilot --case-id CASE_ID
./recon-monitor.sh workspace contexts --target example.com
./recon-monitor.sh workspace differential --target example.com
./recon-monitor.sh workspace coverage --target example.com
./recon-monitor.sh workspace graph --target example.com
./recon-monitor.sh workspace changes --target example.com
./recon-monitor.sh workspace memory --target example.com
./recon-monitor.sh workspace learning --target example.com
./recon-monitor.sh workspace plan --target example.com
./recon-monitor.sh workspace stage-value --target example.com
./recon-monitor.sh workspace report --case-id CASE_ID
./recon-monitor.sh workspace capture-import --target example.com --file capture.json --context 'Account A'
./recon-monitor.sh workspace diagnostics
./recon-monitor.sh workspace safety
./recon-monitor.sh workspace cockpit --target example.com
./recon-monitor.sh workspace search --query orders
```

# Analysis Engine 6.3 — Standards-Grounded Hard Cases

Analysis 6.3 makes **OWASP WSTG and MITRE CWE first-class reasoning anchors across every admission family** and adds a hard/confounder corpus that tests whether nearby vulnerability families remain distinct.

## 1. Standards grounding is global

`app/analysis_standards.py` defines one standards profile for every family in `FAMILY_ADMISSION_POLICIES`.

Each profile contains:

- one or more OWASP WSTG test anchors,
- one or more CWE root-cause candidates,
- the security-condition principle that separates a vulnerability from a surface clue,
- CWE auto-assignment rules when the root cause is precise enough.

The engine refuses to load with an ungrounded admission family. This makes standards coverage a structural invariant rather than optional documentation.

### WSTG role

WSTG describes **what must be tested and what evidence distinguishes a weakness from a surface**. Examples:

- SQL Injection → `WSTG-INPV-05`
- NoSQL Injection → `WSTG-INPV-05.6`
- Command Injection → `WSTG-INPV-12`
- SSTI → `WSTG-INPV-18`
- SSRF → `WSTG-INPV-19`
- Mass Assignment → `WSTG-INPV-20`
- BOLA / IDOR → `WSTG-APIT-02` / `WSTG-ATHZ-04`
- DOM XSS → `WSTG-CLNT-01`
- CORS → `WSTG-CLNT-07`
- WebSockets → `WSTG-CLNT-10`
- Web Messaging → `WSTG-CLNT-11`
- Business Logic → `WSTG-BUSL-*`
- Security Misconfiguration → `WSTG-CONF-*` / `WSTG-ERRH-*`

### CWE role

CWE is used as a **root-cause taxonomy**, not as a keyword tag.

A CWE is auto-assigned only after admission and only when the mapping is sufficiently precise.

Examples:

- SQL Injection → `CWE-89`
- NoSQL Injection → `CWE-943`
- Command Injection → `CWE-78`
- SSTI → `CWE-1336`
- LDAP Injection → `CWE-90`
- SSRF → `CWE-918`
- Path Traversal → `CWE-22`
- Unsafe File Upload → `CWE-434`
- BOLA → `CWE-639`
- Mass Assignment → `CWE-915`
- Account Enumeration → `CWE-204`
- Open Redirect → `CWE-601`
- CORS → `CWE-942`
- Race Condition → `CWE-362`
- Resource Consumption → `CWE-770`
- Sensitive Business Flow Abuse → `CWE-799`

Broad families deliberately use conditional CWE resolution. For example Security Misconfiguration resolves from the decisive signal:

- exposed stack trace → `CWE-209`
- active debug mode → `CWE-489`
- insecure HTTP → `CWE-319`
- exposed dangerous method → `CWE-749`
- directory listing → `CWE-548`
- HTTP desync difference → `CWE-444`
- insecure default → `CWE-1188`

For BFLA, GraphQL authorization, WebSocket authorization, API9, and similar broad families, the engine can retain several CWE candidates and require manual/root-cause refinement rather than forcing an inaccurate CWE.

## 2. Standards never become target evidence

The epistemic boundary remains unchanged:

`external standard / write-up -> detection criteria, not target proof`

WSTG/CWE references:

- do not satisfy a required evidence group,
- do not increase independent-source count,
- do not override contradictions,
- do not promote a finding by themselves.

They are attached to the admission assessment and persisted in the existing knowledge-reference path so every hypothesis/finding remains explainable.

## 3. Golden Dataset v2

`benchmarks/golden/analysis_golden_v2.jsonl` contains the original 45 seed cases plus **24 hard cases**.

The hard corpus deliberately overlaps nearby families:

- SSRF ↔ Open Redirect
- SQL Injection ↔ NoSQL Injection
- Command Injection ↔ SSTI
- File Upload ↔ Path Traversal
- BOLA ↔ BFLA
- Business Logic ↔ Sensitive Business Flow Abuse
- Race Condition ↔ Business Logic
- CORS ↔ Information Disclosure
- Security Misconfiguration ↔ Information Disclosure
- API9 ↔ Security Misconfiguration
- API10 ↔ SSRF

Each hard case carries WSTG/CWE provenance and an explicit `confounders` list.

## 4. New benchmark metrics

Benchmark Engine 2.0 adds:

- `hard_top1_accuracy`
- `hard_top3_accuracy`
- `hard_abstention_accuracy`
- `confounder_leak_rate`
- `standards_coverage`
- hard-case confusion matrix

A **confounder leak** occurs when evidence intended to establish one family accidentally promotes the nearby family.

This is stricter than merely checking whether the expected family is present.

## 5. Quality contract

The core contract is now:

`surface clue -> WSTG/CWE-grounded hypothesis -> target evidence -> contradiction check -> family admission -> precise CWE assignment when justified`

The standards layer improves interpretation and taxonomy precision, but target-specific evidence remains authoritative.

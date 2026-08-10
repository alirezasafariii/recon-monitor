# Analysis Engine 6.0 — vulnerability-condition admission

Analysis Engine 6.0 separates **attack-surface discovery** from **Potential Finding admission** across the main vulnerability families.

The governing rule is:

```text
surface clue -> hidden hypothesis -> decisive family evidence -> Potential Finding
```

OWASP WSTG / OWASP API Security Top 10 define the family preconditions. Real-world write-up patterns are used to identify the evidence that turns a surface into a credible candidate. Knowledge references are stored as context and never counted as target evidence.

Key changes:

- BFLA requires a privileged function plus role context plus observed unauthorized/lower-privilege execution.
- Mass assignment/BOPLA requires a writable privileged property plus evidence the server accepted or applied it outside the intended property policy.
- SSRF requires a controllable remote destination plus stored backend-fetch evidence.
- Open redirect requires destination control, a navigation sink, and evidence an unintended external destination is accepted.
- File upload requires unsafe acceptance/storage/serving/filename behavior; an upload form alone is a hidden hypothesis.
- Path traversal requires a controlled path plus file operation plus filesystem/confinement-failure evidence.
- GraphQL authorization requires resolver/object authorization failure evidence; IDs in operations alone remain hidden.
- CORS parses exact ACAO/ACAC values; the mere presence of an ACAO header is never a finding.
- Business-logic and race families require observed invariant/atomicity failures rather than workflow keywords.
- DOM/static JavaScript proximity remains a hypothesis until runtime/flow/sanitization evidence exists.

Current-projection correctness also changes: JavaScript intelligence is restricted to files observed in the source run, and behavioral diffs compare different source runs so replaying one run with a new engine cannot masquerade as target drift.

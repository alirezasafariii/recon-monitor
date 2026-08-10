# Analysis Engine 6.1 — Coverage Expansion

Analysis 6.1 extends the vulnerability-condition admission model introduced in
6.0. Recon Monitor still preserves weak clues as hidden hypotheses. The new
families do not enter Potential Findings until family-specific decisive target
evidence is present.

## New vulnerability families

- SQL Injection
- NoSQL Injection
- OS Command Injection
- Server-Side Template Injection
- LDAP Injection
- API4:2023 Unrestricted Resource Consumption
- API6:2023 Unrestricted Access to Sensitive Business Flows
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs

## Admission invariant

`surface -> hidden hypothesis -> decisive target behavior -> candidate`

Examples:

- `filter` or `search` parameter alone is not SQL injection.
- a command-like endpoint alone is not command injection.
- `limit`, `page`, `batch`, SMS, email, export, or upload alone is not API4.
- purchase/reservation/signup endpoints alone are not API6.
- `/v1/`, `legacy`, `staging`, or `beta` naming alone is not API9.
- a third-party integration alone is not API10.

Promotion requires stored evidence matching the security condition defined by
OWASP/WSTG, such as query-semantic influence, command/template execution,
missing resource limits, unrestricted automation, directly observed insecure
configuration, active legacy exposure with weaker controls, or unsafe upstream
trust/validation behavior.

External knowledge is explanatory context only and never counts as target
evidence.

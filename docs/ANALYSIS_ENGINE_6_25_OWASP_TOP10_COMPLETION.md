# Analysis Engine 6.25 — OWASP Top 10:2025 Coverage Completion

Analysis 6.25 adds explicit physical families for the five OWASP Top 10:2025 categories that were not previously represented as first-class vulnerability families:

- A03:2025 Software Supply Chain Failures
- A04:2025 Cryptographic Failures
- A08:2025 Software or Data Integrity Failures
- A09:2025 Security Logging and Alerting Failures
- A10:2025 Mishandling of Exceptional Conditions

The five new families use the same WSTG + OWASP + CWE + real-write-up detector contract as the existing families. External standards and write-ups never count as target evidence. Raw collectors are metadata-only; target evidence remains owned by passive/offline detector execution and raw-condition reconstruction.

Precision boundaries are intentional. Supply-chain and logging failures are not inferred from the absence of client-visible evidence. Exceptional-condition findings require an unsafe observed outcome, not just an error message. Cryptographic and integrity findings require security-sensitive context plus an observed control failure.

With these additions the engine has 36 total vulnerability families and explicit coverage for all ten OWASP Top 10:2025 categories while preserving all ten OWASP API Security Top 10:2023 category mappings.

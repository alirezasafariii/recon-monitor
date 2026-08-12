# Analysis Engine 6.25 Seal

Analysis 6.25 seals OWASP Top 10:2025 coverage completion.

Sealed lineage:
- Analysis Engine: `6.25.0`
- Candidate Engine: `6.25.0`
- Security Reasoning Engine: `6.25.0`
- Rule lineage: `2026.08.12.6.25`
- OWASP Top 10:2025 completion collector lineage: `2026.08.12.6.25`

The engine now has 36 vulnerability families. The five Analysis 6.25 families add first-class coverage for A03 Software Supply Chain Failures, A04 Cryptographic Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions. Together with the existing families, OWASP Top 10:2025 and OWASP API Security Top 10:2023 are both explicitly mapped 10/10.

All 36 families retain cross-layer admission, evidence-extractor, reasoner, physical-detector, WSTG, OWASP, CWE, and real-write-up ownership. External standards/write-ups remain detector criteria only and never count as target evidence. Supply-chain/logging absence is not inferred from client visibility, and exceptional/cryptographic/integrity families require concrete stored target conditions before admission.

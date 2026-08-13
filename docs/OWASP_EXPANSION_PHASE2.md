# OWASP/WSTG Analysis Expansion — Phase 2

## Scope

Phase 2 completes the dedicated vulnerability-analysis catalog beyond the original
21 families and the 10 families added in phase 1.

- Existing dedicated families before phase 2: **31**
- New dedicated families in phase 2: **43**
- Canonical dedicated families after phase 2: **74**
- Generic family-analyzer fallback: **disabled**
- Active exploit payload generation: **disabled**
- Knowledge/write-ups as target evidence: **prohibited**

## Architecture

Every canonical family follows the same evidence-preserving path:

`stored target observations -> Dedicated Family Analyzer -> Family Reasoning -> hidden hypothesis -> admission -> Potential Finding -> investigation/confirmation`

Phase 2 uses a data-only canonical catalog (`app/owasp_phase2_catalog.py`) for
taxonomy, evidence vocabulary, contradictions, Safe Validation class, scoring
metadata, and non-evidentiary knowledge mapping. Runtime routing still resolves
each family to a distinct analyzer class.

## Added families

1. **Reflected XSS** (`reflected_xss`) — validation: `manual_only`
2. **Stored XSS** (`stored_xss`) — validation: `manual_only`
3. **HTTP Verb Tampering** (`http_verb_tampering`) — validation: `passive_live`
4. **HTTP Parameter Pollution** (`http_parameter_pollution`) — validation: `manual_only`
5. **ORM Injection** (`orm_injection`) — validation: `manual_only`
6. **XML Injection** (`xml_injection`) — validation: `manual_only`
7. **XML External Entity** (`xml_external_entity`) — validation: `manual_only`
8. **SSI Injection** (`ssi_injection`) — validation: `manual_only`
9. **XPath Injection** (`xpath_injection`) — validation: `manual_only`
10. **IMAP/SMTP Injection** (`imap_smtp_injection`) — validation: `manual_only`
11. **Code Injection** (`code_injection`) — validation: `manual_only`
12. **File Inclusion** (`file_inclusion`) — validation: `manual_only`
13. **Format String Injection** (`format_string_injection`) — validation: `manual_only`
14. **HTTP Response Splitting / CRLF** (`http_response_splitting`) — validation: `manual_only`
15. **HTTP Request Smuggling** (`http_request_smuggling`) — validation: `manual_only`
16. **Host Header Injection** (`host_header_injection`) — validation: `manual_only`
17. **CSV / Formula Injection** (`csv_injection`) — validation: `manual_only`
18. **Prototype Pollution** (`prototype_pollution`) — validation: `manual_only`
19. **Unsafe Deserialization** (`unsafe_deserialization`) — validation: `manual_only`
20. **Cross-Site Request Forgery** (`csrf`) — validation: `manual_only`
21. **Clickjacking** (`clickjacking`) — validation: `passive_live`
22. **HTML Injection** (`html_injection`) — validation: `manual_only`
23. **CSS Injection** (`css_injection`) — validation: `manual_only`
24. **Client-Side Resource Manipulation** (`client_side_resource_manipulation`) — validation: `manual_only`
25. **Cross-Site Script Inclusion** (`xssi`) — validation: `manual_only`
26. **Reverse Tabnabbing** (`reverse_tabnabbing`) — validation: `passive_live`
27. **Client-Side Template Injection** (`client_side_template_injection`) — validation: `manual_only`
28. **Browser Storage Exposure** (`browser_storage_exposure`) — validation: `passive_live`
29. **HTTP Security Header Weakness** (`security_headers`) — validation: `passive_live`
30. **TLS / HSTS Weakness** (`tls_hsts_weakness`) — validation: `passive_live`
31. **Subdomain Takeover** (`subdomain_takeover`) — validation: `manual_only`
32. **Cloud Storage Exposure** (`cloud_storage_exposure`) — validation: `passive_live`
33. **Backup / Unreferenced File Exposure** (`backup_unreferenced_file_exposure`) — validation: `passive_live`
34. **Admin Interface Exposure** (`admin_interface_exposure`) — validation: `passive_live`
35. **Path Confusion** (`path_confusion`) — validation: `manual_only`
36. **JWT Weakness** (`jwt_weakness`) — validation: `manual_only`
37. **OAuth / OIDC Weakness** (`oauth_oidc_weakness`) — validation: `manual_only`
38. **Security Logging / Monitoring Weakness** (`logging_monitoring_weakness`) — validation: `manual_only`
39. **Fail-Open / Exceptional Condition Weakness** (`exceptional_condition_fail_open`) — validation: `manual_only`
40. **Weak Cryptographic Primitive / Usage** (`weak_cryptography`) — validation: `passive_live`
41. **Software / Data Integrity Failure** (`software_data_integrity`) — validation: `manual_only`
42. **Dependency / Supply-Chain Risk** (`dependency_supply_chain`) — validation: `passive_live`
43. **Web Cache Poisoning** (`web_cache_poisoning`) — validation: `manual_only`

## Safety invariants

Manual-only families accept decisive/direct evidence only when the stored
observation is explicitly marked authorized/controlled and benign/non-destructive.
Passive-live families consume already collected metadata or bounded read-only
observations. No phase-2 analyzer sends traffic itself.

Specific prohibited behavior includes destructive HTTP methods, command/code
execution, database extraction/modification, XXE local-file reads, request
desynchronization of shared connections, shared-cache poisoning, claiming
third-party cloud resources, real CSRF/business actions, OAuth token theft,
password/secret brute force, or deployment of tampered artifacts.

## Taxonomy integrity

WSTG identifiers use stable scenario IDs. Subsections such as ORM Injection or
File Inclusion map to their stable parent scenario where OWASP does not publish a
separate stable WSTG identifier. Families without a single authoritative WSTG
scenario keep `wstg=[]` rather than inventing an identifier.

## Practical / write-up intelligence

Phase 2 has two separate knowledge layers for **43 / 43** families:

1. canonical taxonomy/reference context derived from OWASP/WSTG/CWE/CAPEC; and
2. a distinct practical/research reference in `app/vulnerability_writeups_phase2.py`.

Practical references favor OWASP WSTG/Cheat Sheets and PortSwigger Web Security
Academy/Research. Dedicated research material is used where it exists (for
example HTTP request smuggling, prototype pollution, OAuth/OIDC and web-cache
poisoning). Where no suitable dedicated research article exists, the concrete
WSTG testing methodology is retained instead of inventing a write-up.

Each practical record includes a stable internal ID, source, title, HTTPS URL,
reference kind, family-specific methodology note and matching signal vocabulary.
Every record is marked `non_evidentiary=True`: it can improve classification,
retrieval and analyst explanation but cannot become a target observation,
independent evidence root, admission prerequisite, or confirmation proof.

`tests/test_analysis_phase2_completion_v900.py` requires every phase-2 family to
have a retrievable practical reference in addition to its taxonomy reference.

## Regression contract

`tests/fixtures/vulnerability_intelligence_phase2_golden_v2.json` pins one
positive and one surface-only negative evidence set for every phase-2 family.
`tests/test_analysis_phase2_completion_v900.py` verifies:

- 43 unique phase-2 families
- 74 total canonical families
- 74/74 router registration, pending=0, generic fallback=false
- positive admission and confirmation
- surface-only abstention
- Safe Validation classes
- canonical non-evidentiary knowledge references
- practical/research reference coverage and retrieval for 43/43 families
- analyzer-level direct evidence handling
- manual-only direct evidence rejection without controlled/benign markers
- WSTG identifier format and non-empty family contracts

## Alert behavior

This phase changes analysis only. Alert first-scan/delta behavior is intentionally
left unchanged for the separate Alert phase.

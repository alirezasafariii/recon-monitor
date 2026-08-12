# OWASP Vulnerability Intelligence Expansion — Phase 1

Recon Monitor extends its canonical vulnerability-family catalog from 21 to 31
families while preserving the same hypothesis-first safety architecture.

## Added families

1. SQL Injection
2. NoSQL Injection
3. OS Command Injection
4. Server-Side Template Injection (SSTI)
5. LDAP Injection
6. Unrestricted Resource Consumption (OWASP API4:2023)
7. Sensitive Business Flow Abuse (OWASP API6:2023)
8. Security Misconfiguration
9. Improper API Inventory Management (OWASP API9:2023)
10. Unsafe Consumption of APIs (OWASP API10:2023)

## Architecture

Every added family follows the same path:

`stored target observations -> dedicated analyzer -> Family Reasoning -> hidden hypothesis -> admission -> Potential Finding -> investigation/confirmation`

OWASP, WSTG, CWE and write-up material remains non-evidentiary. It may classify,
rank and explain a hypothesis but cannot satisfy promotion or confirmation.

## Injection safety contract

The five injection analyzers never create or send payloads. They require a
concrete input, a relevant server-side interpreter/query sink, and additional
stored unsafe-construction or behavior evidence. Decisive behavioral evidence is
accepted only when the stored observation explicitly records an authorized,
controlled, benign/non-destructive test context.

## API abuse safety contract

Resource-consumption analysis never performs load, concurrency, oversized-body,
or cost-amplification testing. Sensitive-business-flow analysis never automates
real purchases, reservations, registrations, votes, messages, claims, or scarce
inventory consumption. Unsafe API Consumption confirmation uses target-side
observations only and never probes or compromises an upstream third party.

## Validation classes

Manual-only:
- SQL Injection
- NoSQL Injection
- OS Command Injection
- SSTI
- LDAP Injection
- Unrestricted Resource Consumption
- Sensitive Business Flow Abuse
- Unsafe Consumption of APIs

Passive-live (still gated by existing Safe Validation controls):
- Security Misconfiguration
- Improper API Inventory Management

Generic family-analyzer fallback remains disabled.

# Final Analyzers — Pre-main Merge Gate

This document freezes the final-analyzer scope before merge into `main` and
records the invariants that must stay true during merge hardening.

## Frozen canonical family set

No new family is added during pre-main hardening. The canonical migrated set is:

1. broken_object_authorization
2. broken_function_authorization
3. mass_assignment
4. ssrf
5. file_upload
6. path_traversal
7. sql_injection
8. dom_xss
9. cors_misconfiguration
10. authentication_session
11. open_redirect
12. postmessage_trust
13. graphql_authorization
14. account_enumeration
15. information_disclosure
16. source_map_exposure
17. secret_exposure

Adding another family requires leaving feature-freeze explicitly and adding the
same family-spec, reasoning, analyzer, taxonomy-attribution, knowledge, and
regression coverage expected from the existing set.

## Decision authority

There is one vulnerability-admission authority: the canonical Family Reasoning
contract consumed by `hypothesis_admission.py`.

The following inputs are explanatory/ranking context only and must never satisfy
an admission requirement or independent-evidence requirement:

- OWASP / WSTG / CWE / CAPEC references
- curated write-ups
- researcher playbooks
- historical priors
- correlation scores
- meta-ranker output
- LLM/advisory output

## Evidence isolation

Explicitly family-scoped evidence is fail-closed. Evidence scoped to another
family is quarantined before admission. Newly persisted hypothesis evidence is
namespaced with `family_scope` and `evidence_namespace=family:<family>`.

Legacy unscoped evidence remains readable for compatibility, but new persistence
must add the namespace.

## Taxonomy attribution

Taxonomy attribution is post-admission metadata only.

- Each taxonomy reference has exactly one attribution rule.
- WSTG is methodology and never auto-assigned.
- CAPEC is attack-pattern context and never auto-assigned.
- CWE auto-assignment is opt-in and may be condition-specific.
- Generic/contextual CWE references remain manual where root cause cannot be
  established from the admitted evidence contract.
- Taxonomy evaluation with `admitted=False` must assign nothing.

## Required merge checks

Before merging into `main`:

- `final-analyzers` must not be behind its intended merge base.
- `sha256sum --strict -c MANIFEST.sha256` must pass.
- Python 3.11 and 3.13 full unit suites must pass.
- `tests/integration_runner.py` must pass on both supported Python versions.
- source hygiene must pass; no runtime databases, logs, secrets, local target
  policies, `__pycache__`, or temporary verifier assets may remain tracked.
- only permanent CI workflow(s) may remain under `.github/workflows`.
- `tests/test_pre_main_analyzer_merge_gate.py` must pass unchanged unless the
  feature-freeze decision itself is intentionally revised.

## Merge rule

Merge hardening may fix correctness, isolation, transport, compatibility,
manifest, or test defects. It must not weaken evidence gates merely to satisfy a
legacy expectation and must not introduce a second detector/admission authority.

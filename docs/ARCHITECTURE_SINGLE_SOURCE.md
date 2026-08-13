# Architecture Single Source of Truth

Recon Monitor uses `app/family_reasoning.py` as the canonical source for the cross-cutting vulnerability-family contracts.

- Candidate Engine evidence schemas come from `candidate_evidence_schema_map()` for all 74 canonical families.
- Security-case evidence requirements come from `case_requirement_map()` for all 74 canonical families.
- Safe Validation classification comes from `validation_level_for_family()` using the canonical family ID; legacy text hints are fallback-only.
- `app/family_analyzers/router.py` must expose one explicit analyzer class for every canonical family, with zero pending families and no generic analyzer fallback.
- OWASP/WSTG/CWE/CAPEC and write-up knowledge remain classification/retrieval context only; they never become target evidence or satisfy admission/confirmation.

The canonical catalog is layered for compatibility: the historical 21-family core, the 10-family OWASP phase-one expansion, and the 43-family phase-two expansion resolve into one ordered 74-family runtime contract. Historical regression fixtures keep their original slices pinned so expanding the catalog cannot silently rewrite prior decisions.

This removes duplicated per-family policy tables from consumers such as `bug_candidates.py` and `workspace_v7.py`, and removes substring matching as the primary safety classifier in `safe_validation.py`. Unknown future families fail closed to offline validation.

The consolidation does not loosen validation safety limits. Family analyzers normalize already-stored observations and perform no active exploitation. Live Safe Validation remains separately gated by the canonical family validation class and the existing transport/policy envelope.

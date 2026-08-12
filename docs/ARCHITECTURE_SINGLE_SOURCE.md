# Architecture Single Source of Truth

Recon Monitor now uses `app/family_reasoning.py` as the canonical source for three cross-cutting family contracts.

- Candidate Engine evidence schemas come from `candidate_evidence_schema_map()` for all 21 families.
- Security-case evidence requirements come from `case_requirement_map()` for all 21 families.
- Safe Validation classification comes from `validation_level_for_family()` using the canonical family ID; legacy text hints are fallback-only.

This removes duplicated per-family policy tables from `bug_candidates.py` and `workspace_v7.py`, and removes substring matching as the primary safety classifier in `safe_validation.py`. Unknown future families fail closed to offline validation.

The consolidation does not loosen validation safety limits: GET/HEAD/OPTIONS-only execution, request/runtime/response caps, no redirects, no cookies/credentials, no identifier enumeration and no state changes remain unchanged.

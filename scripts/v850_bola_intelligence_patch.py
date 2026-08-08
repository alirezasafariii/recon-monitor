from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    file = ROOT / path
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}: {old[:120]!r}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


def regex_once(path: str, pattern: str, replacement: str) -> None:
    file = ROOT / path
    text = file.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, lambda _m: replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"expected one regex match in {path}, found {count}: {pattern[:120]!r}")
    file.write_text(updated, encoding="utf-8")


replace_once("app/core.py", 'APP_VERSION = "8.4.5"', 'APP_VERSION = "8.5.0"')
replace_once("app/analysis_engine.py", 'ENGINE_VERSION = "5.1.2"\nRULE_VERSION = "2026.08.8.4"', 'ENGINE_VERSION = "5.2.0"\nRULE_VERSION = "2026.08.8.5"')
replace_once("app/bug_candidates.py", 'from hypothesis_admission import mark_promoted, record_hypothesis', 'from hypothesis_admission import mark_promoted, record_hypothesis\nfrom bola_intelligence import analyze_bola_signal')
replace_once("app/bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "5.1.0"\nCANDIDATE_RULE_VERSION = "2026.08.8.3"', 'CANDIDATE_ENGINE_VERSION = "5.2.0"\nCANDIDATE_RULE_VERSION = "2026.08.8.5"')
replace_once(
    "app/bug_candidates.py",
    '"broken_object_authorization": {"required_any": (("object_identifier", "graphql_identifier"), ("object_operation", "graphql_operation")), "label": "object identifier plus object-specific operation"},',
    '"broken_object_authorization": {"required_any": (("object_identifier", "graphql_identifier"), ("object_operation", "graphql_operation"), ("cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch", "parent_child_scope_mismatch", "authorization_response_differential", "object_access_without_secondary_guard", "identity_object_relation_conflict", "unauthorized_object_response")), "label": "object identifier plus object operation plus object-level authorization-boundary evidence"},',
)

new_bola = '''    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.
    # Promotion requires stored target evidence that the identity/scope-to-object authorization relation failed.
    structural_fields = [str(field) for field in path_fields + query_fields + body_fields]
    bola = analyze_bola_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        method=method,
        object_ids=object_ids,
        structural_fields=structural_fields,
        details=details,
        business_context=context,
    )
    if bola:
        emit(
            "broken_object_authorization",
            str(bola["variant"]),
            int(bola["base"]),
            list(bola["support"]),
            list(bola["contradict"]),
            list(bola["missing"]),
            list(bola["rule_ids"]),
            str(bola["summary"]),
            direct=bool(bola["direct"]),
        )

'''
regex_once(
    "app/bug_candidates.py",
    r"    # BOLA / IDOR\n.*?(?=    # Function / role authorization)",
    new_bola,
)

# Keep version contracts aligned without rewriting historical migration docs.
for path in sorted((ROOT / "tests").glob("test_*.py")):
    text = path.read_text(encoding="utf-8")
    updated = text.replace('"8.4.5"', '"8.5.0"').replace("'8.4.5'", "'8.5.0'")
    path.write_text(updated, encoding="utf-8")

# Changelog entry is intentionally concise; the detailed design lives in docs/BOLA_INTELLIGENCE_2.md.
changelog = ROOT / "CHANGELOG.md"
text = changelog.read_text(encoding="utf-8")
entry = '''# Recon Monitor 8.5.0\n\n- Added BOLA/IDOR Intelligence 2.0 with recall-preserving object-authorization admission.\n- Object IDs and object operations now remain hidden hypotheses until stored target evidence establishes an authorization-boundary mismatch.\n- Added cross-owner, cross-tenant, parent-child scope, authorization-differential, and secondary-guard evidence models derived from OWASP/CWE and public GitHub Security Lab advisories.\n- External write-ups are knowledge references only and never count as target evidence.\n- Schema remains 18.\n\n'''
if not text.startswith("# Recon Monitor 8.5.0"):
    changelog.write_text(entry + text, encoding="utf-8")

print("v8.5.0 BOLA intelligence patch applied")

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

# Legacy fixtures that intentionally expect a BOLA candidate must now include actual
# authorization-boundary evidence. This updates test data, not the production gate.
replace_once(
    "tests/test_bug_candidates_v41.py",
    '            "status_code": 401,\n            "method": "PATCH",',
    '            "status_code": 200,\n            "identity_id": "fixture-user-a",\n            "object_owner_id": "fixture-user-b",\n            "method": "PATCH",',
)
replace_once(
    "tests/test_security_reasoning_v46.py",
    '            "status_code": 200,\n            "method": "PATCH",',
    '            "status_code": 200,\n            "request_tenant_id": "tenant-a",\n            "object_tenant_id": "tenant-b",\n            "method": "PATCH",',
)
replace_once(
    "tests/test_bola_intelligence_v850.py",
    '        self.assertTrue(any("authorization-boundary" in " ".join(group) for group in admission["required_missing"]))',
    '        self.assertTrue(any("unauthorized_object_response" in group or "cross_identity_object_access" in group for group in admission["required_missing"]))',
)

# The updater test must continue to model a release newer than the running application.
update_test = ROOT / "tests/test_update_v810.py"
text = update_test.read_text(encoding="utf-8")
text = text.replace('"tagName": "v8.5.0"', '"tagName": "v8.5.1"')
text = text.replace('"name": "Recon Monitor v8.5.0"', '"name": "Recon Monitor v8.5.1"')
text = text.replace('/releases/tag/v8.5.0"', '/releases/tag/v8.5.1"')
text = text.replace('recon-monitor-v8.5.0.zip.sha256', 'recon-monitor-v8.5.1.zip.sha256')
text = text.replace('recon-monitor-v8.5.0.zip', 'recon-monitor-v8.5.1.zip')
text = text.replace('result["available"], "8.5.0"', 'result["available"], "8.5.1"')
update_test.write_text(text, encoding="utf-8")

# Changelog entry is intentionally concise; the detailed design lives in docs/BOLA_INTELLIGENCE_2.md.
changelog = ROOT / "CHANGELOG.md"
text = changelog.read_text(encoding="utf-8")
entry = '''# Recon Monitor 8.5.0\n\n- Added BOLA/IDOR Intelligence 2.0 with recall-preserving object-authorization admission.\n- Object IDs and object operations now remain hidden hypotheses until stored target evidence establishes an authorization-boundary mismatch.\n- Added cross-owner, cross-tenant, parent-child scope, authorization-differential, and secondary-guard evidence models derived from OWASP/CWE and public GitHub Security Lab advisories.\n- External write-ups are knowledge references only and never count as target evidence.\n- Schema remains 18.\n\n'''
if not text.startswith("# Recon Monitor 8.5.0"):
    changelog.write_text(entry + text, encoding="utf-8")

print("v8.5.0 BOLA intelligence patch applied")

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing compatibility marker {label} in {rel}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_test_method(rel: str, method_name: str, body: str) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    marker = f"    def {method_name}(self):\n"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"missing historical method {method_name} in {rel}")
    next_method = text.find("\n    def ", start + len(marker))
    if next_method < 0:
        tail = text.find("\n\nif __name__", start + len(marker))
        if tail < 0:
            raise SystemExit(f"cannot find end of {method_name} in {rel}")
        end = tail
    else:
        end = next_method
    replacement = marker + body.rstrip() + "\n"
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


# Static supplements need candidate impact metadata, not detector metadata.
# Keep the three values explicit here to avoid a circular dependency from the
# static adapter back into bug_candidates; the 6.28 contract checks exact parity.
replace_once(
    "app/static_family_collectors.py",
    '''STATIC_SUPPLEMENTAL_FAMILIES = (\n    "dom_xss",\n    "postmessage_trust",\n    "open_redirect",\n)\n''',
    '''STATIC_SUPPLEMENTAL_FAMILIES = (\n    "dom_xss",\n    "postmessage_trust",\n    "open_redirect",\n)\nSTATIC_SUPPLEMENTAL_IMPACTS = {\n    "dom_xss": 72,\n    "postmessage_trust": 68,\n    "open_redirect": 52,\n}\n''',
    "static supplemental impact registry",
)
replace_once(
    "app/static_family_collectors.py",
    "evidence_strength=_strength(confidence, support, contradict, direct=True), impact=DETECTOR_SPECS[family].impact,",
    "evidence_strength=_strength(confidence, support, contradict, direct=True), impact=STATIC_SUPPLEMENTAL_IMPACTS[family],",
    "static supplemental impact source",
)

# Remove state that existed only for the deleted execution fallback, and remove
# the duplicated static query setup now owned by the static adapter.
replace_once(
    "app/bug_candidates.py",
    "    emitted_execution_families: set[str] = set()\n",
    "",
    "unused execution ownership set",
)
replace_once(
    "app/bug_candidates.py",
    "        emitted_execution_families.add(family)\n",
    "",
    "unused execution ownership marker",
)
replace_once(
    "app/bug_candidates.py",
    '''    count = 0\n    params: list[Any] = [analysis_id]\n    target_clause = ""\n    if target:\n        target_clause = " AND target=?"\n        params.append(target)\n\n    # Analysis 6.28 — static adapters own all persisted static candidate emission.\n''',
    '''    count = 0\n\n    # Analysis 6.28 — static adapters own all persisted static candidate emission.\n''',
    "duplicated static query setup",
)

# Historical phase tests keep all behavioral assertions, but their one source-
# shape assertion must follow the new generic ownership boundary. This is not a
# relaxation: each now asserts both the generic registry call and absence of its
# former direct collector call in bug_candidates.py.
raw_architecture_tests = {
    "tests/test_physical_raw_collector_injection_v6160.py": (
        "test_orchestrator_no_longer_contains_legacy_injection_collector",
        "collect_injection_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_authorization_v6170.py": (
        "test_orchestrator_cutover_removes_legacy_authorization_blocks",
        "collect_authorization_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_file_remote_v6180.py": (
        "test_orchestrator_cutover_removes_legacy_family_emission",
        "collect_file_remote_resource_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_client_side_v6190.py": (
        "test_orchestrator_cutover_removes_legacy_redirect_emission",
        "collect_client_side_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_api_configuration_v6200.py": (
        "test_orchestrator_cutover_removes_all_five_legacy_blocks",
        "collect_api_configuration_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_business_logic_v6210.py": (
        "test_orchestrator_cutover_removes_legacy_business_race_block",
        "collect_business_logic_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_authentication_v6220.py": (
        "test_orchestrator_cutover_removes_legacy_authentication_block",
        "collect_authentication_observations(execution_map)",
    ),
    "tests/test_physical_raw_collector_exposure_headers_v6230.py": (
        "test_orchestrator_cutover_removes_legacy_exposure_header_block",
        "collect_exposure_headers_observations(execution_map)",
    ),
}
for rel, (method_name, old_call) in raw_architecture_tests.items():
    replace_test_method(
        rel,
        method_name,
        f'''        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")\n        self.assertIn("collect_raw_owned_observations(execution_map)", source)\n        self.assertIn("validate_family_ownership()", source)\n        self.assertNotIn({old_call!r}, source)\n        self.assertNotIn("detector-execution-fallback", source)''',
    )

replace_test_method(
    "tests/test_specialized_static_collectors_v6240.py",
    "test_orchestrator_physically_removes_specialized_static_blocks",
    '''        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")\n        self.assertIn("collect_static_candidate_observations(db, analysis_id, target)", source)\n        self.assertNotIn("collect_specialized_static_observations(db, analysis_id, target)", source)\n        self.assertNotIn('if source == "postMessage"', source)\n        self.assertNotIn('elif sink in {"innerHTML", "eval"}', source)\n        self.assertNotIn('elif sink == "navigation"', source)''',
)

# Strengthen the current 6.28 contract: supplemental impact metadata must remain
# exactly aligned with candidate-family metadata and the deleted fallback state
# must not reappear.
test_path = ROOT / "tests" / "test_analysis_628_orchestrator_cleanup.py"
test = test_path.read_text(encoding="utf-8")
old_import = "from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, STATIC_SUPPLEMENTAL_FAMILIES\n"
new_import = "from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, STATIC_SUPPLEMENTAL_FAMILIES, STATIC_SUPPLEMENTAL_IMPACTS\n"
if old_import not in test:
    raise SystemExit("6.28 static import marker missing")
test = test.replace(old_import, new_import, 1)
old_assert = '''        for family in STATIC_SUPPLEMENTAL_FAMILIES:\n            self.assertEqual(PRIMARY_FAMILY_OWNERSHIP[family], "raw")\n'''
new_assert = '''        for family in STATIC_SUPPLEMENTAL_FAMILIES:\n            self.assertEqual(PRIMARY_FAMILY_OWNERSHIP[family], "raw")\n            self.assertEqual(STATIC_SUPPLEMENTAL_IMPACTS[family], int(bug_candidates.BUG_FAMILIES[family]["impact"]))\n'''
if old_assert not in test:
    raise SystemExit("6.28 supplemental ownership assertion marker missing")
test = test.replace(old_assert, new_assert, 1)
old_source_assert = '        self.assertNotIn("detector-execution-fallback", source)\n'
new_source_assert = '        self.assertNotIn("detector-execution-fallback", source)\n        self.assertNotIn("emitted_execution_families", source)\n'
if old_source_assert not in test:
    raise SystemExit("6.28 fallback source assertion marker missing")
test = test.replace(old_source_assert, new_source_assert, 1)
test_path.write_text(test, encoding="utf-8")

print("Analysis 6.28 compatibility and cleanup patch applied")

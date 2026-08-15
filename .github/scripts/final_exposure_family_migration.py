from __future__ import annotations

from hashlib import sha256
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"{label}: expected anchor missing")
    return text.replace(old, new, 1)


def replace_block(text: str, start: str, end: str, replacement: str, label: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{label}: block start missing: {start}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{label}: block end missing: {end}")
    return text[:start_index] + replacement.rstrip() + text[end_index:]


def add_knowledge_alias(path: str, anchor: str, block: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    alias_id = block.split('id="', 1)[1].split('"', 1)[0]
    if alias_id not in text:
        text = replace_once(text, anchor, block + anchor, path)
        file.write_text(text, encoding="utf-8")


# Preserve historical knowledge IDs used by golden compatibility tests while
# keeping all aliases explicitly non-evidentiary through WriteupLesson.
add_knowledge_alias(
    "app/family_specs/account_enumeration.py",
    "        WriteupLesson(\n            id=\"owasp-wstg-idnt-04-response-pattern\"",
    '''        WriteupLesson(
            id="owasp-wstg-idnt-04-account-enumeration",
            source="OWASP WSTG",
            ref="WSTG-IDNT-04 / Account Enumeration",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            relation="historical_knowledge_compatibility",
            lesson="Controlled differences between existing and non-existing test identities define the reusable account-enumeration pattern; endpoint names alone are not target evidence.",
            signal_hints=("identity_lookup", "identity_response_differential", "identity_timing_differential"),
        ),
''',
)
add_knowledge_alias(
    "app/family_specs/information_disclosure.py",
    "        WriteupLesson(\n            id=\"cwe-200-sensitive-information-exposure\"",
    '''        WriteupLesson(
            id="owasp-wstg-information-leakage-boundary",
            source="OWASP WSTG",
            ref="WSTG-INFO-05 / WSTG-ERRH-01 information leakage boundary",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            relation="historical_knowledge_compatibility",
            lesson="Information-looking output is a finding only when stored target evidence shows sensitive or private information crossing an unintended visibility boundary.",
            signal_hints=("sensitive_marker", "sensitive_response_observed", "private_field_publicly_observed"),
        ),
''',
)
add_knowledge_alias(
    "app/family_specs/source_map_exposure.py",
    "        WriteupLesson(\n            id=\"owasp-wstg-info-05-source-maps\"",
    '''        WriteupLesson(
            id="owasp-wstg-info-05-source-map-exposure",
            source="OWASP WSTG",
            ref="WSTG-INFO-05 / Source-map Exposure",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            relation="historical_knowledge_compatibility",
            lesson="A source-map reference is surface only; public reachability of meaningful internal map structure is the decisive exposure condition.",
            signal_hints=("source_map", "internal_sources", "source_map_publicly_reachable"),
        ),
''',
)


# Tighten live evidence contracts for this batch.
reasoning = Path("app/family_reasoning_final_analyzers.py")
t = reasoning.read_text(encoding="utf-8")
t = t.replace('FINAL_ANALYZER_REASONING_VERSION = "1.3.0"', 'FINAL_ANALYZER_REASONING_VERSION = "1.4.0"')
t = t.replace('FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.16.1"', 'FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.16.2"')
anchor = '    catalog["graphql_authorization"] = graphql\n'
if 'catalog["account_enumeration"] = account_enumeration' not in t:
    addition = r'''

    account_enumeration = dict(catalog["account_enumeration"])
    account_enumeration.update(
        {
            "promotion_required": _groups(
                {"identity_lookup", "identity_response_differential", "identity_timing_differential"},
                {"authentication_surface", "client_operation", "identity_response_differential", "identity_timing_differential"},
                {"identity_response_differential", "identity_timing_differential"},
            ),
            "blocking_contradictions": frozenset({"uniform_identity_response", "uniform_identity_timing"}),
            "override_signals": frozenset({"identity_response_differential", "identity_timing_differential"}),
            "confirmation_required": _groups({"identity_response_differential", "identity_timing_differential"}),
        }
    )
    catalog["account_enumeration"] = account_enumeration

    information_disclosure = dict(catalog["information_disclosure"])
    information_disclosure.update(
        {
            "promotion_required": _groups(
                {"sensitive_marker", "sensitive_response_observed", "private_field_publicly_observed"},
                {"stored_evidence", "sensitive_response_observed", "private_field_publicly_observed"},
                {"sensitive_response_observed", "private_field_publicly_observed"},
            ),
            "blocking_contradictions": frozenset({"intended_public_metadata", "redaction_enforced"}),
            "override_signals": frozenset({"sensitive_response_observed", "private_field_publicly_observed"}),
            "confirmation_required": _groups({"sensitive_response_observed", "private_field_publicly_observed"}),
        }
    )
    catalog["information_disclosure"] = information_disclosure

    source_map_exposure = dict(catalog["source_map_exposure"])
    source_map_exposure.update(
        {
            "promotion_required": _groups(
                {"source_map", "source_map_publicly_reachable", "sensitive_source_content_observed"},
                {"internal_sources", "source_map_publicly_reachable", "sensitive_source_content_observed"},
                {"source_map_publicly_reachable", "sensitive_source_content_observed"},
            ),
            "blocking_contradictions": frozenset({"source_map_not_public"}),
            "override_signals": frozenset({"source_map_publicly_reachable"}),
            "confirmation_required": _groups({"source_map_publicly_reachable"}),
        }
    )
    catalog["source_map_exposure"] = source_map_exposure

    secret_exposure = dict(catalog["secret_exposure"])
    secret_exposure.update(
        {
            "promotion_required": _groups(
                {"secret_pattern", "credential_material_confirmed", "live_secret_context"},
                {"context", "credential_material_confirmed", "live_secret_context"},
                {"credential_material_confirmed", "live_secret_context"},
            ),
            "blocking_contradictions": frozenset({"placeholder", "intended_public_client_identifier"}),
            "override_signals": frozenset({"credential_material_confirmed", "live_secret_context"}),
            "confirmation_required": _groups({"credential_material_confirmed", "live_secret_context"}),
        }
    )
    catalog["secret_exposure"] = secret_exposure
'''
    t = replace_once(t, anchor, anchor + addition, "final analyzer reasoning")
reasoning.write_text(t, encoding="utf-8")


# Extend the canonical family registry from 13 to 17 families.
registry = Path("app/family_specs/registry.py")
t = registry.read_text(encoding="utf-8")
t = t.replace('FAMILY_SPEC_REGISTRY_VERSION = "1.5.0"', 'FAMILY_SPEC_REGISTRY_VERSION = "1.6.0"')
import_anchor = 'from .authentication_session import AUTHENTICATION_SESSION_STANDARD_SPEC\n'
imports = (
    'from .account_enumeration import ACCOUNT_ENUMERATION_STANDARD_SPEC\n'
    'from .information_disclosure import INFORMATION_DISCLOSURE_STANDARD_SPEC\n'
    'from .source_map_exposure import SOURCE_MAP_EXPOSURE_STANDARD_SPEC\n'
    'from .secret_exposure import SECRET_EXPOSURE_STANDARD_SPEC\n'
)
if 'ACCOUNT_ENUMERATION_STANDARD_SPEC' not in t:
    t = replace_once(t, import_anchor, import_anchor + imports, "registry imports")
family_anchor = '    "graphql_authorization",\n)'
if '    "account_enumeration",\n' not in t.split('FAMILY_STANDARD_SPECS', 1)[0]:
    t = replace_once(
        t,
        family_anchor,
        '    "graphql_authorization",\n    "account_enumeration",\n    "information_disclosure",\n    "source_map_exposure",\n    "secret_exposure",\n)',
        "registry family list",
    )
spec_anchor = '    GRAPHQL_AUTHORIZATION_STANDARD_SPEC.family: GRAPHQL_AUTHORIZATION_STANDARD_SPEC,\n}'
if 'ACCOUNT_ENUMERATION_STANDARD_SPEC.family' not in t:
    t = replace_once(
        t,
        spec_anchor,
        '    GRAPHQL_AUTHORIZATION_STANDARD_SPEC.family: GRAPHQL_AUTHORIZATION_STANDARD_SPEC,\n'
        '    ACCOUNT_ENUMERATION_STANDARD_SPEC.family: ACCOUNT_ENUMERATION_STANDARD_SPEC,\n'
        '    INFORMATION_DISCLOSURE_STANDARD_SPEC.family: INFORMATION_DISCLOSURE_STANDARD_SPEC,\n'
        '    SOURCE_MAP_EXPOSURE_STANDARD_SPEC.family: SOURCE_MAP_EXPOSURE_STANDARD_SPEC,\n'
        '    SECRET_EXPOSURE_STANDARD_SPEC.family: SECRET_EXPOSURE_STANDARD_SPEC,\n}',
        "registry standards map",
    )
registry.write_text(t, encoding="utf-8")


init_file = Path("app/family_specs/__init__.py")
t = init_file.read_text(encoding="utf-8")
init_anchor = 'from .authentication_session import AUTHENTICATION_SESSION_STANDARD_SPEC\n'
init_imports = (
    'from .account_enumeration import ACCOUNT_ENUMERATION_STANDARD_SPEC\n'
    'from .information_disclosure import INFORMATION_DISCLOSURE_STANDARD_SPEC\n'
    'from .source_map_exposure import SOURCE_MAP_EXPOSURE_STANDARD_SPEC\n'
    'from .secret_exposure import SECRET_EXPOSURE_STANDARD_SPEC\n'
)
if 'ACCOUNT_ENUMERATION_STANDARD_SPEC' not in t:
    t = replace_once(t, init_anchor, init_anchor + init_imports, "family_specs init")
init_file.write_text(t, encoding="utf-8")


# Analyzer compatibility projections. The analyzers remain runtime executors;
# taxonomy/methodology/write-up catalogs now come from family_specs.
def migrate_analyzer(path: str, family: str, start: str, end: str, block: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if 'from family_specs.registry import get_detection_spec' not in text:
        text = replace_once(
            text,
            'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n',
            'from family_reasoning import FAMILY_REASONING, confirmation_gaps\nfrom family_specs.registry import get_detection_spec\n',
            path + " spec import",
        )
    if 'from .remaining_common import policy_ready' not in text:
        text = replace_once(
            text,
            'from .base import FamilyAnalyzer, FamilyAnalyzerContext\n',
            'from .base import FamilyAnalyzer, FamilyAnalyzerContext\nfrom .remaining_common import policy_ready\n',
            path + " policy import",
        )
    text = replace_block(text, start, end, block, path + " canonical block")
    file.write_text(text, encoding="utf-8")


migrate_analyzer(
    "app/family_analyzers/account_enumeration.py",
    "account_enumeration",
    "ACCOUNT_ENUMERATION_TAXONOMY =",
    "\n\ndef _loads",
    '''ACCOUNT_ENUMERATION_SPEC = get_detection_spec("account_enumeration")
ACCOUNT_ENUMERATION_TAXONOMY = ACCOUNT_ENUMERATION_SPEC.taxonomy()
ACCOUNT_ENUMERATION_METHOD = tuple(step.as_dict() for step in ACCOUNT_ENUMERATION_SPEC.standard.methodology)
ACCOUNT_ENUMERATION_FALSE_POSITIVE_CHECKS = tuple(ACCOUNT_ENUMERATION_SPEC.standard.false_positive_checks)
ACCOUNT_ENUMERATION_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in ACCOUNT_ENUMERATION_SPEC.standard.writeups
)
''',
)

migrate_analyzer(
    "app/family_analyzers/information_disclosure.py",
    "information_disclosure",
    "INFORMATION_DISCLOSURE_TAXONOMY =",
    "\n\n_SURFACE_PATTERNS",
    '''INFORMATION_DISCLOSURE_SPEC = get_detection_spec("information_disclosure")
INFORMATION_DISCLOSURE_TAXONOMY = INFORMATION_DISCLOSURE_SPEC.taxonomy()
INFORMATION_DISCLOSURE_METHOD = tuple(step.as_dict() for step in INFORMATION_DISCLOSURE_SPEC.standard.methodology)
INFORMATION_DISCLOSURE_FALSE_POSITIVE_CHECKS = tuple(INFORMATION_DISCLOSURE_SPEC.standard.false_positive_checks)
INFORMATION_DISCLOSURE_KNOWLEDGE_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in INFORMATION_DISCLOSURE_SPEC.standard.writeups
)
''',
)

migrate_analyzer(
    "app/family_analyzers/source_map_exposure.py",
    "source_map_exposure",
    "SOURCE_MAP_TAXONOMY =",
    "\n\ndef _truth",
    '''SOURCE_MAP_EXPOSURE_SPEC = get_detection_spec("source_map_exposure")
SOURCE_MAP_EXPOSURE_TAXONOMY = SOURCE_MAP_EXPOSURE_SPEC.taxonomy()
SOURCE_MAP_EXPOSURE_METHOD = tuple(step.as_dict() for step in SOURCE_MAP_EXPOSURE_SPEC.standard.methodology)
SOURCE_MAP_EXPOSURE_FALSE_POSITIVE_CHECKS = tuple(SOURCE_MAP_EXPOSURE_SPEC.standard.false_positive_checks)
SOURCE_MAP_EXPOSURE_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in SOURCE_MAP_EXPOSURE_SPEC.standard.writeups
)
# Historical analyzer exports remain aliases for compatibility.
SOURCE_MAP_TAXONOMY = SOURCE_MAP_EXPOSURE_TAXONOMY
SOURCE_MAP_METHOD = SOURCE_MAP_EXPOSURE_METHOD
SOURCE_MAP_FALSE_POSITIVE_CHECKS = SOURCE_MAP_EXPOSURE_FALSE_POSITIVE_CHECKS
SOURCE_MAP_WRITEUP_PATTERNS = SOURCE_MAP_EXPOSURE_WRITEUP_PATTERNS
''',
)

migrate_analyzer(
    "app/family_analyzers/secret_exposure.py",
    "secret_exposure",
    "SECRET_EXPOSURE_TAXONOMY =",
    "\n\n_PLACEHOLDER_RE",
    '''SECRET_EXPOSURE_SPEC = get_detection_spec("secret_exposure")
SECRET_EXPOSURE_TAXONOMY = SECRET_EXPOSURE_SPEC.taxonomy()
SECRET_EXPOSURE_METHOD = tuple(step.as_dict() for step in SECRET_EXPOSURE_SPEC.standard.methodology)
SECRET_EXPOSURE_FALSE_POSITIVE_CHECKS = tuple(SECRET_EXPOSURE_SPEC.standard.false_positive_checks)
SECRET_EXPOSURE_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in SECRET_EXPOSURE_SPEC.standard.writeups
)
''',
)


# Make analyzer status use the same live contract as hypothesis admission.
account = Path("app/family_analyzers/account_enumeration.py")
t = account.read_text(encoding="utf-8")
old = '''        direct = bool(explicit_direct or paired_direct)
        contradiction_types = {str(item.get("type") or "") for item in contradict}
        confirmation_missing = confirmation_gaps(self.family, observed)
        policy = FAMILY_REASONING[self.family]
        writeups = _matched_writeups(observed)
'''
new = '''        direct = bool(explicit_direct or paired_direct)
        contradiction_types = {str(item.get("type") or "") for item in contradict}
        state = policy_ready(self.family, support, contradict)
        confirmation_missing = [] if state["confirmation_ready"] else confirmation_gaps(self.family, observed)
        policy = FAMILY_REASONING[self.family]
        writeups = _matched_writeups(observed)
'''
t = replace_once(t, old, new, "account policy state")
t = replace_once(
    t,
    '                "confirmation_missing": confirmation_missing,\n                "confirmation_ready_from_stored_target_evidence": not confirmation_missing,',
    '                "promotion_ready_from_stored_target_evidence": state["promotion_ready"],\n                "confirmation_missing": confirmation_missing,\n                "confirmation_ready_from_stored_target_evidence": state["confirmation_ready"],',
    "account metadata state",
)
if '"ACCOUNT_ENUMERATION_SPEC"' not in t:
    t = replace_once(t, '    "ACCOUNT_ENUMERATION_METHOD",\n', '    "ACCOUNT_ENUMERATION_METHOD",\n    "ACCOUNT_ENUMERATION_SPEC",\n', "account all")
account.write_text(t, encoding="utf-8")


info = Path("app/family_analyzers/information_disclosure.py")
t = info.read_text(encoding="utf-8")
old = '''    observed = {str(item.get("type") or "") for item in support}
    confirmation_missing = list(confirmation_gaps("information_disclosure", observed))
    confirmation_ready = bool(observed.intersection({"sensitive_response_observed", "private_field_publicly_observed"})) and direct
'''
new = '''    observed = {str(item.get("type") or "") for item in support}
    state = policy_ready("information_disclosure", support, contradict)
    confirmation_ready = state["confirmation_ready"]
    confirmation_missing = [] if confirmation_ready else list(confirmation_gaps("information_disclosure", observed))
'''
t = replace_once(t, old, new, "information disclosure policy state")
t = replace_once(
    t,
    '        "promotion_ready_from_stored_target_evidence": direct,',
    '        "promotion_ready_from_stored_target_evidence": state["promotion_ready"],',
    "information disclosure promotion state",
)
info.write_text(t, encoding="utf-8")


source_map = Path("app/family_analyzers/source_map_exposure.py")
t = source_map.read_text(encoding="utf-8")
old = '''    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    promotion_ready = "source_map_publicly_reachable" in observed or "sensitive_source_content_observed" in observed
    confirmation_ready = "source_map_publicly_reachable" in observed and not bool(blockers & {"source_map_not_public"})
    confirmation_missing = list(confirmation_gaps("source_map_exposure", observed))
    if confirmation_ready:
        confirmation_missing = []
'''
new = '''    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    state = policy_ready("source_map_exposure", support, contradict)
    promotion_ready = state["promotion_ready"]
    confirmation_ready = state["confirmation_ready"]
    confirmation_missing = [] if confirmation_ready else list(confirmation_gaps("source_map_exposure", observed))
'''
t = replace_once(t, old, new, "source map policy state")
source_map.write_text(t, encoding="utf-8")


secret = Path("app/family_analyzers/secret_exposure.py")
t = secret.read_text(encoding="utf-8")
old = '''    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    promotion_ready = "secret_pattern" in observed and "context" in observed and "placeholder" not in blockers
    confirmation_ready = bool(observed & {"credential_material_confirmed", "live_secret_context"}) and "placeholder" not in blockers
    confirmation_missing = list(confirmation_gaps("secret_exposure", observed))
    if confirmation_ready:
        confirmation_missing = []
'''
new = '''    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    state = policy_ready("secret_exposure", support, contradict)
    promotion_ready = state["promotion_ready"]
    confirmation_ready = state["confirmation_ready"]
    confirmation_missing = [] if confirmation_ready else list(confirmation_gaps("secret_exposure", observed))
'''
t = replace_once(t, old, new, "secret exposure policy state")
secret.write_text(t, encoding="utf-8")


# Regression expectations: the migrated registry now contains 17 families.
for path in Path("tests").glob("test_final_analyzers_*spec*.py"):
    text = path.read_text(encoding="utf-8")
    text = text.replace('len(MIGRATED_FAMILIES), 13', 'len(MIGRATED_FAMILIES), 17')
    path.write_text(text, encoding="utf-8")

bfla_test = Path("tests/test_final_analyzers_bfla_ssrf_specs.py")
t = bfla_test.read_text(encoding="utf-8")
if '                "account_enumeration",\n' not in t:
    t = replace_once(
        t,
        '                "graphql_authorization",\n            ),',
        '                "graphql_authorization",\n                "account_enumeration",\n                "information_disclosure",\n                "source_map_exposure",\n                "secret_exposure",\n            ),',
        "bfla registry tuple",
    )
bfla_test.write_text(t, encoding="utf-8")

# Current CWE/WSTG projection uses current specific entries rather than the old
# related_cwe bucket and the retired ERRH-02 page.
info_test = Path("tests/_test_family_analyzer_information_disclosure_v879_legacy.py")
t = info_test.read_text(encoding="utf-8")
t = t.replace('        self.assertIn("CWE-209", meta["taxonomy"]["related_cwe"])\n', '        self.assertIn("CWE-209", meta["taxonomy"]["cwe"])\n')
t = t.replace('        self.assertIn("CWE-497", meta["taxonomy"]["related_cwe"])\n', '        self.assertIn("CWE-497", meta["taxonomy"]["cwe"])\n')
t = t.replace('        self.assertIn("CWE-1295", meta["taxonomy"]["related_cwe"])\n', '        self.assertIn("CWE-1295", meta["taxonomy"]["cwe"])\n')
t = t.replace('        self.assertIn("WSTG-ERRH-02", meta["taxonomy"]["wstg"])\n', '')
info_test.write_text(t, encoding="utf-8")

secret_test = Path("tests/_test_family_analyzer_secret_exposure_v881_legacy.py")
t = secret_test.read_text(encoding="utf-8")
t = t.replace(
    '    def test_aws_access_key_id_marker_is_candidate_not_confirmation(self):',
    '    def test_aws_access_key_id_marker_remains_hidden_candidate(self):',
)
t = t.replace(
    '        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])\n        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])',
    '        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])\n        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])',
    1,
)
secret_test.write_text(t, encoding="utf-8")


# Preserve manifest inclusion policy: recompute existing listed paths and append
# only the new permanent files from this batch. Temporary migration files are
# deliberately excluded and will be deleted after matrix verification.
manifest = Path("MANIFEST.sha256")
existing_paths: list[str] = []
for line in manifest.read_text(encoding="utf-8").splitlines():
    if "  " not in line:
        continue
    _, path = line.split("  ", 1)
    if path and Path(path).exists():
        existing_paths.append(path)
for path in (
    "app/family_specs/account_enumeration.py",
    "app/family_specs/information_disclosure.py",
    "app/family_specs/source_map_exposure.py",
    "app/family_specs/secret_exposure.py",
    "tests/test_final_analyzers_exposure_specs.py",
):
    if path not in existing_paths:
        existing_paths.append(path)
rows = []
for path in sorted(set(existing_paths)):
    digest = sha256(Path(path).read_bytes()).hexdigest()
    rows.append(f"{digest}  {path}")
manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")

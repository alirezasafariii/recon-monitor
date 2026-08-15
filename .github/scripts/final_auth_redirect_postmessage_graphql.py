from pathlib import Path
import hashlib
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"{label}: expected anchor missing")
    return text.replace(old, new, 1)


reasoning = Path('app/family_reasoning_final_analyzers.py')
t = reasoning.read_text()
t = t.replace('FINAL_ANALYZER_REASONING_VERSION = "1.2.1"', 'FINAL_ANALYZER_REASONING_VERSION = "1.3.0"')
t = t.replace('FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.15.6"', 'FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.16.1"')
anchor = '    catalog["cors_misconfiguration"] = cors\n'
if 'catalog["authentication_session"] = auth_session' not in t:
    insert = '''

    auth_session = dict(catalog["authentication_session"])
    auth_session.update(
        {
            "promotion_required": _groups(
                {"authentication_surface", "auth_boundary", "session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"},
                {"client_operation", "state_change", "auth_boundary", "session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"},
                {"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"},
            ),
            "blocking_contradictions": frozenset({"session_rotation_observed", "recovery_verification_enforced", "expired_session_rejected"}),
            "override_signals": frozenset({"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"}),
            "confirmation_required": _groups({"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"}),
        }
    )
    catalog["authentication_session"] = auth_session

    open_redirect = dict(catalog["open_redirect"])
    open_redirect.update(
        {
            "promotion_required": _groups(
                {"redirect_parameter", "user_controlled_destination", "external_destination_accepted"},
                {"navigation_context", "dataflow_sink", "external_destination_accepted"},
                {"external_destination_accepted"},
            ),
            "blocking_contradictions": frozenset({"destination_allowlist_observed", "same_origin_navigation_enforced"}),
            "override_signals": frozenset({"external_destination_accepted"}),
            "confirmation_required": _groups({"external_destination_accepted"}),
        }
    )
    catalog["open_redirect"] = open_redirect

    postmessage = dict(catalog["postmessage_trust"])
    postmessage.update(
        {
            "promotion_required": _groups(
                {"dataflow_source", "postmessage_source", "untrusted_message_accepted"},
                {"dataflow_sink", "message_handler", "sensitive_sink", "untrusted_message_accepted"},
                {"untrusted_message_accepted"},
            ),
            "blocking_contradictions": frozenset({"origin_check_observed", "trusted_origin_only"}),
            "override_signals": frozenset({"untrusted_message_accepted"}),
            "confirmation_required": _groups({"untrusted_message_accepted"}),
        }
    )
    catalog["postmessage_trust"] = postmessage

    graphql = dict(catalog["graphql_authorization"])
    graphql.update(
        {
            "promotion_required": _groups(
                {"graphql_identifier", "graphql_unauthorized_object_response", "graphql_authorization_differential"},
                {"graphql_operation", "graphql_unauthorized_object_response", "graphql_authorization_differential"},
                {"graphql_unauthorized_object_response", "graphql_authorization_differential"},
            ),
            "blocking_contradictions": frozenset({"resolver_authorization_observed", "cross_context_denied"}),
            "override_signals": frozenset({"graphql_unauthorized_object_response", "graphql_authorization_differential"}),
            "confirmation_required": _groups({"graphql_unauthorized_object_response", "graphql_authorization_differential"}),
        }
    )
    catalog["graphql_authorization"] = graphql
'''
    t = replace_once(t, anchor, anchor + insert, 'reasoning')
reasoning.write_text(t)

registry = Path('app/family_specs/registry.py')
t = registry.read_text()
new_imports = (
    'from .authentication_session import AUTHENTICATION_SESSION_STANDARD_SPEC\n',
    'from .open_redirect import OPEN_REDIRECT_STANDARD_SPEC\n',
    'from .postmessage_trust import POSTMESSAGE_TRUST_STANDARD_SPEC\n',
    'from .graphql_authorization import GRAPHQL_AUTHORIZATION_STANDARD_SPEC\n',
)
import_anchor = 'from .ssrf import SSRF_STANDARD_SPEC\n'
for line in new_imports:
    if line not in t:
        t = replace_once(t, import_anchor, line + import_anchor, 'registry import')
t = t.replace('FAMILY_SPEC_REGISTRY_VERSION = "1.4.0"', 'FAMILY_SPEC_REGISTRY_VERSION = "1.5.0"')
if '    "authentication_session",\n    "open_redirect",\n    "postmessage_trust",\n    "graphql_authorization",\n)' not in t:
    t = replace_once(
        t,
        '    "cors_misconfiguration",\n)',
        '    "cors_misconfiguration",\n    "authentication_session",\n    "open_redirect",\n    "postmessage_trust",\n    "graphql_authorization",\n)',
        'registry migrated tuple',
    )
if 'AUTHENTICATION_SESSION_STANDARD_SPEC.family' not in t:
    t = replace_once(
        t,
        '    CORS_MISCONFIGURATION_STANDARD_SPEC.family: CORS_MISCONFIGURATION_STANDARD_SPEC,\n}',
        '    CORS_MISCONFIGURATION_STANDARD_SPEC.family: CORS_MISCONFIGURATION_STANDARD_SPEC,\n'
        '    AUTHENTICATION_SESSION_STANDARD_SPEC.family: AUTHENTICATION_SESSION_STANDARD_SPEC,\n'
        '    OPEN_REDIRECT_STANDARD_SPEC.family: OPEN_REDIRECT_STANDARD_SPEC,\n'
        '    POSTMESSAGE_TRUST_STANDARD_SPEC.family: POSTMESSAGE_TRUST_STANDARD_SPEC,\n'
        '    GRAPHQL_AUTHORIZATION_STANDARD_SPEC.family: GRAPHQL_AUTHORIZATION_STANDARD_SPEC,\n}',
        'registry spec map',
    )
registry.write_text(t)

init = Path('app/family_specs/__init__.py')
t = init.read_text()
init_anchor = 'from .ssrf import SSRF_STANDARD_SPEC\n'
for line in new_imports:
    if line not in t:
        t = replace_once(t, init_anchor, line + init_anchor, 'family_specs init')
init.write_text(t)

common = Path('app/family_analyzers/remaining_common.py')
t = common.read_text()
reg_import = 'from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec\n'
if reg_import not in t:
    t = replace_once(
        t,
        'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n',
        'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n' + reg_import,
        'remaining_common import',
    )
old_tax = '    effective_taxonomy = CANONICAL_TAXONOMY.get(family, taxonomy)\n'
if old_tax in t:
    t = replace_once(
        t,
        old_tax,
        '    effective_taxonomy = (\n'
        '        get_detection_spec(family).taxonomy()\n'
        '        if family in MIGRATED_FAMILIES\n'
        '        else CANONICAL_TAXONOMY.get(family, taxonomy)\n'
        '    )\n',
        'remaining_common taxonomy',
    )
common.write_text(t)


def project(path: str, import_anchor: str, start: str, end: str, spec_name: str, family: str, prefix: str) -> None:
    p = Path(path)
    text = p.read_text()
    imp = 'from family_specs.registry import get_detection_spec\n'
    if imp not in text:
        text = replace_once(text, import_anchor, import_anchor + imp, f'{path} import')
    block = f'''{spec_name} = get_detection_spec("{family}")

# Compatibility exports; canonical definitions live in family_specs.
{prefix}_TAXONOMY = {spec_name}.taxonomy()
{prefix}_METHOD = tuple(step.as_dict() for step in {spec_name}.standard.methodology)
{prefix}_FALSE_POSITIVE_CHECKS = tuple({spec_name}.standard.false_positive_checks)
{prefix}_WRITEUP_PATTERNS = tuple(
    {{
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }}
    for item in {spec_name}.standard.writeups
)

'''
    pattern = re.escape(start) + r'.*?' + re.escape(end)
    text, count = re.subn(pattern, block + end, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f'{path}: metadata projection failed')
    p.write_text(text)


project('app/family_analyzers/authentication_session.py', 'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n', 'AUTH_SESSION_TAXONOMY = {', 'def _loads', 'AUTH_SESSION_SPEC', 'authentication_session', 'AUTH_SESSION')
project('app/family_analyzers/open_redirect.py', 'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n', 'OPEN_REDIRECT_TAXONOMY = {', 'def _normalize', 'OPEN_REDIRECT_SPEC', 'open_redirect', 'OPEN_REDIRECT')
project('app/family_analyzers/postmessage_trust.py', 'from family_reasoning import FAMILY_REASONING, confirmation_gaps\n', 'POSTMESSAGE_TAXONOMY = {', 'def _normalize', 'POSTMESSAGE_TRUST_SPEC', 'postmessage_trust', 'POSTMESSAGE')
project('app/family_analyzers/graphql_authorization.py', 'from core import Database\n', 'GRAPHQL_AUTHORIZATION_TAXONOMY = {', 'def _safe_names', 'GRAPHQL_AUTHORIZATION_SPEC', 'graphql_authorization', 'GRAPHQL_AUTHORIZATION')

auth_legacy = Path('tests/_test_family_analyzer_authentication_session_v871_legacy.py')
t = auth_legacy.read_text()
t = t.replace(
    '        self.assertIn("WSTG-SESS-01", meta["taxonomy"]["wstg"])\n',
    '        self.assertIn("WSTG-SESS-06", meta["taxonomy"]["wstg"])\n'
    '        self.assertIn("WSTG-SESS-07", meta["taxonomy"]["wstg"])\n',
)
auth_legacy.write_text(t)

for p in Path('tests').glob('test_final_analyzers_*spec*.py'):
    text = p.read_text().replace(
        'self.assertEqual(len(MIGRATED_FAMILIES), 9)',
        'self.assertEqual(len(MIGRATED_FAMILIES), 13)',
    )
    p.write_text(text)

manifest = Path('MANIFEST.sha256')
paths = []
for line in manifest.read_text().splitlines():
    if not line.strip():
        continue
    parts = line.split(None, 1)
    if len(parts) != 2:
        raise SystemExit(f'bad manifest line {line!r}')
    rel = parts[1].strip()
    if Path(rel).is_file() and rel not in {
        '.github/workflows/final-auth-redirect-postmessage-graphql.yml',
        '.github/scripts/final_auth_redirect_postmessage_graphql.py',
    }:
        paths.append(rel)
paths.extend([
    'app/family_specs/authentication_session.py',
    'app/family_specs/open_redirect.py',
    'app/family_specs/postmessage_trust.py',
    'app/family_specs/graphql_authorization.py',
    'tests/test_final_analyzers_auth_redirect_postmessage_graphql_specs.py',
])
manifest.write_text('\n'.join(
    f'{hashlib.sha256(Path(rel).read_bytes()).hexdigest()}  {rel}'
    for rel in sorted(set(paths))
) + '\n')

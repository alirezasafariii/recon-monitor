from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

ROOT = Path('.')


def replace_once(path: str, old: str, new: str) -> None:
    file = ROOT / path
    text = file.read_text(encoding='utf-8')
    if old not in text:
        raise RuntimeError(f'{path}: expected hardening anchor not found')
    file.write_text(text.replace(old, new, 1), encoding='utf-8')


# Make the core live-request path safe even when safe_validation.py has not been
# imported. The compatibility module remains a patchable facade for existing
# callers/tests, but no longer supplies the security property itself.
core = ROOT / 'app/safe_validation_core.py'
text = core.read_text(encoding='utf-8')
if 'from safe_transport import perform_pinned_request\n' not in text:
    anchor = 'from family_reasoning import FAMILY_REASONING, validation_level_for_family\n'
    if anchor not in text:
        raise RuntimeError('safe_validation_core.py: import anchor missing')
    text = text.replace(anchor, anchor + 'from safe_transport import perform_pinned_request\n', 1)

pattern = re.compile(
    r'def _perform_request\([^\n]*\) -> tuple\[dict\[str, Any\], str\]:\n.*?\n\ndef _classify\(',
    re.S,
)
new_block = '''def _perform_request_via_safe_transport(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    """Canonical core transport hook using the pinned Safe Transport boundary."""
    return perform_pinned_request(
        item,
        policy,
        safe_methods=SAFE_METHODS,
        url_safety=_url_safety,
        observation=_observation,
        max_response_bytes=MAX_RESPONSE_BYTES,
        validation_version=VALIDATION_VERSION,
    )


def _perform_request(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return _perform_request_via_safe_transport(item, policy)


def _classify('''
text, count = pattern.subn(new_block, text, count=1)
if count != 1:
    raise RuntimeError(f'safe_validation_core.py: legacy transport block not found exactly once: {count}')
core.write_text(text, encoding='utf-8')

# Keep the public compatibility patch point, but make its default implementation
# delegate to the intrinsic core safe-transport helper.
facade = ROOT / 'app/safe_validation.py'
text = facade.read_text(encoding='utf-8')
text = text.replace(
    'from safe_transport import SAFE_TRANSPORT_VERSION, perform_pinned_request\n',
    'from safe_transport import SAFE_TRANSPORT_VERSION\n',
    1,
)
old = '''def _perform_request(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return perform_pinned_request(
        item,
        policy,
        safe_methods=_core.SAFE_METHODS,
        url_safety=_core._url_safety,
        observation=_core._observation,
        max_response_bytes=_core.MAX_RESPONSE_BYTES,
        validation_version=_core.VALIDATION_VERSION,
    )
'''
new = '''def _perform_request(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return _core._perform_request_via_safe_transport(item, policy)
'''
if old not in text:
    raise RuntimeError('safe_validation.py: transport facade anchor missing')
facade.write_text(text.replace(old, new, 1), encoding='utf-8')

TEST = r'''from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import safe_validation
import safe_validation_core


class SafeValidationCoreTransportHardeningTests(unittest.TestCase):
    def test_core_transport_helper_delegates_to_pinned_transport(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 200}, "ok")
        with mock.patch(
            "safe_validation_core.perform_pinned_request", return_value=expected
        ) as pinned:
            result = safe_validation_core._perform_request_via_safe_transport(item, policy)
        self.assertEqual(result, expected)
        pinned.assert_called_once()
        kwargs = pinned.call_args.kwargs
        self.assertIs(kwargs["url_safety"], safe_validation_core._url_safety)
        self.assertIs(kwargs["observation"], safe_validation_core._observation)
        self.assertEqual(kwargs["safe_methods"], safe_validation_core.SAFE_METHODS)

    def test_public_patch_point_still_routes_execute_core_hook(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 204}, "ok")
        with mock.patch("safe_validation._perform_request", return_value=expected) as patched:
            result = safe_validation_core._perform_request(item, policy)
        self.assertEqual(result, expected)
        patched.assert_called_once_with(item, policy)

    def test_public_default_uses_core_pinned_helper(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 200}, "ok")
        with mock.patch(
            "safe_validation_core._perform_request_via_safe_transport", return_value=expected
        ) as helper:
            result = safe_validation._perform_request(item, policy)
        self.assertEqual(result, expected)
        helper.assert_called_once_with(item, policy)

    def test_core_source_has_no_second_direct_http_open_path(self):
        source = (ROOT / "app/safe_validation_core.py").read_text(encoding="utf-8")
        start = source.index("def _perform_request_via_safe_transport(")
        end = source.index("\ndef _classify(", start)
        transport_section = source[start:end]
        self.assertIn("perform_pinned_request", transport_section)
        self.assertNotIn("build_opener", transport_section)
        self.assertNotIn("opener.open", transport_section)
        self.assertNotIn("getaddrinfo", transport_section)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / 'tests/test_safe_validation_core_transport_hardening.py').write_text(TEST, encoding='utf-8')

# Refresh manifest for permanent files only. Temporary workflow/migration assets
# are intentionally excluded from the release manifest.
manifest = ROOT / 'MANIFEST.sha256'
paths: list[str] = []
for line in manifest.read_text(encoding='utf-8').splitlines():
    if '  ' not in line:
        continue
    _, file_path = line.split('  ', 1)
    if file_path and (ROOT / file_path).exists():
        paths.append(file_path)
paths.append('tests/test_safe_validation_core_transport_hardening.py')
rows = [
    f"{sha256((ROOT / file_path).read_bytes()).hexdigest()}  {file_path}"
    for file_path in sorted(set(paths))
]
manifest.write_text('\n'.join(rows) + '\n', encoding='utf-8')

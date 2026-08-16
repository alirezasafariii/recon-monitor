from __future__ import annotations

from hashlib import sha256
from pathlib import Path

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
replace_once(
    'app/safe_validation_core.py',
    'from family_reasoning import FAMILY_REASONING, validation_level_for_family\n',
    'from family_reasoning import FAMILY_REASONING, validation_level_for_family\nfrom safe_transport import perform_pinned_request\n',
)

core = ROOT / 'app/safe_validation_core.py'
text = core.read_text(encoding='utf-8')
start = text.index('def _perform_request(\n')
end = text.index('\n\ndef _classify(', start)
new_function = '''def _perform_request_via_safe_transport(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    """Canonical core transport hook: resolve once, validate globally routable
    addresses, pin the connection, disable proxies, and never follow redirects.

    Keeping this helper inside the core means a direct import of
    ``safe_validation_core`` cannot bypass the pinned transport boundary.
    """
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
'''
core.write_text(text[:start] + new_function + text[end:], encoding='utf-8')

# The compatibility facade keeps the historical monkey-patch point used by
# tests/downstream code, while its default implementation calls the immutable
# core helper. `_core._perform_request` is still proxied so patching
# safe_validation._perform_request works as before.
replace_once(
    'app/safe_validation.py',
    'from safe_transport import SAFE_TRANSPORT_VERSION, perform_pinned_request\n',
    'from safe_transport import SAFE_TRANSPORT_VERSION\n',
)
text_path = ROOT / 'app/safe_validation.py'
text = text_path.read_text(encoding='utf-8')
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
text_path.write_text(text.replace(old, new, 1), encoding='utf-8')

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


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / 'tests/test_safe_validation_core_transport_hardening.py').write_text(TEST, encoding='utf-8')

# Refresh manifest for permanent files only. The temporary migration assets are
# intentionally not included.
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

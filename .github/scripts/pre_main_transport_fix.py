from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import subprocess

ROOT = Path('.')
CORE = ROOT / 'app/safe_validation_core.py'
text = CORE.read_text(encoding='utf-8')

import_anchor = 'from family_reasoning import FAMILY_REASONING, validation_level_for_family\n'
transport_import = 'from safe_transport import perform_pinned_request\n'
if transport_import not in text:
    if import_anchor not in text:
        raise RuntimeError('safe_validation_core import anchor missing')
    text = text.replace(import_anchor, import_anchor + transport_import, 1)

pattern = re.compile(
    r'def _perform_request\(item: dict\[str, Any\], policy: TargetPolicy\) -> tuple\[dict\[str, Any\], str\]:\n.*?\n\ndef _classify\(',
    re.S,
)
replacement = '''def _perform_request(item: dict[str, Any], policy: TargetPolicy) -> tuple[dict[str, Any], str]:
    """Use the pinned transport at the core security boundary.

    The compatibility wrapper may still proxy this function for downstream
    patch points, but importing ``safe_validation_core`` directly must never
    restore a validate-then-re-resolve network path.
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


def _classify('''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise RuntimeError(f'expected exactly one _perform_request block; replaced={count}')
CORE.write_text(text, encoding='utf-8')

TEST = ROOT / 'tests/test_merge_hardening_transport.py'
TEST.write_text('''from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import safe_validation_core as core


class MergeHardeningTransportTests(unittest.TestCase):
    def test_core_perform_request_uses_pinned_transport_directly(self):
        sentinel = ({"status_code": 204, "safe_transport_version": "test"}, "ok")
        item = {"method": "GET", "url": "https://example.com/health"}
        policy = object()
        with mock.patch("safe_validation_core.perform_pinned_request", return_value=sentinel) as pinned:
            result = core._perform_request(item, policy)
        self.assertEqual(result, sentinel)
        pinned.assert_called_once_with(
            item,
            policy,
            safe_methods=core.SAFE_METHODS,
            url_safety=core._url_safety,
            observation=core._observation,
            max_response_bytes=core.MAX_RESPONSE_BYTES,
            validation_version=core.VALIDATION_VERSION,
        )

    def test_core_has_no_second_live_http_transport(self):
        source = inspect.getsource(core._perform_request)
        self.assertIn("perform_pinned_request", source)
        self.assertNotIn("build_opener", source)
        self.assertNotIn("getaddrinfo", source)
        self.assertNotIn("opener.open", source)


if __name__ == "__main__":
    unittest.main()
''', encoding='utf-8')

# Build the permanent manifest while excluding this one-shot migration harness.
excluded = {
    'MANIFEST.sha256',
    '.github/PRE_MAIN_TRANSPORT_FIX_TRIGGER',
    '.github/scripts/pre_main_transport_fix.py',
    '.github/workflows/pre-main-transport-fix.yml',
}
paths = subprocess.check_output(['git', 'ls-files', '-z']).decode('utf-8').split('\0')
# Include newly-created permanent test even before it is tracked.
paths.append('tests/test_merge_hardening_transport.py')
lines: list[str] = []
for rel in sorted(set(p for p in paths if p and p not in excluded)):
    path = ROOT / rel
    if not path.is_file():
        continue
    lines.append(f'{sha256(path.read_bytes()).hexdigest()}  {rel}')
(ROOT / 'MANIFEST.sha256').write_text('\n'.join(lines) + '\n', encoding='utf-8')

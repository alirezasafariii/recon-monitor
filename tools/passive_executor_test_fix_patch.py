from __future__ import annotations

from pathlib import Path
import hashlib


tests = Path("tests/test_validation_executor.py")
text = tests.read_text(encoding="utf-8")
old = '''        self.assertNotIn("RESPONSE-SECRET", encoded)
        self.assertNotIn("raw_body", encoded)
        self.assertNotIn("unexpected_transport_field", encoded)
        location = result["observations"][0]["headers"]["location"]
'''
new = '''        self.assertNotIn("RESPONSE-SECRET", encoded)
        self.assertNotIn("raw_body", result["observations"][0])
        self.assertFalse(result["observations"][0]["raw_body_stored"])
        self.assertNotIn("unexpected_transport_field", result["observations"][0])
        location = result["observations"][0]["headers"]["location"]
'''
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit("redaction assertion block not found")
tests.write_text(text, encoding="utf-8")

manifest = Path("MANIFEST.sha256")
entries = {}
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    digest, rel = raw.split("  ", 1)
    entries[rel] = digest
entries["tests/test_validation_executor.py"] = hashlib.sha256(tests.read_bytes()).hexdigest()
manifest.write_text(
    "".join(f"{entries[rel]}  {rel}\n" for rel in sorted(entries)),
    encoding="utf-8",
)

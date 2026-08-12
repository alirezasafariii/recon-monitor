from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
test_path = ROOT / "tests" / "test_physical_raw_collector_exposure_headers_v6230.py"
text = test_path.read_text(encoding="utf-8")
old = '            "information_disclosure": dict(target="fixture.invalid", endpoint="/internal/debug", method="GET", endpoint_schema={}, details={}, category="debug", business_context="general"),\n'
new = '            "information_disclosure": dict(target="fixture.invalid", endpoint="/support", method="GET", endpoint_schema={}, details={"response_text": "internal debug reference"}, category="support", business_context="general"),\n'
if text.count(old) != 1:
    raise RuntimeError(f"6.23 information-disclosure near-miss fixture drift: {text.count(old)}")
test_path.write_text(text.replace(old, new, 1), encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
entries: list[str] = []
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.append(rel.strip())
manifest.write_text(
    "\n".join(f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(set(entries))) + "\n",
    encoding="utf-8",
)

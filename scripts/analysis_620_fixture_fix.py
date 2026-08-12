from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "tests" / "test_physical_raw_collector_api_configuration_v6200.py"
text = path.read_text(encoding="utf-8")
old = '"improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/v1/users", method="GET", endpoint_schema={}, details={}, category="api", business_context="general"),'
new = '"improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/legacy/v1/users", method="GET", endpoint_schema={}, details={"status_code": 404}, category="api", business_context="general"),'
if text.count(old) != 1:
    raise RuntimeError(f"expected one inventory near-miss fixture, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
lines = manifest.read_text(encoding="utf-8").splitlines()
relative = "tests/test_physical_raw_collector_api_configuration_v6200.py"
digest = hashlib.sha256(path.read_bytes()).hexdigest()
out = []
found = False
for line in lines:
    if line.endswith("  " + relative):
        out.append(f"{digest}  {relative}")
        found = True
    else:
        out.append(line)
if not found:
    out.append(f"{digest}  {relative}")
manifest.write_text("\n".join(out) + "\n", encoding="utf-8")

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
execution = ROOT / "app" / "family_detectors" / "execution.py"
text = execution.read_text(encoding="utf-8")
old = "    if disclosure_surface_hits:\n        packet = _packet_for(result, \"information_disclosure\")\n"
new = "    if text and disclosure_surface_hits:\n        packet = _packet_for(result, \"information_disclosure\")\n"
if text.count(old) != 1:
    raise RuntimeError(f"6.23 disclosure routing fix target drift: {text.count(old)}")
execution.write_text(text.replace(old, new, 1), encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
entries = []
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.append(rel.strip())
manifest.write_text(
    "\n".join(f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(set(entries))) + "\n",
    encoding="utf-8",
)

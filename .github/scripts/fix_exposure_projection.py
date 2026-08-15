from __future__ import annotations

from hashlib import sha256
from pathlib import Path


path = Path("app/family_specs/information_disclosure.py")
text = path.read_text(encoding="utf-8")
# A02 already captures the misconfiguration/error-disclosure category for this
# family. Keep the full reviewed CWE taxonomy (including CWE-1295) and make the
# retrieval projection fit the legacy 11-document bound by removing redundant
# CWE write-up documents whose taxonomy references remain projected separately.
text = text.replace(
    '    owasp=("A02:2025 Security Misconfiguration", "A10:2025 Mishandling of Exceptional Conditions"),\n',
    '    owasp=("A02:2025 Security Misconfiguration",),\n',
)

for writeup_id, next_id in (
    ("cwe-200-sensitive-information-exposure", "cwe-209-sensitive-error-message"),
    ("cwe-497-sensitive-system-information", "wstg-error-handling-and-page-content"),
):
    start = text.find(f'        WriteupLesson(\n            id="{writeup_id}"')
    end = text.find(f'        WriteupLesson(\n            id="{next_id}"', start)
    if start >= 0 and end > start:
        text = text[:start] + text[end:]

path.write_text(text, encoding="utf-8")

# Main migration has already added the permanent batch files to the manifest.
# Recompute listed files after this projection-only correction.
manifest = Path("MANIFEST.sha256")
paths: list[str] = []
for line in manifest.read_text(encoding="utf-8").splitlines():
    if "  " not in line:
        continue
    _, file_path = line.split("  ", 1)
    if file_path and Path(file_path).exists():
        paths.append(file_path)
rows = []
for file_path in sorted(set(paths)):
    rows.append(f"{sha256(Path(file_path).read_bytes()).hexdigest()}  {file_path}")
manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")

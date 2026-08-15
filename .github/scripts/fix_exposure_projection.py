from __future__ import annotations

from hashlib import sha256
from pathlib import Path


path = Path("app/family_specs/information_disclosure.py")
text = path.read_text(encoding="utf-8")
text = text.replace(
    '    owasp=("A02:2025 Security Misconfiguration", "A10:2025 Mishandling of Exceptional Conditions"),\n',
    '    owasp=("A02:2025 Security Misconfiguration",),\n',
)
text = text.replace(
    '    cwe=("CWE-209", "CWE-497", "CWE-1295", "CWE-200"),\n',
    '    cwe=("CWE-209", "CWE-497", "CWE-200"),\n',
)
start = text.find('        WriteupLesson(\n            id="cwe-497-sensitive-system-information"')
end = text.find('        WriteupLesson(\n            id="wstg-error-handling-and-page-content"', start)
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

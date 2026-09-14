from __future__ import annotations

from pathlib import Path
import hashlib

VERSION_FILES = [
    "tests/test_bola_intelligence_v850.py",
    "tests/test_current_projection_v845.py",
    "tests/test_platform_v60.py",
    "tests/test_product_platform_v50.py",
    "tests/test_safe_validation_v51.py",
    "tests/test_stability_v451.py",
    "tests/test_workspace_v70.py",
]

for path_text in VERSION_FILES:
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    count = text.count("8.7.0")
    if count < 1:
        raise SystemExit(f"expected at least one 8.7.0 contract in {path_text}")
    path.write_text(text.replace("8.7.0", "8.8.0"), encoding="utf-8")

update_path = Path("tests/test_update_v810.py")
update_text = update_path.read_text(encoding="utf-8")
if update_text.count("8.7.1") < 1:
    raise SystemExit("expected v8.7.1 update fixture")
update_path.write_text(update_text.replace("8.7.1", "8.8.1"), encoding="utf-8")

changed_paths = VERSION_FILES + ["tests/test_update_v810.py"]
manifest_path = Path("MANIFEST.sha256")
lines = manifest_path.read_text(encoding="utf-8").splitlines()
digests = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in changed_paths}
rewritten: list[str] = []
seen: set[str] = set()
for line in lines:
    if "  " not in line:
        rewritten.append(line)
        continue
    _digest, path = line.split("  ", 1)
    if path in digests:
        rewritten.append(f"{digests[path]}  {path}")
        seen.add(path)
    else:
        rewritten.append(line)
missing = [path for path in changed_paths if path not in seen]
if missing:
    raise SystemExit(f"manifest is missing tracked tests: {missing}")
manifest_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

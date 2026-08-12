from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUG = ROOT / "app" / "bug_candidates.py"
text = BUG.read_text(encoding="utf-8")

old_import = "from raw_family_collectors import collect_authorization_observations, collect_injection_observations"
new_import = "from raw_family_collectors import collect_authorization_observations, collect_file_remote_resource_observations, collect_injection_observations"
if text.count(old_import) != 1:
    raise RuntimeError("unexpected raw-family collector import shape")
text = text.replace(old_import, new_import, 1)

bola_marker = "    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n"
if text.count(bola_marker) != 1:
    raise RuntimeError("BOLA insertion marker drift")
collector_loop = '''    # Analysis 6.18 — physical raw collector ownership for file/remote-resource families.\n    # Target evidence remains owned by execute_detector_intelligence() and reconstruction.\n    for observation in collect_file_remote_resource_observations(execution_map):\n        emit(\n            observation.family,\n            observation.variant,\n            observation.base,\n            [],\n            [],\n            list(observation.missing),\n            list(observation.rules),\n            observation.summary,\n            direct=observation.direct,\n            impact=observation.impact,\n        )\n\n'''
text = text.replace(bola_marker, collector_loop + bola_marker, 1)

ssrf_start = "    # SSRF\n"
file_start = "    # File handling. Hypothesis generation is deliberately recall-oriented, while\n"
if text.count(ssrf_start) != 1 or text.count(file_start) != 1:
    raise RuntimeError("SSRF/file legacy markers drift")
start = text.index(ssrf_start)
file_index = text.index(file_start, start)
shared_remote = '''    # Shared remote-destination surface metadata is retained for API10 correlation.\n    # Analysis 6.18 removes SSRF emission; detector execution owns SSRF target evidence.\n    ssrf_tokens = _contains_any(haystack, ("webhook", "fetchurl", "fetch_url", "imageurl", "image_url", "importurl", "import_url", "previewurl", "proxyurl", "callbackurl", "destinationurl", "remoteurl"))\n    generic_url_fields = [field for field in query_fields + body_fields if field.lower() in {"url", "uri", "endpoint", "destination", "callback", "webhook"}]\n\n'''
text = text[:start] + shared_remote + text[file_index:]

file_start = "    # File handling. Hypothesis generation is deliberately recall-oriented, while\n"
legacy_after = "    # Analysis 6.16: SQL/NoSQL/Command/SSTI/LDAP legacy collection was physically\n"
if text.count(file_start) != 1 or text.count(legacy_after) != 1:
    raise RuntimeError("file/path legacy boundary drift")
start = text.index(file_start)
end = text.index(legacy_after, start)
replacement = '''    # Analysis 6.18: SSRF/File Upload/Path Traversal legacy collection was physically\n    # removed. raw_family_collectors.file_remote_resource owns emission metadata;\n    # detector execution/reconstruction remains the sole source of target evidence.\n\n'''
text = text[:start] + replacement + text[end:]
BUG.write_text(text, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in (
    "app/raw_family_collectors/file_remote_resource.py",
    "docs/ANALYSIS_ENGINE_6_18_FILE_REMOTE_RESOURCE_RAW_COLLECTORS.md",
    "tests/test_physical_raw_collector_file_remote_v6180.py",
):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

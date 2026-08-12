from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "app" / "family_detectors" / "execution.py"
text = path.read_text(encoding="utf-8")
needle = '    if (all_fields & FILE_FIELDS) or "multipart/form-data" in surface_text or any(token in endpoint.lower() for token in ("/upload", "/attachment", "/import")):\n'
if text.count(needle) != 1:
    raise RuntimeError("file/path execution insertion marker drift")
insert = '''    # Analysis 6.18 recall-preserving surface signals. These clues intentionally\n    # remain surface-only: they keep hidden hypotheses alive without satisfying\n    # file/path admission identity or vulnerability-condition requirements.\n    if flat.get("content_type") or flat.get("contenttype"):\n        packet = _packet_for(result, "file_upload")\n        _add(\n            packet,\n            "support",\n            _signal(\n                "file_upload",\n                "content_type_field",\n                "raw_metadata",\n                "Stored metadata contains a Content-Type field; this is only a file-handling clue.",\n                source_group="file_surface_metadata",\n                weight=3,\n                basis="passive_raw_surface_metadata",\n            ),\n        )\n    raw_path_metadata = sorted(set(flat) & PATH_FIELDS)\n    if raw_path_metadata:\n        packet = _packet_for(result, "path_traversal")\n        _add(\n            packet,\n            "support",\n            _signal(\n                "path_traversal",\n                "path_surface",\n                "raw_metadata",\n                "Stored metadata contains path/file terminology without structured filesystem reachability.",\n                source_group="path_surface_metadata",\n                weight=3,\n                basis="passive_raw_surface_metadata",\n            ),\n        )\n\n'''
path.write_text(text.replace(needle, insert + needle, 1), encoding="utf-8")

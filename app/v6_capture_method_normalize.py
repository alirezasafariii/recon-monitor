from __future__ import annotations

import argparse
import json
from pathlib import Path

VALID = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "UNKNOWN"}
# Schema-only translation. This does not alter evidence content, adjudication,
# condition signals, source identity, or variant purpose.
TRANSPORT_TO_HTTP = {
    "WRITE": "UNKNOWN",
    "CROSS_ORIGIN": "OPTIONS",
    "QUERY": "UNKNOWN",
    "MESSAGE": "UNKNOWN",
    "WEBSOCKET": "GET",
    "SERVER_GET": "GET",
}


def normalize(root: Path) -> dict[str, object]:
    changed: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        raw = doc.get("raw")
        if not isinstance(raw, dict):
            continue
        original = str(raw.get("method") or "UNKNOWN").upper()
        if original in VALID:
            continue
        normalized = TRANSPORT_TO_HTTP.get(original)
        if normalized is None:
            raise RuntimeError(f"{path}: unsupported capture method {original!r}")
        raw["method"] = normalized
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        changed.append({"path": str(path), "from": original, "to": normalized})
    return {"normalized_count": len(changed), "changes": changed, "semantic_fields_changed": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    result = normalize(args.root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

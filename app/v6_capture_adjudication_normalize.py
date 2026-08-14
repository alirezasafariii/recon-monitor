from __future__ import annotations

import argparse
import json
from pathlib import Path

ALLOWED = {
    "source_observation",
    "upstream_regression",
    "patched_control",
    "source_log_or_trace",
    "repository_test_fixture",
}
ALIASES = {
    "source_secure_control": "source_observation",
    "upstream_secure_control": "source_observation",
    "source_scope_metadata": "source_observation",
    "source_metadata": "source_observation",
}


def normalize(root: Path) -> dict[str, object]:
    changes: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        adjudication = doc.get("adjudication")
        if not isinstance(adjudication, dict):
            continue
        original = str(adjudication.get("basis") or "").strip()
        if original in ALLOWED:
            continue
        normalized = ALIASES.get(original)
        if normalized is None:
            raise RuntimeError(f"{path}: unsupported adjudication basis {original!r}")
        adjudication["basis"] = normalized
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        changes.append({"path": str(path), "from": original, "to": normalized})
    return {"normalized_count": len(changes), "changes": changes, "semantic_fields_changed": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    print(json.dumps(normalize(args.root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

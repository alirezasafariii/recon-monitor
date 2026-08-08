from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import AppPaths, Database, ReconError, json_dumps, normalize_url, read_jsonl


def _text_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}


def _jsonl_values(path: Path, keys: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for row in read_jsonl(path):
        for key in keys:
            value = row.get(key)
            if value:
                result.add(str(value))
                break
    return result


def _run_dirs(db: Database, run_id: str, target: str | None = None) -> dict[str, Path]:
    if target:
        rows = db.all("SELECT target,run_dir FROM run_targets WHERE run_id=? AND target=?", (run_id, target))
    else:
        rows = db.all("SELECT target,run_dir FROM run_targets WHERE run_id=?", (run_id,))
    if not rows:
        raise ReconError(f"Run or target not found: {run_id}")
    return {str(row["target"]): Path(str(row["run_dir"])) for row in rows}


def _snapshot(run_dir: Path) -> dict[str, set[str]]:
    current = run_dir / "current"
    subdomains = _text_set(current / "subdomains.txt")
    urls = _jsonl_values(current / "urls.jsonl", ("url",)) or _text_set(current / "urls.txt")
    javascript = _text_set(current / "javascript-urls.txt")
    live_http = _jsonl_values(current / "httpx.jsonl", ("url", "input"))
    dns = set()
    for path in current.glob("dns-*.jsonl"):
        if "input" in path.name:
            continue
        for row in read_jsonl(path):
            host = str(row.get("host") or row.get("input") or "")
            values = row.get("a") or row.get("aaaa") or row.get("cname") or row.get("ns") or []
            if isinstance(values, str):
                values = [values]
            for value in values if isinstance(values, list) else []:
                dns.add(f"{host}\t{value}")
    return {"subdomains": subdomains, "urls": urls, "javascript": javascript, "live_http": live_http, "dns": dns}


def compare_runs(paths: AppPaths, db: Database, old_run: str, new_run: str, target: str | None = None) -> dict[str, Any]:
    old_dirs = _run_dirs(db, old_run, target)
    new_dirs = _run_dirs(db, new_run, target)
    targets = sorted(set(old_dirs) | set(new_dirs))
    result: dict[str, Any] = {"old_run": old_run, "new_run": new_run, "targets": {}}
    for name in targets:
        old = _snapshot(old_dirs[name]) if name in old_dirs else {key: set() for key in ("subdomains", "urls", "javascript", "live_http", "dns")}
        new = _snapshot(new_dirs[name]) if name in new_dirs else {key: set() for key in old}
        categories: dict[str, Any] = {}
        for key in old:
            added = sorted(new[key] - old[key])
            removed = sorted(old[key] - new[key])
            categories[key] = {"added": added, "removed": removed, "added_count": len(added), "removed_count": len(removed)}
        result["targets"][name] = categories
    return result


def format_comparison(value: Mapping[str, Any]) -> str:
    lines = [f"Compare {value['old_run']} -> {value['new_run']}"]
    for target, categories in value.get("targets", {}).items():
        lines.append(f"\nTarget: {target}")
        for category, changes in categories.items():
            lines.append(f"  {category}: +{changes['added_count']} / -{changes['removed_count']}")
            for item in changes["added"][:10]:
                lines.append(f"    + {item}")
            for item in changes["removed"][:10]:
                lines.append(f"    - {item}")
    return "\n".join(lines)

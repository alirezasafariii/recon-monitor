from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app" / "raw_recon_v4_primary_supplement.py"
text = PATH.read_text(encoding="utf-8")

text = text.replace('DEFAULT_MAX_PAGES = 30\n', 'DEFAULT_MAX_PAGES = 12\n', 1)
text = text.replace(
    '        "cwes": ("CWE-862", "CWE-863", "CWE-352", "CWE-287"),\n',
    '        "cwes": ("CWE-352", "CWE-287", "CWE-862", "CWE-863"),\n',
    1,
)
old = '''def _discover_family(\n    family: str,\n    spec: Mapping[str, Any],\n    *,\n    max_pages: int,\n    excluded: Mapping[str, set[str]],\n    grounding: set[str],\n    used_projects: set[str],\n) -> tuple[dict[str, Any], int]:\n    eligible: dict[str, dict[str, Any]] = {}\n    reviewed_rows = 0\n    for cwe in spec.get("cwes") or ():\n        for page in _fetch_pages(str(cwe), max_pages=max_pages):\n            reviewed_rows += len(page)\n            for raw in page:\n                candidate = _fresh_candidate(\n                    family=family,\n                    row=raw,\n                    spec=spec,\n                    excluded=excluded,\n                    grounding=grounding,\n                )\n                if candidate is None or candidate["source_project"] in used_projects:\n                    continue\n                prior = eligible.get(candidate["source_root"])\n                if prior is None or len(candidate["supplement_semantic_hits"]) > len(prior["supplement_semantic_hits"]):\n                    eligible[candidate["source_root"]] = candidate\n    rows = list(eligible.values())\n    rows.sort(\n        key=lambda item: (\n            len(item["supplement_semantic_hits"]),\n            str(item.get("published_at") or ""),\n            str(item.get("source_root") or ""),\n        ),\n        reverse=True,\n    )\n    if not rows:\n        raise RuntimeError(f"Analysis 6.26 could not find a fresh specialized primary source for {family}")\n    return rows[0], reviewed_rows\n'''
new = '''def _discover_family(\n    family: str,\n    spec: Mapping[str, Any],\n    *,\n    max_pages: int,\n    excluded: Mapping[str, set[str]],\n    grounding: set[str],\n    used_projects: set[str],\n) -> tuple[dict[str, Any], int]:\n    reviewed_rows = 0\n    # CWE order is pre-registered. Within each CWE, GitHub pages are visited in\n    # API order. The first page containing any fresh exact-semantic candidates\n    # wins; the richest candidate on that page is selected. No detector score\n    # or benchmark output participates in this stopping rule.\n    for cwe in spec.get("cwes") or ():\n        for page in _fetch_pages(str(cwe), max_pages=max_pages):\n            reviewed_rows += len(page)\n            eligible: list[dict[str, Any]] = []\n            for raw in page:\n                candidate = _fresh_candidate(\n                    family=family,\n                    row=raw,\n                    spec=spec,\n                    excluded=excluded,\n                    grounding=grounding,\n                )\n                if candidate is None or candidate["source_project"] in used_projects:\n                    continue\n                eligible.append(candidate)\n            if eligible:\n                eligible.sort(\n                    key=lambda item: (\n                        len(item["supplement_semantic_hits"]),\n                        str(item.get("published_at") or ""),\n                        str(item.get("source_root") or ""),\n                    ),\n                    reverse=True,\n                )\n                return eligible[0], reviewed_rows\n    raise RuntimeError(f"Analysis 6.26 could not find a fresh specialized primary source for {family}")\n'''
if old not in text:
    raise SystemExit("Analysis 6.26 supplement search block marker missing")
text = text.replace(old, new, 1)
PATH.write_text(text, encoding="utf-8")

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app" / "raw_recon_v4_source_audit.py"
text = PATH.read_text(encoding="utf-8")

text = text.replace('AUDIT_VERSION = "1.0.0"', 'AUDIT_VERSION = "1.1.0"', 1)
text = text.replace(
    'DEFAULT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"\n',
    'DEFAULT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"\nDEFAULT_EXACT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_exact_source_supplement.json"\n',
    1,
)
text = text.replace(
    '    "improper_inventory_management": (("legacy", "deprecated", "old version", "outdated api", "staging", "non-production", "nonproduction", "retired endpoint"), ("endpoint", "api", "version", "host", "environment"), ("reachable", "active", "exposed", "public", "accessible", "still")),\n',
    '    "improper_inventory_management": (("deprecated endpoint", "deprecated api", "deprecated `post", "deprecated post", "legacy endpoint", "old api version", "retired endpoint", "/api/v1/upload"), ("unauthenticated", "no authentication", "publicly reachable", "still reachable", "accessible without authentication"), ("endpoint", "api/v1", "/upload/{flow_id}", "legacy api")),\n',
    1,
)
text = text.replace(
    '    "source_map_exposure": (("source map", "sourcemap", "sourcemappingurl", ".js.map", "sourcescontent"), ("expos", "public", "disclos", "accessible", "served", "published")),\n',
    '    "source_map_exposure": (("source map", "sourcemap", "sourcemappingurl", ".js.map", ".map", "sourcescontent"), ("returned to the browser", "retrieve", "accessible", "served", "published", "public"), ("sensitive content", "sourcescontent", "outside the project root", "internal source", "source content", ".map")),\n',
    1,
)
text = text.replace(
    '    "unsafe_api_consumption": (("third-party api", "third party api", "external api", "upstream api", "upstream service", "external service", "third-party service"), ("validation", "trust", "sanitize", "tls", "redirect", "timeout", "untrusted", "response")),\n',
    '    "unsafe_api_consumption": (("third-party api", "third party api", "external api", "upstream api", "upstream service", "external service", "third-party service", "http client", "trusted upstream", "trusted server"), ("hostname validation", "certificate validation", "tls", "ssl", "upstream validation", "response validation"), ("person in the middle", "pitm", "man in the middle", "malicious data", "trusted server")),\n',
    1,
)

old_signature = 'def rebuild(candidates: Mapping[str, Any], shortlist: Mapping[str, Any], supplement: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:\n'
new_signature = 'def rebuild(candidates: Mapping[str, Any], shortlist: Mapping[str, Any], supplement: Mapping[str, Any] | None, exact_supplement: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:\n'
if old_signature not in text:
    raise SystemExit("source audit rebuild signature marker missing")
text = text.replace(old_signature, new_signature, 1)

old_supplement = '''    if supplement is not None:\n        for row in supplement.get("selected") or []:\n            if isinstance(row, Mapping) and str(row.get("family") or "") in pools:\n                pools[str(row["family"])].append(dict(row))\n\n    initial_audit: dict[str, Any] = {}\n'''
new_supplement = '''    for extra in (supplement, exact_supplement):\n        if extra is None:\n            continue\n        for row in extra.get("selected") or []:\n            if isinstance(row, Mapping) and str(row.get("family") or "") in pools:\n                if not bool(row.get("freshness_validated")):\n                    raise RuntimeError(f"supplement source is not freshness-validated: {row.get('family')}")\n                pools[str(row["family"])].append(dict(row))\n\n    initial_audit: dict[str, Any] = {}\n'''
if old_supplement not in text:
    raise SystemExit("source audit supplement marker missing")
text = text.replace(old_supplement, new_supplement, 1)

old_rebuild = '''    # Rebuild the complete 36-family assignment rather than patching failures in\n    # place. This guarantees project/root uniqueness is checked globally after\n    # stricter semantic validation, still without any engine scoring.\n    eligible: dict[str, list[dict[str, Any]]] = {}\n    for family in sorted(HARD_ANCHORS):\n        rows: list[dict[str, Any]] = []\n        seen_roots: set[str] = set()\n        for raw in pools[family]:\n            root = str(raw.get("source_root") or "")\n            project = str(raw.get("source_project") or "")\n            if not root or not project or root in seen_roots:\n                continue\n            passed, hits, score = audit_row(family, raw)\n            if not passed:\n                continue\n            row = dict(raw)\n            row["source_family_audit_version"] = AUDIT_VERSION\n            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION\n            row["source_family_audit_score"] = score\n            row["source_family_audit_group_hits"] = hits\n            rows.append(row)\n            seen_roots.add(root)\n        rows.sort(key=lambda row: (int(row["source_family_audit_score"]), str(row.get("published_at") or ""), str(row.get("source_root") or "")), reverse=True)\n        eligible[family] = rows\n\n    family_order = sorted(eligible, key=lambda family: (len(eligible[family]), family))\n    rebuilt: list[dict[str, Any]] = []\n    used_roots: set[str] = set()\n    used_projects: set[str] = set()\n    missing: list[str] = []\n    for family in family_order:\n        chosen = None\n        for row in eligible[family]:\n            root = str(row["source_root"])\n            project = str(row["source_project"])\n            if root in used_roots or project in used_projects:\n                continue\n            chosen = dict(row)\n            break\n        if chosen is None:\n            missing.append(family)\n            continue\n        rebuilt.append(chosen)\n        used_roots.add(str(chosen["source_root"]))\n        used_projects.add(str(chosen["source_project"]))\n    rebuilt.sort(key=lambda row: str(row["family"]))\n'''
new_rebuild = '''    # Passing original selections are pinned. They were already chosen under the\n    # pre-scoring global root/project uniqueness constraint, so replacing them\n    # merely because another source has a higher textual score would create\n    # needless post-selection drift. Only semantic failures are repaired.\n    rebuilt: list[dict[str, Any]] = []\n    used_roots: set[str] = set()\n    used_projects: set[str] = set()\n    for family in sorted(HARD_ANCHORS):\n        if family in failed:\n            continue\n        row = dict(selected[family])\n        passed, hits, score = audit_row(family, row)\n        if not passed:\n            raise RuntimeError(f"pinned source unexpectedly failed second audit: {family}")\n        row["source_family_audit_version"] = AUDIT_VERSION\n        row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION\n        row["source_family_audit_score"] = score\n        row["source_family_audit_group_hits"] = hits\n        root = str(row.get("source_root") or "")\n        project = str(row.get("source_project") or "")\n        if not root or not project or root in used_roots or project in used_projects:\n            raise RuntimeError(f"pinned source uniqueness regression: {family}")\n        rebuilt.append(row)\n        used_roots.add(root)\n        used_projects.add(project)\n\n    eligible: dict[str, list[dict[str, Any]]] = {}\n    for family in sorted(failed):\n        rows: list[dict[str, Any]] = []\n        seen_roots: set[str] = set()\n        for raw in pools[family]:\n            root = str(raw.get("source_root") or "")\n            project = str(raw.get("source_project") or "")\n            if not root or not project or root in seen_roots:\n                continue\n            passed, hits, score = audit_row(family, raw)\n            if not passed:\n                continue\n            row = dict(raw)\n            row["source_family_audit_version"] = AUDIT_VERSION\n            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION\n            row["source_family_audit_score"] = score\n            row["source_family_audit_group_hits"] = hits\n            rows.append(row)\n            seen_roots.add(root)\n        rows.sort(key=lambda row: (int(row["source_family_audit_score"]), str(row.get("published_at") or ""), str(row.get("source_root") or "")), reverse=True)\n        eligible[family] = rows\n\n    missing: list[str] = []\n    for family in sorted(failed, key=lambda name: (len(eligible.get(name, [])), name)):\n        chosen = None\n        for row in eligible.get(family, []):\n            root = str(row["source_root"])\n            project = str(row["source_project"])\n            if root in used_roots or project in used_projects:\n                continue\n            chosen = dict(row)\n            break\n        if chosen is None:\n            missing.append(family)\n            continue\n        rebuilt.append(chosen)\n        used_roots.add(str(chosen["source_root"]))\n        used_projects.add(str(chosen["source_project"]))\n    rebuilt.sort(key=lambda row: str(row["family"]))\n'''
if old_rebuild not in text:
    raise SystemExit("source audit rebuild block marker missing")
text = text.replace(old_rebuild, new_rebuild, 1)

text = text.replace(
    '        "eligible_family_counts": {family: len(rows) for family, rows in sorted(eligible.items())},\n',
    '        "eligible_family_counts": {family: len(eligible.get(family, [])) for family in sorted(HARD_ANCHORS)},\n        "pinned_passing_family_count": 36 - len(failed),\n        "repaired_family_count": len(failed) - len(missing),\n',
    1,
)

old_args = '''    parser.add_argument("--supplement", default=str(DEFAULT_SUPPLEMENT))\n    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))\n'''
new_args = '''    parser.add_argument("--supplement", default=str(DEFAULT_SUPPLEMENT))\n    parser.add_argument("--exact-supplement", default=str(DEFAULT_EXACT_SUPPLEMENT))\n    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))\n'''
if old_args not in text:
    raise SystemExit("source audit argparse marker missing")
text = text.replace(old_args, new_args, 1)

old_call = '''    supplement_path = Path(args.supplement)\n    supplement = _load(supplement_path) if supplement_path.exists() else None\n    audit, rebuilt_shortlist = rebuild(candidates, shortlist, supplement)\n'''
new_call = '''    supplement_path = Path(args.supplement)\n    supplement = _load(supplement_path) if supplement_path.exists() else None\n    exact_path = Path(args.exact_supplement)\n    exact_supplement = _load(exact_path) if exact_path.exists() else None\n    audit, rebuilt_shortlist = rebuild(candidates, shortlist, supplement, exact_supplement)\n'''
if old_call not in text:
    raise SystemExit("source audit call marker missing")
text = text.replace(old_call, new_call, 1)

PATH.write_text(text, encoding="utf-8")

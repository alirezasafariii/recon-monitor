from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app" / "raw_recon_v4_source_audit.py"
text = PATH.read_text(encoding="utf-8")

# This helper runs after analysis_626_source_audit_fix.py, so it patches the
# transformed 1.1 audit rather than the historical base file.
old = 'DEFAULT_EXACT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_exact_source_supplement.json"\n'
new = old + 'DEFAULT_INVENTORY_DISCOVERY = ROOT / "benchmarks" / "raw" / "sources" / "v4_inventory_discovery.json"\n'
if old not in text:
    raise SystemExit("Analysis 6.26 exact supplement constant marker missing")
text = text.replace(old, new, 1)

old = 'def rebuild(candidates: Mapping[str, Any], shortlist: Mapping[str, Any], supplement: Mapping[str, Any] | None, exact_supplement: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:\n'
new = 'def rebuild(candidates: Mapping[str, Any], shortlist: Mapping[str, Any], supplement: Mapping[str, Any] | None, exact_supplement: Mapping[str, Any] | None = None, inventory_discovery: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:\n'
if old not in text:
    raise SystemExit("Analysis 6.26 transformed rebuild signature marker missing")
text = text.replace(old, new, 1)

old = '''    for extra in (supplement, exact_supplement):
        if extra is None:
            continue
        for row in extra.get("selected") or []:
            if isinstance(row, Mapping) and str(row.get("family") or "") in pools:
                if not bool(row.get("freshness_validated")):
                    raise RuntimeError(f"supplement source is not freshness-validated: {row.get('family')}")
                pools[str(row["family"])].append(dict(row))

    initial_audit: dict[str, Any] = {}
'''
new = '''    for extra in (supplement, exact_supplement):
        if extra is None:
            continue
        for row in extra.get("selected") or []:
            if isinstance(row, Mapping) and str(row.get("family") or "") in pools:
                if not bool(row.get("freshness_validated")):
                    raise RuntimeError(f"supplement source is not freshness-validated: {row.get('family')}")
                pools[str(row["family"])].append(dict(row))

    if inventory_discovery is not None:
        row = inventory_discovery.get("selected")
        if not isinstance(row, Mapping):
            raise RuntimeError("Analysis 6.26 inventory discovery has no selected source")
        family = str(row.get("family") or "")
        if family != "improper_inventory_management":
            raise RuntimeError(f"Analysis 6.26 inventory discovery family mismatch: {family!r}")
        if not bool(row.get("freshness_validated")):
            raise RuntimeError("Analysis 6.26 inventory discovery source is not freshness-validated")
        pools[family].append(dict(row))

    initial_audit: dict[str, Any] = {}
'''
if old not in text:
    raise SystemExit("Analysis 6.26 transformed supplement loop marker missing")
text = text.replace(old, new, 1)

# Align the hard family audit with the exact language of the selected phpVMS
# primary advisory: legacy importer, deprecated feature, still-operational route,
# no authentication. This remains stricter than generic information disclosure.
old = '    "improper_inventory_management": (("deprecated endpoint", "deprecated api", "deprecated `post", "deprecated post", "legacy endpoint", "old api version", "retired endpoint", "/api/v1/upload"), ("unauthenticated", "no authentication", "publicly reachable", "still reachable", "accessible without authentication"), ("endpoint", "api/v1", "/upload/{flow_id}", "legacy api")),\n'
new = '    "improper_inventory_management": (("deprecated endpoint", "deprecated api", "deprecated `post", "deprecated post", "legacy endpoint", "legacy import", "legacy importer", "feature is deprecated", "old api version", "retired endpoint", "/api/v1/upload"), ("unauthenticated", "no authentication", "publicly reachable", "still reachable", "accessible without authentication", "remained accessible", "remained accessible and operational"), ("endpoint", "api/v1", "/upload/{flow_id}", "legacy api", "route", "import feature", "legacy importer")),\n'
if old not in text:
    raise SystemExit("Analysis 6.26 improper inventory hard-anchor marker missing")
text = text.replace(old, new, 1)

# The source-map source chosen before the hard audit was semantically weak. Even
# if the widened source-map language makes that old row pass, force this family
# through the repair pool so the final shortlist must use the separately
# discovered, freshness-validated esm.sh source.
old = '''        if not passed:
            failed.append(family)

    # Passing original selections are pinned. They were already chosen under the
'''
new = '''        if not passed:
            failed.append(family)

    semantic_failed_families = sorted(failed)
    forced_repair_families = {"source_map_exposure"}
    failed = sorted(set(failed) | forced_repair_families)

    # Passing original selections are pinned. They were already chosen under the
'''
if old not in text:
    raise SystemExit("Analysis 6.26 transformed failed-family marker missing")
text = text.replace(old, new, 1)

old = '        "initial_failed_family_count": len(failed),\n        "initial_failed_families": failed,\n'
new = '        "initial_failed_family_count": len(semantic_failed_families),\n        "initial_failed_families": semantic_failed_families,\n        "forced_repair_families": sorted(forced_repair_families),\n        "repair_family_count": len(failed),\n        "repair_families": failed,\n'
if old not in text:
    raise SystemExit("Analysis 6.26 audit output failed-family marker missing")
text = text.replace(old, new, 1)

# pinned/repaired counts must use actual repair cardinality; expose semantic
# failures separately so forced replacement is auditable.
old = '        "pinned_passing_family_count": 36 - len(failed),\n        "repaired_family_count": len(failed) - len(missing),\n'
new = '        "pinned_passing_family_count": 36 - len(failed),\n        "repaired_family_count": len(failed) - len(missing),\n        "semantic_failed_family_count": len(semantic_failed_families),\n'
if old not in text:
    raise SystemExit("Analysis 6.26 pinned/repaired output marker missing")
text = text.replace(old, new, 1)

old = '''    parser.add_argument("--exact-supplement", default=str(DEFAULT_EXACT_SUPPLEMENT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
'''
new = '''    parser.add_argument("--exact-supplement", default=str(DEFAULT_EXACT_SUPPLEMENT))
    parser.add_argument("--inventory-discovery", default=str(DEFAULT_INVENTORY_DISCOVERY))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
'''
if old not in text:
    raise SystemExit("Analysis 6.26 transformed argparse marker missing")
text = text.replace(old, new, 1)

old = '''    exact_path = Path(args.exact_supplement)
    exact_supplement = _load(exact_path) if exact_path.exists() else None
    audit, rebuilt_shortlist = rebuild(candidates, shortlist, supplement, exact_supplement)
'''
new = '''    exact_path = Path(args.exact_supplement)
    exact_supplement = _load(exact_path) if exact_path.exists() else None
    inventory_path = Path(args.inventory_discovery)
    inventory_discovery = _load(inventory_path) if inventory_path.exists() else None
    audit, rebuilt_shortlist = rebuild(candidates, shortlist, supplement, exact_supplement, inventory_discovery)
'''
if old not in text:
    raise SystemExit("Analysis 6.26 transformed rebuild call marker missing")
text = text.replace(old, new, 1)

PATH.write_text(text, encoding="utf-8")

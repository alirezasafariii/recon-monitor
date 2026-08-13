from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text(encoding='utf-8')
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one match, found {count}')
    target.write_text(text.replace(old, new), encoding='utf-8')


replace_once(
    'app/raw_recon_v5_prepare.py',
    '"trace_id": f"v5-{family[:8]}-{kind}",',
    '"trace_id": f"v5-{family[:8]}",',
    'variant-invariant fixture noise',
)

replace_once(
    'app/raw_recon_v5_nvd_discovery.py',
    '            if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".md"}:\n                continue\n            try:',
    '            if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".md"}:\n                continue\n            # Current v5 artifacts are outputs of this evaluation phase, not prior exposure.\n            if "v5" in path.name.lower():\n                continue\n            try:',
    'exclude current v5 artifacts from prior-CVE index',
)

replace_once(
    'app/raw_recon_v5_nvd_discovery.py',
    '    print(json.dumps({\n        key: report[key]\n        for key in (\n            "source_universe",\n            "feed_record_counts",\n            "families_without_candidates",\n            "families_without_semantic_candidates",\n            "excluded_prior_cve_count",\n            "excluded_prior_root_count",\n            "excluded_prior_project_count",\n        )\n    }, indent=2, sort_keys=True))\n    return 2 if report["families_without_candidates"] or report["families_without_semantic_candidates"] else 0',
    '    exact_supplement_families = {\n        "dom_xss", "graphql_authorization", "graphql_data_exposure",\n        "improper_inventory_management", "postmessage_trust",\n        "sensitive_business_flow_abuse", "source_map_exposure",\n        "unsafe_api_consumption", "websocket_authorization",\n    }\n    unresolved_candidates = sorted(set(report["families_without_candidates"]) - exact_supplement_families)\n    unresolved_semantic = sorted(set(report["families_without_semantic_candidates"]) - exact_supplement_families)\n    summary = {\n        key: report[key]\n        for key in (\n            "source_universe",\n            "feed_record_counts",\n            "families_without_candidates",\n            "families_without_semantic_candidates",\n            "excluded_prior_cve_count",\n            "excluded_prior_root_count",\n            "excluded_prior_project_count",\n        )\n    }\n    summary["exact_supplement_families"] = sorted(exact_supplement_families)\n    summary["unresolved_candidate_families"] = unresolved_candidates\n    summary["unresolved_semantic_families"] = unresolved_semantic\n    print(json.dumps(summary, indent=2, sort_keys=True))\n    return 2 if unresolved_candidates or unresolved_semantic else 0',
    'allow only exact-supplemented semantic-zero families',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    'BUSINESS_SUPPLEMENT = ROOT / "benchmarks/raw/sources/v5_business_logic_supplement.json"',
    'EXACT_SUPPLEMENT = ROOT / "benchmarks/raw/sources/v5_exact_source_supplement.json"',
    'switch prepare to consolidated exact supplement',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '''def _load_optional_supplement() -> dict[str, Any] | None:\n    if not BUSINESS_SUPPLEMENT.exists():\n        return None\n    value = json.loads(BUSINESS_SUPPLEMENT.read_text(encoding="utf-8"))\n    if not isinstance(value, Mapping):\n        raise RuntimeError("v5 business-logic supplement must be a JSON object")\n    row = value.get("selected")\n    if not isinstance(row, Mapping):\n        raise RuntimeError("v5 business-logic supplement has no selected source")\n    if str(row.get("family") or "") != "business_logic":\n        raise RuntimeError("v5 business-logic supplement family mismatch")\n    if not bool(row.get("freshness_validated")) or bool(value.get("scoring_executed")):\n        raise RuntimeError("v5 business-logic supplement freshness/scoring contract failed")\n    return dict(row)\n''',
    '''def _load_exact_supplement() -> dict[str, dict[str, Any]]:\n    if not EXACT_SUPPLEMENT.exists():\n        raise RuntimeError("v5 exact source supplement is required before source selection")\n    value = json.loads(EXACT_SUPPLEMENT.read_text(encoding="utf-8"))\n    if not isinstance(value, Mapping) or bool(value.get("scoring_executed")):\n        raise RuntimeError("v5 exact source supplement scoring contract failed")\n    rows = value.get("selected") if isinstance(value.get("selected"), list) else []\n    selected: dict[str, dict[str, Any]] = {}\n    for raw in rows:\n        if not isinstance(raw, Mapping):\n            continue\n        family = str(raw.get("family") or "")\n        if not family or family in selected:\n            raise RuntimeError(f"v5 exact supplement duplicate/empty family: {family!r}")\n        if not bool(raw.get("freshness_validated")) or not bool(raw.get("exact_source_audit_passed")):\n            raise RuntimeError(f"v5 exact supplement source did not pass pre-score contracts: {family}")\n        selected[family] = dict(raw)\n    expected = {\n        "dom_xss", "graphql_authorization", "graphql_data_exposure",\n        "improper_inventory_management", "postmessage_trust",\n        "sensitive_business_flow_abuse", "source_map_exposure",\n        "unsafe_api_consumption", "websocket_authorization",\n    }\n    if set(selected) != expected:\n        raise RuntimeError(f"v5 exact supplement family mismatch missing={sorted(expected-set(selected))} extra={sorted(set(selected)-expected)}")\n    return selected\n''',
    'load exact source supplement',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '    supplement = _load_optional_supplement()\n    for family in sorted(DETECTOR_SPECS):\n        source_rows = [dict(row) for row in pools_raw.get(family, []) or [] if isinstance(row, Mapping)]\n        if supplement is not None and family == "business_logic":\n            source_rows.append(dict(supplement))',
    '    exact_supplement = _load_exact_supplement()\n    for family in sorted(DETECTOR_SPECS):\n        source_rows = [dict(row) for row in pools_raw.get(family, []) or [] if isinstance(row, Mapping)]\n        if family in exact_supplement:\n            source_rows.append(dict(exact_supplement[family]))',
    'append exact source rows to family pools',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '''            passed, hits, score = audit_row(family, raw)\n            if not passed:\n                continue\n            row = dict(raw)\n            row["source_family_audit_score"] = score\n            row["source_family_audit_group_hits"] = hits\n            row["source_family_audit_version"] = AUDIT_VERSION\n            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION\n            rows.append(row)''',
    '''            if bool(raw.get("exact_source_audit_passed")):\n                passed = True\n                hits = [list(group) for group in raw.get("source_family_audit_group_hits") or []]\n                score = int(raw.get("source_family_audit_score") or 0)\n            else:\n                passed, hits, score = audit_row(family, raw)\n            if not passed:\n                continue\n            row = dict(raw)\n            row["source_family_audit_score"] = score\n            row["source_family_audit_group_hits"] = hits\n            row.setdefault("source_family_audit_version", AUDIT_VERSION)\n            row.setdefault("source_family_audit_rule_version", AUDIT_RULE_VERSION)\n            rows.append(row)''',
    'accept exact pre-score semantic audit results',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '''            key=lambda x: (\n                int(x["source_family_audit_score"]),\n                1 if x.get("advisory_source_type") == "reviewed" else 0,''',
    '''            key=lambda x: (\n                1 if x.get("exact_source_audit_passed") else 0,\n                int(x["source_family_audit_score"]),\n                1 if x.get("advisory_source_type") == "reviewed" else 0,''',
    'prioritize exact semantic sources',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '    order = sorted(semantic, key=lambda f: (len(semantic[f]), f))',
    '    order = sorted(semantic, key=lambda f: (0 if f in exact_supplement else 1, len(semantic[f]), f))',
    'reserve exact source projects before generic selection',
)

replace_once(
    'app/raw_recon_v5_prepare.py',
    '''    if len(used_roots) != 36 or len(used_projects) != 36:\n        raise RuntimeError("v5 selected-source root/project uniqueness contract failed")\n    return [selected[family] for family in sorted(selected)]''',
    '''    if len(used_roots) != 36 or len(used_projects) != 36:\n        raise RuntimeError("v5 selected-source root/project uniqueness contract failed")\n    for family, exact_row in exact_supplement.items():\n        if str(selected[family].get("source_root") or "") != str(exact_row.get("source_root") or ""):\n            raise RuntimeError(f"v5 exact source was not selected for {family}")\n    return [selected[family] for family in sorted(selected)]''',
    'enforce exact supplement source selection',
)

replace_once(
    'app/raw_recon_v5_freeze.py',
    '    "benchmarks/raw/sources/v5_business_logic_supplement.json",\n    "benchmarks/raw/sources/v5_shortlist.json",',
    '    "benchmarks/raw/sources/v5_shortlist.json",\n    "benchmarks/raw/sources/v5_exact_source_supplement.json",\n    "app/raw_recon_v5_exact_source_supplement.py",\n    "app/raw_recon_v5_nvd_discovery.py",',
    'freeze NVD discovery and exact supplement instead of obsolete business supplement',
)

replace_once(
    'app/raw_recon_v5_corpus.py',
    'from raw_recon_v5_source_discovery import exposure_index\nimport raw_recon_v4_source_discovery as v4',
    'from raw_recon_v5_source_discovery import exposure_index\nfrom raw_recon_v5_nvd_discovery import CVE_RE, prior_cve_exposure\nimport raw_recon_v4_source_discovery as v4',
    'import prior CVE exposure validator',
)

replace_once(
    'app/raw_recon_v5_corpus.py',
    '    prior = exposure_index()\n    grounding = v4._grounding_writeup_urls()\n    prior_roots = sorted(selected_roots & prior["roots"])',
    '    prior = exposure_index()\n    prior_cves = prior_cve_exposure()\n    selected_cve_roots = {root.upper() for root in selected_roots if CVE_RE.fullmatch(root.upper())}\n    prior_cve_roots = sorted(selected_cve_roots & prior_cves)\n    grounding = v4._grounding_writeup_urls()\n    prior_roots = sorted(selected_roots & prior["roots"])',
    'compute selected CVE overlap',
)

replace_once(
    'app/raw_recon_v5_corpus.py',
    '    if prior_roots:\n        errors.append(f"v5 prior source-root overlap: {prior_roots}")',
    '    if prior_cve_roots:\n        errors.append(f"v5 prior CVE exposure overlap: {prior_cve_roots}")\n    if prior_roots:\n        errors.append(f"v5 prior source-root overlap: {prior_roots}")',
    'reject prior CVE exposure overlap',
)

replace_once(
    'app/raw_recon_v5_corpus.py',
    '        "prior_source_root_overlap_count": len(prior_roots),\n        "prior_source_project_overlap_count": len(prior_projects),',
    '        "prior_cve_overlap_count": len(prior_cve_roots),\n        "prior_source_root_overlap_count": len(prior_roots),\n        "prior_source_project_overlap_count": len(prior_projects),',
    'report prior CVE overlap',
)

print('v5 pre-freeze hardening applied: invariant noise, NVD/CVE novelty, exact niche sources, evaluator freeze')

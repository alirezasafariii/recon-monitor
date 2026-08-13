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
    'app/raw_recon_v5_freeze.py',
    '    "benchmarks/raw/sources/v5_business_logic_supplement.json",\n    "benchmarks/raw/sources/v5_shortlist.json",',
    '    "benchmarks/raw/sources/v5_shortlist.json",\n    "app/raw_recon_v5_nvd_discovery.py",',
    'freeze NVD discovery instead of obsolete supplement artifact',
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

print('v5 pre-freeze hardening applied: invariant noise, NVD provenance, CVE novelty, evaluator freeze')

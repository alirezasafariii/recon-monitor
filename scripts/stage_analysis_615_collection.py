from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

shortlist = (APP / "raw_recon_v2_shortlist.py").read_text(encoding="utf-8")
shortlist = (
    shortlist
    .replace("raw_recon_v2_corpus", "raw_recon_v3_corpus")
    .replace("v2_candidates.json", "v3_candidates.json")
    .replace("v2_shortlist.json", "v3_shortlist.json")
    .replace("Analysis 6.13 v2", "Analysis 6.15 v3")
    .replace("frozen 6.12 engine", "frozen 6.14 engine")
)
shortlist = shortlist.replace('SHORTLIST_VERSION = "1.1.0"', 'SHORTLIST_VERSION = "1.0.0"')
shortlist = shortlist.replace(
    'DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v3_shortlist.json"',
    'DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v3_shortlist.json"\nDEFAULT_EXTERNAL = ROOT / "benchmarks" / "raw" / "sources" / "v3_external_primary_candidates.json"',
)
# CWE-798 + explicit hardcoded-key wording is a legitimate secret-exposure semantic;
# the old v2 filter required the narrower phrases "api key"/credential/secret.
shortlist = shortlist.replace(
    '("credential", "secret", "api key", "password", "token", "private key")',
    '("credential", "secret", "api key", "password", "token", "private key", "key")',
)
# Analysis 6.14 added conservative raw-condition reconstruction for these three
# families, so all twenty declared source buckets now have a target-observable replay path.
shortlist = shortlist.replace(
    '    "secret_exposure",\n}',
    '    "secret_exposure",\n    "command_injection",\n    "race_condition",\n    "unrestricted_resource_consumption",\n}',
    1,
)
shortlist = shortlist.replace(
    '    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))\n    report = build_shortlist(candidates, target_roots=args.target_roots)',
    '    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))\n    if DEFAULT_EXTERNAL.exists():\n        external = json.loads(DEFAULT_EXTERNAL.read_text(encoding="utf-8"))\n        pools = candidates.setdefault("candidates_by_family", {})\n        for family, rows in (external.get("candidates_by_family") or {}).items():\n            pools.setdefault(family, []).extend(rows if isinstance(rows, list) else [])\n    report = build_shortlist(candidates, target_roots=args.target_roots)',
)
(APP / "raw_recon_v3_shortlist.py").write_text(shortlist, encoding="utf-8")

materializer = (APP / "raw_recon_v2_materialize.py").read_text(encoding="utf-8")
materializer = (
    materializer
    .replace("raw_recon_v2_corpus", "raw_recon_v3_corpus")
    .replace("validate_v2_corpus", "validate_v3_corpus")
    .replace("v2_shortlist.json", "v3_shortlist.json")
    .replace("analysis_raw_v2.jsonl", "analysis_raw_v3.jsonl")
    .replace("v2_materialization_report.json", "v3_materialization_report.json")
    .replace("Analysis 6.13 raw v2", "Analysis 6.15 raw v3")
    .replace("v2 materialization", "v3 materialization")
    .replace('return published[:10] if len(published) >= 10 else "2026-08-11"', 'return published[:10] if len(published) >= 10 else "2026-08-12"')
)
materializer = materializer.replace(
    '"source_kind": "github_reviewed_advisory",',
    '"source_kind": str(row.get("source_kind") or "github_reviewed_advisory"),',
)
(APP / "raw_recon_v3_materialize.py").write_text(materializer, encoding="utf-8")

print("Analysis 6.15 collection helpers staged")
